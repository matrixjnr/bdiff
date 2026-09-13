mod config;
mod diff;
mod exec;

use config::Config;
use exec::Runner;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

const USAGE: &str = "bdiff: behavioral diff (v0: process boundary only)

USAGE
  bdiff rev  <old-rev> <new-rev> [--repo DIR] [--config FILE] [--json] [--no-trace] [--repeats N]
  bdiff dirs <old-dir> <new-dir>              [--config FILE] [--json] [--no-trace] [--repeats N]
  bdiff accept [--case NAME]... [--repo DIR]

Config (bdiff.toml) is read from the new revision root unless --config is given.
`accept` records the new behavior of changed cases from the last run into
.bdiff/accepted.json (commit it). Accepted deltas are reported but not counted.
Exit code: 0 no behavior change, 1 changes found, 2 error.";

const ACCEPTED: &str = ".bdiff/accepted.json";
const LAST_RUN: &str = ".bdiff/last-run.json";

struct Opts {
    mode: String,
    a: String,
    b: String,
    repo: PathBuf,
    config: Option<PathBuf>,
    json: bool,
    trace: bool,
    repeats: Option<usize>,
    only: Vec<String>,
}

fn parse_args(mut args: impl Iterator<Item = String>) -> Result<Opts, String> {
    let mode = args.next().ok_or(USAGE)?;
    if mode == "-h" || mode == "--help" {
        return Err(USAGE.into());
    }
    let (a, b) = if mode == "accept" {
        (String::new(), String::new())
    } else {
        (args.next().ok_or(USAGE)?, args.next().ok_or(USAGE)?)
    };
    let mut o = Opts {
        mode,
        a,
        b,
        repo: PathBuf::from("."),
        config: None,
        json: false,
        trace: true,
        repeats: None,
        only: Vec::new(),
    };
    while let Some(f) = args.next() {
        match f.as_str() {
            "--repo" => o.repo = PathBuf::from(args.next().ok_or("--repo needs a value")?),
            "--config" => o.config = Some(PathBuf::from(args.next().ok_or("--config needs a value")?)),
            "--json" => o.json = true,
            "--no-trace" => o.trace = false,
            "--repeats" => {
                o.repeats = Some(
                    args.next()
                        .ok_or("--repeats needs a value")?
                        .parse()
                        .map_err(|_| "--repeats must be an integer")?,
                )
            }
            "--case" => o.only.push(args.next().ok_or("--case needs a value")?),
            _ => return Err(format!("unknown flag {f}\n{USAGE}")),
        }
    }
    Ok(o)
}

fn main() {
    let code = match real_main() {
        Ok(changed) => if changed { 1 } else { 0 },
        Err(e) => {
            eprintln!("{e}");
            2
        }
    };
    std::process::exit(code);
}

fn real_main() -> Result<bool, String> {
    let o = parse_args(std::env::args().skip(1))?;
    if o.mode == "accept" {
        return accept(&o).map(|_| false);
    }
    let mut cleanup: Vec<PathBuf> = Vec::new();

    let (old_root, new_root) = match o.mode.as_str() {
        "dirs" => (abs(&o.a)?, abs(&o.b)?),
        "rev" => {
            let repo = abs(&o.repo.to_string_lossy())?;
            let old = worktree(&repo, &o.a)?;
            cleanup.push(old.clone());
            let new = worktree(&repo, &o.b)?;
            cleanup.push(new.clone());
            (old, new)
        }
        m => return Err(format!("unknown mode {m}\n{USAGE}")),
    };

    let result = run(&o, &old_root, &new_root);

    for wt in cleanup {
        let _ = Command::new("git")
            .args(["worktree", "remove", "--force"])
            .arg(&wt)
            .current_dir(&o.repo)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
    }
    result
}

fn run(o: &Opts, old_root: &Path, new_root: &Path) -> Result<bool, String> {
    let cfg_path = o.config.clone().unwrap_or_else(|| new_root.join("bdiff.toml"));
    let cfg = Config::load(&cfg_path)?;
    if cfg.cases.is_empty() {
        return Err("no [[case]] entries in config; nothing to run".into());
    }

    let mut old = Runner::new(old_root.to_path_buf(), cfg.clone(), o.trace)?;
    let mut new = Runner::new(new_root.to_path_buf(), cfg.clone(), o.trace)?;
    if o.mode == "rev" {
        old.reset = Some(exec::Reset::Git);
        new.reset = Some(exec::Reset::Git);
    }

    eprintln!("old: {}", old_root.display());
    old.build()?;
    eprintln!("new: {}", new_root.display());
    new.build()?;

    // Accepted fingerprints travel with the code: read from the new revision.
    let accepted: BTreeMap<String, String> = read_json(&new_root.join(ACCEPTED)).unwrap_or_default();
    let repeats = o.repeats.unwrap_or(cfg.run.repeats).max(1);

    let mut findings = Vec::new();
    for case in &cfg.cases {
        eprintln!("  case: {}", case.name);
        let (a, old_flaky) = run_repeated(&old, case, repeats)?;
        let (b, new_flaky) = run_repeated(&new, case, repeats)?;
        let inp = diff::Inputs {
            case: &case.name,
            expect_exit: &case.expect_exit,
            accepted: accepted.get(&case.name).map(String::as_str),
            old_flaky,
            new_flaky,
        };
        findings.push(diff::compare(&inp, &a, &b));
    }

    let report = diff::Report { old: o.a.clone(), new: o.b.clone(), findings };
    let changed = report.changed() > 0;

    // Persist last run so `bdiff accept` can promote fingerprints.
    let last: BTreeMap<String, LastRunEntry> = report
        .findings
        .iter()
        .map(|f| (f.case.clone(), LastRunEntry { label: f.label, fingerprint: f.fingerprint.clone() }))
        .collect();
    let _ = write_json(&o.repo.join(LAST_RUN), &last);

    if o.json {
        println!("{}", serde_json::to_string_pretty(&report).map_err(|e| e.to_string())?);
    } else {
        report.print_text();
    }
    Ok(changed)
}

/// Run a case `n` times; flaky if the revision disagrees with itself.
fn run_repeated(r: &Runner, case: &config::Case, n: usize) -> Result<(exec::Observation, bool), String> {
    let first = r.run_case(case)?;
    for _ in 1..n {
        let again = r.run_case(case)?;
        if !again.behaves_like(&first) {
            return Ok((first, true));
        }
    }
    Ok((first, false))
}

#[derive(serde::Serialize, serde::Deserialize)]
struct LastRunEntry {
    label: diff::Label,
    fingerprint: String,
}

fn accept(o: &Opts) -> Result<(), String> {
    let last: BTreeMap<String, LastRunEntry> = read_json(&o.repo.join(LAST_RUN))
        .ok_or("no last run found; run bdiff first")?;
    let mut accepted: BTreeMap<String, String> = read_json(&o.repo.join(ACCEPTED)).unwrap_or_default();
    let mut n = 0;
    for (case, e) in &last {
        if !o.only.is_empty() && !o.only.contains(case) {
            continue;
        }
        if e.label.is_change() {
            accepted.insert(case.clone(), e.fingerprint.clone());
            eprintln!("  accepted: {case}");
            n += 1;
        }
    }
    write_json(&o.repo.join(ACCEPTED), &accepted)?;
    eprintln!("{n} accepted -> {}", o.repo.join(ACCEPTED).display());
    Ok(())
}

fn read_json<T: serde::de::DeserializeOwned>(p: &Path) -> Option<T> {
    let text = std::fs::read_to_string(p).ok()?;
    serde_json::from_str(&text).ok()
}

fn write_json<T: serde::Serialize>(p: &Path, v: &T) -> Result<(), String> {
    if let Some(d) = p.parent() {
        std::fs::create_dir_all(d).map_err(|e| e.to_string())?;
    }
    let text = serde_json::to_string_pretty(v).map_err(|e| e.to_string())?;
    std::fs::write(p, text + "\n").map_err(|e| format!("write {}: {e}", p.display()))
}

fn abs(p: &str) -> Result<PathBuf, String> {
    std::fs::canonicalize(p)
        .map(strip_verbatim)
        .map_err(|e| format!("{p}: {e}"))
}

/// Windows canonicalize returns verbatim paths (\\?\C:\...). Children print
/// plain paths, so keep the plain form or $ROOT normalisation never matches.
fn strip_verbatim(p: PathBuf) -> PathBuf {
    let s = p.to_string_lossy();
    match s.strip_prefix(r"\\?\") {
        Some(rest) if !rest.starts_with("UNC") => PathBuf::from(rest),
        _ => p,
    }
}

fn worktree(repo: &Path, rev: &str) -> Result<PathBuf, String> {
    let sha = git(repo, &["rev-parse", "--short", rev])?;
    let dir = std::env::temp_dir().join(format!("bdiff-wt-{}-{}", sha.trim(), std::process::id()));
    git(repo, &["worktree", "add", "--detach", "-q", &dir.to_string_lossy(), rev])?;
    Ok(dir)
}

fn git(repo: &Path, args: &[&str]) -> Result<String, String> {
    let out = Command::new("git")
        .args(args)
        .current_dir(repo)
        .output()
        .map_err(|e| format!("git: {e}"))?;
    if !out.status.success() {
        return Err(format!("git {:?}: {}", args, String::from_utf8_lossy(&out.stderr)));
    }
    Ok(String::from_utf8_lossy(&out.stdout).to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(args: &[&str]) -> Result<Opts, String> {
        parse_args(args.iter().map(|s| s.to_string()))
    }

    #[test]
    fn parses_modes_and_flags() {
        let o = parse(&["rev", "HEAD~1", "HEAD", "--json", "--repeats", "3"]).unwrap();
        assert_eq!(o.mode, "rev");
        assert_eq!((o.a.as_str(), o.b.as_str()), ("HEAD~1", "HEAD"));
        assert!(o.json);
        assert!(o.trace);
        assert_eq!(o.repeats, Some(3));

        let o = parse(&["dirs", "a", "b", "--no-trace"]).unwrap();
        assert!(!o.trace);
        assert!(!o.json);
    }

    #[test]
    fn accept_takes_case_filters() {
        let o = parse(&["accept", "--case", "x", "--case", "y"]).unwrap();
        assert_eq!(o.mode, "accept");
        assert_eq!(o.only, vec!["x", "y"]);
    }

    #[test]
    fn rejects_bad_input() {
        assert!(parse(&[]).is_err());
        assert!(parse(&["rev", "only-one"]).is_err());
        assert!(parse(&["dirs", "a", "b", "--wat"]).is_err());
        assert!(parse(&["dirs", "a", "b", "--repeats", "many"]).is_err());
        assert!(parse(&["--help"]).is_err());
    }

    #[test]
    fn strips_windows_verbatim_prefix() {
        assert_eq!(strip_verbatim(PathBuf::from(r"\\?\C:\repo")), PathBuf::from(r"C:\repo"));
        assert_eq!(
            strip_verbatim(PathBuf::from(r"\\?\UNC\srv\share")),
            PathBuf::from(r"\\?\UNC\srv\share")
        );
        assert_eq!(strip_verbatim(PathBuf::from("/plain/unix")), PathBuf::from("/plain/unix"));
    }
}
