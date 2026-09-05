mod config;
mod diff;
mod exec;

use config::Config;
use exec::Runner;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

const USAGE: &str = "bdiff — behavioral diff (v0: process boundary only)

USAGE
  bdiff rev  <old-rev> <new-rev> [--repo DIR] [--config FILE] [--json] [--no-trace]
  bdiff dirs <old-dir> <new-dir>              [--config FILE] [--json] [--no-trace]

Config (bdiff.toml) is read from the new revision root unless --config is given.
Exit code: 0 no behavior change, 1 changes found, 2 error.";

struct Opts {
    mode: String,
    a: String,
    b: String,
    repo: PathBuf,
    config: Option<PathBuf>,
    json: bool,
    trace: bool,
}

fn parse_args() -> Result<Opts, String> {
    let mut args = std::env::args().skip(1);
    let mode = args.next().ok_or(USAGE)?;
    if mode == "-h" || mode == "--help" {
        return Err(USAGE.into());
    }
    let a = args.next().ok_or(USAGE)?;
    let b = args.next().ok_or(USAGE)?;
    let mut o = Opts {
        mode,
        a,
        b,
        repo: PathBuf::from("."),
        config: None,
        json: false,
        trace: true,
    };
    while let Some(f) = args.next() {
        match f.as_str() {
            "--repo" => o.repo = PathBuf::from(args.next().ok_or("--repo needs a value")?),
            "--config" => o.config = Some(PathBuf::from(args.next().ok_or("--config needs a value")?)),
            "--json" => o.json = true,
            "--no-trace" => o.trace = false,
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
    let o = parse_args()?;
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

    let old = Runner::new(old_root.to_path_buf(), cfg.clone(), o.trace)?;
    let new = Runner::new(new_root.to_path_buf(), cfg.clone(), o.trace)?;

    eprintln!("old: {}", old_root.display());
    old.build()?;
    eprintln!("new: {}", new_root.display());
    new.build()?;

    let mut findings = Vec::new();
    for case in &cfg.cases {
        eprintln!("  case: {}", case.name);
        let a = old.run_case(case)?;
        let b = new.run_case(case)?;
        findings.push(diff::compare(&case.name, &a, &b));
    }

    let report = diff::Report { old: o.a.clone(), new: o.b.clone(), findings };
    let changed = report.findings.iter().any(|f| f.label != diff::Label::Unchanged);
    if o.json {
        println!("{}", serde_json::to_string_pretty(&report).map_err(|e| e.to_string())?);
    } else {
        report.print_text();
    }
    Ok(changed)
}

fn abs(p: &str) -> Result<PathBuf, String> {
    std::fs::canonicalize(p).map_err(|e| format!("{p}: {e}"))
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
