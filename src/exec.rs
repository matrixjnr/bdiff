use crate::config::{Case, Config};
use regex::Regex;
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet};
use std::hash::{Hash, Hasher};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

/// Everything we observed about one invocation at the process boundary.
#[derive(Debug, Serialize, Clone, PartialEq, Eq)]
pub struct Observation {
    pub exit: Option<i32>,
    pub stdout: String,
    pub stderr: String,
    pub fs: FsDelta,
    pub syscalls: SyscallSummary,
}

#[derive(Debug, Serialize, Clone, PartialEq, Eq, Default)]
pub struct FsDelta {
    pub created: Vec<String>,
    pub modified: Vec<String>,
    pub deleted: Vec<String>,
    /// Trace mode: paths under $ROOT opened for writing / unlinked / renamed.
    pub written: Vec<String>,
}

#[derive(Debug, Serialize, Clone, PartialEq, Eq, Default)]
pub struct SyscallSummary {
    pub available: bool,
    pub counts: BTreeMap<String, u64>,
    pub writes: BTreeSet<String>,
    pub connects: BTreeSet<String>,
    pub execs: BTreeSet<String>,
}

impl Observation {
    /// Stable hash of the behavioral subset (excludes syscall counts).
    pub fn fingerprint(&self) -> String {
        use std::collections::hash_map::DefaultHasher;
        let mut h = DefaultHasher::new();
        self.exit.hash(&mut h);
        self.stdout.hash(&mut h);
        self.stderr.hash(&mut h);
        self.fs.created.hash(&mut h);
        self.fs.modified.hash(&mut h);
        self.fs.deleted.hash(&mut h);
        self.fs.written.hash(&mut h);
        self.syscalls.writes.hash(&mut h);
        self.syscalls.connects.hash(&mut h);
        self.syscalls.execs.hash(&mut h);
        format!("{:016x}", h.finish())
    }

    pub fn behaves_like(&self, o: &Observation) -> bool {
        self.fingerprint() == o.fingerprint()
    }
}

pub struct Runner {
    pub root: PathBuf,
    pub cfg: Config,
    normalisers: Vec<Regex>,
    trace: bool,
    /// If set, restore the tree to this state before every case run so
    /// repeats and cases never see each other's side effects.
    pub reset: Option<Reset>,
}

pub enum Reset {
    Git,
}

impl Runner {
    pub fn new(root: PathBuf, cfg: Config, trace: bool) -> Result<Runner, String> {
        let mut normalisers = Vec::new();
        for p in &cfg.normalise.patterns {
            normalisers.push(Regex::new(p).map_err(|e| format!("normalise pattern {p:?}: {e}"))?);
        }
        let trace = if trace && being_traced() {
            eprintln!("  warn: already under a tracer (nested ptrace unsupported); syscall tracing disabled");
            false
        } else {
            trace
        };
        Ok(Runner { root, cfg, normalisers, trace, reset: None })
    }

    fn reset_tree(&self) -> Result<(), String> {
        let Some(Reset::Git) = &self.reset else { return Ok(()) };
        let mut clean = Command::new("git");
        clean.args(["clean", "-fdxq"]);
        for i in &self.cfg.fs.ignore {
            clean.arg("-e").arg(i);
        }
        for (name, mut cmd) in [("clean", clean), ("checkout", {
            let mut c = Command::new("git");
            c.args(["checkout", "-q", "--", "."]);
            c
        })] {
            let st = cmd
                .current_dir(&self.root)
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status()
                .map_err(|e| format!("git {name}: {e}"))?;
            if !st.success() {
                return Err(format!("git {name} failed in {}", self.root.display()));
            }
        }
        Ok(())
    }

    pub fn build(&self) -> Result<(), String> {
        let Some(cmd) = &self.cfg.build.cmd else { return Ok(()) };
        eprintln!("  build: {cmd}");
        let st = shell(cmd)
            .current_dir(&self.root)
            .stdout(Stdio::null())
            .stderr(Stdio::inherit())
            .status()
            .map_err(|e| format!("spawn build: {e}"))?;
        if !st.success() {
            return Err(format!("build failed in {}", self.root.display()));
        }
        Ok(())
    }

    pub fn run_case(&self, case: &Case) -> Result<Observation, String> {
        let cmd = case
            .cmd
            .as_ref()
            .or(self.cfg.run.cmd.as_ref())
            .ok_or("no run.cmd and case has no cmd")?;
        let mut argv: Vec<String> = cmd.split_whitespace().map(String::from).collect();
        argv.extend(case.args.iter().cloned());
        if argv.is_empty() {
            return Err("empty command".into());
        }
        let cwd = self.root.join(&self.cfg.run.cwd);
        self.reset_tree()?;

        let trace_file = if self.trace && have_strace() {
            Some(std::env::temp_dir().join(format!("bdiff-trace-{}", std::process::id())))
        } else {
            None
        };
        let walk = match self.cfg.fs.mode.as_str() {
            "walk" => true,
            "trace" => false,
            _ => trace_file.is_none(),
        };
        let before = if walk { Some(snapshot(&self.root, &self.cfg.fs.ignore)) } else { None };

        let mut command = if let Some(tf) = &trace_file {
            let mut c = Command::new("strace");
            c.args(["-f", "-qq", "-e", "trace=%file,%network,%process", "-s", "0", "-o"])
                .arg(tf)
                .arg("--")
                .args(&argv);
            c
        } else {
            let mut c = Command::new(&argv[0]);
            c.args(&argv[1..]);
            c
        };
        command
            .current_dir(&cwd)
            .env("BDIFF_ROOT", &self.root)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());

        let mut child = command
            .spawn()
            .map_err(|e| format!("spawn {:?}: {e}", argv))?;
        if let Some(mut stdin) = child.stdin.take() {
            let _ = stdin.write_all(case.stdin.as_bytes());
        }
        let out = child
            .wait_with_output()
            .map_err(|e| format!("wait {:?}: {e}", argv))?;

        let mut fs = match &before {
            Some(b) => fs_delta(b, &snapshot(&self.root, &self.cfg.fs.ignore)),
            None => FsDelta::default(),
        };

        let syscalls = match &trace_file {
            Some(tf) => {
                let s = parse_strace(tf, &self.root);
                let _ = std::fs::remove_file(tf);
                s
            }
            None => SyscallSummary::default(),
        };
        if !walk {
            fs.written = syscalls
                .writes
                .iter()
                .filter(|w| w.starts_with("$ROOT/"))
                .map(|w| w["$ROOT/".len()..].to_string())
                .filter(|w| !self.cfg.fs.ignore.iter().any(|i| w == i || w.starts_with(&format!("{i}/"))))
                .collect();
        }

        Ok(Observation {
            exit: out.status.code(),
            stdout: self.normalise(&String::from_utf8_lossy(&out.stdout)),
            stderr: self.normalise(&String::from_utf8_lossy(&out.stderr)),
            fs,
            syscalls,
        })
    }

    fn normalise(&self, s: &str) -> String {
        normalise_text(s, &self.root.to_string_lossy(), &self.normalisers)
    }
}

/// Replace the revision root with $ROOT, then apply configured patterns.
fn normalise_text(s: &str, root: &str, patterns: &[Regex]) -> String {
    let mut s = s.replace(root, "$ROOT");
    for re in patterns {
        s = re.replace_all(&s, "<N>").into_owned();
    }
    s
}

/// Run a config-supplied command line through the platform shell.
fn shell(cmd: &str) -> Command {
    #[cfg(windows)]
    {
        let mut c = Command::new("cmd");
        c.args(["/C", cmd]);
        c
    }
    #[cfg(not(windows))]
    {
        let mut c = Command::new("sh");
        c.args(["-c", cmd]);
        c
    }
}

/// A process can have only one tracer. If something is already tracing us,
/// strace on our children would fail and yield a wrong-but-plausible report.
#[cfg(target_os = "linux")]
fn being_traced() -> bool {
    std::fs::read_to_string("/proc/self/status")
        .map(|t| {
            t.lines()
                .find_map(|l| l.strip_prefix("TracerPid:"))
                .map(|v| v.trim() != "0")
                .unwrap_or(false)
        })
        .unwrap_or(false)
}

#[cfg(not(target_os = "linux"))]
fn being_traced() -> bool {
    false
}

fn have_strace() -> bool {
    if !cfg!(target_os = "linux") {
        return false;
    }
    Command::new("strace")
        .arg("-V")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

// ---------- filesystem snapshots ----------

type Snapshot = BTreeMap<String, (u64, u64)>; // rel path -> (len, content hash)

fn snapshot(root: &Path, ignore: &[String]) -> Snapshot {
    let mut out = Snapshot::new();
    walk(root, root, ignore, &mut out);
    out
}

fn walk(root: &Path, dir: &Path, ignore: &[String], out: &mut Snapshot) {
    let Ok(rd) = std::fs::read_dir(dir) else { return };
    for entry in rd.flatten() {
        let path = entry.path();
        let rel = path.strip_prefix(root).unwrap_or(&path).to_string_lossy().to_string();
        if dir == root && ignore.iter().any(|i| i == &rel) {
            continue;
        }
        let Ok(meta) = entry.metadata() else { continue };
        if meta.is_dir() {
            walk(root, &path, ignore, out);
        } else if meta.is_file() {
            let h = std::fs::read(&path)
                .map(|b| {
                    let mut hs = std::collections::hash_map::DefaultHasher::new();
                    b.hash(&mut hs);
                    hs.finish()
                })
                .unwrap_or(0);
            out.insert(rel, (meta.len(), h));
        }
    }
}

fn fs_delta(before: &Snapshot, after: &Snapshot) -> FsDelta {
    let mut d = FsDelta::default();
    for (p, v) in after {
        match before.get(p) {
            None => d.created.push(p.clone()),
            Some(old) if old != v => d.modified.push(p.clone()),
            _ => {}
        }
    }
    for p in before.keys() {
        if !after.contains_key(p) {
            d.deleted.push(p.clone());
        }
    }
    d
}

// ---------- strace parsing (placeholder tracer) ----------

fn parse_strace(path: &Path, root: &Path) -> SyscallSummary {
    let mut s = SyscallSummary { available: true, ..Default::default() };
    let Ok(text) = std::fs::read_to_string(path) else { return s };
    let root_s = root.to_string_lossy();
    // `PID  name(args) = ret` ; with -s 0 strings are elided but paths are kept.
    // Under -f, a call interrupted by another process's event is split into
    // `PID name(args <unfinished ...>` and `PID <... name resumed>...) = ret`.
    let line_re = Regex::new(r#"^\d+\s+(\w+)\((.*)\)\s*=\s*(-?\d+|\?)"#).unwrap();
    let unfinished_re = Regex::new(r#"^(\d+)\s+(\w+)\((.*) <unfinished \.\.\.>$"#).unwrap();
    let resumed_re = Regex::new(r#"^(\d+)\s+<\.\.\. (\w+) resumed>.*=\s*(-?\d+|\?)"#).unwrap();
    let path_re = Regex::new(r#""([^"]*)""#).unwrap();
    let flags_re = Regex::new(r#"O_(WRONLY|RDWR|CREAT|TRUNC|APPEND)"#).unwrap();
    let mut pending: BTreeMap<String, (String, String)> = BTreeMap::new(); // pid -> (name, args)
    for line in text.lines() {
        let (name, args, ret): (String, String, String) = if let Some(c) = line_re.captures(line) {
            (c[1].to_string(), c[2].to_string(), c[3].to_string())
        } else if let Some(c) = unfinished_re.captures(line) {
            pending.insert(c[1].to_string(), (c[2].to_string(), c[3].to_string()));
            continue;
        } else if let Some(c) = resumed_re.captures(line) {
            match pending.remove(&c[1]) {
                Some((n, a)) if n == &c[2] => (n, a, c[3].to_string()),
                _ => continue,
            }
        } else {
            continue;
        };
        let args = args.as_str();
        *s.counts.entry(name.clone()).or_insert(0) += 1;
        // Failed syscalls are not behavior (PATH probes, ENOENT on optional files).
        if ret.starts_with('-') {
            continue;
        }
        match name.as_str() {
            "openat" | "open" | "creat" => {
                if flags_re.is_match(args) || name == "creat" {
                    if let Some(p) = path_re.captures(args) {
                        let path = rel(&p[1], &root_s);
                        if !path.contains("bdiff-trace-") {
                            s.writes.insert(path);
                        }
                    }
                }
            }
            "unlink" | "unlinkat" | "rename" | "renameat" | "renameat2" | "mkdir" | "mkdirat" => {
                for p in path_re.captures_iter(args) {
                    s.writes.insert(rel(&p[1], &root_s));
                }
            }
            "connect" => {
                s.connects.insert(args.to_string());
            }
            "execve" => {
                if let Some(p) = path_re.captures(args) {
                    s.execs.insert(rel(&p[1], &root_s));
                }
            }
            _ => {}
        }
    }
    s
}

fn rel(p: &str, root: &str) -> String {
    p.replace(root, "$ROOT")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn obs() -> Observation {
        Observation {
            exit: Some(0),
            stdout: "out".into(),
            stderr: String::new(),
            fs: FsDelta::default(),
            syscalls: SyscallSummary::default(),
        }
    }

    #[test]
    fn fingerprint_ignores_syscall_counts() {
        let a = obs();
        let mut b = obs();
        b.syscalls.counts.insert("openat".into(), 42);
        assert!(a.behaves_like(&b));
    }

    #[test]
    fn fingerprint_tracks_boundary_changes() {
        let a = obs();

        let mut b = obs();
        b.stdout = "different".into();
        assert!(!a.behaves_like(&b));

        let mut c = obs();
        c.exit = Some(1);
        assert!(!a.behaves_like(&c));

        let mut d = obs();
        d.syscalls.connects.insert("127.0.0.1:5432".into());
        assert!(!a.behaves_like(&d));
    }

    #[test]
    fn normalise_replaces_root_and_patterns() {
        let res = vec![Regex::new(r"\d{4}-\d{2}-\d{2}").unwrap()];
        let s = normalise_text("/work/repo/file at 2026-09-13", "/work/repo", &res);
        assert_eq!(s, "$ROOT/file at <N>");
    }

    #[test]
    fn fs_delta_reports_created_modified_deleted() {
        let mut before = Snapshot::new();
        before.insert("keep".into(), (1, 1));
        before.insert("change".into(), (1, 2));
        before.insert("gone".into(), (1, 3));
        let mut after = Snapshot::new();
        after.insert("keep".into(), (1, 1));
        after.insert("change".into(), (2, 9));
        after.insert("fresh".into(), (5, 5));

        let d = fs_delta(&before, &after);
        assert_eq!(d.created, vec!["fresh"]);
        assert_eq!(d.modified, vec!["change"]);
        assert_eq!(d.deleted, vec!["gone"]);
    }

    #[test]
    fn strace_parse_writes_ignores_failures_pairs_resumed() {
        let text = "\
100  openat(AT_FDCWD, \"/r/out.txt\", O_WRONLY|O_CREAT) = 3
100  openat(AT_FDCWD, \"/r/readonly\", O_RDONLY) = 4
100  openat(AT_FDCWD, \"/r/missing\", O_WRONLY) = -1
100  unlink(\"/r/tmp\") = 0
101  connect(3, {sa_family=AF_INET} <unfinished ...>
100  execve(\"/bin/tool\", []) = 0
101  <... connect resumed>) = 0
";
        let f = std::env::temp_dir().join(format!("bdiff-test-strace-{}", std::process::id()));
        std::fs::write(&f, text).unwrap();
        let s = parse_strace(&f, Path::new("/r"));
        let _ = std::fs::remove_file(&f);

        assert!(s.available);
        assert!(s.writes.contains("$ROOT/out.txt"));
        assert!(s.writes.contains("$ROOT/tmp"));
        assert!(!s.writes.iter().any(|w| w.contains("readonly")));
        assert!(!s.writes.iter().any(|w| w.contains("missing")));
        assert_eq!(s.connects.len(), 1);
        assert!(s.execs.contains("/bin/tool"));
        assert_eq!(s.counts["openat"], 3);
    }

    #[test]
    fn snapshot_skips_ignored_top_level_entries() {
        let root = std::env::temp_dir().join(format!("bdiff-test-snap-{}", std::process::id()));
        std::fs::create_dir_all(root.join("skipme")).unwrap();
        std::fs::write(root.join("skipme/inner"), "x").unwrap();
        std::fs::write(root.join("seen"), "y").unwrap();

        let snap = snapshot(&root, &["skipme".to_string()]);
        let _ = std::fs::remove_dir_all(&root);

        assert!(snap.contains_key("seen"));
        assert!(!snap.keys().any(|k| k.contains("inner")));
    }
}
