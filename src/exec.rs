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
    pub execs: Vec<String>,
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
        Ok(Runner { root, cfg, normalisers, trace })
    }

    pub fn build(&self) -> Result<(), String> {
        let Some(cmd) = &self.cfg.build.cmd else { return Ok(()) };
        eprintln!("  build: {cmd}");
        let st = Command::new("sh")
            .arg("-c")
            .arg(cmd)
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
        let root = self.root.to_string_lossy();
        let mut s = s.replace(root.as_ref(), "$ROOT");
        for re in &self.normalisers {
            s = re.replace_all(&s, "<N>").into_owned();
        }
        s
    }
}

/// A process can have only one tracer. If something is already tracing us,
/// strace on our children would fail and yield a wrong-but-plausible report.
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

fn have_strace() -> bool {
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
    let line_re = Regex::new(r#"^\d+\s+(\w+)\((.*)\)\s*=\s*(-?\d+|\?)"#).unwrap();
    let path_re = Regex::new(r#""([^"]*)""#).unwrap();
    let flags_re = Regex::new(r#"O_(WRONLY|RDWR|CREAT|TRUNC|APPEND)"#).unwrap();
    for line in text.lines() {
        let Some(c) = line_re.captures(line) else { continue };
        let name = c[1].to_string();
        let args = &c[2];
        let ret = &c[3];
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
                    s.execs.push(rel(&p[1], &root_s));
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
