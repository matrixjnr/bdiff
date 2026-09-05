use crate::exec::Observation;
use serde::Serialize;

#[derive(Debug, Serialize, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Label {
    Unchanged,
    NewBehavior,        // old failed, new succeeds
    RegressionCandidate, // old succeeded, new fails or differs
    Changed,            // both failed, differently
}

#[derive(Debug, Serialize)]
pub struct Finding {
    pub case: String,
    pub label: Label,
    pub exit: Option<(Option<i32>, Option<i32>)>,
    pub stdout: Vec<DiffLine>,
    pub stderr: Vec<DiffLine>,
    pub fs: Vec<String>,
    pub syscalls: Vec<String>,
}

#[derive(Debug, Serialize, Clone)]
pub struct DiffLine {
    pub op: char, // ' ', '-', '+'
    pub text: String,
}

pub fn compare(case: &str, old: &Observation, new: &Observation) -> Finding {
    let old_ok = old.exit == Some(0);
    let new_ok = new.exit == Some(0);
    // Behavioral equality: what crosses the boundary. Syscall *counts* are
    // informational only (an extra import is not a behavior change).
    let same = old.exit == new.exit
        && old.stdout == new.stdout
        && old.stderr == new.stderr
        && old.fs == new.fs
        && old.syscalls.writes == new.syscalls.writes
        && old.syscalls.connects == new.syscalls.connects
        && old.syscalls.execs == new.syscalls.execs;

    let label = match (same, old_ok, new_ok) {
        (true, _, _) => Label::Unchanged,
        (false, false, true) => Label::NewBehavior,
        (false, true, _) => Label::RegressionCandidate,
        (false, false, false) => Label::Changed,
    };

    let mut fs = Vec::new();
    for p in &new.fs.created {
        if !old.fs.created.contains(p) {
            fs.push(format!("+ created {p}"));
        }
    }
    for p in &old.fs.created {
        if !new.fs.created.contains(p) {
            fs.push(format!("- no longer created {p}"));
        }
    }
    for p in &new.fs.modified {
        if !old.fs.modified.contains(p) {
            fs.push(format!("+ modified {p}"));
        }
    }
    for p in &old.fs.modified {
        if !new.fs.modified.contains(p) {
            fs.push(format!("- no longer modified {p}"));
        }
    }
    for p in &new.fs.deleted {
        if !old.fs.deleted.contains(p) {
            fs.push(format!("+ deleted {p}"));
        }
    }

    let mut syscalls = Vec::new();
    if old.syscalls.available && new.syscalls.available {
        for w in new.syscalls.writes.difference(&old.syscalls.writes) {
            syscalls.push(format!("+ write {w}"));
        }
        for w in old.syscalls.writes.difference(&new.syscalls.writes) {
            syscalls.push(format!("- write {w}"));
        }
        for c in new.syscalls.connects.difference(&old.syscalls.connects) {
            syscalls.push(format!("+ connect {c}"));
        }
        for c in old.syscalls.connects.difference(&new.syscalls.connects) {
            syscalls.push(format!("- connect {c}"));
        }
        if old.syscalls.execs != new.syscalls.execs {
            syscalls.push(format!(
                "exec {:?} -> {:?}",
                old.syscalls.execs, new.syscalls.execs
            ));
        }
    }

    Finding {
        case: case.to_string(),
        label,
        exit: if old.exit != new.exit { Some((old.exit, new.exit)) } else { None },
        stdout: if old.stdout != new.stdout { line_diff(&old.stdout, &new.stdout) } else { vec![] },
        stderr: if old.stderr != new.stderr { line_diff(&old.stderr, &new.stderr) } else { vec![] },
        fs,
        syscalls,
    }
}

/// Minimal LCS line diff. Outputs only changed lines plus one line of context.
pub fn line_diff(a: &str, b: &str) -> Vec<DiffLine> {
    let a: Vec<&str> = a.lines().collect();
    let b: Vec<&str> = b.lines().collect();
    let (n, m) = (a.len(), b.len());
    if n * m > 4_000_000 {
        // too big for quadratic LCS; fall back to whole replacement
        let mut v: Vec<DiffLine> = a.iter().map(|l| DiffLine { op: '-', text: l.to_string() }).collect();
        v.extend(b.iter().map(|l| DiffLine { op: '+', text: l.to_string() }));
        return v;
    }
    let mut dp = vec![vec![0u32; m + 1]; n + 1];
    for i in (0..n).rev() {
        for j in (0..m).rev() {
            dp[i][j] = if a[i] == b[j] {
                dp[i + 1][j + 1] + 1
            } else {
                dp[i + 1][j].max(dp[i][j + 1])
            };
        }
    }
    let mut full = Vec::new();
    let (mut i, mut j) = (0, 0);
    while i < n && j < m {
        if a[i] == b[j] {
            full.push(DiffLine { op: ' ', text: a[i].to_string() });
            i += 1;
            j += 1;
        } else if dp[i + 1][j] >= dp[i][j + 1] {
            full.push(DiffLine { op: '-', text: a[i].to_string() });
            i += 1;
        } else {
            full.push(DiffLine { op: '+', text: b[j].to_string() });
            j += 1;
        }
    }
    while i < n {
        full.push(DiffLine { op: '-', text: a[i].to_string() });
        i += 1;
    }
    while j < m {
        full.push(DiffLine { op: '+', text: b[j].to_string() });
        j += 1;
    }
    // keep changed lines plus 1 line of context each side
    let keep: Vec<bool> = (0..full.len())
        .map(|k| {
            let lo = k.saturating_sub(1);
            let hi = (k + 1).min(full.len() - 1);
            (lo..=hi).any(|x| full[x].op != ' ')
        })
        .collect();
    full.into_iter().zip(keep).filter(|(_, k)| *k).map(|(l, _)| l).collect()
}

#[derive(Serialize)]
pub struct Report {
    pub old: String,
    pub new: String,
    pub findings: Vec<Finding>,
}

impl Report {
    pub fn print_text(&self) {
        let changed: Vec<&Finding> = self.findings.iter().filter(|f| f.label != Label::Unchanged).collect();
        println!("bdiff {} -> {}", self.old, self.new);
        println!(
            "{} cases, {} unchanged, {} changed",
            self.findings.len(),
            self.findings.len() - changed.len(),
            changed.len()
        );
        for f in changed {
            println!();
            let tag = match f.label {
                Label::NewBehavior => "+behavior",
                Label::RegressionCandidate => "⚠ regression?",
                Label::Changed => "~ changed",
                Label::Unchanged => "",
            };
            println!("[{tag}] {}", f.case);
            if let Some((o, n)) = f.exit {
                println!("  exit: {} -> {}", fmt_exit(o), fmt_exit(n));
            }
            if !f.stdout.is_empty() {
                println!("  stdout:");
                for l in &f.stdout {
                    println!("    {} {}", l.op, l.text);
                }
            }
            if !f.stderr.is_empty() {
                println!("  stderr:");
                for l in &f.stderr {
                    println!("    {} {}", l.op, l.text);
                }
            }
            for l in &f.fs {
                println!("  fs: {l}");
            }
            for l in &f.syscalls {
                println!("  sys: {l}");
            }
        }
    }
}

fn fmt_exit(e: Option<i32>) -> String {
    e.map(|c| c.to_string()).unwrap_or_else(|| "signal".into())
}
