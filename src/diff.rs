use crate::exec::Observation;
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Label {
    Unchanged,
    NewBehavior,         // old failed, new succeeds
    RegressionCandidate, // old succeeded, new fails or differs
    Changed,             // both failed, differently
    Accepted,            // differs, but new behavior was accepted via `bdiff accept`
    Flaky,               // a revision disagreed with itself; excluded from comparison
}

impl Label {
    pub fn is_change(self) -> bool {
        matches!(self, Label::NewBehavior | Label::RegressionCandidate | Label::Changed)
    }
}

pub struct Inputs<'a> {
    pub case: &'a str,
    pub expect_exit: &'a [i32],
    pub accepted: Option<&'a str>,
    pub old_flaky: bool,
    pub new_flaky: bool,
}

#[derive(Debug, Serialize)]
pub struct Finding {
    pub case: String,
    pub label: Label,
    pub fingerprint: String,
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

pub fn compare(inp: &Inputs, old: &Observation, new: &Observation) -> Finding {
    let ok = |o: &Observation| o.exit.map(|c| inp.expect_exit.contains(&c)).unwrap_or(false);
    let old_ok = ok(old);
    let new_ok = ok(new);
    // Behavioral equality: what crosses the boundary. Syscall *counts* are
    // informational only (an extra import is not a behavior change).
    let same = old.behaves_like(new);
    let fingerprint = new.fingerprint();

    let label = if inp.old_flaky || inp.new_flaky {
        Label::Flaky
    } else if same {
        Label::Unchanged
    } else if inp.accepted == Some(fingerprint.as_str()) {
        Label::Accepted
    } else {
        match (old_ok, new_ok) {
            (false, true) => Label::NewBehavior,
            (true, _) => Label::RegressionCandidate,
            (false, false) => Label::Changed,
        }
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
    for p in &new.fs.written {
        if !old.fs.written.contains(p) {
            fs.push(format!("+ written {p}"));
        }
    }
    for p in &old.fs.written {
        if !new.fs.written.contains(p) {
            fs.push(format!("- no longer written {p}"));
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
        case: inp.case.to_string(),
        label,
        fingerprint,
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
    pub fn changed(&self) -> usize {
        self.findings.iter().filter(|f| f.label.is_change()).count()
    }

    pub fn print_text(&self) {
        let count = |l: Label| self.findings.iter().filter(|f| f.label == l).count();
        println!("bdiff {} -> {}", self.old, self.new);
        let mut parts = vec![
            format!("{} cases", self.findings.len()),
            format!("{} unchanged", count(Label::Unchanged)),
            format!("{} changed", self.changed()),
        ];
        if count(Label::Accepted) > 0 {
            parts.push(format!("{} accepted", count(Label::Accepted)));
        }
        if count(Label::Flaky) > 0 {
            parts.push(format!("{} flaky", count(Label::Flaky)));
        }
        println!("{}", parts.join(", "));
        for f in self.findings.iter().filter(|f| f.label != Label::Unchanged) {
            println!();
            let tag = match f.label {
                Label::NewBehavior => "+behavior",
                Label::RegressionCandidate => "⚠ regression?",
                Label::Changed => "~ changed",
                Label::Accepted => "✓ accepted",
                Label::Flaky => "? flaky",
                Label::Unchanged => "",
            };
            println!("[{tag}] {}", f.case);
            if f.label == Label::Flaky {
                println!("  nondeterministic on its own; excluded from comparison");
                continue;
            }
            if f.label == Label::Accepted {
                continue;
            }
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::exec::{FsDelta, Observation, SyscallSummary};

    fn obs(exit: i32, stdout: &str) -> Observation {
        Observation {
            exit: Some(exit),
            stdout: stdout.into(),
            stderr: String::new(),
            fs: FsDelta::default(),
            syscalls: SyscallSummary::default(),
        }
    }

    fn inputs<'a>(expect_exit: &'a [i32], accepted: Option<&'a str>) -> Inputs<'a> {
        Inputs { case: "t", expect_exit, accepted, old_flaky: false, new_flaky: false }
    }

    #[test]
    fn label_unchanged() {
        let f = compare(&inputs(&[0], None), &obs(0, "x"), &obs(0, "x"));
        assert_eq!(f.label, Label::Unchanged);
        assert!(f.stdout.is_empty());
        assert!(f.exit.is_none());
    }

    #[test]
    fn label_new_behavior_when_old_failed() {
        let f = compare(&inputs(&[0], None), &obs(1, "err"), &obs(0, "ok"));
        assert_eq!(f.label, Label::NewBehavior);
    }

    #[test]
    fn label_regression_when_old_ok() {
        let f = compare(&inputs(&[0], None), &obs(0, "a"), &obs(0, "b"));
        assert_eq!(f.label, Label::RegressionCandidate);
        let f = compare(&inputs(&[0], None), &obs(0, "a"), &obs(1, "boom"));
        assert_eq!(f.label, Label::RegressionCandidate);
    }

    #[test]
    fn label_changed_when_both_fail_differently() {
        let f = compare(&inputs(&[0], None), &obs(1, "a"), &obs(2, "b"));
        assert_eq!(f.label, Label::Changed);
    }

    #[test]
    fn label_respects_expect_exit() {
        // exit 1 counts as success for this case, so a 0 -> 1 flip with the
        // same output rules is still just a candidate, not new behavior
        let f = compare(&inputs(&[0, 1], None), &obs(1, "a"), &obs(0, "b"));
        assert_eq!(f.label, Label::RegressionCandidate);
    }

    #[test]
    fn label_accepted_by_fingerprint() {
        let new = obs(0, "b");
        let fp = new.fingerprint();
        let f = compare(&inputs(&[0], Some(&fp)), &obs(0, "a"), &new);
        assert_eq!(f.label, Label::Accepted);
        assert!(f.label == Label::Accepted && !f.label.is_change());
    }

    #[test]
    fn label_flaky_wins() {
        let mut inp = inputs(&[0], None);
        inp.new_flaky = true;
        let f = compare(&inp, &obs(0, "a"), &obs(0, "b"));
        assert_eq!(f.label, Label::Flaky);
    }

    #[test]
    fn finding_reports_exit_and_fs_deltas() {
        let old = obs(0, "x");
        let mut new = obs(3, "x");
        new.fs = FsDelta { created: vec!["f".into()], ..FsDelta::default() };
        let f = compare(&inputs(&[0], None), &old, &new);
        assert_eq!(f.exit, Some((Some(0), Some(3))));
        assert_eq!(f.fs, vec!["+ created f"]);
    }

    #[test]
    fn line_diff_keeps_changes_with_one_line_context() {
        let d = line_diff("1\n2\n3\n4\n5", "1\n2\nX\n4\n5");
        let rendered: Vec<(char, &str)> = d.iter().map(|l| (l.op, l.text.as_str())).collect();
        assert_eq!(rendered, vec![(' ', "2"), ('-', "3"), ('+', "X"), (' ', "4")]);
    }

    #[test]
    fn line_diff_pure_insert_and_delete() {
        assert!(line_diff("", "").is_empty());
        let d = line_diff("", "a");
        assert_eq!((d[0].op, d[0].text.as_str()), ('+', "a"));
        let d = line_diff("a", "");
        assert_eq!((d[0].op, d[0].text.as_str()), ('-', "a"));
    }
}
