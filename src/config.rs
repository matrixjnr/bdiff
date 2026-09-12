use serde::Deserialize;
use std::path::Path;

#[derive(Debug, Deserialize, Default, Clone)]
pub struct Config {
    #[serde(default)]
    pub build: Build,
    #[serde(default)]
    pub run: Run,
    #[serde(default, rename = "case")]
    pub cases: Vec<Case>,
    #[serde(default)]
    pub normalise: Normalise,
    #[serde(default)]
    pub fs: Fs,
}

#[derive(Debug, Deserialize, Default, Clone)]
pub struct Build {
    /// Shell command run in the revision root before cases. Optional.
    pub cmd: Option<String>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct Run {
    /// Program + fixed leading args, whitespace-split. Case args appended.
    pub cmd: Option<String>,
    /// Working directory relative to the revision root.
    #[serde(default = "dot")]
    pub cwd: String,
    /// Times each case is run per revision. >1 enables flakiness detection.
    #[serde(default = "two")]
    pub repeats: usize,
}

impl Default for Run {
    fn default() -> Self {
        Run { cmd: None, cwd: dot(), repeats: two() }
    }
}

#[derive(Debug, Deserialize, Clone)]
pub struct Case {
    pub name: String,
    #[serde(default)]
    pub args: Vec<String>,
    #[serde(default)]
    pub stdin: String,
    /// Override run.cmd for this case.
    pub cmd: Option<String>,
    /// Exit codes that count as success for this case. Default [0].
    #[serde(default = "zero")]
    pub expect_exit: Vec<i32>,
}

#[derive(Debug, Deserialize, Default, Clone)]
pub struct Normalise {
    /// Regexes replaced with `<N>` before diffing stdout/stderr.
    #[serde(default)]
    pub patterns: Vec<String>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct Fs {
    /// Top-level entries excluded from filesystem snapshots.
    #[serde(default = "default_ignore")]
    pub ignore: Vec<String>,
    /// "auto": trace-derived write set when a tracer is available, else walk.
    /// "walk": always hash the tree before/after. "trace": never walk.
    #[serde(default = "auto")]
    pub mode: String,
}

impl Default for Fs {
    fn default() -> Self {
        Fs { ignore: default_ignore(), mode: auto() }
    }
}

fn dot() -> String {
    ".".into()
}
fn two() -> usize {
    2
}
fn zero() -> Vec<i32> {
    vec![0]
}
fn auto() -> String {
    "auto".into()
}

fn default_ignore() -> Vec<String> {
    vec![".git".into(), "target".into(), "node_modules".into(), "__pycache__".into()]
}

impl Config {
    pub fn load(path: &Path) -> Result<Config, String> {
        let text = std::fs::read_to_string(path)
            .map_err(|e| format!("read {}: {e}", path.display()))?;
        toml::from_str(&text).map_err(|e| format!("parse {}: {e}", path.display()))
    }
}
