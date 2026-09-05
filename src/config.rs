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

#[derive(Debug, Deserialize, Default, Clone)]
pub struct Run {
    /// Program + fixed leading args, whitespace-split. Case args appended.
    pub cmd: Option<String>,
    /// Working directory relative to the revision root.
    #[serde(default = "dot")]
    pub cwd: String,
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
}

impl Default for Fs {
    fn default() -> Self {
        Fs { ignore: default_ignore() }
    }
}

fn dot() -> String {
    ".".into()
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
