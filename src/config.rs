//! Configuration model for `lanespec.toml`.
//!
//! The schema is intentionally closed ([`serde` deny_unknown_fields]): only
//! proof kinds expressible here are process-tree proofs. There is no mtime
//! proof kind — mtime is never evidence for a kill, so it cannot be declared.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use regex::Regex;
use serde::{Deserialize, Serialize};

/// A named config file could not be read: missing, unreadable, or not a
/// file. This is an operational-precondition failure, not a verdict: the CLI
/// maps it to `exit::OPERATIONAL` (70). A file that reads but parses badly
/// is a different thing — a plain error the CLI keeps as the generic 1.
#[derive(Debug)]
pub struct ConfigUnreadable {
    /// The path that could not be read.
    pub path: PathBuf,
    /// Why the read failed.
    pub source: std::io::Error,
}

impl std::fmt::Display for ConfigUnreadable {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "reading config {}", self.path.display())
    }
}

impl std::error::Error for ConfigUnreadable {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.source)
    }
}

/// Where the registry and scratch space live.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Paths {
    /// Registry root: one directory per lane.
    #[serde(default = "default_registry")]
    pub registry: PathBuf,
    /// Scratch root for detached launches and ladder logs.
    #[serde(default = "default_scratch")]
    pub scratch: PathBuf,
}

fn default_registry() -> PathBuf {
    PathBuf::from("/var/tmp/lanes")
}

fn default_scratch() -> PathBuf {
    PathBuf::from("/var/tmp")
}

impl Default for Paths {
    fn default() -> Self {
        Self {
            registry: default_registry(),
            scratch: default_scratch(),
        }
    }
}

/// The gate lock whose holders the audit reports and `unlock` resolves.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Lock {
    /// Lock file path (opened by gate runners via `flock`).
    #[serde(default = "default_lock_path")]
    pub path: PathBuf,
}

fn default_lock_path() -> PathBuf {
    PathBuf::from("/var/tmp/lanespec.lock")
}

impl Default for Lock {
    fn default() -> Self {
        Self {
            path: default_lock_path(),
        }
    }
}

/// Rules for the parent-gone (reparent) proof.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ParentRule {
    /// Process names that a dead spawner's children get reparented to
    /// (besides pid 1, which is always a target).
    #[serde(default = "default_reparent_targets", alias = "reparent-targets")]
    pub reparent_targets: Vec<String>,
    /// Maximum ancestry chain length walked by the orphan proof recursion.
    #[serde(
        default = "default_max_ancestry_depth",
        rename = "max-ancestry-depth",
        alias = "max_ancestry_depth"
    )]
    pub max_ancestry_depth: u32,
}

fn default_reparent_targets() -> Vec<String> {
    vec!["systemd".to_owned()]
}

fn default_max_ancestry_depth() -> u32 {
    8
}

impl Default for ParentRule {
    fn default() -> Self {
        Self {
            reparent_targets: default_reparent_targets(),
            max_ancestry_depth: default_max_ancestry_depth(),
        }
    }
}

/// A process class the audit matches by an anchored cmdline regex.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
pub struct LaneClass {
    /// Class identifier used by `sweep --class` and audit/plan output.
    pub name: String,
    /// Regex matched against the process cmdline, anchored by the tool.
    pub cmdline_anchor: String,
    /// Optional external proof: argv (no shell), `{pid}` / `{cmdline}`
    /// placeholders. Exit 0 means the proof holds for that process.
    #[serde(default)]
    pub proof_command: Option<Vec<String>>,
    /// Optional recovery-step template printed by `plan` for this class,
    /// with `{pid}` / `{pgid}` / `{name}` placeholders.
    #[serde(default)]
    pub recovery_step: Option<String>,
}

/// A sentinel glob reported as an age HINT by the audit (age is never
/// evidence — hints only inform inspection order).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
pub struct Sentinel {
    /// Glob pattern for sentinel files, e.g. `/var/tmp/*.final`.
    pub glob: String,
    /// Age past which the audit prints a hint.
    pub age_hint_hours: u64,
}

/// Full lanespec configuration.
#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
pub struct Config {
    /// Registry and scratch locations.
    #[serde(default)]
    pub paths: Paths,
    /// Gate lock location.
    #[serde(default)]
    pub lock: Lock,
    /// Parent-gone proof rules.
    #[serde(default)]
    pub parent_rule: ParentRule,
    /// Process classes.
    #[serde(default)]
    pub class: Vec<LaneClass>,
    /// Sentinel globs for audit age hints.
    #[serde(default)]
    pub sentinel: Vec<Sentinel>,
}

impl Config {
    /// Parse a `lanespec.toml` file and validate class regexes.
    pub fn load(path: &Path) -> Result<Self> {
        let text = std::fs::read_to_string(path).map_err(|source| ConfigUnreadable {
            path: path.to_path_buf(),
            source,
        })?;
        let cfg: Self =
            toml::from_str(&text).with_context(|| format!("parsing {}", path.display()))?;
        cfg.validate()?;
        Ok(cfg)
    }

    /// Resolve the config: `--config` flag, then `LANESPEC_CONFIG` env,
    /// then the built-in defaults.
    pub fn resolve(explicit: Option<&Path>) -> Result<(Config, Option<PathBuf>)> {
        if let Some(p) = explicit {
            return Ok((Self::load(p)?, Some(p.to_path_buf())));
        }
        if let Ok(env) = std::env::var("LANESPEC_CONFIG") {
            let p = PathBuf::from(env);
            return Ok((Self::load(&p)?, Some(p)));
        }
        Ok((Self::default(), None))
    }

    /// Fail loud on an unusable class regex — and on an anchor that
    /// MATCHES EVERYTHING: an empty/whitespace-only anchor (the empty
    /// regex matches every cmdline) or a bare `.*` would rebuild the
    /// match-everything pattern from a config file, so the load refuses.
    pub fn validate(&self) -> Result<()> {
        for class in &self.class {
            let anchor = class.cmdline_anchor.trim();
            if anchor.is_empty() || anchor == ".*" {
                anyhow::bail!(
                    "class '{}' has a match-everything cmdline-anchor ({}): refusing to load — declare a specific, anchored pattern",
                    class.name,
                    if anchor.is_empty() { "empty or whitespace-only" } else { "bare .*" }
                );
            }
            Regex::new(&class.cmdline_anchor).with_context(|| {
                format!("class '{}' has an invalid cmdline-anchor regex", class.name)
            })?;
        }
        Ok(())
    }

    /// The compiled matcher for one class anchor.
    pub fn class_regex(class: &LaneClass) -> Result<Regex> {
        Regex::new(&class.cmdline_anchor)
            .with_context(|| format!("class '{}' has an invalid cmdline-anchor regex", class.name))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_document_yields_defaults() {
        let cfg: Config = toml::from_str("").unwrap();
        assert_eq!(cfg, Config::default());
        assert_eq!(cfg.paths.registry, PathBuf::from("/var/tmp/lanes"));
        assert_eq!(cfg.parent_rule.max_ancestry_depth, 8);
    }

    #[test]
    fn full_document_parses() {
        let doc = r#"
[paths]
registry = "/tmp/reg"
scratch = "/tmp/scratch"

[lock]
path = "/tmp/gate.lock"

[parent-rule]
reparent_targets = ["systemd", "init"]
max-ancestry-depth = 4

[[class]]
name = "daemon-fleet"
cmdline-anchor = '^/usr/lib/git-core/git-daemon fleet-'
proof-command = ["/bin/true", "{pid}"]
recovery-step = "report pid {pid} to the orchestrator"

[[sentinel]]
glob = "/tmp/*.final"
age-hint-hours = 6
"#;
        let cfg: Config = toml::from_str(doc).unwrap();
        assert_eq!(cfg.lock.path, PathBuf::from("/tmp/gate.lock"));
        assert_eq!(cfg.class.len(), 1);
        assert_eq!(cfg.class[0].name, "daemon-fleet");
        assert_eq!(cfg.class[0].recovery_step.as_deref(), Some("report pid {pid} to the orchestrator"));
        assert_eq!(cfg.sentinel[0].age_hint_hours, 6);
        cfg.validate().unwrap();
    }

    #[test]
    fn mtime_proof_kind_is_not_expressible() {
        // The schema has no field that would declare mtime as proof; any
        // attempt to add one must fail closed.
        let doc = r#"
[[class]]
name = "x"
cmdline-anchor = "x"
proof = "mtime"
"#;
        let err = toml::from_str::<Config>(doc).unwrap_err();
        assert!(err.to_string().contains("unknown field"), "{err}");
    }

    /// The CLI maps this error class to `exit::OPERATIONAL` (70): a named
    /// config that cannot be read is a precondition failure, while a config
    /// that reads but parses badly stays the generic 1.
    #[test]
    fn unreadable_config_is_typed_as_operational() {
        let tmp = tempfile::tempdir().unwrap();
        let missing = tmp.path().join("absent.lanespec.toml");
        let err = Config::load(&missing).unwrap_err();
        assert!(
            err.downcast_ref::<ConfigUnreadable>().is_some(),
            "missing config must carry ConfigUnreadable for the 70 mapping"
        );
        let bad = tmp.path().join("bad.lanespec.toml");
        std::fs::write(&bad, "[paths]\nregistry = 42\n").unwrap();
        let err = Config::load(&bad).unwrap_err();
        assert!(
            err.downcast_ref::<ConfigUnreadable>().is_none(),
            "a config that reads but parses badly is not operational"
        );
    }

    #[test]
    fn invalid_class_regex_fails_validation() {
        let cfg = Config {
            class: vec![LaneClass {
                name: "broken".to_owned(),
                cmdline_anchor: "([".to_owned(),
                proof_command: None,
                recovery_step: None,
            }],
            ..Default::default()
        };
        assert!(cfg.validate().is_err());
    }

    /// N3 regression: a match-everything class anchor must fail at LOAD
    /// with a clear message — an empty/whitespace anchor or a bare `.*`
    /// would rebuild the match-everything pattern from the config file.
    #[test]
    fn match_everything_class_anchor_refuses_at_load() {
        for anchor in ["", "   ", ".*"] {
            let tmp = tempfile::tempdir().unwrap();
            let path = tmp.path().join("lanespec.toml");
            std::fs::write(
                &path,
                format!("[[class]]\nname = \"matchall\"\ncmdline-anchor = {anchor:?}\n"),
            )
            .unwrap();
            let err = Config::load(&path)
                .err()
                .unwrap_or_else(|| panic!("anchor {anchor:?} must refuse to load"));
            let msg = format!("{err:#}");
            assert!(msg.contains("match-everything"), "clear message expected, got: {msg}");
            assert!(msg.contains("matchall"), "class name expected, got: {msg}");
        }
        // A specific anchored pattern still loads; so does a .*-containing
        // pattern that is not BARE (it cannot match everything on its own).
        for anchor in ["^/usr/lib/fleetd fleet-", "^lane-tool.*"] {
            let cfg = Config {
                class: vec![LaneClass {
                    name: "specific".to_owned(),
                    cmdline_anchor: anchor.to_owned(),
                    proof_command: None,
                    recovery_step: None,
                }],
                ..Default::default()
            };
            cfg.validate().unwrap_or_else(|e| panic!("anchor {anchor:?} must load: {e}"));
        }
    }
}
