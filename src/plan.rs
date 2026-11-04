//! Ordered recovery plan for the debris the audit finds.

use std::path::Path;

use anyhow::Result;
use serde::Serialize;

use crate::audit::{self, AuditReport};
use crate::config::Config;
use crate::procfs::Procfs;
use crate::worktree::{self, WorktreeVerdict};

/// The plan document.
#[derive(Debug, Clone, Serialize)]
pub struct Plan {
    /// Ordered recovery steps.
    pub steps: Vec<String>,
}

impl Plan {
    /// Build ordered steps from an audit report.
    #[must_use]
    pub fn from_report(rep: &AuditReport, cfg: &Config) -> Self {
        let mut steps = Vec::new();
        for lane in rep.lanes.iter().filter(|l| l.orphan) {
            // A dead-uncollected lane has no group left to kill: collect
            // is the step. A leader-dead group is ALIVE (fd heirs), so it
            // needs the kill (reap) first and only then the collection.
            let verbs = if lane.verdict.contains("dead-uncollected") {
                format!("lanespec collect {}", lane.name)
            } else {
                format!(
                    "lanespec reap {n} and then lanespec collect {n}",
                    n = lane.name
                )
            };
            steps.push(format!(
                "{}. lane {} (orphan): run: {verbs}",
                steps.len() + 1,
                lane.name
            ));
            let wt = lane.worktree.clone().unwrap_or_default();
            let verdict = match lane.worktree_verdict.as_str() {
                "dirty" => WorktreeVerdict::Dirty,
                "clean" => WorktreeVerdict::Clean,
                "missing" => WorktreeVerdict::Missing,
                "none" => WorktreeVerdict::None,
                other => {
                    let n = other
                        .strip_prefix("committed-ahead ")
                        .and_then(|s| s.parse().ok())
                        .unwrap_or(0);
                    WorktreeVerdict::CommittedAhead(n)
                }
            };
            match verdict {
                WorktreeVerdict::Dirty => steps.push(format!(
                    "{}.   worktree {wt} is DIRTY: commit or salvage the files there FIRST — a commit may have died with the lane",
                    steps.len() + 1
                )),
                WorktreeVerdict::CommittedAhead(n) => {
                    let head = lane
                        .worktree
                        .as_ref()
                        .and_then(|w| worktree::head_sha(Path::new(w)))
                        .unwrap_or_else(|| "<head>".to_owned());
                    steps.push(format!(
                        "{}.   worktree {wt} has {n} commits ahead: land with git -C {} merge --ff-only {head}, then push main per repo policy",
                        steps.len() + 1,
                        rep.repo.display()
                    ));
                }
                WorktreeVerdict::Clean => steps.push(format!(
                    "{}.   worktree {wt} is clean: remove only after the hash it carried is ancestor-verified on origin/main: git -C {} worktree remove {wt}",
                    steps.len() + 1,
                    rep.repo.display()
                )),
                WorktreeVerdict::Missing | WorktreeVerdict::None => {}
            }
        }
        if rep
            .lock
            .holders
            .iter()
            .any(|h| !matches!(h.class.as_str(), "live"))
            || rep.lock.error.is_some()
        {
            steps.push(format!(
                "{}. gate lock held by orphans or scan failed — run: lanespec unlock (orphans killed by parent-gone proof, live holders awaited)",
                steps.len() + 1
            ));
        } else if !rep.lock.holders.is_empty() {
            steps.push(format!(
                "{}. gate lock held by a live process — a running gate must finish; lanespec unlock waits",
                steps.len() + 1
            ));
        }
        for c in &rep.classes {
            let orphan_pids: Vec<String> = c
                .procs
                .iter()
                .filter(|p| p.orphan)
                .map(|p| p.pid.to_string())
                .collect();
            if orphan_pids.is_empty() {
                if !c.procs.is_empty() {
                    steps.push(format!(
                        "{}. class {} matches live processes — nothing to do",
                        steps.len() + 1,
                        c.name
                    ));
                }
                continue;
            }
            let template = cfg
                .class
                .iter()
                .find(|k| k.name == c.name)
                .and_then(|k| k.recovery_step.clone());
            let text = match template {
                Some(t) => t.replace("{pid}", &orphan_pids.join(" ")),
                None => format!(
                    "sweep class {name}: lanespec sweep --class {name} (parent-gone proof only; report pids if the class needs a live-ref check)",
                    name = c.name
                ),
            };
            steps.push(format!(
                "{}. class {} has orphan pids {} — {}",
                steps.len() + 1,
                c.name,
                orphan_pids.join(" "),
                text
            ));
        }
        for w in rep.worktrees.iter().filter(|w| !w.registered) {
            steps.push(format!(
                "{}. stale worktree dir {} (no git worktree registers it): after checking for uncommitted content, git -C {} worktree prune and remove the dir",
                steps.len() + 1,
                w.path.display(),
                rep.repo.display()
            ));
        }
        if steps.is_empty() {
            steps.push("(no dead-lane debris — nothing to plan)".to_owned());
        }
        Plan { steps }
    }
}

/// `plan` command.
pub fn run<P: Procfs>(cfg: &Config, proc: &P, repo: &Path, json: bool) -> Result<i32> {
    let rep = audit::collect(cfg, proc, repo)?;
    let plan = Plan::from_report(&rep, cfg);
    if json {
        println!("{}", serde_json::to_string_pretty(&plan)?);
    } else {
        println!("== plan — ordered recovery for dead-lane debris ==");
        for s in &plan.steps {
            println!("{s}");
        }
        println!("end plan");
    }
    Ok(crate::exit::OK)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{Lock, Paths};
    use crate::fake::FakeProcfs;

    fn cfg_in(dir: &Path) -> Config {
        Config {
            paths: Paths {
                registry: dir.join("reg"),
                scratch: dir.to_path_buf(),
            },
            lock: Lock {
                path: dir.join("gate.lock"),
            },
            ..Default::default()
        }
    }

    #[test]
    fn orphan_lane_produces_collect_step() {
        let tmp = tempfile::tempdir().unwrap();
        let cfg = cfg_in(tmp.path());
        let reg = crate::registry::Registry::new(cfg.paths.registry.clone());
        std::fs::create_dir_all(reg.dir("dead")).unwrap();
        reg.write_pid("dead", 987_654, Some(1)).unwrap();
        let f = FakeProcfs::new();
        let rep = audit::collect(&cfg, &f, Path::new(".")).unwrap();
        let plan = Plan::from_report(&rep, &cfg);
        assert!(
            plan.steps
                .iter()
                .any(|s| s.contains("lane dead (orphan)") && s.contains("lanespec collect dead")),
            "{:?}",
            plan.steps
        );
    }

    #[test]
    fn clean_state_plans_nothing() {
        let tmp = tempfile::tempdir().unwrap();
        let cfg = cfg_in(tmp.path());
        let f = FakeProcfs::new();
        let rep = audit::collect(&cfg, &f, Path::new(".")).unwrap();
        let plan = Plan::from_report(&rep, &cfg);
        assert_eq!(plan.steps.len(), 1);
        assert!(plan.steps[0].starts_with('('));
    }

    #[test]
    fn orphan_lock_holder_yields_unlock_step() {
        let tmp = tempfile::tempdir().unwrap();
        let cfg = cfg_in(tmp.path());
        std::fs::write(tmp.path().join("gate.lock"), "").unwrap();
        let f = FakeProcfs::new();
        // orphan fleet parent + holder child of it
        f.add(987_001, 777, 987_001, 1, "flock", "flock gate.lock -c leg");
        f.add(987_002, 987_001, 987_001, 1, "child", "run-unit-tests");
        f.add_holder(&cfg.lock.path, 987_002);
        let rep = audit::collect(&cfg, &f, Path::new(".")).unwrap();
        let plan = Plan::from_report(&rep, &cfg);
        assert!(
            plan.steps
                .iter()
                .any(|s| s.contains("gate lock") && s.contains("lanespec unlock")),
            "{:?}",
            plan.steps
        );
    }
}
