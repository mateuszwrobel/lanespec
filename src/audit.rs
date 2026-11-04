//! Debris audit: lanes, class fleets, lock holders, ahead-count, stale
//! worktrees, sentinel age HINTS. Age is never evidence — hints only.

use std::path::{Path, PathBuf};
use std::time::SystemTime;

use anyhow::Result;
use serde::Serialize;

use crate::config::Config;
use crate::exit;
use crate::glob;
use crate::lifecycle::{lane_verdict, utc_stamp};
use crate::orphan;
use crate::procfs::{Pid, Procfs};
use crate::registry::Registry;
use crate::worktree;

/// One lane's audit row.
#[derive(Debug, Clone, Serialize)]
pub struct LaneAudit {
    /// Lane name.
    pub name: String,
    /// Recorded pgid, if any.
    pub pgid: Option<Pid>,
    /// Verdict text.
    pub verdict: String,
    /// True when the lane is an uncollected orphan.
    pub orphan: bool,
    /// Recorded worktree path.
    pub worktree: Option<String>,
    /// Worktree verdict text.
    pub worktree_verdict: String,
}

/// One matched process of a class.
#[derive(Debug, Clone, Serialize)]
pub struct ProcAudit {
    /// The process id.
    pub pid: Pid,
    /// Parent-gone proof result.
    pub orphan: bool,
    /// Optional proof-command outcome (None = no proof configured).
    pub proof: Option<bool>,
}

/// One configured class's audit rows.
#[derive(Debug, Clone, Serialize)]
pub struct ClassAudit {
    /// Class name.
    pub name: String,
    /// Anchor regex.
    pub anchor: String,
    /// Matched processes.
    pub procs: Vec<ProcAudit>,
}

/// One lock holder.
#[derive(Debug, Clone, Serialize)]
pub struct HolderAudit {
    /// Holder pid.
    pub pid: Pid,
    /// live | orphan.
    pub class: String,
}

/// Lock audit row.
#[derive(Debug, Clone, Serialize)]
pub struct LockAudit {
    /// Lock path.
    pub path: PathBuf,
    /// Lock file absent (definitely free).
    pub absent: bool,
    /// Scan could not complete (refuse to call it free).
    pub error: Option<String>,
    /// Holder rows.
    pub holders: Vec<HolderAudit>,
}

/// Stale-worktrees section.
#[derive(Debug, Clone, Serialize)]
pub struct WorktreeAudit {
    /// Directory path found in scratch.
    pub path: PathBuf,
    /// Some repo registers it.
    pub registered: bool,
}

/// Sentinel age hint.
#[derive(Debug, Clone, Serialize)]
pub struct SentinelHint {
    /// Sentinel path.
    pub path: PathBuf,
    /// Configured hint threshold.
    pub age_hint_hours: u64,
    /// Actual age (hint only — never evidence).
    pub age_hours: u64,
}

/// The full audit report.
#[derive(Debug, Clone, Serialize)]
pub struct AuditReport {
    /// UTC stamp.
    pub utc: String,
    /// Registry root.
    pub registry: PathBuf,
    /// Lane rows.
    pub lanes: Vec<LaneAudit>,
    /// Class fleet rows.
    pub classes: Vec<ClassAudit>,
    /// Lock rows.
    pub lock: LockAudit,
    /// Repo path for the ahead-count.
    pub repo: PathBuf,
    /// `origin/main..main` count; None = unknown.
    pub ahead: Option<u32>,
    /// Scratch `wt-*` directories vs the repo's worktree list.
    pub worktrees: Vec<WorktreeAudit>,
    /// Sentinel age hints.
    pub sentinels: Vec<SentinelHint>,
    /// True when any orphan lane / fleet / holder or stale worktree exists.
    pub debris: bool,
}

fn age_hours(path: &Path) -> u64 {
    let mtime = path
        .metadata()
        .ok()
        .and_then(|m| m.modified().ok())
        .unwrap_or(SystemTime::UNIX_EPOCH);
    SystemTime::now()
        .duration_since(mtime)
        .map(|d| d.as_secs() / 3600)
        .unwrap_or(0)
}

/// Run a class proof-command (`{pid}`/`{cmdline}` substituted, argv, no
/// shell). True = exit 0 = the proof holds. Also gates `sweep` kills.
pub(crate) fn proof_holds(argv: &[String], pid: Pid, cmdline: &str) -> bool {
    let subst = |s: &str| s.replace("{pid}", &pid.to_string()).replace("{cmdline}", cmdline);
    let arg0 = subst(&argv[0]);
    let args: Vec<String> = argv[1..].iter().map(|a| subst(a)).collect();
    std::process::Command::new(&arg0)
        .args(&args)
        .status()
        .is_ok_and(|s| s.success())
}

/// Collect the full audit state.
pub fn collect<P: Procfs>(cfg: &Config, proc: &P, repo: &Path) -> Result<AuditReport> {
    let reg = Registry::new(cfg.paths.registry.clone());
    let chain = orphan::ancestry_chain(proc, cfg.parent_rule.max_ancestry_depth);

    let mut lanes = Vec::new();
    for name in reg.list() {
        let v = lane_verdict(&reg, &name, proc);
        let wt = Registry::meta_field(&reg.dir(&name), "worktree").map(PathBuf::from);
        let wv = worktree::classify(wt.as_deref());
        lanes.push(LaneAudit {
            orphan: matches!(
                v,
                crate::registry::LaneVerdict::DeadOrphan
                    | crate::registry::LaneVerdict::LeaderDeadGroupAlive
            ),
            pgid: reg.read_pid(&name).map(|(p, _)| p),
            verdict: v.to_string(),
            worktree: wt.map(|p| p.display().to_string()),
            worktree_verdict: wv.to_string(),
            name,
        });
    }

    let mut classes = Vec::new();
    let mut any_orphan_proc = false;
    for class in &cfg.class {
        let re = Config::class_regex(class)?;
        let mut procs = Vec::new();
        for st in orphan::scan_matching(proc, &re, &chain) {
            let orphan = orphan::is_orphan(proc, st.pid, &cfg.parent_rule);
            let proof = class
                .proof_command
                .as_ref()
                .map(|argv| proof_holds(argv, st.pid, &st.cmdline));
            if orphan && proof.unwrap_or(true) {
                any_orphan_proc = true;
            }
            procs.push(ProcAudit {
                pid: st.pid,
                orphan,
                proof,
            });
        }
        classes.push(ClassAudit {
            name: class.name.clone(),
            anchor: class.cmdline_anchor.clone(),
            procs,
        });
    }

    let mut lock = LockAudit {
        path: cfg.lock.path.clone(),
        absent: !cfg.lock.path.exists(),
        error: None,
        holders: Vec::new(),
    };
    let mut orphan_holders = false;
    if !lock.absent {
        match proc.lock_holders(&cfg.lock.path) {
            Ok(pids) => {
                for pid in pids {
                    let cls = orphan::holder_class(proc, pid, &cfg.parent_rule);
                    orphan_holders |= matches!(cls, orphan::HolderClass::Orphan);
                    lock.holders.push(HolderAudit {
                        pid,
                        class: cls.to_string(),
                    });
                }
            }
            Err(e) => lock.error = Some(format!("{e:#}")),
        }
    }

    let ahead = worktree::ahead_count(repo);

    let registered: Vec<String> = worktree::registered_worktrees(repo);
    let mut worktrees = Vec::new();
    if let Ok(rd) = std::fs::read_dir(&cfg.paths.scratch) {
        let mut dirs: Vec<PathBuf> = rd
            .flatten()
            .map(|e| e.path())
            .filter(|p| {
                p.is_dir()
                    && p.file_name()
                        .is_some_and(|n| n.to_string_lossy().starts_with("wt-"))
            })
            .collect();
        dirs.sort();
        for p in dirs {
            let canon = p.canonicalize().unwrap_or_else(|_| p.clone());
            worktrees.push(WorktreeAudit {
                registered: registered.contains(&canon.to_string_lossy().to_string()),
                path: p,
            });
        }
    }

    let mut sentinels = Vec::new();
    for s in &cfg.sentinel {
        let mut paths = glob::expand(&s.glob);
        paths.sort();
        for p in paths {
            let age = age_hours(&p);
            if age >= s.age_hint_hours {
                sentinels.push(SentinelHint {
                    path: p,
                    age_hint_hours: s.age_hint_hours,
                    age_hours: age,
                });
            }
        }
    }

    let debris = lanes.iter().any(|l| l.orphan)
        || any_orphan_proc
        || orphan_holders
        || worktrees.iter().any(|w| !w.registered);

    Ok(AuditReport {
        utc: utc_stamp(),
        registry: cfg.paths.registry.clone(),
        lanes,
        classes,
        lock,
        repo: repo.to_path_buf(),
        ahead,
        worktrees,
        sentinels,
        debris,
    })
}

/// Human-readable audit text (mirrors the bash layout).
pub fn print_text(rep: &AuditReport) {
    println!("== audit {} ==", rep.utc);
    println!("-- lanes ({}) --", rep.registry.display());
    for l in &rep.lanes {
        println!("lane {}: {}", l.name, l.verdict);
    }
    if rep.lanes.iter().all(|l| !l.orphan) {
        println!("(no orphan lanes)");
    }
    for c in &rep.classes {
        println!("-- class '{}' ({}) --", c.name, c.anchor);
        if c.procs.is_empty() {
            println!("(no matches)");
        }
        for p in &c.procs {
            let state = if p.orphan {
                match p.proof {
                    Some(true) => "ORPHAN (reparented — holds inherited fds)".to_owned(),
                    Some(false) => "reparented but PROOF FAILED — inspect before kill".to_owned(),
                    None => "ORPHAN (reparented — holds inherited fds)".to_owned(),
                }
            } else {
                "live parent".to_owned()
            };
            println!("pid {}: {}", p.pid, state);
        }
    }
    println!("-- gate lock ({}) holders --", rep.lock.path.display());
    if rep.lock.absent {
        println!("(lock file absent — free)");
    } else if let Some(err) = &rep.lock.error {
        println!("SCAN FAILED: {err} — refusing to call the lock free");
    } else if rep.lock.holders.is_empty() {
        println!("(no holders — free)");
    } else {
        for h in &rep.lock.holders {
            let state = if h.class == "orphan" {
                "ORPHAN (reparented fd-201 heir)"
            } else {
                "live"
            };
            println!("pid {}: {}", h.pid, state);
        }
    }
    println!("-- commits ahead of origin --");
    match rep.ahead {
        Some(n) => println!("origin/main..main: {n}"),
        None => println!("origin/main..main: unknown (no origin/main in {})", rep.repo.display()),
    }
    println!("-- scratch wt-* vs git worktree list --");
    if rep.worktrees.is_empty() {
        println!("(none)");
    }
    for w in &rep.worktrees {
        if w.registered {
            println!("{}: registered worktree", w.path.display());
        } else {
            println!(
                "{}: STALE (no git worktree registers it — evidence of a dead lane; mtime NOT used)",
                w.path.display()
            );
        }
    }
    println!("-- sentinels older than hint (age hint ONLY — mtime is never evidence) --");
    if rep.sentinels.is_empty() {
        println!("(none)");
    }
    for s in &rep.sentinels {
        println!(
            "{}: age {}h past {}h hint — inspect, do not kill by age",
            s.path.display(),
            s.age_hours,
            s.age_hint_hours
        );
    }
}

/// `audit` command.
pub fn run<P: Procfs>(cfg: &Config, proc: &P, repo: &Path, json: bool) -> Result<i32> {
    let rep = collect(cfg, proc, repo)?;
    if let Some(err) = &rep.lock.error {
        // An unreadable fd table must never read as free: fail loud.
        anyhow::bail!("lock-holder scan failed: {err}");
    }
    if json {
        println!("{}", serde_json::to_string_pretty(&rep)?);
    } else {
        print_text(&rep);
    }
    Ok(if rep.debris { exit::DEBRIS } else { exit::OK })
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
    fn clean_registry_is_ok() {
        let tmp = tempfile::tempdir().unwrap();
        let f = FakeProcfs::new();
        let code = run(&cfg_in(tmp.path()), &f, Path::new("."), false).unwrap();
        assert_eq!(code, exit::OK);
    }

    #[test]
    fn orphan_lane_sets_debris_exit3() {
        let tmp = tempfile::tempdir().unwrap();
        let cfg = cfg_in(tmp.path());
        let reg = Registry::new(cfg.paths.registry.clone());
        std::fs::create_dir_all(reg.dir("dead")).unwrap();
        reg.write_pid("dead", 987_654, Some(1)).unwrap(); // nothing fake alive
        let f = FakeProcfs::new();
        let code = run(&cfg, &f, Path::new("."), false).unwrap();
        assert_eq!(code, exit::DEBRIS);
    }

    #[test]
    fn json_reports_debris() {
        let tmp = tempfile::tempdir().unwrap();
        let cfg = cfg_in(tmp.path());
        let reg = Registry::new(cfg.paths.registry.clone());
        std::fs::create_dir_all(reg.dir("dead")).unwrap();
        reg.write_pid("dead", 987_654, Some(1)).unwrap();
        let f = FakeProcfs::new();
        let rep = collect(&cfg, &f, Path::new(".")).unwrap();
        let j = serde_json::to_string(&rep).unwrap();
        assert!(j.contains("\"debris\":true"), "{j}");
    }

    #[test]
    fn unreadable_fd_fails_loud() {
        let tmp = tempfile::tempdir().unwrap();
        let cfg = cfg_in(tmp.path());
        std::fs::write(tmp.path().join("gate.lock"), "").unwrap();
        let f = FakeProcfs::new();
        f.add(999_998, 1, 999_998, 1, "holder", "flock -c gate");
        f.unreadable.borrow_mut().insert(999_998);
        let r = run(&cfg, &f, Path::new("."), false);
        assert!(r.is_err(), "unreadable fd table must fail loud, not read free");
    }

    #[test]
    fn stale_worktree_sets_debris() {
        let tmp = tempfile::tempdir().unwrap();
        let cfg = cfg_in(tmp.path());
        std::fs::create_dir_all(tmp.path().join("wt-ghost")).unwrap();
        let f = FakeProcfs::new();
        let code = run(&cfg, &f, Path::new("."), false).unwrap();
        assert_eq!(code, exit::DEBRIS);
    }

    #[test]
    fn sentinel_age_is_hint_not_debris() {
        let tmp = tempfile::tempdir().unwrap();
        let cfg = Config {
            sentinel: vec![crate::config::Sentinel {
                glob: tmp.path().join("*.final").to_string_lossy().to_string(),
                age_hint_hours: 6,
            }],
            ..cfg_in(tmp.path())
        };
        let p = tmp.path().join("x.final");
        std::fs::write(&p, "").unwrap();
        set_old_mtime(&p, 7 * 3600);
        let f = FakeProcfs::new();
        let rep = collect(&cfg, &f, Path::new(".")).unwrap();
        assert_eq!(rep.sentinels.len(), 1);
        assert!(!rep.debris, "age alone is never debris");
    }

    fn set_old_mtime(path: &Path, secs_ago: i64) {
        let t = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64
            - secs_ago;
        let ts = [
            libc::timespec { tv_sec: t, tv_nsec: 0 },
            libc::timespec { tv_sec: t, tv_nsec: 0 },
        ];
        let c = std::ffi::CString::new(path.to_string_lossy().into_owned()).unwrap();
        let rc = unsafe { libc::utimensat(libc::AT_FDCWD, c.as_ptr(), ts.as_ptr(), 0) };
        assert_eq!(rc, 0);
    }
}
