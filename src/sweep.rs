//! `sweep` — kill ONLY parent-gone-proven processes within a bound.
//!
//! A bound (`--namespace` or `--class`) is REQUIRED: without it a sweep
//! could match real processes, so the command refuses (exit 5). A live
//! parent is never touched; the table is re-scanned after every kill.

use std::collections::BTreeSet;
use std::time::{Duration, Instant};

use anyhow::Result;
use regex::Regex;

use crate::audit;
use crate::config::Config;
use crate::exit;
use crate::lifecycle::{kill_pgid_settle, lane_verdict};
use crate::orphan::{self, ancestry_chain};
use crate::procfs::{Pid, Procfs};
use crate::registry::{LaneVerdict, Registry};

fn re_quote(s: &str) -> String {
    regex::escape(s)
}

/// True when the error chain bottoms out at EPERM — "this pid is not
/// ours to signal" (m1): a sweep logs it and CONTINUES, never aborts.
fn is_eperm(e: &anyhow::Error) -> bool {
    e.root_cause()
        .downcast_ref::<std::io::Error>()
        .is_some_and(|io| io.raw_os_error() == Some(libc::EPERM))
}

/// `sweep` with `--namespace` and/or `--class`; neither → exit 5.
/// An empty/whitespace-only bound is the same refusal: it would build a
/// pattern that matches every cmdline. The rescan-kill loop carries a
/// deadline and an iteration cap; hitting either is a loud TIMEOUT.
pub fn sweep<P: Procfs>(
    cfg: &Config,
    proc: &P,
    ns: Option<&str>,
    class: Option<&str>,
    settle: Duration,
    max_scans: u32,
    deadline: Duration,
) -> Result<i32> {
    let blank = |s: Option<&str>| s.is_some_and(|v| v.trim().is_empty());
    if (ns.is_none() && class.is_none()) || blank(ns) || blank(class) {
        eprintln!("lanespec: sweep: refusing without a non-empty --namespace/--class — a nameless sweep could match real processes");
        return Ok(exit::MISSING_BOUND);
    }
    let reg = Registry::new(cfg.paths.registry.clone());
    let label = format!(
        "ns={} class={}",
        ns.unwrap_or("-"),
        class.unwrap_or("-")
    );
    println!("== sweep {label} — parent-gone proof only, mtime never evidence ==");

    // 1. Registered lanes within the namespace bound.
    if let Some(ns) = ns {
        for name in reg.list() {
            let dir = reg.dir(&name);
            let lane_ns = Registry::meta_field(&dir, "ns").unwrap_or_else(|| "default".to_owned());
            if lane_ns != ns {
                println!("lane {name}: kept (other namespace)");
                continue;
            }
            let Some((pgid, start)) = reg.read_pid(&name) else {
                continue;
            };
            let v = lane_verdict(&reg, &name, proc);
            match v {
                LaneVerdict::Done(_) => {
                    println!("lane {name}: dead, nothing to kill");
                    continue;
                }
                LaneVerdict::StaleRecord => {
                    println!("lane {name}: stale-record (pid recycled) — NOT killed");
                    continue;
                }
                LaneVerdict::DeadOrphan => {
                    println!("lane {name}: pgid {pgid} already gone");
                    continue;
                }
                // Running AND leader-dead-group-alive both need the
                // live-session check and may end in a group kill.
                LaneVerdict::Running | LaneVerdict::LeaderDeadGroupAlive => {}
            }
            // Alive lane: a live session (launcher pid) keeps it.
            let launcher: Option<Pid> = Registry::meta_field(&dir, "launcher")
                .and_then(|s| s.parse().ok());
            if let Some(session) = launcher.filter(|p| proc.pid_alive(*p)) {
                println!("lane {name}: kept (live session pid {session})");
                continue;
            }
            if proc.pgid_alive(pgid) {
                let leader = proc.stat(pgid);
                let recycled = leader.is_some()
                    && !start.is_some_and(|s| leader.as_ref().is_some_and(|st| st.start_time == s));
                if recycled {
                    println!("lane {name}: pgid {pgid} stale-record — NOT killed");
                    continue;
                }
                if let Err(e) = kill_pgid_settle(proc, pgid, settle) {
                    if is_eperm(&e) {
                        println!("lane {name}: kept (eperm — pgid {pgid} is not ours to signal)");
                    } else {
                        eprintln!(
                            "lane {name}: kill error ({e:#}) — skipping, sweep continues"
                        );
                    }
                    continue;
                }
                let l = launcher.map_or_else(|| "?".to_owned(), |p| p.to_string());
                if leader.is_some() {
                    println!("lane {name}: killed pgid {pgid} (proven parent-gone: launcher {l} dead)");
                } else {
                    println!(
                        "lane {name}: killed pgid {pgid} (leader dead, group alive — fd-heir group kill; launcher {l} dead)"
                    );
                }
            } else {
                println!("lane {name}: pgid {pgid} already gone");
            }
        }
    }

    // 2. Tagged/class-matched processes, re-scanned after every kill.
    let mut pattern = String::new();
    let mut class_re: Option<Regex> = None;
    let mut class_proof: Option<&Vec<String>> = None;
    if let Some(ns) = ns {
        // m2: the tag prefix `lanespec:NS:` is the anchored match; the bare
        // ns alternative matches only as a whole WORD in the cmdline, never
        // as a substring ("tool-ns-x" must not match ns "ns").
        pattern.push_str(&format!("lanespec:{}:", re_quote(ns)));
        pattern.push('|');
        pattern.push_str(&format!("(^|\\s){}(\\s|$)", re_quote(ns)));
    }
    if let Some(cname) = class {
        let cls = cfg
            .class
            .iter()
            .find(|c| c.name == cname)
            .ok_or_else(|| anyhow::anyhow!("sweep: unknown class '{cname}'"))?;
        if !pattern.is_empty() {
            pattern.push('|');
        }
        pattern.push_str(&cls.cmdline_anchor);
        class_re = Some(Config::class_regex(cls)?);
        class_proof = cls.proof_command.as_ref();
    }
    let re = Regex::new(&pattern)?;
    let chain = ancestry_chain(proc, cfg.parent_rule.max_ancestry_depth);
    let mut kept_reported: Vec<Pid> = Vec::new();
    // Every-wait-has-a-deadline law: the rescan-kill loop is bounded by
    // both an iteration cap and a wall-clock deadline. A candidate that
    // survives its kill (D-state, protected pid) must never spin this
    // loop at full CPU: each matched pid is signalled at most once per
    // sweep, and a survivor ends the loop loudly, not silently.
    let started = Instant::now();
    let mut scans: u32 = 0;
    let mut attempted: BTreeSet<Pid> = BTreeSet::new();
    // m1: pids kept with EPERM are deliberately left alone — a rescan
    // seeing them again is expected, NOT the "survived kill" stuck signal.
    let mut kept_eperm: BTreeSet<Pid> = BTreeSet::new();
    let mut stuck = false;
    loop {
        scans += 1;
        let hits = orphan::scan_matching(proc, &re, &chain);
        let mut killed = false;
        for st in hits {
            if kept_eperm.contains(&st.pid) {
                continue; // intentionally kept (eperm) — not a survivor
            }
            if attempted.contains(&st.pid) {
                eprintln!(
                    "pid {} (pgid {}): survived kill and still matches — refusing to loop forever",
                    st.pid, st.pgid
                );
                stuck = true;
                continue;
            }
            // M3: classify AND kill from the SAME fresh stat — a stat
            // taken here, a proof from another stat, and a kill on a
            // third would race the pid-reuse window.
            let Some(cur) = proc.stat(st.pid) else {
                continue; // vanished mid-scan — skip, never signal blind (M2)
            };
            if cur.start_time != st.start_time {
                println!(
                    "pid {}: SKIPPED — pid recycled since the scan (start_time changed)",
                    cur.pid
                );
                kept_reported.push(cur.pid);
                continue;
            }
            if !orphan::is_orphan_stat(proc, &cur, &cfg.parent_rule) {
                if !kept_reported.contains(&cur.pid) {
                    kept_reported.push(cur.pid);
                    println!(
                        "pid {}: KEPT — live parent {} (never touched)",
                        cur.pid, cur.ppid
                    );
                }
                continue;
            }
            // M5: the class proof-command gates every kill it covers.
            if let (Some(cre), Some(proof)) = (&class_re, class_proof)
                && cre.is_match(&cur.cmdline)
                && !audit::proof_holds(proof, cur.pid, &cur.cmdline)
            {
                println!("pid {}: KEPT — class proof-command refused (nonzero exit)", cur.pid);
                kept_reported.push(cur.pid);
                continue;
            }
            attempted.insert(cur.pid);
            match orphan::kill_orphan_safely(proc, cur.pid, Some(cur.start_time), settle) {
                Ok(true) => {
                    println!(
                        "pid {} (pgid {}): killed (reparented — spawner dead; live groups never touched)",
                        cur.pid, cur.pgid
                    );
                    killed = true;
                    break; // re-scan after each kill
                }
                Ok(false) => {
                    println!("pid {}: SKIPPED — vanished or recycled between proof and kill", cur.pid);
                    kept_reported.push(cur.pid);
                }
                Err(e) if is_eperm(&e) => {
                    println!(
                        "pid {}: kept (eperm — not ours to signal), sweep continues",
                        cur.pid
                    );
                    // not a survivor: drop from attempted, remember as kept.
                    attempted.remove(&cur.pid);
                    kept_eperm.insert(cur.pid);
                    kept_reported.push(cur.pid);
                }
                Err(e) => {
                    eprintln!("pid {}: refused kill ({e:#}) — skipping, sweep continues", cur.pid);
                    kept_reported.push(cur.pid);
                }
            }
        }
        if !killed {
            break;
        }
        if scans >= max_scans || started.elapsed() >= deadline {
            eprintln!(
                "lanespec: sweep: TIMEOUT after {scans} scans / {:?} — kill loop bound reached with candidates still matching",
                started.elapsed()
            );
            stuck = true;
            break;
        }
    }
    println!("end sweep");
    if stuck {
        return Ok(exit::TIMEOUT);
    }
    Ok(exit::OK)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{LaneClass, Paths};
    use crate::fake::FakeProcfs;

    fn cfg_in(dir: &std::path::Path) -> Config {
        Config {
            paths: Paths {
                registry: dir.join("reg"),
                scratch: dir.to_path_buf(),
            },
            class: vec![LaneClass {
                name: "fleet".to_owned(),
                cmdline_anchor: "^/usr/lib/fleetd fleet-".to_owned(),
                proof_command: None,
                recovery_step: None,
            }],
            ..Default::default()
        }
    }

    #[test]
    fn nameless_sweep_refuses_with5() {
        let tmp = tempfile::tempdir().unwrap();
        let f = FakeProcfs::new();
        let code = sweep(&cfg_in(tmp.path()), &f, None, None, Duration::from_millis(10), 100, Duration::from_secs(30)).unwrap();
        assert_eq!(code, exit::MISSING_BOUND);
        assert!(f.sent.borrow().is_empty());
    }

    /// B1: `--namespace ""` used to pass the presence check and build an
    /// alternation with an empty branch — a match-everything kill loop.
    /// An empty (or whitespace-only) bound must refuse with exit 5.
    #[test]
    fn empty_or_blank_bound_refuses_with5_never_signals() {
        let tmp = tempfile::tempdir().unwrap();
        let cfg = cfg_in(tmp.path());
        let f = FakeProcfs::new();
        f.add(950_040, 1, 950_040, 7, "sleep", "sleep 31");
        for (ns, class) in [
            (Some(""), None),
            (Some("   "), None),
            (Some(""), Some("fleet")),
            (None, Some("")),
        ] {
            let code = sweep(&cfg, &f, ns, class, Duration::from_millis(1), 100, Duration::from_secs(30))
                .unwrap();
            assert_eq!(code, exit::MISSING_BOUND, "ns={ns:?} class={class:?} must refuse");
        }
        assert!(
            f.sent.borrow().is_empty(),
            "empty bound must never signal anything: {:?}",
            f.sent.borrow()
        );
    }

    /// B2: a candidate that survives TERM and KILL used to spin the
    /// rescan-kill loop forever at full CPU. The loop must terminate via
    /// its per-pid kill bound / scan cap / deadline and exit loudly.
    #[test]
    fn unkillable_candidate_terminates_loop_with_timeout() {
        let tmp = tempfile::tempdir().unwrap();
        let cfg = cfg_in(tmp.path());
        let f = FakeProcfs::new();
        f.add(std::process::id(), 1, std::process::id(), 7, "me", "lanespec sweep t9");
        f.add(950_050, 1, 950_050, 7, "zombie", "bash -c x lanespec:t9:worker");
        f.set_unkillable(950_050);
        let code = sweep(&cfg, &f, Some("t9"), None, Duration::from_millis(1), 100, Duration::from_secs(30))
            .unwrap();
        assert_eq!(code, exit::TIMEOUT, "unkillable candidate must exit loudly, not spin");
        // One TERM+KILL pair for the group — a kill storm is the bug.
        assert!(
            f.sent.borrow().len() <= 2,
            "bounded kill expected, got {:?}",
            f.sent.borrow()
        );
    }

    /// m1: EPERM used to propagate through `?` and ABORT the sweep
    /// mid-kill — another user's process stranded every candidate after
    /// it. EPERM must be logged ("kept (eperm)") and the sweep must
    /// continue with the remaining candidates and reach its normal exit.
    #[test]
    fn eperm_candidate_is_kept_and_sweep_continues() {
        let tmp = tempfile::tempdir().unwrap();
        let cfg = cfg_in(tmp.path());
        let f = FakeProcfs::new();
        // eperm orphan: another user's reparented process.
        f.add(950_060, 1, 950_060, 7, "otherd", "bash -c x lanespec:ep:otheruser");
        f.set_eperm(950_060);
        // ordinary reparented orphan AFTER it — must still be killed.
        f.add(950_061, 1, 950_061, 7, "orphaned", "bash -c x lanespec:ep:worker");
        let code = sweep(
            &cfg,
            &f,
            Some("ep"),
            None,
            Duration::from_millis(1),
            100,
            Duration::from_secs(30),
        )
        .unwrap();
        assert_eq!(code, exit::OK, "EPERM must not abort or time out the sweep");
        assert!(f.pid_alive(950_060), "EPERM candidate stays — not ours to kill");
        assert!(!f.pid_alive(950_061), "sweep must continue PAST the EPERM pid");
        // EPERM means NO signal was delivered to that group.
        assert!(
            !f.sent.borrow().iter().any(|s| format!("{s:?}").contains("950060")),
            "no signal may be recorded for the EPERM pid: {:?}",
            f.sent.borrow()
        );
    }

    /// m2: the bare-ns regex alternative matched the namespace ANYWHERE
    /// as a substring — `--namespace ns` matched "tool-ns-x run". The bare
    /// form must match whole words only; the tag prefix stays the anchor.
    #[test]
    fn bare_ns_alternative_matches_words_never_substrings() {
        let tmp = tempfile::tempdir().unwrap();
        let cfg = cfg_in(tmp.path());
        let f = FakeProcfs::new();
        // substring-only mention of the namespace — must NEVER match.
        f.add(950_070, 1, 950_070, 7, "tool", "mytool-nsx-run --job backup-nsx-data");
        // namespace as a whole word — matches the bare alternative.
        f.add(950_071, 1, 950_071, 7, "worker", "worker nsx data");
        let code = sweep(
            &cfg,
            &f,
            Some("nsx"),
            None,
            Duration::from_millis(1),
            100,
            Duration::from_secs(30),
        )
        .unwrap();
        assert_eq!(code, exit::OK);
        assert!(
            f.pid_alive(950_070),
            "substring mention of the namespace must never be a kill target"
        );
        assert!(!f.pid_alive(950_071), "whole-word namespace is in the bound");
    }

    #[test]
    fn live_session_lane_is_kept() {
        let tmp = tempfile::tempdir().unwrap();
        let cfg = cfg_in(tmp.path());
        let reg = Registry::new(cfg.paths.registry.clone());
        std::fs::create_dir_all(reg.dir("l1")).unwrap();
        reg.write_meta("l1", &[
            ("name".to_owned(), "l1".to_owned()),
            ("ns".to_owned(), "t1".to_owned()),
            ("launcher".to_owned(), std::process::id().to_string()),
        ])
        .unwrap();
        reg.write_pid("l1", 950_001, Some(7)).unwrap();
        let f = FakeProcfs::new();
        f.add(std::process::id(), 1, std::process::id(), 1, "lanespec", "lanespec sweep t1");
        f.add(950_001, std::process::id(), 950_001, 7, "sleep", "sleep 31");
        let code = sweep(&cfg, &f, Some("t1"), None, Duration::from_millis(10), 100, Duration::from_secs(30)).unwrap();
        assert_eq!(code, exit::OK);
        assert!(f.sent.borrow().is_empty(), "live session lane must be kept");
    }

    #[test]
    fn orphaned_lane_killed_tagged_orphan_killed_live_kept() {
        let tmp = tempfile::tempdir().unwrap();
        let cfg = cfg_in(tmp.path());
        let reg = Registry::new(cfg.paths.registry.clone());
        std::fs::create_dir_all(reg.dir("l1")).unwrap();
        reg.write_meta("l1", &[
            ("name".to_owned(), "l1".to_owned()),
            ("ns".to_owned(), "t1".to_owned()),
            ("launcher".to_owned(), "999999999".to_owned()), // dead launcher
        ])
        .unwrap();
        reg.write_pid("l1", 950_002, Some(7)).unwrap();
        let f = FakeProcfs::new();
        f.add(950_002, 999_999_999, 950_002, 7, "sleep", "sleep 31");
        // tagged orphan (reparented to init)
        f.add(950_003, 1, 950_003, 7, "bash", "bash -c runner lanespec:t1:worker");
        // tagged but live-parented
        f.add(std::process::id(), 1, std::process::id(), 7, "me", "lanespec sweep t1");
        f.add(950_004, std::process::id(), std::process::id(), 7, "bash", "bash -c x lanespec:t1:decoy");
        let code = sweep(&cfg, &f, Some("t1"), None, Duration::from_millis(10), 100, Duration::from_secs(30)).unwrap();
        assert_eq!(code, exit::OK);
        assert!(!f.pgid_alive(950_002), "orphaned lane group must die");
        assert!(!f.pid_alive(950_003), "tagged reparented pid must die");
        assert!(f.pid_alive(950_004), "tagged pid with live parent must survive");
    }

    #[test]
    fn class_sweep_uses_anchor_kill_only_proven() {
        let tmp = tempfile::tempdir().unwrap();
        let cfg = cfg_in(tmp.path());
        let f = FakeProcfs::new();
        f.add(950_010, 1, 950_010, 7, "fleetd", "/usr/lib/fleetd fleet-orphan");
        f.add(std::process::id(), 1, std::process::id(), 7, "me", "lanespec sweep --class fleet");
        f.add(950_011, std::process::id(), std::process::id(), 7, "fleetd", "/usr/lib/fleetd fleet-live");
        let code = sweep(&cfg, &f, None, Some("fleet"), Duration::from_millis(10), 100, Duration::from_secs(30)).unwrap();
        assert_eq!(code, exit::OK);
        assert!(!f.pid_alive(950_010));
        assert!(f.pid_alive(950_011));
    }

    #[test]
    fn unknown_class_errors() {
        let tmp = tempfile::tempdir().unwrap();
        let f = FakeProcfs::new();
        assert!(sweep(&cfg_in(tmp.path()), &f, None, Some("nope"), Duration::from_millis(10), 100, Duration::from_secs(30)).is_err());
    }

    /// M1 regression: a registered lane whose leader pid is GONE but
    /// whose group is still alive (fd-heir) must be KILLED by sweep, not
    /// collapsed into "stale-record — NOT killed".
    #[test]
    fn sweep_kills_leader_dead_group_lane() {
        let tmp = tempfile::tempdir().unwrap();
        let cfg = cfg_in(tmp.path());
        let reg = Registry::new(cfg.paths.registry.clone());
        std::fs::create_dir_all(reg.dir("l1")).unwrap();
        reg.write_meta("l1", &[
            ("name".to_owned(), "l1".to_owned()),
            ("ns".to_owned(), "t1".to_owned()),
            ("launcher".to_owned(), "999999999".to_owned()), // dead launcher
        ])
        .unwrap();
        reg.write_pid("l1", 950_006, Some(7)).unwrap();
        let f = FakeProcfs::new();
        f.add(std::process::id(), 1, std::process::id(), 7, "me", "lanespec sweep t1");
        f.add(950_006, 999_999_999, 950_006, 7, "bash", "bash -c runner lanespec:t1:runner");
        f.add(950_007, 950_006, 950_006, 7, "sleep", "sleep 40"); // fd-heir member
        f.expire(950_006); // the leader died, the group lives
        let code = sweep(&cfg, &f, Some("t1"), None, Duration::from_millis(10), 100, Duration::from_secs(30))
            .unwrap();
        assert_eq!(code, exit::OK);
        assert!(!f.pgid_alive(950_006), "leader-dead group must be killed");
        assert!(!f.pid_alive(950_007), "the fd-heir member must die with the group");
    }

    /// M5 regression: the class proof-command must GATE sweep kills —
    /// a nonzero proof refuses that candidate, printed with its verdict.
    #[test]
    fn class_proof_gates_sweep_kill() {
        let tmp = tempfile::tempdir().unwrap();
        let mut cfg = cfg_in(tmp.path());
        cfg.class[0].proof_command =
            Some(vec!["/bin/false".to_owned(), "{pid}".to_owned()]);
        let f = FakeProcfs::new();
        f.add(std::process::id(), 1, std::process::id(), 7, "me", "lanespec sweep --class fleet");
        f.add(950_012, 1, 950_012, 7, "fleetd", "/usr/lib/fleetd fleet-proofno");
        let code = sweep(&cfg, &f, None, Some("fleet"), Duration::from_millis(10), 100, Duration::from_secs(30))
            .unwrap();
        assert_eq!(code, exit::OK);
        assert!(
            f.pid_alive(950_012),
            "proof-refused orphan must NOT be killed"
        );
        assert!(f.sent.borrow().is_empty(), "no signal may precede the proof: {:?}", f.sent.borrow());
        // With a passing proof the very same orphan IS killed.
        cfg.class[0].proof_command =
            Some(vec!["/bin/true".to_owned(), "{pid}".to_owned()]);
        let code = sweep(&cfg, &f, None, Some("fleet"), Duration::from_millis(10), 100, Duration::from_secs(30))
            .unwrap();
        assert_eq!(code, exit::OK);
        assert!(!f.pid_alive(950_012), "proof-passed orphan must die");
    }
}
