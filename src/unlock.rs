//! `unlock` — resolve gate-lock holders.
//!
//! Live holder → wait with a deadline (a live gate must finish). Orphan
//! holder → kill its chain, re-classifying every round (killing the flock
//! parent surfaces its command child as a new orphan). A live surfacer
//! means someone else took the lock: refuse.

use std::time::{Duration, Instant};

use anyhow::Result;

use crate::config::Config;
use crate::exit;
use crate::orphan::{self, ancestry_chain, HolderClass};
use crate::procfs::Procfs;

/// `unlock [deadline-s]`
pub fn unlock<P: Procfs>(cfg: &Config, proc: &P, deadline: u64) -> Result<i32> {
    if !cfg.lock.path.exists() {
        println!("gate lock: file absent — free");
        return Ok(exit::OK);
    }
    let holders = proc.lock_holders(&cfg.lock.path)?;
    if holders.is_empty() {
        println!("gate lock: no holders — free");
        return Ok(exit::OK);
    }
    // M6: a holder that IS us or one of our ancestors is an inherited fd
    // (gate-hook shape). Killing it would TERM our own lineage — refuse.
    let chain = ancestry_chain(proc, cfg.parent_rule.max_ancestry_depth);
    if let Some(self_pid) = holders.iter().find(|p| chain.contains(p)) {
        eprintln!(
            "gate lock: holder pid {self_pid} is our own pid or an ancestor (inherited fd) — refusing to kill our own lineage"
        );
        return Ok(exit::BAD);
    }
    let (live, orphans): (Vec<_>, Vec<_>) = holders.into_iter().partition(|pid| {
        matches!(
            orphan::holder_class(proc, *pid, &cfg.parent_rule),
            HolderClass::Live
        )
    });
    if !live.is_empty() {
        println!(
            "gate lock: held LIVE by {} — waiting up to {deadline}s (a live gate must finish)",
            live.iter()
                .map(|p| p.to_string())
                .collect::<Vec<_>>()
                .join(" ")
        );
        let started = Instant::now();
        loop {
            let now = proc.lock_holders(&cfg.lock.path)?;
            if now.is_empty() {
                println!("gate lock: free");
                return Ok(exit::OK);
            }
            if started.elapsed() >= Duration::from_secs(deadline) {
                eprintln!(
                    "gate lock: TIMEOUT — still held by {} — refuse, retry later",
                    now.iter()
                        .map(|p| p.to_string())
                        .collect::<Vec<_>>()
                        .join(" ")
                );
                return Ok(exit::BAD);
            }
            std::thread::sleep(Duration::from_millis(200));
        }
    }
    println!(
        "gate lock: orphan holder(s) {} — killing chain",
        orphans
            .iter()
            .map(|p| p.to_string())
            .collect::<Vec<_>>()
            .join(" ")
    );
    let started = Instant::now();
    let chain_deadline = Duration::from_secs(30);
    loop {
        let now = proc.lock_holders(&cfg.lock.path)?;
        if now.is_empty() {
            println!("gate lock: free (orphan holders killed)");
            return Ok(exit::OK);
        }
        // Holders form a chain: killing the flock parent reparents its
        // command child, which still holds the inherited fd. Re-classify
        // every round; a LIVE surfacer is a normal busy gate — refuse.
        for pid in now {
            if !proc.pid_alive(pid) {
                continue; // died this round (group kill); dead holders release their fds
            }
            // M2: read the stat and carry its start_time into the kill —
            // a recycled holder pid is skipped, never killed blind.
            let Some(st) = proc.stat(pid) else {
                continue; // vanished before the kill — skip
            };
            match orphan::holder_class(proc, pid, &cfg.parent_rule) {
                HolderClass::Orphan => {
                    println!("gate lock: killing orphan holder pid {pid}");
                    if !orphan::kill_orphan_safely(proc, pid, Some(st.start_time), Duration::from_secs(5))?
                    {
                        println!("gate lock: holder pid {pid} vanished/recycled before the kill — skipped");
                    }
                }
                HolderClass::Live => {
                    eprintln!("gate lock: live holder pid {pid} appeared — refuse (wait for it)");
                    return Ok(exit::BAD);
                }
            }
        }
        if started.elapsed() >= chain_deadline {
            let now = proc.lock_holders(&cfg.lock.path)?;
            eprintln!(
                "gate lock: TIMEOUT after killing orphans — still held by {} (mtime not used)",
                now.iter()
                    .map(|p| p.to_string())
                    .collect::<Vec<_>>()
                    .join(" ")
            );
            return Ok(exit::BAD);
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{Lock, Paths};
    use crate::fake::FakeProcfs;

    fn cfg_in(dir: &std::path::Path) -> Config {
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
    fn absent_lock_is_free() {
        let tmp = tempfile::tempdir().unwrap();
        let f = FakeProcfs::new();
        assert_eq!(unlock(&cfg_in(tmp.path()), &f, 1).unwrap(), exit::OK);
    }

    #[test]
    fn live_holder_wait_times_out_and_refuses() {
        let tmp = tempfile::tempdir().unwrap();
        let cfg = cfg_in(tmp.path());
        std::fs::write(&cfg.lock.path, "").unwrap();
        let f = FakeProcfs::new();
        f.add(6, 999_999_999, 6, 1, "harness", "nextest");
        f.add(std::process::id(), 6, std::process::id(), 1, "lanespec", "lanespec unlock");
        f.add(940_001, std::process::id(), std::process::id(), 1, "gate", "flock gate.lock -c leg");
        f.add_holder(&cfg.lock.path, 940_001);
        assert_eq!(unlock(&cfg, &f, 0).unwrap(), exit::BAD);
        assert!(f.sent.borrow().is_empty(), "live holder must never be killed");
    }

    #[test]
    fn orphan_chain_is_killed_round_by_round() {
        let tmp = tempfile::tempdir().unwrap();
        let cfg = cfg_in(tmp.path());
        std::fs::write(&cfg.lock.path, "").unwrap();
        let f = FakeProcfs::new();
        // flock parent reparented (ppid dead), its command child holds the fd
        f.add(940_010, 999_999_999, 940_010, 1, "flock", "flock gate.lock -c leg");
        f.add(940_011, 940_010, 940_010, 1, "leg", "run-unit-tests");
        f.add_holder(&cfg.lock.path, 940_010);
        f.add_holder(&cfg.lock.path, 940_011);
        assert_eq!(unlock(&cfg, &f, 60).unwrap(), exit::OK);
        assert!(!f.pid_alive(940_010));
        assert!(!f.pid_alive(940_011));
    }

    /// M6 regression: a holder that is our own pid (or an ancestor with
    /// the inherited fd) must cause a REFUSAL — killing it would TERM our
    /// own lineage (gate-hook-invokes-unlock self-kill shape).
    #[test]
    fn holder_is_self_or_ancestor_refuses_never_signals() {
        // holder == own pid
        let tmp = tempfile::tempdir().unwrap();
        let cfg = cfg_in(tmp.path());
        std::fs::write(&cfg.lock.path, "").unwrap();
        let f = FakeProcfs::new();
        f.add(std::process::id(), 1, std::process::id(), 1, "lanespec", "lanespec unlock");
        f.add_holder(&cfg.lock.path, std::process::id());
        assert_eq!(unlock(&cfg, &f, 1).unwrap(), exit::BAD, "self holder must refuse");
        assert!(f.sent.borrow().is_empty(), "self holder must never be killed");

        // holder == own parent
        let f2 = FakeProcfs::new();
        let mypid = std::process::id();
        f2.add(940_099, 1, 940_099, 1, "gate", "flock gate.lock -c hook");
        f2.add(mypid, 940_099, 940_099, 1, "lanespec", "lanespec unlock");
        f2.add_holder(&cfg.lock.path, 940_099);
        assert_eq!(unlock(&cfg, &f2, 1).unwrap(), exit::BAD, "ancestor holder must refuse");
        assert!(f2.sent.borrow().is_empty(), "ancestor holder must never be killed");
    }

    #[test]
    fn live_surfacer_refuses() {
        let tmp = tempfile::tempdir().unwrap();
        let cfg = cfg_in(tmp.path());
        std::fs::write(&cfg.lock.path, "").unwrap();
        let f = FakeProcfs::new();
        f.add(940_020, 999_999_999, 940_020, 1, "flock", "flock gate.lock -c leg");
        f.add_holder(&cfg.lock.path, 940_020);
        f.add(6, 999_999_999, 6, 1, "harness", "nextest");
        f.add(std::process::id(), 6, std::process::id(), 1, "lanespec", "x");
        f.add(940_021, std::process::id(), std::process::id(), 1, "newgate", "flock gate.lock -c other");
        f.add_holder(&cfg.lock.path, 940_021);
        // 940_020 orphan, 940_021 live → initial classify puts 940_021 in
        // the LIVE bucket → wait branch, deadline 0 → refuse.
        assert_eq!(unlock(&cfg, &f, 0).unwrap(), exit::BAD);
        assert!(f.pid_alive(940_020), "live branch kills nothing");
    }
}
