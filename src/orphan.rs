//! Parent-gone (reparent) proofs and safe orphan killing.
//!
//! Laws honoured here:
//! - mtime is NEVER evidence; only the process tree is consulted;
//! - a LIVE parent is NEVER touched;
//! - pgrep-self-match: every pattern scan excludes own pid + ancestors.

use std::collections::BTreeSet;
use std::time::Duration;

use anyhow::Result;
use regex::Regex;

use crate::config::ParentRule;
use crate::lifecycle::kill_pgid_settle;
use crate::procfs::{Pid, ProcStat, Procfs, Signal, current_uid};

/// Classification of a lock-fd holder.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HolderClass {
    /// Spawner died: the holder (or its parent) was reparented.
    Orphan,
    /// Ancestry leads to live, un-reparented processes.
    Live,
}

impl std::fmt::Display for HolderClass {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            HolderClass::Orphan => write!(f, "orphan"),
            HolderClass::Live => write!(f, "live"),
        }
    }
}

/// Pids the kernel reparents orphans to: init (1) plus the running
/// reparent-target processes (own uid, exact comm match).
#[must_use]
pub fn reparent_target_pids<P: Procfs>(proc: &P, rule: &ParentRule) -> BTreeSet<Pid> {
    let mut out = BTreeSet::from([1]);
    for pid in proc.pids() {
        if proc.uid_of(pid) != Some(current_uid()) {
            continue;
        }
        if let Some(st) = proc.stat(pid)
            && rule.reparent_targets.contains(&st.comm)
        {
            out.insert(pid);
        }
    }
    out
}

/// True when `pid`'s parent is a reparent target (init/systemd-user) or is
/// dead: the spawner died, so this process is a proven orphan.
#[must_use]
pub fn is_orphan<P: Procfs>(proc: &P, pid: Pid, rule: &ParentRule) -> bool {
    match proc.stat(pid) {
        // a dead pid is not a process to classify
        Some(st) => is_orphan_stat(proc, &st, rule),
        None => false,
    }
}

/// Same proof as [`is_orphan`] but on a stat the caller ALREADY holds:
/// classify and kill must read the SAME snapshot, or the classification
/// races the pid-reuse window (TOCTOU law).
#[must_use]
pub fn is_orphan_stat<P: Procfs>(proc: &P, st: &ProcStat, rule: &ParentRule) -> bool {
    if rule.reparent_targets.contains(&st.comm) {
        return false; // never treat a reparent target itself as reparented
    }
    if st.ppid <= 1 {
        return true;
    }
    reparent_target_pids(proc, rule).contains(&st.ppid) || !proc.pid_alive(st.ppid)
}

/// Holder class of a lock-fd holder, mirroring the bash supervisor:
/// directly reparented → orphan; otherwise the parent decides one level
/// up (flock-spawned fleet children), so a running gate's own children
/// are never classified orphan.
#[must_use]
pub fn holder_class<P: Procfs>(proc: &P, pid: Pid, rule: &ParentRule) -> HolderClass {
    if is_orphan(proc, pid, rule) {
        return HolderClass::Orphan;
    }
    if let Some(st) = proc.stat(pid)
        && st.ppid > 1
        && proc.pid_alive(st.ppid)
        && is_orphan(proc, st.ppid, rule)
    {
        return HolderClass::Orphan;
    }
    HolderClass::Live
}

/// Own pid + ancestors: the pgrep-self-match exclusion set. Lives in
/// [`crate::procfs::ancestry_chain`] so the lifecycle layer consults the
/// same lineage guard without a module cycle; re-exported here.
pub use crate::procfs::ancestry_chain;

/// All live pids whose cmdline matches `re`, excluding `exclude`.
#[must_use]
pub fn scan_matching<P: Procfs>(
    proc: &P,
    re: &Regex,
    exclude: &BTreeSet<Pid>,
) -> Vec<ProcStat> {
    proc.pids()
        .into_iter()
        .filter(|p| !exclude.contains(p))
        .filter_map(|p| proc.stat(p))
        .filter(|st| re.is_match(&st.cmdline))
        .collect()
}

/// Kill a proven-orphan pid without ever dragging a live group down:
/// the whole group when the pid leads it or its leader is dead (and the
/// group is not our own); otherwise the pid alone.
///
/// `expect_start` is the start_time read when the caller PROVED the pid
/// orphaned: it is re-validated here immediately before signalling. A pid
/// that vanished (stat → None) is SKIPPED, never blind-killed — the old
/// blind `kill -KILL` could hit a recycled pid (pid-reuse law).
/// Returns whether a signal was actually delivered.
pub fn kill_orphan_safely<P: Procfs>(
    proc: &P,
    pid: Pid,
    expect_start: Option<u64>,
    settle: Duration,
) -> Result<bool> {
    let Some(st) = proc.stat(pid) else {
        return Ok(false); // vanished before the kill — skip, never signal blind
    };
    if let Some(s) = expect_start
        && st.start_time != s
    {
        return Ok(false); // pid recycled since the proof — skip
    }
    let my_pgid = proc.stat(std::process::id()).map(|s| s.pgid);
    let leader_dead_group =
        st.pgid != st.pid && Some(st.pgid) != my_pgid && !proc.pid_alive(st.pgid);
    if st.pgid == st.pid || leader_dead_group {
        kill_pgid_settle(proc, st.pgid, settle)?;
    } else {
        proc.signal_pid(st.pid, Signal::Term)?;
    }
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fake::FakeProcfs;

    fn rule() -> ParentRule {
        ParentRule::default()
    }

    /// fake tree: systemd-user(777) alive; 5=live agent, 10=shell(child of 5),
    /// 20=runner(child of 10, live chain), 30=reparented to 777,
    /// 40=child of dead 999.
    fn tree() -> FakeProcfs {
        let f = FakeProcfs::new();
        f.add(777, 1, 777, 1, "systemd", "/usr/lib/systemd/userd");
        f.add(5, 777, 5, 1, "worker", "other-tool run");
        f.add(10, 5, 10, 1, "shell", "bash");
        f.add(20, 10, 10, 1, "runner", "bash run.sh");
        f.add(30, 777, 30, 1, "gate", "flock -c gate");
        f.add(40, 999, 40, 1, "daemon", "/usr/lib/git-core/git-daemon lane-fixture-x");
        f
    }

    #[test]
    fn orphan_by_reparent_and_dead_parent() {
        let f = tree();
        let r = rule();
        assert!(!is_orphan(&f, 10, &r)); // live, un-reparented parent (5)
        assert!(!is_orphan(&f, 20, &r)); // live parent (10)
        assert!(is_orphan(&f, 30, &r)); // reparented to systemd-user
        assert!(is_orphan(&f, 40, &r)); // parent 999 dead
    }

    #[test]
    fn holder_class_fleet_vs_live() {
        let f = tree();
        let r = rule();
        // flock child whose PARENT is a reparented orphan → fleet orphan.
        f.add(50, 30, 30, 1, "git-daemon", "/usr/lib/git-core/git-daemon lane-fixture-f");
        assert_eq!(holder_class(&f, 50, &r), HolderClass::Orphan);
        // child of a live chain → live, never touched.
        assert_eq!(holder_class(&f, 20, &r), HolderClass::Live);
    }

    #[test]
    fn target_itself_is_not_reparented() {
        let f = tree();
        let r = rule();
        // 5's parent is 777 (a live systemd-user comm match), so 5 is
        // reparented by definition — same as the bash supervisor:
        assert!(is_orphan(&f, 5, &r));
        // but a target process itself is never an orphan:
        assert!(!is_orphan(&f, 777, &r));
    }

    #[test]
    fn safe_kill_leader_group_pid_only() {
        let f = FakeProcfs::new();
        let mypid = std::process::id();
        f.add(mypid, 1, mypid, 1, "lanespec", "lanespec test");
        // group leader: whole group goes
        f.add(100, 1, 100, 1, "leader", "leader");
        f.add(101, 100, 100, 1, "member", "member");
        kill_orphan_safely(&f, 100, Some(1), Duration::from_millis(20)).unwrap();
        assert!(!f.pgid_alive(100));
        // member of a live leader group: only the pid gets TERM
        f.add(200, 1, 200, 1, "leader2", "leader2");
        f.add(201, 200, 200, 1, "member2", "member2");
        kill_orphan_safely(&f, 201, Some(1), Duration::from_millis(20)).unwrap();
        assert!(f.pid_alive(200), "live group leader must survive");
        assert!(!f.pid_alive(201), "the orphan pid itself must die");
    }

    /// M2 regression: a pid that vanished (or got recycled) between the
    /// scan and the kill must NEVER be blind-killed.
    #[test]
    fn vanished_or_recycled_pid_is_skipped_never_blind_killed() {
        let f = FakeProcfs::new();
        let mypid = std::process::id();
        f.add(mypid, 1, mypid, 1, "lanespec", "lanespec test");
        f.add(300, 1, 300, 5, "gone", "lanespec:t:worker");
        f.expire(300); // vanished before the kill
        assert!(!kill_orphan_safely(&f, 300, Some(5), Duration::from_millis(5)).unwrap());
        // recycled: same pid number, different incarnation
        f.add(301, 1, 301, 5, "reused", "sleep 1");
        assert!(
            !kill_orphan_safely(&f, 301, Some(99), Duration::from_millis(5)).unwrap(),
            "start_time mismatch must skip the kill"
        );
        assert!(f.sent.borrow().is_empty(), "no signal may be sent: {:?}", f.sent.borrow());
    }

    #[test]
    fn scan_excludes_self_chain() {
        let f = FakeProcfs::new();
        let mypid = std::process::id();
        f.add(mypid, 1, mypid, 1, "me", "lanespec sweep lr-tag");
        f.add(300, 1, 300, 1, "other", "lr-tag worker");
        let excl = ancestry_chain(&f, 8);
        assert!(excl.contains(&mypid));
        let re = Regex::new("lr-tag").unwrap();
        let hits: Vec<Pid> = scan_matching(&f, &re, &excl).into_iter().map(|s| s.pid).collect();
        assert_eq!(hits, vec![300]);
    }
}
