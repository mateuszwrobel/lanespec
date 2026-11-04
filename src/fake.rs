//! Fake process table for unit tests. Signals are recorded, never real:
//! unit tests must not kill real pids.

use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use anyhow::{Result, bail};

use crate::procfs::{Pid, ProcStat, Procfs, Signal};

/// One fake process.
#[derive(Debug, Clone)]
pub struct FakeProc {
    /// Parent pid.
    pub ppid: Pid,
    /// Process group id.
    pub pgid: Pid,
    /// Simulated incarnation stamp.
    pub start_time: u64,
    /// Short name.
    pub comm: String,
    /// Command line (match target for classes/tags).
    pub cmdline: String,
    /// When true, TERM does not kill it; only KILL does.
    pub survives_term: bool,
}

/// A recorded signal: negative target = whole process group.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Sent {
    /// A whole group was signalled.
    Group(Pid, Signal),
    /// A single pid was signalled.
    One(Pid, Signal),
}

/// In-memory process table implementing [`Procfs`].
#[derive(Debug, Default)]
pub struct FakeProcfs {
    procs: RefCell<BTreeMap<Pid, FakeProc>>,
    dead: RefCell<BTreeSet<Pid>>,
    /// Every signal delivered, in order.
    pub sent: RefCell<Vec<Sent>>,
    holders: RefCell<BTreeMap<PathBuf, BTreeSet<Pid>>>,
    /// Pids whose fd table reads as unreadable (lock scan must fail loud).
    pub unreadable: RefCell<BTreeSet<Pid>>,
    /// Pids that survive TERM and KILL (models a D-state/unkillable candidate).
    unkillable: RefCell<BTreeSet<Pid>>,
    /// Pids owned by another user: signalling them fails EPERM (m1).
    eperm: RefCell<BTreeSet<Pid>>,
}

impl FakeProcfs {
    /// Empty table.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Insert a process (alive).
    pub fn add(&self, pid: Pid, ppid: Pid, pgid: Pid, start_time: u64, comm: &str, cmdline: &str) {
        self.procs.borrow_mut().insert(
            pid,
            FakeProc {
                ppid,
                pgid,
                start_time,
                comm: comm.to_owned(),
                cmdline: cmdline.to_owned(),
                survives_term: false,
            },
        );
        self.dead.borrow_mut().remove(&pid);
    }

    /// Make TERM insufficient for `pid` (it dies only on KILL).
    pub fn set_survives_term(&self, pid: Pid) {
        if let Some(p) = self.procs.borrow_mut().get_mut(&pid) {
            p.survives_term = true;
        }
    }

    /// Pretend `pid` exited (without any signal) — models a crash.
    pub fn expire(&self, pid: Pid) {
        self.dead.borrow_mut().insert(pid);
    }

    /// Re-record `pid` with a different start_time — models pid recycling.
    pub fn recycle(&self, pid: Pid, start_time: u64) {
        if let Some(p) = self.procs.borrow_mut().get_mut(&pid) {
            p.start_time = start_time;
        }
    }

    /// Make `pid` survive TERM and KILL — models an unkillable candidate
    /// (D-state, or a protected pid) that must never spin a kill loop.
    pub fn set_unkillable(&self, pid: Pid) {
        self.unkillable.borrow_mut().insert(pid);
    }

    /// Make signalling `pid` fail EPERM — models another user's process.
    /// A sweep must log it and CONTINUE, never abort mid-kill (m1).
    pub fn set_eperm(&self, pid: Pid) {
        self.eperm.borrow_mut().insert(pid);
    }

    /// Make `pid` hold `path` open (lock holder).
    pub fn add_holder(&self, path: &Path, pid: Pid) {
        self.holders
            .borrow_mut()
            .entry(path.to_path_buf())
            .or_default()
            .insert(pid);
    }

    /// True when any ALIVE member of `pgid` is marked eperm.
    fn has_eperm_in_group(&self, pgid: Pid) -> bool {
        let eperm = self.eperm.borrow();
        let dead = self.dead.borrow();
        self.procs.borrow().iter().any(|(pid, p)| {
            p.pgid == pgid && !dead.contains(pid) && eperm.contains(pid)
        })
    }

    fn mark_group_dead(&self, pgid: Pid, sig: Signal) {
        let unkillable = self.unkillable.borrow();
        let victims: Vec<Pid> = self
            .procs
            .borrow()
            .iter()
            .filter(|(_, p)| p.pgid == pgid)
            .filter(|(pid, _)| !unkillable.contains(pid))
            .filter(|(_, p)| sig == Signal::Kill || !p.survives_term)
            .map(|(pid, _)| *pid)
            .collect();
        for pid in victims {
            self.dead.borrow_mut().insert(pid);
        }
    }

    fn mark_dead(&self, pid: Pid, sig: Signal) {
        if self.unkillable.borrow().contains(&pid) {
            return;
        }
        let survives = self
            .procs
            .borrow()
            .get(&pid)
            .is_some_and(|p| p.survives_term && sig == Signal::Term);
        if !survives {
            self.dead.borrow_mut().insert(pid);
        }
    }
}

impl Procfs for FakeProcfs {
    fn stat(&self, pid: Pid) -> Option<ProcStat> {
        if self.dead.borrow().contains(&pid) {
            return None;
        }
        let p = self.procs.borrow().get(&pid).cloned()?;
        Some(ProcStat {
            pid,
            ppid: p.ppid,
            pgid: p.pgid,
            start_time: p.start_time,
            comm: p.comm,
            cmdline: p.cmdline,
        })
    }

    fn pids(&self) -> Vec<Pid> {
        let dead = self.dead.borrow();
        self.procs
            .borrow()
            .keys()
            .filter(|p| !dead.contains(p))
            .copied()
            .collect()
    }

    fn pid_alive(&self, pid: Pid) -> bool {
        self.procs.borrow().contains_key(&pid) && !self.dead.borrow().contains(&pid)
    }

    fn pgid_alive(&self, pgid: Pid) -> bool {
        let dead = self.dead.borrow();
        self.procs
            .borrow()
            .iter()
            .any(|(pid, p)| p.pgid == pgid && !dead.contains(pid))
    }

    fn signal_pgid(&self, pgid: Pid, sig: Signal) -> Result<()> {
        if pgid == 0 {
            bail!("refusing to signal pgid 0 (own process group)");
        }
        if pgid <= 1 {
            bail!("refusing to signal pgid {pgid} — pid/pgid 1 is the kernel's reparent floor, never a kill target");
        }
        if self.has_eperm_in_group(pgid) {
            // m1: a member belongs to another user — real kill(-pgid) answers EPERM.
            return Err(std::io::Error::from_raw_os_error(libc::EPERM).into());
        }
        self.sent.borrow_mut().push(Sent::Group(pgid, sig));
        self.mark_group_dead(pgid, sig);
        Ok(())
    }

    fn signal_pid(&self, pid: Pid, sig: Signal) -> Result<()> {
        if pid <= 1 {
            bail!("refusing to signal pid {pid} — pid/pgid 1 is the kernel's reparent floor, never a kill target");
        }
        if self.eperm.borrow().contains(&pid) {
            // m1: another user's pid — EPERM, no signal delivered.
            return Err(std::io::Error::from_raw_os_error(libc::EPERM).into());
        }
        self.sent.borrow_mut().push(Sent::One(pid, sig));
        self.mark_dead(pid, sig);
        Ok(())
    }

    fn lock_holders(&self, lock: &Path) -> Result<Vec<Pid>> {
        for pid in self.unreadable.borrow().iter() {
            if self.pid_alive(*pid) {
                bail!("reading /proc/{pid}/fd: unreadable — refusing to call the lock free");
            }
        }
        let alive = |p: &Pid| self.pid_alive(*p);
        let mut out: Vec<Pid> = self
            .holders
            .borrow()
            .get(lock)
            .map(|s| s.iter().copied().filter(alive).collect())
            .unwrap_or_default();
        out.sort_unstable();
        Ok(out)
    }

    fn uid_of(&self, _pid: Pid) -> Option<u32> {
        // Every fake process is owned by the current uid.
        Some(crate::procfs::current_uid())
    }
}

#[cfg(test)]
mod tests {
    use super::FakeProcfs;
    use crate::procfs::{Procfs, RealProcfs, Signal};

    /// M7 regression: nothing may ever signal pid 1 or pgid 1 (init is
    /// the reparent TARGET; signalling it is the worst kill available).
    #[test]
    fn signal_floor_refuses_pid_and_pgid_one() {
        let rp = RealProcfs::new();
        assert!(rp.signal_pid(0, Signal::Kill).is_err());
        assert!(rp.signal_pgid(0, Signal::Kill).is_err());
        assert!(rp.signal_pid(1, Signal::Kill).is_err(), "pid 1 must never be signalled");
        assert!(rp.signal_pgid(1, Signal::Term).is_err(), "pid 1 must never be signalled");
        let f = FakeProcfs::new();
        assert!(f.signal_pid(1, Signal::Kill).is_err());
        assert!(f.signal_pgid(1, Signal::Term).is_err());
        assert!(f.sent.borrow().is_empty(), "floor refusal must record no signal");
    }
}
