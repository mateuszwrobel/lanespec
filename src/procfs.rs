//! Process inspection behind a trait so unit tests run against a fake
//! process table and never signal real processes.

use std::collections::BTreeSet;
use std::io;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};

/// A process id.
pub type Pid = u32;

/// Signals lanespec sends. Nothing else.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Signal {
    /// Polite termination.
    Term,
    /// Immediate kill.
    Kill,
}

impl Signal {
    fn num(self) -> i32 {
        match self {
            Signal::Term => libc::SIGTERM,
            Signal::Kill => libc::SIGKILL,
        }
    }
}

/// The slice of `/proc/<pid>/stat` + cmdline lanespec needs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcStat {
    /// The process id.
    pub pid: Pid,
    /// Parent pid.
    pub ppid: Pid,
    /// Process group id.
    pub pgid: Pid,
    /// `starttime` (field 22 of stat): unique per pid incarnation —
    /// the pid-reuse guard.
    pub start_time: u64,
    /// Short name (field 2 of stat).
    pub comm: String,
    /// argv joined with spaces.
    pub cmdline: String,
}

/// Everything lanespec can ask the process table.
pub trait Procfs {
    /// Stat one pid; `None` when the pid does not exist.
    fn stat(&self, pid: Pid) -> Option<ProcStat>;
    /// All visible pids.
    fn pids(&self) -> Vec<Pid>;
    /// `kill -0` on a pid (EPERM counts as alive: it exists).
    fn pid_alive(&self, pid: Pid) -> bool;
    /// `kill -0` on a whole process group.
    fn pgid_alive(&self, pgid: Pid) -> bool;
    /// Signal a whole process group; ESRCH is not an error.
    fn signal_pgid(&self, pgid: Pid, sig: Signal) -> Result<()>;
    /// Signal a single pid; ESRCH is not an error.
    fn signal_pid(&self, pid: Pid, sig: Signal) -> Result<()>;
    /// Pids holding the lock file open. Fails loud when the fd table of a
    /// live own-uid process cannot be read — silence must never look free.
    fn lock_holders(&self, lock: &Path) -> Result<Vec<Pid>>;
    /// Real uid of a pid; `None` when the pid does not exist.
    fn uid_of(&self, pid: Pid) -> Option<u32>;
}

/// The uid lanespec inspects as "own".
#[must_use]
pub fn current_uid() -> u32 {
    unsafe { libc::getuid() }
}

/// Own pid + ancestors, capped by `max_depth`: the exclusion set every
/// pattern scan must apply (pgrep-self-match law) and the lineage every
/// kill must refuse to signal. Lives here so both the orphan proofs and
/// the lifecycle kills consult ONE implementation.
#[must_use]
pub fn ancestry_chain<P: Procfs>(proc: &P, max_depth: u32) -> std::collections::BTreeSet<Pid> {
    let mut out = std::collections::BTreeSet::new();
    let mut cur = std::process::id();
    for _ in 0..=max_depth {
        if !out.insert(cur) {
            break; // cycle guard
        }
        match proc.stat(cur) {
            Some(st) if st.ppid > 1 && proc.pid_alive(st.ppid) => cur = st.ppid,
            _ => break,
        }
    }
    out
}

/// Major of an `st_dev` in the glibc `gnu_dev_major` encoding — matches
/// the hex `maj` the kernel prints in /proc/locks.
#[must_use]
fn gnu_dev_major(dev: u64) -> u32 {
    (((dev >> 8) & 0xfff) | ((dev >> 27) & 0x000f_ffff_0000)) as u32
}

/// Minor of an `st_dev` in the glibc `gnu_dev_minor` encoding.
#[must_use]
fn gnu_dev_minor(dev: u64) -> u32 {
    ((dev & 0xff) | ((dev >> 12) & 0x000f_ffff_0000)) as u32
}

/// Real `/proc`-backed implementation.
pub struct RealProcfs {
    proc_root: PathBuf,
}

impl RealProcfs {
    /// New instance reading the live `/proc`.
    #[must_use]
    pub fn new() -> Self {
        Self {
            proc_root: PathBuf::from("/proc"),
        }
    }

    /// Instance reading an alternate proc tree (hermetic test seam).
    #[must_use]
    pub fn with_root(proc_root: PathBuf) -> Self {
        Self { proc_root }
    }

    fn pid_path(&self, pid: Pid, leaf: &str) -> PathBuf {
        self.proc_root.join(pid.to_string()).join(leaf)
    }

    /// `kill -0` classification: 0 or EPERM means the pid exists.
    fn probe(pid: i32) -> bool {
        let rc = unsafe { libc::kill(pid, 0) };
        if rc == 0 {
            return true;
        }
        io::Error::last_os_error().raw_os_error() == Some(libc::EPERM)
    }

    fn kill(p: i32, sig: Signal) -> Result<()> {
        let rc = unsafe { libc::kill(p, sig.num()) };
        if rc == 0 {
            return Ok(());
        }
        let err = io::Error::last_os_error();
        if err.raw_os_error() == Some(libc::ESRCH) {
            return Ok(()); // already gone
        }
        Err(err).context(format!("kill({p}, {})", sig.num()))
    }

    fn same_inode(path: &Path, dev: u64, ino: u64) -> bool {
        match std::fs::metadata(path) {
            Ok(m) => m.dev() == dev && m.ino() == ino,
            Err(_) => false,
        }
    }

    /// Does the kernel's lock table list a FLOCK on `maj:min:ino`?
    /// Unreadable table → error (the cross-check is mandatory).
    fn proc_locks_holds(&self, want: (u32, u32, u64)) -> Result<bool> {
        let raw = std::fs::read_to_string(self.proc_root.join("locks"))
            .context("reading /proc/locks — refusing to call the lock free")?;
        Ok(raw.lines().any(|line| {
            // FLOCK owner lines: `N: FLOCK ADVISORY WRITE pid maj:min:ino …`
            // (the kernel prints maj/min in hex, ino in decimal).
            let mut f = line.split_whitespace();
            let (Some(_num), Some(kind), Some(_features), Some(_access), Some(_pid), Some(devino)) =
                (f.next(), f.next(), f.next(), f.next(), f.next(), f.next())
            else {
                return false;
            };
            if kind != "FLOCK" {
                return false;
            }
            let mut d = devino.split(':');
            match (d.next(), d.next(), d.next()) {
                (Some(a), Some(b), Some(c)) => {
                    let ok = (
                        u32::from_str_radix(a, 16).ok(),
                        u32::from_str_radix(b, 16).ok(),
                        c.parse::<u64>().ok(),
                    );
                    matches!(ok, (Some(maj), Some(min), Some(ino)) if (maj, min, ino) == want)
                }
                _ => false,
            }
        }))
    }
}

impl Default for RealProcfs {
    fn default() -> Self {
        Self::new()
    }
}

impl Procfs for RealProcfs {
    fn stat(&self, pid: Pid) -> Option<ProcStat> {
        let raw = std::fs::read_to_string(self.pid_path(pid, "stat")).ok()?;
        let (ppid, pgid, start_time, comm) = parse_stat(&raw)?;
        let cmdline_raw =
            std::fs::read(self.pid_path(pid, "cmdline")).unwrap_or_default();
        let mut cmdline: String = cmdline_raw
            .iter()
            .map(|b| if *b == 0 { ' ' } else { *b as char })
            .collect();
        while cmdline.ends_with(' ') {
            cmdline.pop();
        }
        if cmdline.is_empty() {
            cmdline.clone_from(&comm); // kernel thread: no argv
        }
        Some(ProcStat {
            pid,
            ppid,
            pgid,
            start_time,
            comm,
            cmdline,
        })
    }

    fn pids(&self) -> Vec<Pid> {
        let mut out = Vec::new();
        if let Ok(rd) = std::fs::read_dir(&self.proc_root) {
            for e in rd.flatten() {
                if let Some(p) = e.file_name().to_str().and_then(|s| s.parse().ok()) {
                    out.push(p);
                }
            }
        }
        out
    }

    fn pid_alive(&self, pid: Pid) -> bool {
        pid > 0 && Self::probe(pid as i32)
    }

    fn pgid_alive(&self, pgid: Pid) -> bool {
        pgid > 0 && Self::probe(-(pgid as i32))
    }

    fn signal_pgid(&self, pgid: Pid, sig: Signal) -> Result<()> {
        if pgid == 0 {
            bail!("refusing to signal pgid 0 (own process group)");
        }
        if pgid <= 1 {
            bail!("refusing to signal pgid {pgid} — pid/pgid 1 is the kernel's reparent floor, never a kill target");
        }
        Self::kill(-(pgid as i32), sig)
    }

    fn signal_pid(&self, pid: Pid, sig: Signal) -> Result<()> {
        if pid == 0 {
            bail!("refusing to signal pid 0");
        }
        if pid <= 1 {
            bail!("refusing to signal pid {pid} — pid/pgid 1 is the kernel's reparent floor, never a kill target");
        }
        Self::kill(pid as i32, sig)
    }

    fn lock_holders(&self, lock: &Path) -> Result<Vec<Pid>> {
        let meta = match std::fs::metadata(lock) {
            Ok(m) => m,
            Err(_) => return Ok(Vec::new()), // absent lock file: nothing open
        };
        let (dev, ino) = (meta.dev(), meta.ino());
        // Cross-check the kernel's lock table first: it knows whether the
        // flock is HELD even when the holder's fd table is invisible to
        // us (ptrace-restricted processes of our own uid exist on desktops).
        // Unreadable table → fail loud (the check is not optional).
        let want = (gnu_dev_major(dev), gnu_dev_minor(dev), ino);
        let locked = self.proc_locks_holds(want)?;
        let mine = current_uid();
        let mut holders = BTreeSet::new();
        for pid in self.pids() {
            let proc_dir = self.proc_root.join(pid.to_string());
            // Only scan own-uid processes: other users' fd tables are
            // unreadable and none of them is our gate's flock heir.
            if self.uid_of(pid) != Some(mine) {
                continue;
            }
            let fd_dir = proc_dir.join("fd");
            let rd = match std::fs::read_dir(&fd_dir) {
                Ok(rd) => rd,
                // Gone/zombie (ENOENT) or ptrace-restricted (EACCES):
                // such a pid cannot present the fd; the lock table above
                // still decides whether a lock is held at all.
                Err(e) if matches!(e.raw_os_error(), Some(libc::ENOENT | libc::EACCES | libc::EPERM)) => {
                    continue;
                }
                Err(e) => {
                    return Err(anyhow::Error::new(e)
                        .context(format!("reading {}", fd_dir.display()))
                        .context("lock-holder scan unreadable — refusing to call the lock free"));
                }
            };
            for e in rd.flatten() {
                if Self::same_inode(&e.path(), dev, ino) {
                    holders.insert(pid);
                    break;
                }
            }
        }
        if locked && holders.is_empty() {
            anyhow::bail!(
                "{} is held per /proc/locks but no holder's fd table was visible — refusing to call the lock free",
                lock.display()
            );
        }
        Ok(holders.into_iter().collect())
    }

    fn uid_of(&self, pid: Pid) -> Option<u32> {
        std::fs::metadata(self.proc_root.join(pid.to_string()))
            .ok()
            .map(|m| m.uid())
    }
}

/// Parse `(ppid, pgid, starttime, comm)` from `/proc/<pid>/stat`.
/// The comm field may contain spaces and parentheses, so fields are
/// taken after the LAST `)`.
fn parse_stat(raw: &str) -> Option<(Pid, Pid, u64, String)> {    let open = raw.find('(')?;
    let close = raw.rfind(')')?;
    if close < open {
        return None;
    }
    let comm = raw[open + 1..close].to_owned();
    let fields: Vec<&str> = raw[close + 2..].split_whitespace().collect();
    // fields[0]=state(field 3) .. ppid=field 4 → index 1, pgrp=field 5 →
    // index 2, starttime=field 22 → index 19.
    if fields.len() < 20 {
        return None;
    }
    let ppid = fields[1].parse().ok()?;
    let pgid = fields[2].parse().ok()?;
    let start_time = fields[19].parse().ok()?;
    Some((ppid, pgid, start_time, comm))
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::MetadataExt as _;
    use std::os::unix::fs::PermissionsExt as _;

    use super::{Procfs, RealProcfs, gnu_dev_major, gnu_dev_minor, parse_stat};

    #[test]
    fn real_lock_holders_scans_fd_tables_with_locks_crosscheck() {
        let tmp = tempfile::tempdir().unwrap();
        let proc = tmp.path().join("proc");
        let lock = tmp.path().join("gate.lock");
        std::fs::create_dir_all(proc.join("9001/fd")).unwrap();
        std::fs::create_dir_all(proc.join("9002/fd")).unwrap();
        std::fs::create_dir_all(proc.join("9004")).unwrap(); // zombie/gone
        std::fs::write(&lock, "").unwrap();
        std::fs::write(
            proc.join("locks"),
            "9: POSIX  ADVISORY  WRITE 777 00:00:1 0 EOF\n",
        )
        .unwrap();
        std::os::unix::fs::symlink(&lock, proc.join("9001/fd/9")).unwrap();
        // 9002: ptrace-restricted (unreadable fd table) — skipped; the
        // table says no flock is held, so nothing is hiding.
        std::fs::set_permissions(proc.join("9002/fd"), std::fs::Permissions::from_mode(0o000))
            .unwrap();
        let rp = RealProcfs::with_root(proc.clone());
        assert_eq!(rp.lock_holders(&lock).unwrap(), vec![9001u32]);

        // Kernel says the flock IS held, and every holder is invisible →
        // must fail loud, never call the lock free.
        let meta = std::fs::metadata(&lock).unwrap();
        std::fs::write(
            proc.join("locks"),
            format!(
                "12: FLOCK  ADVISORY  WRITE 9999 {:x}:{:x}:{} 0 EOF\n",
                gnu_dev_major(meta.dev()),
                gnu_dev_minor(meta.dev()),
                meta.ino()
            ),
        )
        .unwrap();
        std::fs::remove_file(proc.join("9001/fd/9")).unwrap();
        assert!(
            rp.lock_holders(&lock).is_err(),
            "held lock with invisible holder must fail loud"
        );

        // Absent lock file: free without any scan.
        assert_eq!(
            rp.lock_holders(&tmp.path().join("absent.lock")).unwrap(),
            Vec::<u32>::new()
        );
        // Unreadable lock table: the cross-check is mandatory → fail loud.
        std::fs::remove_file(proc.join("locks")).unwrap();
        assert!(rp.lock_holders(&lock).is_err());
        // Restore permissions so the fixture can be removed.
        std::fs::set_permissions(proc.join("9002/fd"), std::fs::Permissions::from_mode(0o755))
            .unwrap();
    }

    #[test]
    fn parses_plain_stat_line() {
        // "pid (comm) state ppid pgrp ... starttime" — fields 1..3 + 19.
        let raw = "4242 (bash) S 100 4242 4242 34816 4242 1073741824 4147168 \
                   0 0 0 0 0 0 0 20 0 1 0 98765 1234";
        let (ppid, pgid, start, comm) = parse_stat(raw).unwrap();
        assert_eq!((ppid, pgid, start, comm.as_str()), (100, 4242, 98765, "bash"));
    }

    #[test]
    fn parses_stat_with_spaces_in_comm() {
        let raw = "7 (my (weird) proc) R 1 7 7 0 -1 0 0 0 0 0 0 0 0 0 0 0 0 0 4321";
        let (ppid, pgid, start, comm) = parse_stat(raw).unwrap();
        assert_eq!((ppid, pgid, start, comm.as_str()), (1, 7, 4321, "my (weird) proc"));
    }

    #[test]
    fn rejects_short_stat() {
        assert!(parse_stat("1 (a) S 1 2").is_none());
    }

}
