//! The lane registry: `<root>/<name>/{pid,meta,log,.done}`.
//!
//! Every registry mutation that matters goes through an exclusive
//! `flock` on `<root>/.lock`, and every file write is temp+rename so a
//! reader can never observe a half-written verdict.

use std::collections::BTreeMap;
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::os::fd::AsRawFd;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};

use crate::procfs::Pid;

/// Verdict of one lane, derived from its files and its recorded pgid.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LaneVerdict {
    /// pgid alive and the recorded start_time still matches.
    Running,
    /// `.done` exists with the lane's exit code.
    Done(i32),
    /// The group leader pid exists but its start_time differs from the
    /// record (pid recycled), or the record carries no start_time at all
    /// (legacy, unprovable). NEVER kill on this verdict.
    StaleRecord,
    /// The group is alive but its leader pid is GONE: the session leader
    /// died and left fd-heir members (bash `sleep & kill $$` shape). This
    /// is NOT a recycled pid — the group kill is proven safe (kill -0
    /// -pgid needs no leader) and this verdict KILLS.
    LeaderDeadGroupAlive,
    /// No `.done`, no live pgid: the spawner died uncollected.
    DeadOrphan,
}

impl LaneVerdict {
    /// Whether this verdict counts as "the lane still exists" for the
    /// launch already-live guard. A leader-dead group is still alive
    /// (fd-heir members hold it), so it also blocks.
    #[must_use]
    pub fn blocks_launch(&self) -> bool {
        matches!(
            self,
            LaneVerdict::Running | LaneVerdict::Done(_) | LaneVerdict::LeaderDeadGroupAlive
        )
    }
}

impl std::fmt::Display for LaneVerdict {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LaneVerdict::Running => write!(f, "running"),
            LaneVerdict::Done(rc) => write!(f, "done rc={rc}"),
            LaneVerdict::StaleRecord => write!(f, "stale-record (pid recycled — never kill)"),
            LaneVerdict::LeaderDeadGroupAlive => write!(f, "leader-dead group-alive (reap kills)"),
            LaneVerdict::DeadOrphan => write!(f, "orphan dead-uncollected"),
        }
    }
}

/// A registry rooted at a directory.
#[derive(Debug, Clone)]
pub struct Registry {
    /// Registry root.
    pub root: PathBuf,
}

impl Registry {
    /// The registry for a root path.
    #[must_use]
    pub fn new(root: PathBuf) -> Self {
        Self { root }
    }

    /// One lane's directory.
    #[must_use]
    pub fn dir(&self, name: &str) -> PathBuf {
        self.root.join(name)
    }

    /// Sorted lane names (directories under the root).
    #[must_use]
    pub fn list(&self) -> Vec<String> {
        let mut names = Vec::new();
        if let Ok(rd) = fs::read_dir(&self.root) {
            for e in rd.flatten() {
                if e.path().is_dir()
                    && let Some(n) = e.file_name().to_str()
                {
                    names.push(n.to_owned());
                }
            }
        }
        names.sort();
        names
    }

    /// Write a file atomically: temp file in the same directory, then rename.
    pub fn write_atomic(dir: &Path, file: &str, content: &str) -> Result<()> {
        let tmp = dir.join(format!("{file}.tmp.{}", std::process::id()));
        {
            let mut f = File::create(&tmp)
                .with_context(|| format!("creating {}", tmp.display()))?;
            f.write_all(content.as_bytes())
                .with_context(|| format!("writing {}", tmp.display()))?;
        }
        fs::rename(&tmp, dir.join(file))
            .with_context(|| format!("renaming {tmp:?} -> {file}"))
    }

    /// Write `meta` as `key=value` lines.
    pub fn write_meta(&self, name: &str, fields: &[(String, String)]) -> Result<()> {
        let text: String = fields
            .iter()
            .map(|(k, v)| format!("{k}={v}\n"))
            .collect();
        Self::write_atomic(&self.dir(name), "meta", &text)
    }

    /// First value of `key` in a lane's meta.
    #[must_use]
    pub fn meta_field(dir: &Path, key: &str) -> Option<String> {
        let text = fs::read_to_string(dir.join("meta")).ok()?;
        let prefix = format!("{key}=");
        text.lines()
            .find_map(|l| l.strip_prefix(&prefix))
            .map(|v| v.to_owned())
    }

    /// Record `(pgid, start_time)` in the lane's `pid` file. A missing
    /// start_time (unknown incarnation) is recorded bare and never trusted.
    pub fn write_pid(&self, name: &str, pgid: Pid, start_time: Option<u64>) -> Result<()> {
        let line = match start_time {
            Some(s) => format!("{pgid} {s}\n"),
            None => format!("{pgid}\n"),
        };
        Self::write_atomic(&self.dir(name), "pid", &line)
    }

    /// Read the recorded `(pgid, start_time)`; `None` when absent or
    /// unreadable.
    #[must_use]
    pub fn read_pid(&self, name: &str) -> Option<(Pid, Option<u64>)> {
        let text = fs::read_to_string(self.dir(name).join("pid")).ok()?;
        let mut it = text.split_whitespace();
        let pgid = it.next()?.parse().ok()?;
        Some((pgid, it.next().and_then(|s| s.parse().ok())))
    }

    /// Exit code from `.done`, if the lane finished.
    #[must_use]
    pub fn done_rc(&self, name: &str) -> Option<i32> {
        let text = fs::read_to_string(self.dir(name).join(".done")).ok()?;
        text.trim().parse().ok()
    }

    /// Whether `.done` exists at all (even with an unparseable code).
    #[must_use]
    pub fn is_done(&self, name: &str) -> bool {
        self.dir(name).join(".done").exists()
    }

    /// Derive the lane verdict. `pgid_alive` and `start_time_ok` come from
    /// the process table; `leader_present` says whether the leader pid
    /// still exists. A live group whose leader pid is GONE is the fd-heir
    /// shape (leader-dead group-alive), NOT a recycled pid — the group
    /// kill is proven safe there (pid-reuse law: only an EXISTING leader
    /// with a mismatched start_time is recycled).
    #[must_use]
    pub fn verdict(
        &self,
        name: &str,
        pgid_alive: bool,
        start_time_ok: bool,
        leader_present: bool,
    ) -> LaneVerdict {
        if let Some(rc) = self.done_rc(name) {
            return LaneVerdict::Done(rc);
        }
        if self.is_done(name) {
            // .done present but no parseable rc: treat as done rc=1.
            return LaneVerdict::Done(1);
        }
        match self.read_pid(name) {
            None => LaneVerdict::DeadOrphan,
            Some(_) if !pgid_alive => LaneVerdict::DeadOrphan,
            Some(_) if !leader_present => LaneVerdict::LeaderDeadGroupAlive,
            Some((_, None)) => LaneVerdict::StaleRecord, // legacy record, unprovable
            Some(_) if !start_time_ok => LaneVerdict::StaleRecord,
            Some(_) => LaneVerdict::Running,
        }
    }

    /// Sentinel file content (`.final`): `LANDED <token>` or `FAILED`.
    #[must_use]
    pub fn final_sentinel(&self, name: &str) -> Option<String> {
        fs::read_to_string(self.dir(name).join(".final"))
            .ok()
            .map(|s| s.trim().to_owned())
    }

    /// Run `f` while holding an exclusive `flock` on `<root>/.lock`.
    pub fn with_lock<T>(&self, f: impl FnOnce() -> Result<T>) -> Result<T> {
        fs::create_dir_all(&self.root)
            .with_context(|| format!("creating registry root {}", self.root.display()))?;
        let lock = OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .open(self.root.join(".lock"))
            .context("opening registry lock")?;
        let fd = lock.as_raw_fd();
        // SAFETY: plain advisory flock on an owned fd; retried on EINTR.
        loop {
            let rc = unsafe { libc::flock(fd, libc::LOCK_EX) };
            if rc == 0 {
                break;
            }
            let err = std::io::Error::last_os_error();
            if err.raw_os_error() != Some(libc::EINTR) {
                return Err(anyhow::Error::new(err).context("locking registry"));
            }
        }
        let out = f();
        unsafe { libc::flock(fd, libc::LOCK_UN) };
        drop(lock);
        out
    }

    /// Read all lanes' meta as maps (used by audit/plan).
    #[must_use]
    pub fn metas(&self) -> BTreeMap<String, BTreeMap<String, String>> {
        self.list()
            .into_iter()
            .map(|n| {
                let map = fs::read_to_string(self.dir(&n).join("meta"))
                    .unwrap_or_default()
                    .lines()
                    .filter_map(|l| l.split_once('='))
                    .map(|(k, v)| (k.to_owned(), v.to_owned()))
                    .collect();
                (n, map)
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn reg_in(dir: &tempfile::TempDir) -> Registry {
        Registry::new(dir.path().join("reg"))
    }

    #[test]
    fn pid_roundtrip_and_verdicts() {
        let tmp = tempfile::tempdir().unwrap();
        let r = reg_in(&tmp);
        fs::create_dir_all(r.dir("a")).unwrap();
        r.write_pid("a", 4242, Some(99)).unwrap();
        assert_eq!(r.read_pid("a"), Some((4242, Some(99))));
        assert_eq!(r.verdict("a", true, true, true), LaneVerdict::Running);
        assert_eq!(r.verdict("a", true, false, true), LaneVerdict::StaleRecord);
        assert_eq!(r.verdict("a", false, true, true), LaneVerdict::DeadOrphan);
        assert_eq!(r.verdict("zz", true, true, true), LaneVerdict::DeadOrphan);
        // Leader pid gone but the group alive → reap/sweep KILL the group.
        assert_eq!(
            r.verdict("a", true, false, false),
            LaneVerdict::LeaderDeadGroupAlive
        );
    }

    #[test]
    fn done_wins_over_liveness() {
        let tmp = tempfile::tempdir().unwrap();
        let r = reg_in(&tmp);
        fs::create_dir_all(r.dir("a")).unwrap();
        r.write_pid("a", 1, Some(1)).unwrap();
        fs::write(r.dir("a").join(".done"), "7\n").unwrap();
        assert_eq!(r.verdict("a", true, true, true), LaneVerdict::Done(7));
    }

    #[test]
    fn meta_roundtrip() {
        let tmp = tempfile::tempdir().unwrap();
        let r = reg_in(&tmp);
        fs::create_dir_all(r.dir("a")).unwrap();
        r.write_meta(
            "a",
            &[
                ("name".to_owned(), "a".to_owned()),
                ("worktree".to_owned(), "/tmp/wt-a".to_owned()),
            ],
        )
        .unwrap();
        assert_eq!(
            Registry::meta_field(&r.dir("a"), "worktree").as_deref(),
            Some("/tmp/wt-a")
        );
        assert_eq!(Registry::meta_field(&r.dir("a"), "nope"), None);
    }

    #[test]
    fn atomic_write_leaves_no_temp() {
        let tmp = tempfile::tempdir().unwrap();
        let r = reg_in(&tmp);
        fs::create_dir_all(r.dir("a")).unwrap();
        Registry::write_atomic(&r.dir("a"), "meta", "k=v\n").unwrap();
        let leftovers: Vec<_> = fs::read_dir(r.dir("a"))
            .unwrap()
            .flatten()
            .filter(|e| e.file_name().to_string_lossy().contains(".tmp."))
            .collect();
        assert!(leftovers.is_empty(), "temp leftovers: {leftovers:?}");
    }
}
