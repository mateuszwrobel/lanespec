//! The orphan oracle (F-2r): ownerless-worktree attribution and removal.
//!
//! Laws honoured here (decision record F-2r, binding):
//! * removal requires POSITIVE owner attribution proven dead — an absence
//!   of record is never evidence of an absent owner (B1/B2: the selection
//!   paradox class is protected, never removed);
//! * the removal itself runs through ONE guard site — the worktree-side
//!   guards in [`crate::worktree::prune_carrier`] plus the registry-side
//!   freshness guards in [`crate::lifecycle::carrier_prune`];
//! * the classification listing is read-only: this verb's `--dry-run`
//!   listing and `audit` never remove anything, removal fires ONLY under
//!   the explicit verb (M1: every guard re-evaluates at removal time);
//! * every removal or refusal prints exactly one named `PRUNE-*`,
//!   `PRUNE-ORPHAN-*` or `PROTECT-*` line; the vanished dir is the named
//!   prune class; removal never uses `--force` and never `rm -rf`;
//! * the removal phase takes the gate lock with a bounded opportunistic
//!   flock — a busy lock is a named refusal, never a queue (M7);
//! * mtime and age are never evidence; the process table decides.

use std::collections::BTreeMap;
use std::fs::OpenOptions;
use std::os::fd::AsRawFd;
use std::path::Path;
use std::time::{Duration, Instant};

use anyhow::Result;

use crate::config::Config;
use crate::exit;
use crate::lifecycle::{CollectOutcome, carrier_prune_with, collect_proof};
use crate::procfs::Procfs;
use crate::registry::Registry;
use crate::worktree::{self, WorktreeVerdict};

/// Opportunistic bound for the gate lock: try for this long, then refuse
/// by name. The oracle never queues behind the gate (M7).
const GATE_LOCK_TRY: Duration = Duration::from_secs(3);
const GATE_LOCK_STEP: Duration = Duration::from_millis(200);

/// Try to take the gate lock without queueing. `Some(file)` = held (the
/// caller's drop releases it); `None` = still busy at the bound.
fn try_gate_lock(path: &Path) -> Option<std::fs::File> {
    let file = OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .open(path)
        .ok()?;
    let fd = file.as_raw_fd();
    let deadline = Instant::now() + GATE_LOCK_TRY;
    loop {
        // SAFETY: plain advisory flock on an owned fd; LOCK_NB never waits.
        let rc = unsafe { libc::flock(fd, libc::LOCK_EX | libc::LOCK_NB) };
        if rc == 0 {
            return Some(file);
        }
        let err = std::io::Error::last_os_error();
        if err.raw_os_error() != Some(libc::EWOULDBLOCK) && err.raw_os_error() != Some(libc::EINTR) {
            return None;
        }
        if Instant::now() >= deadline {
            return None;
        }
        std::thread::sleep(GATE_LOCK_STEP);
    }
}

/// What one registered worktree turned out to be. Built for tests; the
/// verb prints and acts on it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Verdict {
    /// The main checkout (porcelain `branch refs/heads/main`): excluded.
    Main,
    /// Equal to, an ancestor of, or a descendant of the oracle's own
    /// checkout (M5): never touched by this process.
    SelfCheckout,
    /// Path absent but still registered: the named prune class.
    Vanished,
    /// A lane record names the path and its owner is proven dead.
    AttributedDead { lanes: Vec<String> },
    /// A lane record names the path and its owner is NOT proven dead.
    ProtectedLive { lane: String, why: String },
    /// No record names the path: the owner is UNKNOWN, never absent (B1).
    Unattributable,
}

/// Positive attribution map: realpath key of every worktree path named in
/// some lane record, to every lane naming it. A path claimed by several
/// records is dead only when EVERY claimant is proven dead.
fn claims(reg: &Registry) -> BTreeMap<String, Vec<String>> {
    let mut map: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for name in reg.list() {
        if let Some(p) = Registry::meta_field(&reg.dir(&name), "worktree") {
            map.entry(worktree::path_key(Path::new(&p))).or_default().push(name);
        }
    }
    map
}

/// Classify one porcelain entry. Pure with respect to the filesystem and
/// the process table — it removes nothing.
pub(crate) fn classify_entry<P: Procfs>(
    reg: &Registry,
    proc: &P,
    claims: &BTreeMap<String, Vec<String>>,
    self_dir: Option<&Path>,
    path: &str,
    branch: Option<&str>,
) -> Verdict {
    if branch == Some("refs/heads/main") {
        return Verdict::Main;
    }
    let p = Path::new(path);
    if let Some(sd) = self_dir {
        let sd = sd.to_string_lossy();
        // M5: the oracle refuses any path equal to, ancestor of, or
        // descendant of its own realpath.
        if path == sd.as_ref() || worktree::under(path, &sd) || worktree::under(&sd, path) {
            return Verdict::SelfCheckout;
        }
    }
    if !p.is_dir() {
        return Verdict::Vanished;
    }
    match claims.get(path) {
        None => Verdict::Unattributable,
        Some(lanes) => {
            let mut dead = Vec::new();
            for lane in lanes {
                match collect_proof(reg, proc, lane) {
                    CollectOutcome::Collected { .. } => dead.push(lane.clone()),
                    CollectOutcome::Refused(why) => {
                        return Verdict::ProtectedLive {
                            lane: lane.clone(),
                            why,
                        };
                    }
                }
            }
            Verdict::AttributedDead { lanes: dead }
        }
    }
}

/// The `prune-orphans` verb: classify every registered worktree and remove
/// ONLY the positively attributed carriers whose owners the process table
/// proves dead. `dry_run` prints the listing and touches nothing.
pub fn prune_orphans<P: Procfs>(
    cfg: &Config,
    proc: &P,
    repo: &Path,
    dry_run: bool,
) -> Result<i32> {
    prune_orphans_with(cfg, proc, repo, dry_run, &worktree::mountinfo_path())
}

/// Same verb with an explicit mountinfo table — the hermetic-test seam;
/// production reaches it through [`prune_orphans`].
pub(crate) fn prune_orphans_with<P: Procfs>(
    cfg: &Config,
    proc: &P,
    repo: &Path,
    dry_run: bool,
    mountinfo: &Path,
) -> Result<i32> {
    let entries = match worktree::porcelain_entries(repo) {
        Some(e) => e,
        None => {
            println!(
                "PRUNE-ORPHAN-REFUSE no-repo — git worktree list failed for {} — fail-closed, nothing removed",
                repo.display()
            );
            return Ok(exit::BAD);
        }
    };
    if entries.is_empty() {
        println!("prune-orphans: no worktrees registered in {}", repo.display());
        return Ok(exit::OK);
    }

    // M7: the removal phase holds the gate lock, opportunistically and
    // bounded; a busy lock is a named refusal, never a queue, and never a
    // removal. The read-only listing takes no lock.
    let _gate = if dry_run {
        None
    } else {
        match try_gate_lock(&cfg.lock.path) {
            Some(f) => Some(f),
            None => {
                println!(
                    "PRUNE-ORPHAN-REFUSE gate-lock-busy {} — the gate lock is held — nothing removed",
                    cfg.lock.path.display()
                );
                return Ok(exit::BAD);
            }
        }
    };

    let reg = Registry::new(cfg.paths.registry.clone());
    let claims = claims(&reg);
    let self_dir = std::env::current_dir().ok().and_then(|d| d.canonicalize().ok());

    let mut refusal = false; // a removal fell to a named guard refusal
    let mut debris = false; // a PROTECT line an operator must see (M2)

    for (path, branch) in &entries {
        let p = Path::new(path);
        let verdict = classify_entry(&reg, proc, &claims, self_dir.as_deref(), path, branch.as_deref());
        match verdict {
            Verdict::Main => {
                println!("PRUNE-ORPHAN-SKIP main-checkout {path} — main is never a carrier — kept");
            }
            Verdict::SelfCheckout => {
                println!("PROTECT-SELF {path} — equal to, above or below the oracle's own checkout — never removed");
            }
            Verdict::Vanished => {
                if dry_run {
                    println!("PRUNE-ORPHAN-VANISHED {path} dir-absent=yes action=dry-run — a removal run prunes the registration");
                } else {
                    for line in worktree::prune_carrier_with(p, Some(repo), mountinfo) {
                        println!("{line}");
                    }
                }
            }
            Verdict::Unattributable => {
                println!(
                    "PROTECT-UNATTRIBUTABLE {path} — named in no lane record — owner unknown, never removed (absence of record is not absence of owner)"
                );
                debris = true;
            }
            Verdict::ProtectedLive { lane, why } => {
                println!("PROTECT-LIVE {path} lane={lane} — {why} — skipped");
            }
            Verdict::AttributedDead { lanes } => {
                let names = lanes.join(",");
                match worktree::classify(Some(p)) {
                    // Bug shapes: a dead owner left uncommitted or unlanded
                    // work behind. That work belongs to an operator, never
                    // to this verb — protected by name, not removed.
                    WorktreeVerdict::Dirty => {
                        println!("PROTECT-DIRTY {path} lane={names} — dead lane left uncommitted work (bug shape) — kept, never --force");
                        debris = true;
                    }
                    WorktreeVerdict::CommittedAhead(n) => {
                        println!("PROTECT-AHEAD {path} lane={names} — dead lane left {n} unmerged commits (bug shape) — kept for the operator");
                        debris = true;
                    }
                    WorktreeVerdict::Missing => {
                        if dry_run {
                            println!("PRUNE-ORPHAN-VANISHED {path} dir-absent=yes action=dry-run — a removal run prunes the registration");
                        } else {
                            for line in worktree::prune_carrier_with(p, Some(repo), mountinfo) {
                                println!("{line}");
                            }
                        }
                    }
                    _ => {
                        // M4: if the carrier carries a sentinel, its VALUE
                        // prints before the dir goes — a late-polling
                        // orchestrator still gets its hook.
                        let note = sentinel_note(p)
                            .map(|n| format!(" {n}"))
                            .unwrap_or_default();
                        println!("PRUNE-ORPHAN-OWNER {path} lane={names} attributed-dead=yes{note}");
                        if dry_run {
                            println!("PRUNE-ORPHAN-DRY {path} — listing only, this run removes nothing");
                        } else {
                            let launched =
                                Registry::meta_field(&reg.dir(&lanes[0]), "launched");
                            let lines =
                                carrier_prune_with(&reg, proc, &lanes[0], launched.as_deref(), p, mountinfo);
                            for line in lines {
                                if line.starts_with("PRUNE-REFUSE")
                                    || line.starts_with("PROTECT-MOUNT")
                                {
                                    refusal = true;
                                }
                                println!("{line}");
                            }
                        }
                    }
                }
            }
        }
    }

    Ok(if refusal {
        exit::BAD
    } else if debris {
        exit::DEBRIS
    } else {
        exit::OK
    })
}

/// Read a carrier dir's sentinel markers as one note: `.final <value>`
/// and/or `.done <value>` (M4: sentinels are data; the VALUE rides the
/// PRUNE line so a late-polling orchestrator still gets its hook).
#[must_use]
pub(crate) fn sentinel_note(dir: &Path) -> Option<String> {
    let mut notes = Vec::new();
    for name in [".final", ".done"] {
        if let Ok(text) = std::fs::read_to_string(dir.join(name)) {
            let text = text.trim().to_owned();
            if !text.is_empty() {
                notes.push(format!("{name} {text}"));
            }
        }
    }
    (!notes.is_empty()).then(|| notes.join(" "))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{Config, Lock, Paths};
    use crate::fake::FakeProcfs;
    use crate::procfs::Pid;
    use std::path::PathBuf;
    use std::process::{Command, Stdio};

    fn git_in(dir: &Path, args: &[&str]) {
        let out = Command::new("git")
            .arg("-C")
            .arg(dir)
            .args(args)
            .env("GIT_AUTHOR_NAME", "t")
            .env("GIT_AUTHOR_EMAIL", "t@t")
            .env("GIT_COMMITTER_NAME", "t")
            .env("GIT_COMMITTER_EMAIL", "t@t")
            // The fixtures are hermetic: no hooks may run (the ambient
            // core.hooksPath of the source checkout would otherwise leak in).
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .env("GIT_CONFIG_SYSTEM", "/dev/null")
            .env_remove("GIT_DIR")
            .env_remove("GIT_WORK_TREE")
            .env_remove("GIT_INDEX_FILE")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .unwrap();
        assert!(out.success(), "git {args:?} failed");
    }

    /// Repo with a bare origin and main pushed, ready for carriers.
    fn repo_with_origin(dir: &Path) {
        let origin = dir.parent().unwrap().join(format!(
            "{}-origin.git",
            dir.file_name().unwrap().to_string_lossy()
        ));
        std::fs::create_dir(&origin).unwrap();
        git_in(&origin, &["init", "-q", "--bare"]);
        git_in(dir, &["init", "-q", "-b", "main"]);
        // Fixture repos run without hooks (the source checkout's core.
        // hooksPath must never be inherited).
        git_in(dir, &["-c", "core.hooksPath=/dev/null", "config", "core.hooksPath", "/dev/null"]);
        std::fs::write(dir.join("f"), "1\n").unwrap();
        git_in(dir, &["add", "-A"]);
        git_in(dir, &["commit", "-q", "-m", "one"]);
        git_in(dir, &["remote", "add", "origin", origin.to_str().unwrap()]);
        git_in(dir, &["push", "-q", "-u", "origin", "main"]);
    }

    fn add_worktree(work: &Path, wt: &Path) {
        git_in(work, &["worktree", "add", "--detach", wt.to_str().unwrap(), "HEAD"]);
    }

    fn test_cfg(root: &Path) -> Config {
        Config {
            paths: Paths {
                registry: root.join("reg"),
                scratch: root.to_path_buf(),
            },
            // Fixture-local gate lock: a unit run never flocks the shared one.
            lock: Lock {
                path: root.join("gate.lock"),
            },
            ..Default::default()
        }
    }

    /// An empty mountinfo table: the scan answers, sees no mount, clears —
    /// the hermetic stand-in for a mount-free machine.
    fn mount_clear(tmp: &tempfile::TempDir) -> PathBuf {
        let p = tmp.path().join("mountinfo-clear");
        std::fs::write(&p, "").unwrap();
        p
    }

    /// A mountinfo table with one mount whose MOUNT POINT is `wt`: the
    /// idle container-leg bind class (F-2r B3) — lsof-blind, scan-visible.
    fn mount_under(tmp: &tempfile::TempDir, wt: &Path) -> PathBuf {
        let p = tmp.path().join("mountinfo-held");
        std::fs::write(
            &p,
            format!(
                "36 35 0:30 / {} rw relatime shared:1 - ext4 /dev/sda1 rw\n",
                worktree::path_key(wt)
            ),
        )
        .unwrap();
        p
    }

    /// A DONE record (pgid absent from the fake table — the ESRCH proof)
    /// naming a carrier worktree.
    fn done_lane(reg: &Registry, name: &str, wt: Option<&Path>, launched: &str, pgid: Pid) {
        std::fs::create_dir_all(reg.dir(name)).unwrap();
        reg.write_pid(name, pgid, Some(10)).unwrap();
        let mut fields = vec![
            ("name".to_owned(), name.to_owned()),
            ("launched".to_owned(), launched.to_owned()),
        ];
        if let Some(p) = wt {
            fields.push(("worktree".to_owned(), p.display().to_string()));
        }
        reg.write_meta(name, &fields).unwrap();
        std::fs::write(reg.dir(name).join(".done"), "0\n").unwrap();
    }

    /// A RUNNING record naming a carrier worktree (pgid live in the fake).
    fn live_lane(reg: &Registry, proc: &FakeProcfs, name: &str, wt: &Path, launched: &str, pgid: Pid) {
        std::fs::create_dir_all(reg.dir(name)).unwrap();
        reg.write_pid(name, pgid, Some(10)).unwrap();
        reg.write_meta(
            name,
            &[
                ("name".to_owned(), name.to_owned()),
                ("launched".to_owned(), launched.to_owned()),
                ("worktree".to_owned(), wt.display().to_string()),
            ],
        )
        .unwrap();
        proc.add(pgid, 1, pgid, 10, "sleep", "sleep 42");
    }

    /// Fixture: repo + carrier + one record.
    fn seeded(tmp: &tempfile::TempDir, name: &str, pgid: Pid) -> (Config, Registry, PathBuf, PathBuf) {
        let work = tmp.path().join("work");
        std::fs::create_dir(&work).unwrap();
        repo_with_origin(&work);
        let wt = tmp.path().join("wt-oracle");
        add_worktree(&work, &wt);
        let cfg = test_cfg(tmp.path());
        let reg = Registry::new(cfg.paths.registry.clone());
        done_lane(&reg, name, Some(&wt), "2026-11-01T00:00:00Z", pgid);
        (cfg, reg, work, wt)
    }

    /// Dead owner, clean contained carrier: attributed-dead verdict, the
    /// verb removes the worktree, keeps the record (collect owns records),
    /// and answers 0.
    #[test]
    fn prune_orphans_removes_dead_owner_carrier() {
        let tmp = tempfile::tempdir().unwrap();
        let fake = FakeProcfs::new();
        let (cfg, reg, work, wt) = seeded(&tmp, "gone", 900_160);
        let rc = prune_orphans_with(&cfg, &fake, &work, false, &mount_clear(&tmp)).unwrap();
        assert_eq!(rc, exit::OK, "clean removal answers OK");
        assert!(!wt.exists(), "attributed-dead carrier must be removed");
        assert!(reg.dir("gone").exists(), "records belong to collect, not the oracle");
    }

    /// Live owner: a named PROTECT-LIVE skip, dir survives, exit 0 —
    /// a live lane is healthy, not debris.
    #[test]
    fn prune_orphans_skips_live_lane() {
        let tmp = tempfile::tempdir().unwrap();
        let fake = FakeProcfs::new();
        let (cfg, reg, work, wt) = seeded(&tmp, "liver", 900_161);
        live_lane(&reg, &fake, "running", &wt, "2026-11-02T00:00:00Z", 900_162);
        let rc = prune_orphans_with(&cfg, &fake, &work, false, &mount_clear(&tmp)).unwrap();
        assert_eq!(rc, exit::OK);
        assert!(wt.exists(), "a live lane's carrier must survive");
    }

    /// No record names the path: PROTECT-UNATTRIBUTABLE (exit 3 debris),
    /// never removed — B1 in force.
    #[test]
    fn prune_orphans_attribution_unknown_protects() {
        let tmp = tempfile::tempdir().unwrap();
        let fake = FakeProcfs::new();
        let work = tmp.path().join("work");
        std::fs::create_dir(&work).unwrap();
        repo_with_origin(&work);
        let wt = tmp.path().join("wt-unattr");
        add_worktree(&work, &wt);
        let cfg = test_cfg(tmp.path());
        let rc = prune_orphans_with(&cfg, &fake, &work, false, &mount_clear(&tmp)).unwrap();
        assert_eq!(rc, exit::DEBRIS, "unattributable present checkouts are debris");
        assert!(wt.exists(), "absence of record is not absence of owner");
    }

    /// Dead owner, dirty carrier: bug shape — PROTECT-DIRTY (exit 3), the
    /// work survives, nothing is forced.
    #[test]
    fn prune_orphans_dirty_unlanded_protects() {
        let tmp = tempfile::tempdir().unwrap();
        let fake = FakeProcfs::new();
        let (cfg, _reg, work, wt) = seeded(&tmp, "messy", 900_163);
        std::fs::write(wt.join("uncommitted"), "wip\n").unwrap();
        let rc = prune_orphans_with(&cfg, &fake, &work, false, &mount_clear(&tmp)).unwrap();
        assert_eq!(rc, exit::DEBRIS);
        assert!(wt.exists(), "uncommitted work in a dead lane is never removed");
    }

    /// The main checkout is excluded via the porcelain branch line.
    #[test]
    fn prune_orphans_main_exclusion() {
        let tmp = tempfile::tempdir().unwrap();
        let fake = FakeProcfs::new();
        let work = tmp.path().join("work");
        std::fs::create_dir(&work).unwrap();
        repo_with_origin(&work);
        let cfg = test_cfg(tmp.path());
        let rc = prune_orphans_with(&cfg, &fake, &work, false, &mount_clear(&tmp)).unwrap();
        assert_eq!(rc, exit::OK, "only main is listed: no debris, nothing due");
        assert!(work.exists(), "main is never a carrier");
    }

    /// Vanished-but-registered: the named prune class — registration goes,
    /// exit 0, never a death.
    #[test]
    fn prune_orphans_vanished_dir_named_class() {
        let tmp = tempfile::tempdir().unwrap();
        let fake = FakeProcfs::new();
        let (cfg, _reg, work, wt) = seeded(&tmp, "ghost", 900_164);
        std::fs::remove_dir_all(&wt).unwrap();
        let rc = prune_orphans_with(&cfg, &fake, &work, false, &mount_clear(&tmp)).unwrap();
        assert_eq!(rc, exit::OK);
        let listed = worktree::registered_worktrees(&work)
            .iter()
            .any(|p| *p == worktree::path_key(&wt));
        assert!(!listed, "the vanished registration must be pruned");
    }

    /// The listing mode removes NOTHING — not even a fully due removal.
    #[test]
    fn prune_orphans_dry_run_never_removes() {
        let tmp = tempfile::tempdir().unwrap();
        let fake = FakeProcfs::new();
        let (cfg, _reg, work, wt) = seeded(&tmp, "due", 900_165);
        let rc = prune_orphans_with(&cfg, &fake, &work, true, &mount_clear(&tmp)).unwrap();
        assert_eq!(rc, exit::OK);
        assert!(wt.exists(), "a listing run never removes");
        assert!(
            worktree::registered_worktrees(&work)
                .iter()
                .any(|p| *p == worktree::path_key(&wt)),
            "a listing run never prunes registrations"
        );
    }

    /// Several records claim one path: dead only when EVERY claimant is
    /// proven dead — one live claimant protects the checkout (B1/B2).
    #[test]
    fn prune_orphans_multiple_claims_need_all_dead() {
        let tmp = tempfile::tempdir().unwrap();
        let fake = FakeProcfs::new();
        let (cfg, reg, work, wt) = seeded(&tmp, "elder", 900_166);
        live_lane(&reg, &fake, "young", &wt, "2026-11-02T00:00:00Z", 900_167);
        let rc = prune_orphans_with(&cfg, &fake, &work, false, &mount_clear(&tmp)).unwrap();
        assert_eq!(rc, exit::OK);
        assert!(wt.exists(), "a live claimant keeps the checkout");
    }

    /// A mount sits AT the carrier dir (idle container bind, zero open
    /// fds): the bounded scan holds the guard — a named PROTECT-MOUNT
    /// refusal, the dir survives, exit BAD. Never removed, never forced.
    #[test]
    fn prune_orphans_mount_holder_refuses() {
        let tmp = tempfile::tempdir().unwrap();
        let fake = FakeProcfs::new();
        let (cfg, _reg, work, wt) = seeded(&tmp, "held", 900_169);
        let rc =
            prune_orphans_with(&cfg, &fake, &work, false, &mount_under(&tmp, &wt)).unwrap();
        assert_eq!(rc, exit::BAD, "a guard refusal is BAD, not debris");
        assert!(wt.exists(), "a mounted checkout is never removed");
    }

    /// classify_entry: the Verdicts without touching removal.
    #[test]
    fn classify_entry_verdicts() {
        let tmp = tempfile::tempdir().unwrap();
        let fake = FakeProcfs::new();
        let (cfg, reg, work, wt) = seeded(&tmp, "cv", 900_168);
        let claims = claims(&reg);
        let key = worktree::path_key(&wt);
        assert_eq!(
            classify_entry(&reg, &fake, &claims, None, &key, Some("detached")),
            Verdict::AttributedDead { lanes: vec!["cv".to_owned()] }
        );
        let main = worktree::path_key(&work);
        assert_eq!(
            classify_entry(&reg, &fake, &claims, None, &main, Some("refs/heads/main")),
            Verdict::Main
        );
        assert_eq!(
            classify_entry(&reg, &fake, &claims, None, "/no/such/dir", Some("detached")),
            Verdict::Vanished
        );
        let other = tmp.path().join("other-checkout");
        std::fs::create_dir_all(&other).unwrap();
        assert_eq!(
            classify_entry(&reg, &fake, &claims, None, other.to_str().unwrap(), Some("detached")),
            Verdict::Unattributable
        );
        // M5: equal to, above, or below the oracle's own checkout.
        let selfd = work.join("sub");
        std::fs::create_dir_all(&selfd).unwrap();
        assert_eq!(
            classify_entry(&reg, &fake, &claims, Some(&selfd), &main, Some("detached")),
            Verdict::SelfCheckout
        );
        let _ = cfg;
    }
}
