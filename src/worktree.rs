//! Git worktree verdicts, mirroring the bash supervisor's classify, plus
//! the collect-side carrier removal (`prune_carrier`).

use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

/// Verdict for a lane's worktree.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WorktreeVerdict {
    /// No worktree recorded for the lane.
    None,
    /// Path absent, or not a git repository.
    Missing,
    /// Uncommitted changes present.
    Dirty,
    /// Clean, but `ahead` commits are not on `origin/main`.
    CommittedAhead(u32),
    /// Clean and nothing ahead.
    Clean,
}

impl std::fmt::Display for WorktreeVerdict {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            WorktreeVerdict::None => write!(f, "none"),
            WorktreeVerdict::Missing => write!(f, "missing"),
            WorktreeVerdict::Dirty => write!(f, "dirty"),
            WorktreeVerdict::CommittedAhead(n) => write!(f, "committed-ahead {n}"),
            WorktreeVerdict::Clean => write!(f, "clean"),
        }
    }
}

/// HEAD sha of a worktree, for plan's land-step text.
#[must_use]
pub fn head_sha(wt: &Path) -> Option<String> {
    git(wt, &["rev-parse", "HEAD"])
        .filter(|out| out.status.success())
        .map(|out| String::from_utf8_lossy(&out.stdout).trim().to_owned())
}

/// `origin/main..main` count; `None` when origin/main is unknown.
#[must_use]
pub fn ahead_count(repo: &Path) -> Option<u32> {
    let has = matches!(git(repo, &["rev-parse", "--verify", "origin/main"]), Some(out) if out.status.success());
    if !has {
        return None;
    }
    git(repo, &["rev-list", "--count", "origin/main..main"])
        .filter(|out| out.status.success())
        .map(|out| String::from_utf8_lossy(&out.stdout).trim().parse().unwrap_or(0))
}

/// Absolute paths of worktrees the repo registers.#[must_use]
pub fn registered_worktrees(repo: &Path) -> Vec<String> {
    git(repo, &["worktree", "list", "--porcelain"])
        .map(|out| {
            String::from_utf8_lossy(&out.stdout)
                .lines()
                .filter_map(|l| l.strip_prefix("worktree "))
                .map(|p| {
                    Path::new(p)
                        .canonicalize()
                        .map(|c| c.to_string_lossy().to_string())
                        .unwrap_or_else(|_| p.to_owned())
                })
                .collect()
        })
        .unwrap_or_default()
}

/// The repo runner convention (M8): every git subprocess starts with the
/// hook's GIT_* seams stripped, so a fixture can never operate on the
/// enclosing checkout.
fn git_cmd(cwd: &Path, base: &str) -> Command {
    let mut cmd = Command::new("git");
    cmd.arg(base)
        .arg(cwd)
        .env_remove("GIT_DIR")
        .env_remove("GIT_WORK_TREE")
        .env_remove("GIT_INDEX_FILE")
        .env_remove("GIT_PREFIX")
        .env_remove("GIT_COMMON_DIR")
        .env_remove("GIT_NAMESPACE")
        .env_remove("GIT_OBJECT_DIRECTORY")
        .env_remove("GIT_ALTERNATE_OBJECT_DIRECTORIES");
    cmd
}

fn git(wt: &Path, args: &[&str]) -> Option<std::process::Output> {
    git_cmd(wt, "-C").args(args).output().ok()
}

/// Same probe anchored on the common dir instead of a live checkout — the
/// shape that survives the target directory being gone (post-removal
/// confirms, vanished-dir prune).
fn git_common(gd: &Path, args: &[&str]) -> Option<std::process::Output> {
    git_cmd(gd, "--git-dir").args(args).output().ok()
}

/// Absolute-path key used to match a recorded path against porcelain
/// entries; a path that cannot canonicalize keeps its own spelling.
pub(crate) fn path_key(p: &Path) -> String {
    p.canonicalize()
        .map(|c| c.to_string_lossy().to_string())
        .unwrap_or_else(|_| p.display().to_string())
}

/// Porcelain entries of `git worktree list`: `(path, branch-line)` pairs.
/// `None` when the probe failed (not a repo, git missing).
fn worktree_entries(ctx: GitCtx<'_>) -> Option<Vec<(String, Option<String>)>> {
    let out = match ctx {
        GitCtx::Dir(d) => git(d, &["worktree", "list", "--porcelain"]),
        GitCtx::CommonDir(g) => git_common(g, &["worktree", "list", "--porcelain"]),
    }?;
    if !out.status.success() {
        return None;
    }
    let mut entries: Vec<(String, Option<String>)> = Vec::new();
    for line in String::from_utf8_lossy(&out.stdout).lines() {
        if let Some(p) = line.strip_prefix("worktree ") {
            entries.push((
                Path::new(p)
                    .canonicalize()
                    .map(|c| c.to_string_lossy().to_string())
                    .unwrap_or_else(|_| p.to_owned()),
                None,
            ));
        } else if let Some(b) = line.strip_prefix("branch ")
            && let Some(e) = entries.last_mut()
        {
            e.1 = Some(b.to_owned());
        }
    }
    Some(entries)
}

/// Where a `worktree list` probe runs from.
enum GitCtx<'a> {
    /// A live checkout directory (`git -C dir`).
    Dir(&'a Path),
    /// The repository's common dir (`git --git-dir dir`).
    CommonDir(&'a Path),
}

/// Porcelain entries of a live checkout as `(path, branch-line)` pairs with
/// paths canonicalized to their realpath key. `None` when the probe failed.
/// This is the oracle's enumeration source (M9): the worktree list, never a
/// directory glob.
pub(crate) fn porcelain_entries(repo: &Path) -> Option<Vec<(String, Option<String>)>> {
    worktree_entries(GitCtx::Dir(repo))
}

/// True when `child` is `parent` itself or sits under it. Absolute paths
/// only; the comparison is on path-component boundaries, never string
/// prefixes that could match a sibling like `/var/tmp/wt-1x` under `/wt-1`.
#[must_use]
pub(crate) fn under(child: &str, parent: &str) -> bool {
    let parent = parent.trim_end_matches('/');
    let parent = if parent.is_empty() { "/" } else { parent };
    child == parent || (child.starts_with(parent) && child.as_bytes().get(parent.len()) == Some(&b'/'))
}

/// Verdict of the bounded mount scan (F-2r B3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum MountScan {
    /// The scan answered inside its bound and found no mount touching the
    /// checkout.
    Clear,
    /// At least one mount sits at or under the checkout, or binds a subtree
    /// of it elsewhere: `n` counts the matched entries.
    Mounted(usize),
    /// The scan could not answer — unreadable source or timeout. Guard
    /// unproven: the same fail-closed law as the lsof-timeout arm.
    Failed(String),
}

/// The mountinfo path. `LANESPEC_MOUNTINFO` overrides `/proc/self/mountinfo`
/// so the hermetic cells can feed the scan a fixture table; production reads
/// the real one.
#[must_use]
pub(crate) fn mountinfo_path() -> PathBuf {
    match std::env::var("LANESPEC_MOUNTINFO") {
        Ok(v) if !v.is_empty() => PathBuf::from(v),
        _ => PathBuf::from("/proc/self/mountinfo"),
    }
}

/// Bound of the mount scan: a hung `/proc` read must surface as a named
/// refusal, never as a silent pass or an unbounded wait.
const MOUNT_SCAN_TIMEOUT: Duration = Duration::from_secs(5);

/// Bounded bind-mount scan (F-2r B3): an idle container leg binds the
/// checkout and keeps zero open fds — `lsof +D` is blind there. A mount
/// whose mount point sits at or under the checkout, or whose source root is
/// at or under the checkout (the bind of the checkout or a subtree of it,
/// visible under a container path), marks the checkout held. Timeout or an
/// unreadable table is `Failed` — the guard refuses, it never guesses.
pub(crate) fn mount_scan(want: &str, mountinfo: &Path, timeout: Duration) -> MountScan {
    let want = want.to_owned();
    let path = mountinfo.to_path_buf();
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let out = match std::fs::read_to_string(&path) {
            Ok(text) => Ok(scan_lines(&text, &want)),
            Err(e) => Err(format!("cannot read {}: {e}", path.display())),
        };
        let _ = tx.send(out);
    });
    match rx.recv_timeout(timeout) {
        Ok(Ok(res)) => res,
        Ok(Err(why)) => MountScan::Failed(why),
        Err(_) => MountScan::Failed(format!("no answer within {}s", timeout.as_secs())),
    }
}

/// Decode mountinfo's octal path escapes (`\040` space, `\011` tab,
/// `\012` newline, `\134` backslash).
fn unescape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut it = s.chars();
    while let Some(c) = it.next() {
        if c != '\\' {
            out.push(c);
            continue;
        }
        let oct: String = it.by_ref().take(3).collect();
        match oct.as_str() {
            "040" => out.push(' '),
            "011" => out.push('\t'),
            "012" => out.push('\n'),
            "134" => out.push('\\'),
            other => {
                out.push('\\');
                out.push_str(other);
            }
        }
    }
    out
}

/// Classify one mountinfo table against the checkout realpath. Fields:
/// `id parent major:minor root mountpoint opts ... - fstype source super`;
/// the two paths that can name the checkout are `root` (bind source inside
/// its filesystem) and `mountpoint` (where the mount sits).
fn scan_lines(text: &str, want: &str) -> MountScan {
    let mut hits = 0;
    for line in text.lines() {
        let mut it = line.split(' ');
        let (Some(_id), Some(_parent), Some(_dev), Some(root), Some(mp)) =
            (it.next(), it.next(), it.next(), it.next(), it.next())
        else {
            continue;
        };
        let (root, mp) = (unescape(root), unescape(mp));
        if under(&mp, want) || under(&root, want) {
            hits += 1;
        }
    }
    if hits == 0 {
        MountScan::Clear
    } else {
        MountScan::Mounted(hits)
    }
}

/// The collect-side carrier removal: the worktree-side guards of the
/// collect verb. The registry-side freshness guard lives
/// with the collect verb itself. The shape follows the house removal
/// protocol:
/// every probe is wrapped, every removal and every refusal prints ONE named
/// `PRUNE-*` line, removal is the plain verb (NEVER `--force`, NEVER
/// `rm -rf`), and the check→remove window carries the salvage pin (r1 B1):
/// `refs/salvage/<head>` is written BEFORE the removal and unpinned only
/// when containment re-verifies afterwards.
///
/// Guards, in order — a failing one returns its named line and removes
/// nothing:
/// * dir absent (vanished-but-registered, r1 M1): `git worktree prune` on
///   the first repo that still registers the path, then `PRUNE-VANISHED`.
/// * not a registered worktree of any reachable repo: `PRUNE-SKIP` —
///   plain scratch dirs are never this verb's business.
/// * the main worktree (porcelain `branch refs/heads/main`, r1 minor):
///   `PRUNE-REFUSE main-checkout`.
/// * `status --porcelain` non-empty, or the probe itself failing (fail
///   closed): `PRUNE-REFUSE dirty` / `status-failed`.
/// * HEAD not fully contained in `origin/main` (`merge-base --is-ancestor`
///   — analysis lanes sit at the base and pass, unmerged lanes never):
///   `PRUNE-REFUSE not-contained`; an unreadable HEAD or an unresolved
///   `origin/main` is containment-unprovable and refuses.
/// * a mount at or under the checkout, or a bind-mount root under it
///   (F-2r B3, bounded scan): `PROTECT-MOUNT`; an unreadable or timed-out
///   mount table is `PROTECT-MOUNT-SCAN`, the same fail-closed arm.
///
/// Before the plain removal the guard pins `refs/salvage/<head>` (r1 B1)
/// and copies every not-yet-contained HEAD-reflog entry into salvage pins
/// (r2 F1a, one `PRUNE-REFLOG` line), so a late commit stays reachable
/// after the admin dir dies.
#[must_use]
pub fn prune_carrier(wt: &Path, anchor: Option<&Path>) -> Vec<String> {
    prune_carrier_with(wt, anchor, &mountinfo_path())
}

/// Same guards with an explicit mountinfo table — the hermetic-test seam;
/// production reaches it through [`prune_carrier`].
pub(crate) fn prune_carrier_with(
    wt: &Path,
    anchor: Option<&Path>,
    mountinfo: &Path,
) -> Vec<String> {
    let mut lines = Vec::new();
    let disp = wt.display().to_string();
    let want = path_key(wt);

    if !wt.is_dir() {
        // Vanished-but-registered class: prune the registration, never the
        // filesystem. The anchor is the collect caller's repo context.
        if let Some(a) = anchor.filter(|a| a.is_dir()) {
            let listed = worktree_entries(GitCtx::Dir(a))
                .is_some_and(|es| es.iter().any(|(p, _)| *p == want));
            if listed {
                let _ = git(a, &["worktree", "prune"]);
                let gone = worktree_entries(GitCtx::Dir(a))
                    .is_some_and(|es| !es.iter().any(|(p, _)| *p == want));
                let state = if gone { "yes" } else { "no" };
                lines.push(format!(
                    "PRUNE-VANISHED {disp} dir-absent=yes unregistered={state} — ran git worktree prune"
                ));
            } else {
                lines.push(format!(
                    "PRUNE-VANISHED {disp} dir-absent=yes unregistered=unknown — no repo at {} registers the path — nothing to prune",
                    a.display()
                ));
            }
        } else {
            lines.push(format!(
                "PRUNE-VANISHED {disp} dir-absent=yes unregistered=unknown — no repo context reachable — nothing to prune"
            ));
        }
        return lines;
    }

    let Some(entries) = worktree_entries(GitCtx::Dir(wt)) else {
        lines.push(format!(
            "PRUNE-SKIP unregistered {disp} — no git worktree list reachable — nothing to remove"
        ));
        return lines;
    };
    let Some((_, branch)) = entries.iter().find(|(p, _)| *p == want) else {
        lines.push(format!(
            "PRUNE-SKIP unregistered {disp} — not a registered git worktree — nothing to remove"
        ));
        return lines;
    };
    if branch.as_deref() == Some("refs/heads/main") {
        lines.push(
            "PRUNE-REFUSE main-checkout — the recorded path names the main worktree — kept".to_string(),
        );
        return lines;
    }

    if let Some(out) = git(wt, &["status", "--porcelain"]) {
        if !out.status.success() {
            lines.push(format!(
                "PRUNE-REFUSE status-failed — the dirtiness probe failed for {disp}, fail-closed — worktree kept"
            ));
            return lines;
        }
        if String::from_utf8_lossy(&out.stdout).lines().count() > 0 {
            lines.push(format!(
                "PRUNE-REFUSE dirty — uncommitted work in {disp} — worktree kept (never --force)"
            ));
            return lines;
        }
    } else {
        lines.push(format!(
            "PRUNE-REFUSE status-failed — git status could not run for {disp}, fail-closed — worktree kept"
        ));
        return lines;
    }

    let Some(head) = head_sha(wt) else {
        lines.push(format!(
            "PRUNE-REFUSE head-unreadable — containment unprovable for {disp} — worktree kept"
        ));
        return lines;
    };
    if contained(wt, &head) != Some(true) {
        lines.push(format!(
            "PRUNE-REFUSE not-contained — {head} is not proven inside origin/main — worktree kept (unmerged lane)"
        ));
        return lines;
    }

    // Bounded mount scan (F-2r B3): an idle container leg bind-mounts the
    // checkout with zero open fds — lsof is blind there. A mount at or
    // under the checkout, or a bind root under it, is a named refusal; so
    // is a scan that cannot answer (fail-closed, same law as lsof-timeout).
    match mount_scan(&want, mountinfo, MOUNT_SCAN_TIMEOUT) {
        MountScan::Clear => {}
        MountScan::Mounted(n) => {
            lines.push(format!(
                "PROTECT-MOUNT {disp} mounts={n} — a mount sits at or under the checkout — worktree kept"
            ));
            return lines;
        }
        MountScan::Failed(why) => {
            lines.push(format!(
                "PROTECT-MOUNT-SCAN {disp} — {why} — mount guard unproven, fail-closed — worktree kept"
            ));
            return lines;
        }
    }

    // Salvage pin BEFORE the removal (r1 B1): a commit made in the
    // check→remove window would otherwise die with the admin dir.
    let mut pinned = vec![head.clone()];
    if !git(wt, &["update-ref", &format!("refs/salvage/{head}"), &head])
        .is_some_and(|o| o.status.success())
    {
        lines.push(
            "PRUNE-REFUSE pin-failed — no salvage pin, fail-closed — worktree kept".to_string(),
        );
        return lines;
    }
    lines.push(format!("PRUNE-PIN refs/salvage/{head} {head}"));

    // Late commits the HEAD read missed stay reachable (r2 F1a).
    if !reflog_copy(wt, &disp, &mut pinned, &mut lines) {
        return lines;
    }

    let common = git(wt, &["rev-parse", "--path-format=absolute", "--git-common-dir"])
        .filter(|o| o.status.success())
        .map(|o| PathBuf::from(String::from_utf8_lossy(&o.stdout).trim()));

    // Plain removal — locked or otherwise refused worktrees stay (r1 m3).
    let remove_rc = git(wt, &["worktree", "remove", &disp])
        .map_or(1, |o| o.status.code().unwrap_or(1));

    // The removal triple: rc + dir-absent + unregistered.
    let dir_absent = if wt.is_dir() { "no" } else { "yes" };
    let unregistered = match common.as_deref() {
        Some(gd) => {
            let gone = worktree_entries(GitCtx::CommonDir(gd))
                .is_some_and(|es| !es.iter().any(|(p, _)| *p == want));
            if gone {
                "yes"
            } else {
                "no"
            }
        }
        None => "unknown",
    };
    lines.push(format!(
        "PRUNE-REMOVED {disp} rc={remove_rc} dir-absent={dir_absent} unregistered={unregistered}"
    ));
    if remove_rc != 0 {
        lines.push(format!(
            "PRUNE-REFUSE remove-rc={remove_rc} — git worktree remove refused — worktree kept"
        ));
    }

    // Containment decides the pin, never the removal (r1 M4/M2).
    let recheck = match common.as_deref() {
        Some(gd) => contained_common(gd, &head),
        None => contained(wt, &head),
    };
    if recheck == Some(true) {
        if let Some(gd) = common.as_deref() {
            let _ = git_common(gd, &["update-ref", "-d", &format!("refs/salvage/{head}")]);
        } else {
            let _ = git(wt, &["update-ref", "-d", &format!("refs/salvage/{head}")]);
        }
        lines.push(format!(
            "PRUNE-UNPIN refs/salvage/{head} — {head} is contained in origin/main"
        ));
    } else {
        lines.push(format!(
            "SALVAGE-PIN {head} kept — commits not on origin"
        ));
    }
    lines
}

/// The r2 F1a reflog-copy pass at the shared guard site: every non-zero
/// entry of the carrier's HEAD reflog that exists as a commit, is not
/// already pinned, and is not contained in `origin/main` gets a salvage
/// pin BEFORE the removal — a late commit the HEAD read missed stays
/// reachable after the admin dir dies. One `PRUNE-REFLOG` line per pass;
/// a pin failure pushes its own refusal and reports `false`.
fn reflog_copy(wt: &Path, disp: &str, pinned: &mut Vec<String>, lines: &mut Vec<String>) -> bool {
    let logs = git(wt, &["rev-parse", "--absolute-git-dir"])
        .filter(|o| o.status.success())
        .map(|o| PathBuf::from(String::from_utf8_lossy(&o.stdout).trim()).join("logs/HEAD"));
    let text = match logs.as_deref().and_then(|l| std::fs::read_to_string(l).ok()) {
        Some(t) => t,
        None => {
            lines.push(format!(
                "PRUNE-REFLOG {disp} scanned=0 pinned=0 — no HEAD reflog to copy"
            ));
            return true;
        }
    };
    let mut scanned = 0;
    let mut pinned_n = 0;
    for entry in text.lines() {
        let new = match entry.split(' ').nth(1) {
            Some(n) => n,
            None => continue,
        };
        if new.len() != 40 || new.bytes().any(|b| !b.is_ascii_hexdigit()) {
            continue;
        }
        if new.chars().all(|c| c == '0') {
            continue;
        }
        scanned += 1;
        if pinned.iter().any(|p| p == new) {
            continue;
        }
        if !git(wt, &["cat-file", "-e", &format!("{new}^{{commit}}")]).is_some_and(|o| o.status.success()) {
            continue;
        }
        if contained(wt, new) == Some(true) {
            continue;
        }
        if !git(wt, &["update-ref", &format!("refs/salvage/{new}"), new]).is_some_and(|o| o.status.success()) {
            lines.push("PRUNE-REFUSE pin-failed — no salvage pin, fail-closed — worktree kept".to_string());
            return false;
        }
        lines.push(format!("PRUNE-PIN refs/salvage/{new} {new}"));
        pinned.push(new.to_owned());
        pinned_n += 1;
    }
    lines.push(format!("PRUNE-REFLOG {disp} scanned={scanned} pinned={pinned_n}"));
    true
}

/// `merge-base --is-ancestor <head> origin/main` from a live checkout:
/// `Some(true)` contained, `Some(false)` not, `None` the probe failed.
fn contained(dir: &Path, head: &str) -> Option<bool> {
    let origin = git(dir, &["rev-parse", "--verify", "origin/main"])?;
    if !origin.status.success() {
        return None;
    }
    let out = git(dir, &["merge-base", "--is-ancestor", head, "origin/main"])?;
    Some(out.status.success())
}

/// Same containment read anchored on the common dir.
fn contained_common(gd: &Path, head: &str) -> Option<bool> {
    let origin = git_common(gd, &["rev-parse", "--verify", "origin/main"])?;
    if !origin.status.success() {
        return None;
    }
    let out = git_common(gd, &["merge-base", "--is-ancestor", head, "origin/main"])?;
    Some(out.status.success())
}

/// Classify a worktree: `dirty | committed-ahead N | clean | missing`.
/// mtime is never consulted.
#[must_use]
pub fn classify(path: Option<&Path>) -> WorktreeVerdict {
    let Some(wt) = path else {
        return WorktreeVerdict::None;
    };
    if !wt.is_dir() {
        return WorktreeVerdict::Missing;
    }
    match git(wt, &["rev-parse", "HEAD"]) {
        Some(out) if out.status.success() => {}
        _ => return WorktreeVerdict::Missing,
    }
    let dirty = match git(wt, &["status", "--porcelain"]) {
        Some(out) => String::from_utf8_lossy(&out.stdout).lines().count() > 0,
        None => true,
    };
    if dirty {
        return WorktreeVerdict::Dirty;
    }
    let has_origin = matches!(git(wt, &["rev-parse", "--verify", "origin/main"]), Some(out) if out.status.success());
    if has_origin {
        let ahead = git(wt, &["rev-list", "--count", "origin/main..HEAD"])
            .filter(|out| out.status.success())
            .and_then(|out| String::from_utf8_lossy(&out.stdout).trim().parse::<u32>().ok())
            .unwrap_or(0);
        if ahead > 0 {
            return WorktreeVerdict::CommittedAhead(ahead);
        }
    }
    WorktreeVerdict::Clean
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::process::Stdio;

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

    fn init_repo(dir: &Path) {
        git_in(dir, &["init", "-q", "-b", "main"]);
        fs::write(dir.join("f"), "1\n").unwrap();
        git_in(dir, &["add", "-A"]);
        git_in(dir, &["commit", "-q", "-m", "one"]);
    }

    #[test]
    fn none_missing_dirty_clean() {
        assert_eq!(classify(None), WorktreeVerdict::None);
        assert_eq!(classify(Some(Path::new("/nonexistent-xyz"))), WorktreeVerdict::Missing);
        let tmp = tempfile::tempdir().unwrap();
        init_repo(tmp.path());
        assert_eq!(classify(Some(tmp.path())), WorktreeVerdict::Clean);
        fs::write(tmp.path().join("f2"), "x\n").unwrap();
        assert_eq!(classify(Some(tmp.path())), WorktreeVerdict::Dirty);
    }

    #[test]
    fn committed_ahead_counts_against_origin() {
        let tmp = tempfile::tempdir().unwrap();
        let origin = tmp.path().join("origin.git");
        fs::create_dir(&origin).unwrap();
        git_in(&origin, &["init", "-q", "--bare"]);
        let work = tmp.path().join("work");
        fs::create_dir(&work).unwrap();
        init_repo(&work);
        git_in(&work, &["remote", "add", "origin", origin.to_str().unwrap()]);
        git_in(&work, &["push", "-q", "-u", "origin", "main"]);
        assert_eq!(classify(Some(&work)), WorktreeVerdict::Clean);
        fs::write(work.join("f2"), "2\n").unwrap();
        git_in(&work, &["add", "-A"]);
        git_in(&work, &["commit", "-q", "-m", "two"]);
        assert_eq!(classify(Some(&work)), WorktreeVerdict::CommittedAhead(1));
    }

    #[test]
    fn not_a_repo_is_missing() {
        let tmp = tempfile::tempdir().unwrap();
        assert_eq!(classify(Some(tmp.path())), WorktreeVerdict::Missing);
    }

    // --- prune_carrier: the collect-side removal guards ------------------

    /// Repo with a bare origin and main pushed, ready for carriers.
    fn repo_with_origin(dir: &Path) {
        let origin = dir.parent().unwrap().join(format!(
            "{}-origin.git",
            dir.file_name().unwrap().to_string_lossy()
        ));
        fs::create_dir(&origin).unwrap();
        git_in(&origin, &["init", "-q", "--bare"]);
        init_repo(dir);
        git_in(dir, &["remote", "add", "origin", origin.to_str().unwrap()]);
        git_in(dir, &["push", "-q", "-u", "origin", "main"]);
    }

    fn add_worktree(work: &Path, wt: &Path) {
        git_in(work, &["worktree", "add", "--detach", wt.to_str().unwrap(), "HEAD"]);
    }

    fn salvage_refs(dir: &Path) -> Vec<String> {
        let out = Command::new("git")
            .arg("-C")
            .arg(dir)
            .args(["for-each-ref", "refs/salvage"])
            .output()
            .unwrap();
        assert!(out.status.success());
        String::from_utf8_lossy(&out.stdout)
            .lines()
            .map(|l| l.to_owned())
            .collect()
    }

    /// The happy arm: clean carrier at an origin-contained HEAD — pin, plain
    /// removal, the triple, unpin; dir gone and unregistered.
    #[test]
    fn prune_clean_contained_carrier_removed_and_unpinned() {
        let tmp = tempfile::tempdir().unwrap();
        let work = tmp.path().join("work");
        fs::create_dir(&work).unwrap();
        repo_with_origin(&work);
        let wt = tmp.path().join("wt1");
        add_worktree(&work, &wt);
        let lines = prune_carrier(&wt, None);
        let text = lines.join("\n");
        assert!(text.contains("PRUNE-PIN refs/salvage/"), "{text}");
        assert!(
            text.contains("PRUNE-REMOVED")
                && text.contains("rc=0")
                && text.contains("dir-absent=yes")
                && text.contains("unregistered=yes"),
            "{text}"
        );
        assert!(text.contains("PRUNE-UNPIN"), "{text}");
        assert!(!wt.exists(), "clean contained carrier must be removed");
        assert!(salvage_refs(&work).is_empty(), "the pin must be released: {:?}", salvage_refs(&work));
    }

    /// Uncommitted work: dirty is a named refusal, the worktree survives,
    /// no pin is taken, and `--force` is never reached.
    #[test]
    fn prune_refuses_dirty_carrier() {
        let tmp = tempfile::tempdir().unwrap();
        let work = tmp.path().join("work");
        fs::create_dir(&work).unwrap();
        repo_with_origin(&work);
        let wt = tmp.path().join("wt2");
        add_worktree(&work, &wt);
        fs::write(wt.join("uncommitted"), "wip\n").unwrap();
        let lines = prune_carrier(&wt, None);
        assert_eq!(lines.len(), 1, "{}", lines.join("\n"));
        assert!(lines[0].starts_with("PRUNE-REFUSE dirty"), "{}", lines[0]);
        assert!(wt.exists());
        assert!(salvage_refs(&work).is_empty());
    }

    /// Unmerged lane: HEAD carries a commit absent from origin/main — the
    /// containment guard refuses BEFORE any pin, so nothing unmerged is
    /// ever kept by a pin either.
    #[test]
    fn prune_refuses_not_contained_carrier() {
        let tmp = tempfile::tempdir().unwrap();
        let work = tmp.path().join("work");
        fs::create_dir(&work).unwrap();
        repo_with_origin(&work);
        let wt = tmp.path().join("wt3");
        add_worktree(&work, &wt);
        fs::write(wt.join("lane-only"), "unmerged\n").unwrap();
        git_in(&wt, &["add", "-A"]);
        git_in(&wt, &["commit", "-q", "-m", "lane-only"]);
        let lines = prune_carrier(&wt, None);
        assert_eq!(lines.len(), 1, "{}", lines.join("\n"));
        assert!(lines[0].starts_with("PRUNE-REFUSE not-contained"), "{}", lines[0]);
        assert!(wt.exists());
        assert!(salvage_refs(&work).is_empty());
    }

    /// Vanished-but-registered (r1 M1): the named VANISHED line plus the
    /// registration prune — never a 128 death, never the filesystem.
    #[test]
    fn prune_vanished_carrier_prunes_registration() {
        let tmp = tempfile::tempdir().unwrap();
        let work = tmp.path().join("work");
        fs::create_dir(&work).unwrap();
        repo_with_origin(&work);
        let wt = tmp.path().join("wt4");
        add_worktree(&work, &wt);
        fs::remove_dir_all(&wt).unwrap();
        let lines = prune_carrier(&wt, Some(&work));
        assert_eq!(lines.len(), 1, "{}", lines.join("\n"));
        assert!(
            lines[0].starts_with("PRUNE-VANISHED")
                && lines[0].contains("dir-absent=yes")
                && lines[0].contains("unregistered=yes"),
            "{}",
            lines[0]
        );
        assert!(
            !registered_worktrees(&work).iter().any(|p| p == &path_key(&wt)),
            "the stale registration must be gone"
        );
    }

    /// A plain recorded dir (the scratch class) is not a registered
    /// worktree: a named SKIP line, the dir untouched.
    #[test]
    fn prune_skips_plain_dir_as_unregistered() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join("scratch");
        fs::create_dir(&dir).unwrap();
        let lines = prune_carrier(&dir, None);
        assert_eq!(lines.len(), 1, "{}", lines.join("\n"));
        assert!(lines[0].starts_with("PRUNE-SKIP unregistered"), "{}", lines[0]);
        assert!(dir.exists());
    }

    /// The main checkout is never a carrier (r1 minor: named via the
    /// porcelain `branch refs/heads/main` line).
    #[test]
    fn prune_refuses_main_checkout() {
        let tmp = tempfile::tempdir().unwrap();
        let work = tmp.path().join("work");
        fs::create_dir(&work).unwrap();
        repo_with_origin(&work);
        let lines = prune_carrier(&work, None);
        assert_eq!(lines.len(), 1, "{}", lines.join("\n"));
        assert!(lines[0].starts_with("PRUNE-REFUSE main-checkout"), "{}", lines[0]);
        assert!(work.exists());
    }

    /// The mount guard (F-2r B3): a clean, contained carrier whose dir
    /// carries a mount is a named PROTECT-MOUNT refusal — the idle
    /// container-leg class `lsof` cannot see. An unreadable table is the
    /// same fail-closed arm under the PROTECT-MOUNT-SCAN name.
    #[test]
    fn prune_carrier_mount_holder_refuses() {
        let tmp = tempfile::tempdir().unwrap();
        let work = tmp.path().join("work");
        fs::create_dir(&work).unwrap();
        repo_with_origin(&work);
        let wt = tmp.path().join("wt-mnt");
        git_in(&work, &["worktree", "add", "--detach", wt.to_str().unwrap(), "HEAD"]);

        // A bind of the checkout visible under a container path: the ROOT
        // field sits under the checkout — the scan's second arm.
        let held = tmp.path().join("mountinfo-held");
        fs::write(
            &held,
            format!(
                "36 35 0:30 {} /srv/leg rw relatime shared:1 - ext4 /dev/sda1 rw\n",
                path_key(&wt)
            ),
        )
        .unwrap();
        let lines = prune_carrier_with(&wt, None, &held);
        assert_eq!(lines.len(), 1, "{}", lines.join("\n"));
        assert!(lines[0].starts_with("PROTECT-MOUNT "), "{}", lines[0]);
        assert!(wt.is_dir(), "a mounted checkout is never removed");

        // The fail-closed arm: an unreadable mount table is a refusal too.
        let gone = tmp.path().join("mountinfo-missing");
        let lines = prune_carrier_with(&wt, None, &gone);
        assert_eq!(lines.len(), 1, "{}", lines.join("\n"));
        assert!(
            lines[0].starts_with("PROTECT-MOUNT-SCAN"),
            "{}",
            lines[0]
        );
        assert!(wt.is_dir(), "an unanswerable scan never removes");
    }
}
