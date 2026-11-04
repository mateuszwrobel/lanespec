//! Git worktree verdicts, mirroring the bash supervisor's classify, plus
//! the collect-side carrier removal (`prune_carrier`).

use std::path::{Path, PathBuf};
use std::process::Command;

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

fn git(wt: &Path, args: &[&str]) -> Option<std::process::Output> {
    Command::new("git")
        .arg("-C")
        .arg(wt)
        .args(args)
        .output()
        .ok()
}

/// Same probe anchored on the common dir instead of a live checkout — the
/// shape that survives the target directory being gone (post-removal
/// confirms, vanished-dir prune).
fn git_common(gd: &Path, args: &[&str]) -> Option<std::process::Output> {
    Command::new("git")
        .arg("--git-dir")
        .arg(gd)
        .args(args)
        .output()
        .ok()
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
#[must_use]
pub fn prune_carrier(wt: &Path, anchor: Option<&Path>) -> Vec<String> {
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

    // Salvage pin BEFORE the removal (r1 B1): a commit made in the
    // check→remove window would otherwise die with the admin dir.
    if !git(wt, &["update-ref", &format!("refs/salvage/{head}"), &head])
        .is_some_and(|o| o.status.success())
    {
        lines.push(
            "PRUNE-REFUSE pin-failed — no salvage pin, fail-closed — worktree kept".to_string(),
        );
        return lines;
    }
    lines.push(format!("PRUNE-PIN refs/salvage/{head} {head}"));

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
}
