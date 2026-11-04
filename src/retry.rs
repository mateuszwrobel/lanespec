//! `retry` — the generic detached ladder.
//!
//! Shape (per the detach-ladder law): yield-to-live guard, spaced
//! attempts, tee'd per-attempt logs, and a `.final` sentinel that is
//! either `LANDED <token>` or `FAILED`. The token identifies WHAT landed:
//! the last non-empty stdout line of `--success-cmd`, or `rc=0` when no
//! success command is given.

use std::io::Write;
use std::time::Duration;

use anyhow::Result;

use crate::config::Config;
use crate::exit;
use crate::lifecycle::{lane_verdict, utc_stamp};
use crate::procfs::Procfs;
use crate::registry::{LaneVerdict, Registry};

/// Retry lane parameters (recorded in meta).
#[derive(Debug, Clone)]
pub struct RetrySpec {
    /// Command to run each attempt (executed by the shell).
    pub cmd: String,
    /// Command that verifies success; its last stdout line is the token.
    pub success_cmd: Option<String>,
    /// Attempt count.
    pub attempts: u32,
    /// Seconds between attempts.
    pub space: u64,
}

fn run_shell(cmd: &str, log: &mut dyn Write) -> (i32, String) {
    match std::process::Command::new("/bin/bash")
        .arg("-c")
        .arg(cmd)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .output()
    {
        Ok(out) => {
            let stdout = String::from_utf8_lossy(&out.stdout).to_string();
            let stderr = String::from_utf8_lossy(&out.stderr).to_string();
            let _ = log.write_all(stdout.as_bytes());
            let _ = log.write_all(stderr.as_bytes());
            (out.status.code().unwrap_or(1), stdout)
        }
        Err(e) => {
            let _ = writeln!(log, "spawn failed: {e}");
            (1, String::new())
        }
    }
}

fn token_from(stdout: &str) -> String {
    stdout
        .lines()
        .rev()
        .map(str::trim)
        .find(|l| !l.is_empty())
        .unwrap_or("rc=0")
        .to_owned()
}

/// Inline ladder: attempts, tee'd logs, `.final` sentinel.
pub fn retry_inline(reg: &Registry, name: &str, spec: &RetrySpec) -> Result<i32> {
    let dir = reg.dir(name);
    for attempt in 1..=spec.attempts {
        let mut attempt_log = std::fs::File::create(dir.join(format!("push-{attempt}.log")))?;
        // Every push.log line carries a UTC stamp (ADR-027: retry attempts
        // are timestamped — the viewer reads the ladder's history from it).
        {
            let mut started = std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(dir.join("push.log"))?;
            let _ = writeln!(
                started,
                "{} retry {name}: attempt {attempt} started",
                utc_stamp()
            );
        }
        let (rc, _) = run_shell(&spec.cmd, &mut attempt_log);
        let mut success = rc == 0;
        let mut token = "rc=0".to_owned();
        if success
            && let Some(sc) = &spec.success_cmd
        {
            let (src, sout) = run_shell(sc, &mut attempt_log);
            success = src == 0;
            token = token_from(&sout);
        }
        let mut total_log = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(dir.join("push.log"))?;
        if success {
            let _ = writeln!(
                total_log,
                "{} retry {name}: attempt {attempt} — landed {token}",
                utc_stamp()
            );
            reg.with_lock(|| Registry::write_atomic(&dir, ".final", &format!("LANDED {token}\n")))?;
            return Ok(exit::OK);
        }
        let _ = writeln!(
            total_log,
            "{} retry {name}: attempt {attempt} failed rc={rc} — spacing {}s",
            utc_stamp(),
            spec.space
        );
        drop(total_log);
        if attempt < spec.attempts {
            std::thread::sleep(Duration::from_secs(spec.space));
        }
    }
    reg.with_lock(|| Registry::write_atomic(&dir, ".final", "FAILED\n"))?;
    let mut total_log = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(dir.join("push.log"))?;
    let _ = writeln!(
        total_log,
        "{} retry {name}: FAILED after {} attempts",
        utc_stamp(),
        spec.attempts
    );
    Ok(exit::BAD)
}

/// `retry <name> --cmd CMD [--success-cmd CMD] [--attempts N] [--space S] [--inline]`
#[allow(clippy::too_many_arguments)]
pub fn retry<P: Procfs>(
    cfg: &Config,
    proc: &P,
    ns: &str,
    name: &str,
    spec: RetrySpec,
    inline: bool,
    config_path: Option<&std::path::Path>,
) -> Result<i32> {
    if name.is_empty()
        || !name
            .bytes()
            .next()
            .is_some_and(|b| b.is_ascii_alphanumeric())
        || !name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
    {
        anyhow::bail!("bad lane name: '{name}' (allowed: [A-Za-z0-9._-]+, first alphanumeric)");
    }
    let reg = Registry::new(cfg.paths.registry.clone());
    let dir = reg.dir(name);
    // M4: the yield-to-live guard, the directory claim, the .final reset,
    // the meta write, the inline self-record and the detached spawn+record
    // all run under ONE exclusive flock — two concurrent retry lanes can
    // never both claim or interleave their bookkeeping (launch-merge
    // pattern).
    // N1: the yield scan does NOT skip the lane's own name. A second
    // retry under a live same-name lane yields instead of deleting or
    // resetting the `.final` the running ladder owns. The only same-name
    // pass-through is a record pointing at OUR OWN process group: that is
    // the inline re-entry of the detached ladder this very process runs.
    enum Claim {
        YieldedTo(String),
        Ready,
        Spawned(crate::procfs::Pid),
    }
    let fields = || {
        vec![
            ("name".to_owned(), name.to_owned()),
            ("kind".to_owned(), "retry".to_owned()),
            ("ns".to_owned(), ns.to_owned()),
            ("launched".to_owned(), utc_stamp()),
            ("launcher".to_owned(), std::process::id().to_string()),
            ("cmd".to_owned(), spec.cmd.clone()),
            ("success_cmd".to_owned(), spec.success_cmd.clone().unwrap_or_default()),
            ("attempts".to_owned(), spec.attempts.to_string()),
            ("space".to_owned(), spec.space.to_string()),
        ]
    };
    let claim = reg.with_lock(|| -> Result<Claim> {
        for other in reg.list() {
            if other == name {
                continue;
            }
            let d = reg.dir(&other);
            if Registry::meta_field(&d, "kind").as_deref() != Some("retry") {
                continue;
            }
            if Registry::meta_field(&d, "cmd").as_deref() != Some(spec.cmd.as_str()) {
                continue;
            }
            if matches!(lane_verdict(&reg, &other, proc), LaneVerdict::Running) {
                return Ok(Claim::YieldedTo(other));
            }
        }
        // N1: same-name guard. A live ladder under THIS name must never
        // be reclaimed from the outside: its .final stays untouched and
        // no second ladder starts. A record that points at our own group
        // is the inline re-entry of OUR OWN detached ladder — proceed.
        if let Some((pgid, _)) = reg.read_pid(name) {
            let own_pgid = proc
                .stat(std::process::id())
                .map_or(std::process::id(), |s| s.pgid);
            if pgid != own_pgid && lane_verdict(&reg, name, proc).blocks_launch() {
                return Ok(Claim::YieldedTo(name.to_owned()));
            }
        }
        std::fs::create_dir_all(&dir)?;
        let _ = std::fs::remove_file(dir.join(".final"));
        reg.write_meta(name, &fields())?;
        if inline {
            // Record our own pgid under the SAME lock, so a second
            // claimant racing us sees a live record before it can claim.
            let st = proc.stat(std::process::id());
            reg.write_pid(
                name,
                st.as_ref().map_or(std::process::id(), |s| s.pgid),
                st.as_ref().map(|s| s.start_time),
            )?;
            return Ok(Claim::Ready);
        }
        // Detached: re-exec this binary with --inline in its own session.
        // Spawn + record under the SAME lock (launch-merge pattern): the
        // claim and the live record land atomically together.
        let exe = std::env::current_exe()?;
        let mut c = std::process::Command::new(&exe);
        if ns != "default" {
            c.args(["--namespace", ns]);
        }
        if let Some(p) = config_path {
            c.args(["--config"]).arg(p);
        }
        c
            .arg("retry")
            .arg(name)
            .arg("--cmd")
            .arg(&spec.cmd)
            .arg("--attempts")
            .arg(spec.attempts.to_string())
            .arg("--space")
            .arg(spec.space.to_string())
            .arg("--inline");
        if let Some(sc) = &spec.success_cmd {
            c.arg("--success-cmd").arg(sc);
        }
        c.stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::from(std::fs::File::create(dir.join("log"))?))
            .stderr(std::process::Stdio::null());
        // Own session; the handshake makes the recorded pgid the
        // ladder's NEW group, never this process's (see launch in
        // lifecycle.rs for the race this closes).
        let mut handshake = crate::lifecycle::exec_in_new_session(&mut c)?;
        let child = c.spawn()?;
        let pid = child.id();
        std::mem::forget(child); // detach: the ladder outlives this process
        {
            use std::io::Read;
            let _ = handshake.read(&mut [0u8; 1]);
        }
        let st = proc.stat(pid);
        let pgid = st.as_ref().map_or(pid, |s| s.pgid);
        reg.write_pid(name, pgid, st.as_ref().map(|s| s.start_time))?;
        Ok(Claim::Spawned(pgid))
    })?;
    match claim {
        Claim::YieldedTo(other) => {
            let why = if other == name { "same lane" } else { "same cmd" };
            println!("retry {name}: yielding to live retry {other} ({why})");
            Ok(exit::OK)
        }
        Claim::Ready => retry_inline(&reg, name, &spec),
        Claim::Spawned(pgid) => {
            println!(
                "retry {name}: launched detached pgid {pgid} — sentinel {}",
                dir.join(".final").display()
            );
            Ok(exit::OK)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Paths;
    use crate::fake::FakeProcfs;

    fn cfg_in(dir: &std::path::Path) -> Config {
        Config {
            paths: Paths {
                registry: dir.join("reg"),
                scratch: dir.to_path_buf(),
            },
            ..Default::default()
        }
    }

    #[test]
    fn inline_lands_final_against_success_stub() {
        let tmp = tempfile::tempdir().unwrap();
        let cfg = cfg_in(tmp.path());
        let reg = Registry::new(cfg.paths.registry.clone());
        std::fs::create_dir_all(reg.dir("r1")).unwrap();
        reg.write_meta("r1", &[("name".to_owned(), "r1".to_owned())]).unwrap();
        let spec = RetrySpec {
            cmd: "echo doing".to_owned(),
            success_cmd: Some("echo ok sha-abc".to_owned()),
            attempts: 3,
            space: 0,
        };
        let rc = retry_inline(&reg, "r1", &spec).unwrap();
        assert_eq!(rc, exit::OK);
        assert_eq!(
            reg.final_sentinel("r1").as_deref(),
            Some("LANDED ok sha-abc")
        );
        assert!(reg.dir("r1").join("push-1.log").exists());
    }

    #[test]
    fn push_log_lines_carry_utc_stamps() {
        // ADR-027: every attempt line in push.log carries a UTC stamp, so a
        // viewer can read the ladder's history without touching the process
        // table — both the per-attempt started line and the verdict lines.
        let tmp = tempfile::tempdir().unwrap();
        let cfg = cfg_in(tmp.path());
        let reg = Registry::new(cfg.paths.registry.clone());
        std::fs::create_dir_all(reg.dir("ts1")).unwrap();
        let spec = RetrySpec {
            cmd: "false".to_owned(),
            success_cmd: None,
            attempts: 2,
            space: 0,
        };
        let rc = retry_inline(&reg, "ts1", &spec).unwrap();
        assert_eq!(rc, exit::BAD);
        let text = std::fs::read_to_string(reg.dir("ts1").join("push.log")).unwrap();
        let mut lines = 0;
        for line in text.lines() {
            assert!(is_utc_stamp_prefix(line), "line lacks UTC stamp prefix: {line}");
            lines += 1;
        }
        assert_eq!(
            lines, 5,
            "started + failed per attempt plus the final FAILED-after line: {text}"
        );
        assert!(
            text.contains("FAILED after 2 attempts"),
            "the terminal verdict line must be in the stamped history: {text}"
        );
    }

    /// True when the line opens with a "<YYYY-MM-DD>T<HH:MM:SS>Z " stamp —
    /// the exact shape lifecycle::utc_stamp() produces (20 chars + a space).
    fn is_utc_stamp_prefix(line: &str) -> bool {
        let p = match line.get(..20) {
            Some(p) if line.as_bytes().get(20) == Some(&b' ') => p,
            _ => return false,
        };
        let b = p.as_bytes();
        let digit = |i: usize| b[i].is_ascii_digit();
        b[4] == b'-'
            && b[7] == b'-'
            && b[10] == b'T'
            && b[13] == b':'
            && b[16] == b':'
            && b[19] == b'Z'
            && (0..4).all(digit)
            && (5..7).all(digit)
            && (8..10).all(digit)
            && (11..13).all(digit)
            && (14..16).all(digit)
            && (17..19).all(digit)
    }

    #[test]
    fn inline_fails_after_attempts() {
        let tmp = tempfile::tempdir().unwrap();
        let cfg = cfg_in(tmp.path());
        let reg = Registry::new(cfg.paths.registry.clone());
        std::fs::create_dir_all(reg.dir("r2")).unwrap();
        let spec = RetrySpec {
            cmd: "false".to_owned(),
            success_cmd: None,
            attempts: 2,
            space: 0,
        };
        let rc = retry_inline(&reg, "r2", &spec).unwrap();
        assert_eq!(rc, exit::BAD);
        assert_eq!(reg.final_sentinel("r2").as_deref(), Some("FAILED"));
    }

    #[test]
    fn yields_to_live_sibling() {
        let tmp = tempfile::tempdir().unwrap();
        let cfg = cfg_in(tmp.path());
        let reg = Registry::new(cfg.paths.registry.clone());
        std::fs::create_dir_all(reg.dir("other")).unwrap();
        reg.write_meta("other", &[
            ("name".to_owned(), "other".to_owned()),
            ("kind".to_owned(), "retry".to_owned()),
            ("cmd".to_owned(), "git push".to_owned()),
        ])
        .unwrap();
        reg.write_pid("other", 930_001, Some(9)).unwrap();
        let f = FakeProcfs::new();
        f.add(930_001, 1, 930_001, 9, "lanespec", "lanespec retry other --inline");
        let spec = RetrySpec {
            cmd: "git push".to_owned(),
            success_cmd: None,
            attempts: 1,
            space: 0,
        };
        let rc = retry(&cfg, &f, "ns", "mine", spec, false, None).unwrap();
        assert_eq!(rc, exit::OK);
        // No .final written for ours: we yielded before running.
        assert_eq!(reg.final_sentinel("mine"), None);
    }

    #[test]
    fn token_takes_last_stdout_line() {
        assert_eq!(token_from("a\nsha-123\n"), "sha-123");
        assert_eq!(token_from("\n  \n"), "rc=0");
    }

    /// N1 regression: a live ladder under the SAME lane name must make a
    /// second retry YIELD — never reset `.final` under the running first
    /// ladder, never spawn a second ladder (the orchestrator's landing
    /// hook is owned by the first one).
    #[test]
    fn same_name_live_ladder_yields_never_resets_final() {
        let tmp = tempfile::tempdir().unwrap();
        let cfg = cfg_in(tmp.path());
        let reg = Registry::new(cfg.paths.registry.clone());
        std::fs::create_dir_all(reg.dir("gate2")).unwrap();
        reg.write_meta("gate2", &[
            ("name".to_owned(), "gate2".to_owned()),
            ("kind".to_owned(), "retry".to_owned()),
            ("cmd".to_owned(), "git push".to_owned()),
        ])
        .unwrap();
        // The live first ladder: its own session group, NOT our group.
        reg.write_pid("gate2", 950_001, Some(9)).unwrap();
        std::fs::write(reg.dir("gate2").join(".final"), "LANDED sha-first\n").unwrap();
        let f = FakeProcfs::new();
        f.add(950_001, 1, 950_001, 9, "lanespec", "lanespec retry gate2 --inline");
        let spec = RetrySpec {
            cmd: "git push".to_owned(),
            success_cmd: None,
            attempts: 1,
            space: 0,
        };
        let rc = retry(&cfg, &f, "ns", "gate2", spec, false, None).unwrap();
        assert_eq!(rc, exit::OK, "same-name live lane must yield (rc 0)");
        assert_eq!(
            reg.final_sentinel("gate2").as_deref(),
            Some("LANDED sha-first"),
            "the running ladder's .final must stay untouched"
        );
        assert!(f.sent.borrow().is_empty());
    }

    /// N1 pass-through: the inline re-entry of a detached ladder records
    /// OUR OWN pgid; that record is the ladder itself, so the claim must
    /// proceed (and land .final), not yield to itself.
    #[test]
    fn inline_reentry_with_own_group_record_proceeds() {
        let tmp = tempfile::tempdir().unwrap();
        let cfg = cfg_in(tmp.path());
        let reg = Registry::new(cfg.paths.registry.clone());
        std::fs::create_dir_all(reg.dir("gate3")).unwrap();
        let f = FakeProcfs::new();
        // our own pid lives in group 950_050, whose leader exists.
        let own_pgid = 950_050;
        f.add(own_pgid, 1, own_pgid, 5, "bash", "bash -c ladder");
        f.add(std::process::id(), own_pgid, own_pgid, 7, "lanespec", "lanespec retry gate3 --inline");
        reg.write_pid("gate3", own_pgid, Some(5)).unwrap();
        std::fs::write(reg.dir("gate3").join(".final"), "STALE\n").unwrap();
        let spec = RetrySpec {
            cmd: "echo did".to_owned(),
            success_cmd: None,
            attempts: 1,
            space: 0,
        };
        let rc = retry(&cfg, &f, "ns", "gate3", spec, true, None).unwrap();
        assert_eq!(rc, exit::OK, "own-group re-entry must run the ladder, not yield");
        assert_eq!(reg.final_sentinel("gate3").as_deref(), Some("LANDED rc=0"));
    }
}
