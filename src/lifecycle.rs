//! Lane lifecycle commands: launch, status, wait, reap, collect.

use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};

use crate::config::Config;
use crate::exit;
use crate::procfs::{Pid, Procfs, Signal, ancestry_chain};
use crate::registry::{LaneVerdict, Registry};
use crate::worktree;

/// Allowed lane-name characters; the first character must be alphanumeric
/// so a name can never parse as a flag on re-spawns.
fn valid_name(name: &str) -> bool {
    let mut chars = name.bytes();
    let Some(first) = chars.next() else {
        return false;
    };
    first.is_ascii_alphanumeric()
        && name.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
}

/// Shell-escape one argument (`printf %q`-ish) for the meta `cmd` field.
fn sh_quote(arg: &str) -> String {
    if !arg.is_empty()
        && arg
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'@' | b'%' | b'+' | b'=' | b':' | b'_' | b'/' | b'.' | b'-' ))
    {
        return arg.to_owned();
    }
    format!("'{}'", arg.replace('\'', r"'\''"))
}

/// `YYYY-MM-DDTHH:MM:SSZ` UTC stamp (no wall-clock parsing, just time(2)).
#[must_use]
pub fn utc_stamp() -> String {
    let secs = unsafe { libc::time(std::ptr::null_mut()) };
    let days = secs.div_euclid(86_400);
    let rem = secs.rem_euclid(86_400);
    let (y, m, d) = civil_from_days(days);
    format!(
        "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}Z",
        rem / 3600,
        (rem % 3600) / 60,
        rem % 60
    )
}

/// Days since 1970-01-01 to (year, month, day) — Howard Hinnant's algorithm.
fn civil_from_days(days: i64) -> (i64, u32, u32) {
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64; // day of era [0, 146096]
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365; // year of era
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // day of year [0, 365]
    let mp = (5 * doy + 2) / 153; // [0, 11], March = 0
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

/// Lane verdict with start_time re-validation against the process table
/// (pid-reuse law). Leader-gone-but-group-alive is a distinct verdict:
/// the fd-heir group kill is proven safe there, so it never collapses
/// into "stale record".
#[must_use]
pub fn lane_verdict<P: Procfs>(reg: &Registry, name: &str, proc: &P) -> LaneVerdict {
    match reg.read_pid(name) {
        Some((pgid, start)) => {
            let alive = proc.pgid_alive(pgid);
            let leader = proc.stat(pgid);
            let start_ok =
                start.is_some_and(|s| leader.as_ref().is_some_and(|st| st.start_time == s));
            reg.verdict(name, alive, start_ok, leader.is_some())
        }
        None => reg.verdict(name, false, false, false),
    }
}

/// TERM the whole group, settle, then KILL whatever is left.
pub fn kill_pgid_settle<P: Procfs>(proc: &P, pgid: Pid, settle: Duration) -> Result<()> {
    proc.signal_pgid(pgid, Signal::Term)?;
    let started = Instant::now();
    while proc.pgid_alive(pgid) && started.elapsed() < settle {
        std::thread::sleep(Duration::from_millis(100));
    }
    if proc.pgid_alive(pgid) {
        proc.signal_pgid(pgid, Signal::Kill)?;
    }
    Ok(())
}

/// The runner kept alive in the launched command line: it carries the
/// namespace tag in argv[0] (scan anchor), ignores HUP, and lands `.done`
/// atomically under the registry flock. m5: a lock-open failure is RETRIED
/// and then LOUD-FAILS — `.done` must never silently vanish, and must
/// never land without the lock held.
const RUNNER: &str = r#"trap '' HUP
d=$1; l=$2; shift 2
rc=0; "$@" || rc=$?
t=$d.tmp.$$
if ! printf '%s\n' "$rc" >"$t"; then
  echo "lanespec runner: cannot write temp $t — .done NOT landed" >&2
  exit 75
fi
ok=
i=0
while [ "$i" -lt 5 ]; do
  if exec 9<>"$l" 2>/dev/null; then ok=1; break; fi
  i=$((i+1)); sleep 0.1
done
if [ -z "$ok" ]; then
  echo "lanespec runner: cannot open lock $l — .done NOT landed" >&2
  rm -f "$t"; exit 75
fi
if ! flock 9; then
  echo "lanespec runner: cannot flock $l — .done NOT landed" >&2
  rm -f "$t"; exit 75
fi
if ! mv "$t" "$d"; then
  echo "lanespec runner: cannot land .done at $d" >&2
  rm -f "$t"; exit 75
fi
"#;

/// Put the child of `c` into its own session before exec and return a
/// handle whose read end unblocks once the child has passed `setsid`
/// (or died). Without this handshake the parent can read /proc while
/// the child still sits in the PARENT's process group and record that
/// pgid; a later `kill -9 -<pgid>` is then a broadcast to the parent's
/// whole tree (the container class: pgid 1 is every process in it).
/// The write-end is O_CLOEXEC, so a successful exec closes it and the
/// parent sees EOF; a child that dies before exec also gives EOF.
pub(crate) fn exec_in_new_session(c: &mut Command) -> Result<std::fs::File> {
    use std::os::unix::io::FromRawFd;
    let mut fds = [0i32; 2];
    // SAFETY: plain pipe2 on a two-element array.
    if unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) } != 0 {
        return Err(std::io::Error::last_os_error()).context("pipe2 for session handshake");
    }
    let (rd, wr) = (fds[0], fds[1]);
    // SAFETY: pre_exec runs in the forked child before exec; write(2) and
    // setsid(2) are async-signal-safe, and wr is a plain inherited fd.
    unsafe {
        c.pre_exec(move || {
            if libc::setsid() == -1 {
                return Err(std::io::Error::last_os_error());
            }
            let byte = 0u8;
            // The result is irrelevant: reaching past this point means
            // setsid succeeded; the parent only waits for exec-or-death.
            libc::write(wr, (&raw const byte).cast::<libc::c_void>(), 1);
            Ok(())
        });
    }
    // SAFETY: close the parent's copy of the write end; if the child dies
    // before exec the read below gets EOF instead of hanging.
    unsafe { libc::close(wr) };
    // SAFETY: rd is a valid fd created above and is now owned by the File.
    Ok(unsafe { std::fs::File::from_raw_fd(rd) })
}

/// `launch <name> [--worktree PATH] -- CMD...`
pub fn launch<P: Procfs>(
    cfg: &Config,
    proc: &P,
    ns: &str,
    name: &str,
    worktree: Option<&Path>,
    cmd: &[String],
) -> Result<i32> {
    if !valid_name(name) {
        bail!("bad lane name: '{name}' (allowed: [A-Za-z0-9._-]+)");
    }
    if cmd.is_empty() {
        bail!("launch: no command after --");
    }
    let reg = Registry::new(cfg.paths.registry.clone());
    let dir = reg.dir(name);
    let ns_owned = ns.to_owned();
    let name_owned = name.to_owned();
    let cmd_owned = cmd.to_vec();
    let worktree_owned = worktree.map(|p| p.display().to_string());
    // The already-live check and the claim happen under the SAME exclusive
    // flock: two concurrent same-name launches must never both pass the
    // guard (registry-races law).
    let outcome = reg.with_lock(|| {
        if dir.exists() {
            let verdict = lane_verdict(&reg, name, proc);
            if verdict.blocks_launch() {
                eprintln!("lanespec: launch: lane '{name}' already exists ({verdict}) — reap it first");
                return Ok(exit::ALREADY_LIVE);
            }
        }
        std::fs::create_dir_all(&dir).with_context(|| format!("creating {}", dir.display()))?;
        let _ = std::fs::remove_file(dir.join(".done"));
        let _ = std::fs::remove_file(dir.join(".final"));
        let mut fields = vec![
            ("name".to_owned(), name_owned.clone()),
            ("ns".to_owned(), ns_owned.clone()),
            ("kind".to_owned(), "lane".to_owned()),
            ("launched".to_owned(), utc_stamp()),
            ("launcher".to_owned(), std::process::id().to_string()),
        ];
        if let Some(wt) = &worktree_owned {
            fields.push(("worktree".to_owned(), wt.clone()));
        }
        fields.push((
            "cmd".to_owned(),
            cmd_owned.iter().map(|a| sh_quote(a)).collect::<Vec<_>>().join(" "),
        ));
        reg.write_meta(&name_owned, &fields)?;

        let log = std::fs::File::create(dir.join("log"))
            .with_context(|| format!("creating {}", dir.join("log").display()))?;
        let log_err = log
            .try_clone()
            .context("cloning lane log fd for stderr")?;
        let done = dir.join(".done");
        let lock = reg.root.join(".lock");
        let mut c = Command::new("/bin/bash");
        c.arg("-c")
            .arg(RUNNER)
            .arg(format!("lanespec:{ns_owned}:{name_owned}")) // becomes $0: scan anchor in cmdline
            .arg(&done)
            .arg(&lock)
            .args(&cmd_owned)
            .stdin(Stdio::null())
            .stdout(Stdio::from(log))
            .stderr(Stdio::from(log_err));
        // Own session, and the handshake below guarantees the pgid we
        // record is the runner's NEW group, not this process's (race fix:
        // the old code could read /proc before the child's setsid ran).
        let mut handshake = exec_in_new_session(&mut c)?;
        let child = c
            .spawn()
            .with_context(|| format!("spawning lane command: {cmd:?}"))?;
        let pid = child.id();
        std::mem::forget(child); // detach: the lane outlives this process
        {
            use std::io::Read;
            let _ = handshake.read(&mut [0u8; 1]);
        }
        let st = proc.stat(pid);
        let pgid = st.as_ref().map_or(pid, |s| s.pgid);
        let start_time = st.as_ref().map(|s| s.start_time);
        reg.write_pid(&name_owned, pgid, start_time)?;
        println!("launched lane {name_owned}: pgid={pgid} log={}", dir.join("log").display());
        Ok(exit::OK)
    })?;
    Ok(outcome)
}

/// `status [name]`
pub fn status<P: Procfs>(cfg: &Config, proc: &P, only: Option<&str>) -> Result<i32> {
    let reg = Registry::new(cfg.paths.registry.clone());
    let names: Vec<String> = match only {
        Some(n) => {
            if !valid_name(n) {
                bail!("bad lane name: '{n}' (allowed: [A-Za-z0-9._-]+)");
            }
            if !reg.dir(n).is_dir() {
                bail!("status: no lane '{n}' under {}", reg.root.display());
            }
            vec![n.to_owned()]
        }
        None => reg.list(),
    };
    if names.is_empty() {
        println!("no lanes registered under {}", reg.root.display());
        return Ok(exit::OK);
    }
    for n in names {
        let pgid = reg
            .read_pid(&n)
            .map_or_else(|| "?".to_owned(), |(p, _)| p.to_string());
        println!("lane {n}: pgid={pgid} {}", lane_verdict(&reg, &n, proc));
    }
    Ok(exit::OK)
}

/// `wait <name> [timeout-s]` — poll `.done` with a deadline.
pub fn wait<P: Procfs>(cfg: &Config, proc: &P, name: &str, timeout: u64) -> Result<i32> {
    if !valid_name(name) {
        bail!("bad lane name: '{name}' (allowed: [A-Za-z0-9._-]+)");
    }
    let reg = Registry::new(cfg.paths.registry.clone());
    if !reg.dir(name).is_dir() {
        bail!("wait: no lane '{name}' under {}", reg.root.display());
    }
    let started = Instant::now();
    loop {
        if let Some(rc) = reg.done_rc(name) {
            println!("lane {name}: done rc={rc}");
            return Ok(rc);
        }
        if reg.is_done(name) {
            println!("lane {name}: done rc=1");
            return Ok(1);
        }
        if let Some((pgid, start)) = reg.read_pid(name) {
            // The GROUP is the lane: pgid_alive decides. A start_time
            // mismatch only disqualifies when the leader pid EXISTS with
            // a different incarnation (recycled). Leader gone + group
            // alive = fd-heir members still running → keep waiting.
            let leader = proc.stat(pgid);
            let alive = proc.pgid_alive(pgid)
                && match (leader.as_ref(), start) {
                    (Some(st), Some(s)) => st.start_time == s,
                    _ => true,
                };
            if !alive {
                println!(
                    "lane {name}: DEAD without .done (killed or crashed) — treat as orphan, run: reap/audit"
                );
                return Ok(exit::BAD);
            }
        }
        if started.elapsed() >= Duration::from_secs(timeout) {
            let pgid = reg.read_pid(name).map_or(0, |(p, _)| p);
            println!("lane {name}: TIMEOUT after {timeout}s — still running (pgid {pgid})");
            return Ok(exit::TIMEOUT);
        }
        std::thread::sleep(Duration::from_millis(200));
    }
}

/// `reap <name>` — TERM, bounded settle, KILL the whole group; then the
/// worktree verdict. start_time is re-validated immediately before killing.
pub fn reap<P: Procfs>(
    cfg: &Config,
    proc: &P,
    name: &str,
    settle: Duration,
) -> Result<i32> {
    if !valid_name(name) {
        bail!("bad lane name: '{name}' (allowed: [A-Za-z0-9._-]+)");
    }
    let reg = Registry::new(cfg.paths.registry.clone());
    if !reg.dir(name).is_dir() {
        bail!("reap: no lane '{name}' under {}", reg.root.display());
    }
    match reg.read_pid(name) {
        None => println!("lane {name}: no pgid recorded"),
        Some((pgid, start)) => {
            // N2: an inline-retry record carries the CALLER's pgid. A
            // recorded group that IS our own group or an ancestor's group
            // must never be signalled — same lineage guard `unlock` got
            // from M6: killing it would TERM our own session.
            if proc.pgid_alive(pgid) {
                let chain = ancestry_chain(proc, cfg.parent_rule.max_ancestry_depth);
                let own_pgid = proc
                    .stat(std::process::id())
                    .map_or(std::process::id(), |s| s.pgid);
                let own_lineage = pgid == own_pgid
                    || chain
                        .iter()
                        .any(|p| proc.stat(*p).is_some_and(|st| st.pgid == pgid));
                if own_lineage {
                    eprintln!(
                        "lane {name}: refusing to reap pgid {pgid} — it is our own process group or an ancestor's (inline-retry record): never signal our own lineage"
                    );
                    return Ok(exit::BAD);
                }
            }
            let leader = proc.stat(pgid);
            let start_ok =
                start.is_some_and(|s| leader.as_ref().is_some_and(|st| st.start_time == s));
            if !proc.pgid_alive(pgid) {
                println!("lane {name}: pgid {pgid} already gone");
            } else if leader.is_none() {
                // Leader-dead group-alive (fd-heir shape): the pid does not
                // exist, so no pid can be recycled into it; the group kill
                // needs no leader. Kill it — this is the tool's mission.
                kill_pgid_settle(proc, pgid, settle)?;
                println!("lane {name}: reaped pgid {pgid} (leader dead, group alive — fd-heir group kill)");
            } else if !start_ok {
                println!("lane {name}: pgid {pgid} stale-record (pid recycled) — NOT killed");
            } else {
                kill_pgid_settle(proc, pgid, settle)?;
                println!("lane {name}: reaped pgid {pgid} (TERM then KILL)");
            }
        }
    }
    let wt = Registry::meta_field(&reg.dir(name), "worktree").map(std::path::PathBuf::from);
    println!(
        "lane {name}: worktree {}",
        worktree::classify(wt.as_deref())
    );
    Ok(exit::OK)
}

/// Outcome of one `collect` proof for a single record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CollectOutcome {
    /// Death is proven and the record was removed. `evidence` names the
    /// proof and any sentinel the record carried (the transcript keeps
    /// what the directory held).
    Collected { pgid: Pid, evidence: Vec<String> },
    /// The record stays; the reason names the missing proof. Nothing was
    /// signalled and nothing was removed.
    Refused(String),
}

/// The collect proof for one record (decision record:
/// `lanespec/worklog/2026-11-02-collect-verb.md`). A DeadOrphan verdict
/// means `kill -0 -pgid` answered ESRCH: the group has no members — that
/// is the death proof, re-read here at decision time. `Done(rc)` means
/// the runner landed `.done` after the command exited, so only the
/// runner's own group still needs the same ESRCH proof. A stale record
/// is unprovable (pid-reuse law: NEVER act on it), and a record without
/// a pgid has nothing to prove — both are refused. Collect NEVER
/// signals: a group that is alive is a refusal, not a target.
#[must_use]
pub fn collect_proof<P: Procfs>(reg: &Registry, proc: &P, name: &str) -> CollectOutcome {
    let recorded = reg.read_pid(name);
    let pgid_s = match recorded {
        Some((p, _)) => p.to_string(),
        None => "none".to_owned(),
    };
    match lane_verdict(reg, name, proc) {
        LaneVerdict::Running => CollectOutcome::Refused(format!(
            "lane {name} is running (pgid {pgid_s}): a live lane's record is never collected"
        )),
        LaneVerdict::LeaderDeadGroupAlive => CollectOutcome::Refused(format!(
            "lane {name} group {pgid_s} is alive without its leader (fd heirs): run lanespec reap {name} first"
        )),
        LaneVerdict::StaleRecord => CollectOutcome::Refused(format!(
            "lane {name} is stale-record (pgid {pgid_s} recycled or unprovable): death NOT proven, never collect"
        )),
        LaneVerdict::Done(rc) => match recorded {
            None => CollectOutcome::Refused(format!(
                "lane {name} is done rc={rc} but records no pgid: the runner's group cannot be proven gone"
            )),
            Some((pgid, _)) if pgid < 2 => CollectOutcome::Refused(format!(
                "lane {name} is done rc={rc} but records pgid {pgid}, not a process group: no death proof"
            )),
            Some((pgid, _)) if proc.pgid_alive(pgid) => CollectOutcome::Refused(format!(
                "lane {name} is done rc={rc} but group {pgid} is still alive (runner exiting): collect again once it exits"
            )),
            Some((pgid, _)) => {
                let mut evidence = vec![format!("done rc={rc}"), format!("pgid {pgid} gone (ESRCH proof)")];
                if let Some(fin) = reg.final_sentinel(name) {
                    evidence.push(format!(".final {fin}"));
                }
                CollectOutcome::Collected { pgid, evidence }
            }
        },
        LaneVerdict::DeadOrphan => match recorded {
            None => CollectOutcome::Refused(format!(
                "lane {name} records no pgid: nothing can be proven dead, record kept for inspection"
            )),
            Some((pgid, _)) if pgid < 2 => CollectOutcome::Refused(format!(
                "lane {name} records pgid {pgid}, not a process group: no death proof, record kept"
            )),
            Some((pgid, _)) if proc.pgid_alive(pgid) => CollectOutcome::Refused(format!(
                "lane {name} group {pgid} is alive after all — refusing at the delete moment"
            )),
            Some((pgid, _)) => {
                let mut evidence = vec![format!("pgid {pgid} gone (ESRCH proof)")];
                if let Some(fin) = reg.final_sentinel(name) {
                    evidence.push(format!(".final {fin}"));
                }
                CollectOutcome::Collected { pgid, evidence }
            }
        },
    }
}

/// `collect <name>` / `collect --all` — remove registry records whose
/// lanes are PROVEN dead by the process table. The proof and the remove
/// run under the same registry `flock` that `launch` and `retry` claim
/// under, and the group liveness is re-read at the delete moment, so no
/// same-name relaunch can interleave (TOCTOU law). collect signals nothing
/// — a live group is a refusal, not a target.
///
/// When the collected record carries a `worktree` path, collect also
/// removes that carrier worktree IF every guard holds: no other record
/// claims the same path with a newer (or
/// tied/unparsable) `launched` stamp and none runs live on it; the
/// worktree is a registered, clean, non-main worktree whose HEAD is fully
/// contained in `origin/main`. Removal is the plain `git worktree remove`
/// — never `--force`, never `rm -rf` — and every removal or refusal
/// prints one named `PRUNE-*` line. Unregistered scratch directories are
/// never this verb's business: their owners are `git worktree` and the
/// hygiene tool.
pub fn collect<P: Procfs>(cfg: &Config, proc: &P, only: Option<&str>) -> Result<i32> {
    let reg = Registry::new(cfg.paths.registry.clone());
    let names: Vec<String> = match only {
        Some(n) => {
            if !valid_name(n) {
                bail!("bad lane name: '{n}' (allowed: [A-Za-z0-9._-]+)");
            }
            if !reg.dir(n).is_dir() {
                bail!("collect: no lane '{n}' under {}", reg.root.display());
            }
            vec![n.to_owned()]
        }
        None => {
            let names = reg.list();
            if names.is_empty() {
                println!("collect: no lanes registered under {}", reg.root.display());
                return Ok(exit::OK);
            }
            names
        }
    };
    // (name, outcome, recorded worktree read BEFORE the remove, prune lines).
    let mut events: Vec<(String, CollectOutcome, Option<PathBuf>, Vec<String>)> = Vec::new();
    reg.with_lock(|| {
        events = Vec::new();
        for n in &names {
            if !reg.dir(n).is_dir() {
                continue; // vanished under us
            }
            let wt = Registry::meta_field(&reg.dir(n), "worktree").map(PathBuf::from);
            let launched = Registry::meta_field(&reg.dir(n), "launched");
            let oc = collect_proof(&reg, proc, n);
            let mut prune = Vec::new();
            if matches!(oc, CollectOutcome::Collected { .. }) {
                std::fs::remove_dir_all(reg.dir(n))
                    .with_context(|| format!("collecting {}", reg.dir(n).display()))?;
                // The carrier guards run INSIDE the lock: `launch` claims
                // new records under the same flock, so no newer claim of
                // this path can interleave behind the freshness scan.
                if let Some(p) = &wt {
                    prune = carrier_prune(&reg, proc, n, launched.as_deref(), p);
                }
            }
            events.push((n.clone(), oc, wt, prune));
        }
        Ok(())
    })?;
    let mut refused = false;
    for (n, oc, wt, prune) in events {
        match oc {
            CollectOutcome::Collected { evidence, .. } => {
                match wt {
                    Some(p) => println!(
                        "lane {n}: collected ({}) — recorded worktree {}",
                        evidence.join(", "),
                        p.display()
                    ),
                    None => println!(
                        "lane {n}: collected ({}) — no worktree recorded",
                        evidence.join(", ")
                    ),
                }
                for line in prune {
                    println!("{line}");
                }
            }
            CollectOutcome::Refused(why) => {
                refused = true;
                eprintln!("collect refused: {why} — record kept");
            }
        }
    }
    Ok(if refused { exit::BAD } else { exit::OK })
}

/// Registry-side freshness guard for one collected record's carrier
/// (the path-reuse guard: an old DONE record must never
/// remove a newer lane's live worktree). `launched` stamps are UTC ISO
/// strings, so lexicographic order is time order. A NEWER (or same-second
/// or unparsable) record claiming the same path refuses the removal; an
/// OLDER record that is still live on the path also refuses (a process
/// could commit into the check→remove window). Everything else hands the
/// path to the worktree-side guards in [`worktree::prune_carrier`].
fn carrier_prune<P: Procfs>(
    reg: &Registry,
    proc: &P,
    name: &str,
    launched: Option<&str>,
    wt: &Path,
) -> Vec<String> {
    let want = worktree::path_key(wt);
    for other in reg.list() {
        if other == name {
            continue;
        }
        let Some(p2) = Registry::meta_field(&reg.dir(&other), "worktree") else {
            continue;
        };
        if worktree::path_key(Path::new(&p2)) != want {
            continue;
        }
        let s2 = Registry::meta_field(&reg.dir(&other), "launched");
        match (launched, s2.as_deref()) {
            (Some(a), Some(b)) if stamp_ok(a) && stamp_ok(b) => match b.cmp(a) {
                std::cmp::Ordering::Greater => {
                    return vec![format!(
                        "PRUNE-REFUSE newer-record — lane '{other}' launched {b} claims {}: a newer record owns the path — worktree kept",
                        wt.display()
                    )];
                }
                std::cmp::Ordering::Equal => {
                    return vec![format!(
                        "PRUNE-REFUSE stamp-ambiguous — lane '{other}' launched {b} ties {} — path ownership undecidable — worktree kept",
                        wt.display()
                    )];
                }
                std::cmp::Ordering::Less => {
                    if matches!(
                        lane_verdict(reg, &other, proc),
                        LaneVerdict::Running | LaneVerdict::LeaderDeadGroupAlive
                    ) {
                        return vec![format!(
                            "PRUNE-REFUSE live-record — lane '{other}' launched {b} still runs on {} — worktree kept",
                            wt.display()
                        )];
                    }
                }
            },
            _ => {
                return vec![format!(
                    "PRUNE-REFUSE stamp-ambiguous — lane '{other}' carries no comparable launched stamp — worktree kept"
                )];
            }
        }
    }
    let anchor = std::env::current_dir().ok();
    worktree::prune_carrier(wt, anchor.as_deref())
}

/// Whether a `launched` stamp is comparable by lexicographic order: the
/// exact `utc_stamp()` shape (2026-11-03T12:34:56Z), nothing else.
fn stamp_ok(s: &str) -> bool {
    let b = s.as_bytes();
    s.len() == 20 && b[4] == b'-' && b[10] == b'T' && s.ends_with('Z')
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{Config, Paths};
    use crate::fake::FakeProcfs;
    use std::path::PathBuf;

    fn test_cfg(root: PathBuf) -> Config {
        Config {
            paths: Paths {
                registry: root,
                scratch: std::env::temp_dir(),
            },
            ..Default::default()
        }
    }

    /// Registry with one lane whose pgid is live in the fake table.
    fn seeded(tmp: &tempfile::TempDir, fake: &FakeProcfs, name: &str, pgid: Pid, start: u64) -> Config {
        let cfg = test_cfg(tmp.path().join("reg"));
        let reg = Registry::new(cfg.paths.registry.clone());
        std::fs::create_dir_all(reg.dir(name)).unwrap();
        reg.write_pid(name, pgid, Some(start)).unwrap();
        fake.add(pgid, 1, pgid, start, "sleep", "sleep 31");
        cfg
    }

    /// Regression (container class): the recorded child must be in its
    /// OWN session. Without the handshake the parent can read /proc
    /// before the child's setsid ran and record the parent's pgid —
    /// `kill -9 -<that>` then broadcasts to the parent's whole tree.
    #[test]
    fn exec_in_new_session_child_leaves_parents_group() {
        let mut c = Command::new("sleep");
        c.arg("30").stdin(std::process::Stdio::null());
        let mut handshake = exec_in_new_session(&mut c).unwrap();
        let child = c.spawn().unwrap();
        let pid = child.id();
        std::mem::forget(child); // detached, like launch; reaped below
        {
            use std::io::Read;
            let _ = handshake.read(&mut [0u8; 1]);
        }
        let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).unwrap();
        let rest = &stat[stat.rfind(')').unwrap() + 1..];
        let fields: Vec<&str> = rest.split_whitespace().collect();
        let pgrp: u32 = fields[2].parse().unwrap();
        assert_eq!(pgrp, pid, "child must lead its own process group");
        // Cleanup: kill the own-group child, then reap it (std may have
        // reaped it already via its SIGCHLD handler; ECHILD is fine).
        // SAFETY: pid is this test's own detached child.
        unsafe { libc::kill(pid as libc::pid_t, libc::SIGKILL) };
        // SAFETY: waiting on our own child; status not needed.
        let _ = unsafe { libc::waitpid(pid as libc::pid_t, std::ptr::null_mut(), 0) };
    }

    #[test]
    fn launch_guard_exit4_when_running() {
        let tmp = tempfile::tempdir().unwrap();
        let fake = FakeProcfs::new();
        let cfg = seeded(&tmp, &fake, "l1", 900_001, 10);
        let code = launch(&cfg, &fake, "ns", "l1", None, &[true_path()]).unwrap();
        assert_eq!(code, exit::ALREADY_LIVE);
    }

    #[test]
    fn launch_guard_exit4_when_done() {
        let tmp = tempfile::tempdir().unwrap();
        let fake = FakeProcfs::new();
        let cfg = seeded(&tmp, &fake, "l1", 900_002, 10);
        let reg = Registry::new(cfg.paths.registry.clone());
        std::fs::write(reg.dir("l1").join(".done"), "0\n").unwrap();
        let code = launch(&cfg, &fake, "ns", "l1", None, &[true_path()]).unwrap();
        assert_eq!(code, exit::ALREADY_LIVE);
    }

    #[test]
    fn stale_record_never_blocks_and_never_kills() {
        let tmp = tempfile::tempdir().unwrap();
        let fake = FakeProcfs::new();
        let cfg = seeded(&tmp, &fake, "l1", 900_003, 10);
        fake.recycle(900_003, 99); // pid reused by someone else
        let reg = Registry::new(cfg.paths.registry.clone());
        let v = lane_verdict(&reg, "l1", &fake);
        assert_eq!(v, LaneVerdict::StaleRecord);
        assert!(!v.blocks_launch());
        // reap on a stale record must not signal anything.
        let code = reap(&cfg, &fake, "l1", Duration::from_millis(50)).unwrap();
        assert_eq!(code, exit::OK);
        assert!(fake.sent.borrow().is_empty(), "stale record must never be killed");
    }

    #[test]
    fn wait_propagates_rc_timeout_and_dead() {
        let tmp = tempfile::tempdir().unwrap();
        let fake = FakeProcfs::new();
        let cfg = seeded(&tmp, &fake, "l1", 900_004, 10);
        let reg = Registry::new(cfg.paths.registry.clone());
        std::fs::write(reg.dir("l1").join(".done"), "7\n").unwrap();
        assert_eq!(wait(&cfg, &fake, "l1", 1).unwrap(), 7);
        std::fs::remove_file(reg.dir("l1").join(".done")).unwrap();
        assert_eq!(wait(&cfg, &fake, "l1", 0).unwrap(), exit::TIMEOUT);
        fake.expire(900_004); // group died without .done
        assert_eq!(wait(&cfg, &fake, "l1", 30).unwrap(), exit::BAD);
    }

    #[test]
    fn reap_term_then_kill_when_term_ignored() {
        let tmp = tempfile::tempdir().unwrap();
        let fake = FakeProcfs::new();
        let cfg = seeded(&tmp, &fake, "l1", 900_005, 10);
        fake.add(900_006, 900_005, 900_005, 10, "sleep", "sleep 31"); // grandchild in group
        fake.set_survives_term(900_005);
        let code = reap(&cfg, &fake, "l1", Duration::from_millis(120)).unwrap();
        assert_eq!(code, exit::OK);
        assert_eq!(
            fake.sent.borrow().len(),
            2,
            "TERM then KILL expected: {:?}",
            fake.sent.borrow()
        );
        assert!(!fake.pgid_alive(900_005));
    }

    /// M1 regression: leader pid gone but the GROUP alive (fd-heir shape,
    /// e.g. `bash -c "sleep 40 & kill $$"`) is NOT a stale record: reap
    /// kills the group, the verdict blocks launch, and wait keeps waiting.
    #[test]
    fn leader_dead_group_alive_is_reaped_not_declared_stale() {
        let tmp = tempfile::tempdir().unwrap();
        let fake = FakeProcfs::new();
        let cfg = seeded(&tmp, &fake, "l1", 900_010, 10);
        fake.add(900_011, 900_010, 900_010, 10, "sleep", "sleep 40"); // group member
        fake.expire(900_010); // the leader killed itself
        let reg = Registry::new(cfg.paths.registry.clone());
        let v = lane_verdict(&reg, "l1", &fake);
        assert_eq!(v, LaneVerdict::LeaderDeadGroupAlive);
        assert!(v.blocks_launch(), "an alive fd-heir group is still the lane");
        // wait must WAIT (timeout), not declare the lane DEAD.
        assert_eq!(
            wait(&cfg, &fake, "l1", 0).unwrap(),
            exit::TIMEOUT,
            "leader-dead group-alive lane is still running — wait must not call it DEAD"
        );
        let code = reap(&cfg, &fake, "l1", Duration::from_millis(50)).unwrap();
        assert_eq!(code, exit::OK);
        assert!(!fake.pgid_alive(900_010), "the fd-heir group must die");
        assert!(!fake.pid_alive(900_011));
    }

    /// M4 regression: the already-live check and the claim must be under
    /// the SAME flock — two concurrent same-name launches must produce
    /// exactly one winner (0) and exactly one refusal (4).
    #[test]
    fn concurrent_launch_same_name_exactly_one_wins() {
        let tmp = tempfile::tempdir().unwrap();
        let cfg = test_cfg(tmp.path().join("reg"));
        let pr = crate::procfs::RealProcfs::new();
        let proc = &pr;
        let codes = std::thread::scope(|s| {
            let handles: Vec<_> = (0..2)
                .map(|_| {
                    let cfg = &cfg;
                    s.spawn(move || {
                        launch(cfg, proc, "ns", "race", None, &["/bin/sleep".to_owned(), "20".to_owned()])
                            .unwrap()
                    })
                })
                .collect();
            handles.into_iter().map(|h| h.join().unwrap()).collect::<Vec<i32>>()
        });
        let wins = codes.iter().filter(|c| **c == exit::OK).count();
        let refusals = codes.iter().filter(|c| **c == exit::ALREADY_LIVE).count();
        // Land the child we own before asserting (never leak it).
        let reg = Registry::new(cfg.paths.registry.clone());
        if let Some((pgid, _)) = reg.read_pid("race") {
            let _ = kill_pgid_settle(proc, pgid, std::time::Duration::from_millis(200));
        }
        assert_eq!((wins, refusals), (1, 1), "launch codes: {codes:?}");
    }

    /// m5: the old runner swallowed lock failures with `|| true` and moved
    /// `.done` into place UNLOCKED (racing readers) — or the move silently
    /// failed and `.done` vanished with no word. A lock that cannot be
    /// opened after retries must be LOUD (stderr + exit 75), must land
    /// nothing, and must leave no temp; the happy path must still land rc.
    #[test]
    fn runner_lock_failure_is_loud_and_never_drops_done() {
        let tmp = tempfile::tempdir().unwrap();
        let lane_dir = tmp.path().join("lane");
        std::fs::create_dir_all(&lane_dir).unwrap();
        let done = lane_dir.join(".done");
        // A directory cannot be opened read-write: every lock attempt fails.
        let lock_bad = tmp.path().join("lock-is-a-dir");
        std::fs::create_dir_all(&lock_bad).unwrap();
        // Same invocation shape as launch: bash -c RUNNER $0=tag $1=done $2=lock.
        let out = std::process::Command::new("/bin/bash")
            .arg("-c")
            .arg(RUNNER)
            .arg("lanespec:ns5:lane")
            .arg(&done)
            .arg(&lock_bad)
            .arg("/bin/true")
            .output()
            .expect("run runner");
        assert_eq!(
            out.status.code(),
            Some(75),
            "lock failure must exit 75, stderr: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        assert!(
            String::from_utf8_lossy(&out.stderr).contains(".done NOT landed"),
            "lock failure must be loud, got: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        assert!(!done.exists(), ".done must never land without the lock");
        let leftovers: Vec<_> = std::fs::read_dir(&lane_dir)
            .unwrap()
            .filter(|e| e.as_ref().unwrap().file_name() != ".done")
            .collect();
        assert!(leftovers.is_empty(), "no temp file may leak: {leftovers:?}");
        // Happy path: rc still lands through the lock.
        let lock_ok = tmp.path().join("reg.lock");
        let out2 = std::process::Command::new("/bin/bash")
            .arg("-c")
            .arg(RUNNER)
            .arg("lanespec:ns5:lane")
            .arg(&done)
            .arg(&lock_ok)
            .arg("/bin/sh")
            .args(["-c", "exit 3"])
            .output()
            .expect("run runner happy path");
        assert!(
            out2.status.success(),
            "stderr: {}",
            String::from_utf8_lossy(&out2.stderr)
        );
        assert_eq!(std::fs::read_to_string(&done).unwrap().trim(), "3");
    }

    fn true_path() -> String {
        "/bin/true".to_owned()
    }

    /// N2 regression: an inline-retry record carries the CALLER's pgid.
    /// Reap must carry the same lineage guard `unlock` got from M6: when
    /// the recorded group IS our own group or an ancestor's, refuse and
    /// signal NOTHING (otherwise reap could TERM the invoking session).
    #[test]
    fn reap_refuses_record_pointing_at_own_group_or_ancestor() {
        let mypid = std::process::id();

        // own-group shape: the record's pgid is the group we run in.
        let tmp = tempfile::tempdir().unwrap();
        let fake = FakeProcfs::new();
        let cfg = test_cfg(tmp.path().join("reg"));
        let reg = Registry::new(cfg.paths.registry.clone());
        std::fs::create_dir_all(reg.dir("r1")).unwrap();
        fake.add(950_100, 1, 950_100, 1, "bash", "bash -l"); // session leader = our group
        fake.add(mypid, 950_100, 950_100, 7, "lanespec", "lanespec reap r1");
        reg.write_pid("r1", 950_100, Some(1)).unwrap();
        let code = reap(&cfg, &fake, "r1", Duration::from_millis(50)).unwrap();
        assert_eq!(code, exit::BAD, "own-group record must refuse");
        assert!(fake.sent.borrow().is_empty(), "own group must never be signalled");

        // ancestor-group shape: a parent runs in ANOTHER group; the
        // record points at that group.
        let fake2 = FakeProcfs::new();
        std::fs::create_dir_all(reg.dir("r2")).unwrap();
        fake2.add(950_201, 1, 950_201, 1, "sshd", "sshd"); // leader of the ancestor's group
        fake2.add(950_200, 1, 950_201, 1, "sudo", "sudo bash"); // our parent, in that group
        fake2.add(mypid, 950_200, 950_200, 7, "lanespec", "lanespec reap r2"); // we changed group
        reg.write_pid("r2", 950_201, Some(1)).unwrap();
        let code = reap(&cfg, &fake2, "r2", Duration::from_millis(50)).unwrap();
        assert_eq!(code, exit::BAD, "ancestor-group record must refuse");
        assert!(fake2.sent.borrow().is_empty(), "ancestor group must never be signalled");

        // control: a foreign lane (no lineage link) is still reaped.
        let fake3 = FakeProcfs::new();
        std::fs::create_dir_all(reg.dir("r3")).unwrap();
        reg.write_pid("r3", 950_300, Some(1)).unwrap();
        fake3.add(950_300, 1, 950_300, 1, "sleep", "sleep 31");
        let code = reap(&cfg, &fake3, "r3", Duration::from_millis(50)).unwrap();
        assert_eq!(code, exit::OK, "foreign lane must still be reaped");
        assert!(!fake3.pgid_alive(950_300));
    }

    #[test]
    fn names_validated() {
        assert!(valid_name("lane-1.x_y"));
        assert!(!valid_name(""));
        assert!(!valid_name("bad name"));
        assert!(!valid_name("bad/name"));
        assert!(!valid_name("--x"));
    }

    #[test]
    fn sh_quote_roundtrip() {
        assert_eq!(sh_quote("plain-1.0/x"), "plain-1.0/x");
        assert_eq!(sh_quote("a b"), "'a b'");
        assert_eq!(sh_quote("it's"), r"'it'\''s'");
    }

    #[test]
    fn civil_dates_known_fixedpoints() {
        assert_eq!(civil_from_days(0), (1970, 1, 1));
        assert_eq!(civil_from_days(-1), (1969, 12, 31));
        assert_eq!(civil_from_days(20_454), (2026, 1, 1));
        assert_eq!(civil_from_days(20_735), (2026, 10, 9));
    }

    #[test]
    fn utc_stamp_shape() {
        let s = utc_stamp();
        let b = s.as_bytes();
        assert!(
            s.ends_with('Z') && s.len() == 20 && b[4] == b'-' && b[10] == b'T' && b[7] == b'-',
            "{s}"
        );
    }

    // --- collect: deletion only on a process-table death proof -----------

    /// The gap cell: a proven-dead lane (group answered ESRCH) is collected
    /// — record gone, exit 0, nothing signalled.
    #[test]
    fn collect_dead_proven_lane_removes_record_exit0() {
        let tmp = tempfile::tempdir().unwrap();
        let fake = FakeProcfs::new();
        let cfg = seeded(&tmp, &fake, "l1", 900_020, 10);
        fake.expire(900_020); // the group died on its own
        let rc = collect(&cfg, &fake, Some("l1")).unwrap();
        assert_eq!(rc, exit::OK);
        let reg = Registry::new(cfg.paths.registry.clone());
        assert!(!reg.dir("l1").exists(), "record must be collected");
        assert!(fake.sent.borrow().is_empty(), "collect never signals");
    }

    /// The refusal cell: a live lane is refused, record kept, nonzero,
    /// and collect signals NOTHING (it is not a kill tool).
    #[test]
    fn collect_live_lane_refuses_keeps_record_never_signals() {
        let tmp = tempfile::tempdir().unwrap();
        let fake = FakeProcfs::new();
        let cfg = seeded(&tmp, &fake, "l1", 900_021, 10);
        let rc = collect(&cfg, &fake, Some("l1")).unwrap();
        assert_eq!(rc, exit::BAD);
        let reg = Registry::new(cfg.paths.registry.clone());
        assert!(reg.dir("l1").exists(), "live record must survive");
        assert!(fake.sent.borrow().is_empty(), "collect never signals");
    }

    /// Leader-dead group-alive (fd-heir members): the group is ALIVE, so
    /// there is no death proof. Reap kills first; collect must refuse and
    /// must not kill by itself.
    #[test]
    fn collect_leader_dead_group_alive_refuses_and_never_kills() {
        let tmp = tempfile::tempdir().unwrap();
        let fake = FakeProcfs::new();
        let cfg = seeded(&tmp, &fake, "l1", 900_022, 10);
        fake.add(900_023, 900_022, 900_022, 10, "sleep", "sleep 40");
        fake.expire(900_022);
        let rc = collect(&cfg, &fake, Some("l1")).unwrap();
        assert_eq!(rc, exit::BAD);
        let reg = Registry::new(cfg.paths.registry.clone());
        assert!(reg.dir("l1").exists(), "alive group: record kept");
        assert!(fake.sent.borrow().is_empty(), "collect is not a kill tool");
    }

    /// Pid-reuse law: a stale record is UNPROVABLE — the same refusal
    /// class as for a kill.
    #[test]
    fn collect_stale_record_refuses_keeps_record() {
        let tmp = tempfile::tempdir().unwrap();
        let fake = FakeProcfs::new();
        let cfg = seeded(&tmp, &fake, "l1", 900_024, 10);
        fake.recycle(900_024, 99);
        let rc = collect(&cfg, &fake, Some("l1")).unwrap();
        assert_eq!(rc, exit::BAD);
        let reg = Registry::new(cfg.paths.registry.clone());
        assert!(reg.dir("l1").exists(), "unprovable record must be kept");
        assert!(fake.sent.borrow().is_empty());
    }

    /// A done lane whose runner group is gone is collectible (the name is
    /// otherwise blocked forever by the already-live guard), and the
    /// .done rc + .final are printed before the remove.
    #[test]
    fn collect_done_lane_group_gone_removes_record() {
        let tmp = tempfile::tempdir().unwrap();
        let fake = FakeProcfs::new();
        let cfg = seeded(&tmp, &fake, "l1", 900_025, 10);
        let reg = Registry::new(cfg.paths.registry.clone());
        std::fs::write(reg.dir("l1").join(".done"), "7\n").unwrap();
        Registry::write_atomic(&reg.dir("l1"), ".final", "LANDED sha-abc\n").unwrap();
        fake.expire(900_025);
        let oc = collect_proof(&reg, &fake, "l1");
        match oc {
            CollectOutcome::Collected { evidence, .. } => {
                let ev = evidence.join(" ");
                assert!(ev.contains("done rc=7"), "{ev}");
                assert!(ev.contains(".final LANDED sha-abc"), "{ev}");
            }
            other => panic!("expected Collected, got {other:?}"),
        }
        let rc = collect(&cfg, &fake, Some("l1")).unwrap();
        assert_eq!(rc, exit::OK);
        assert!(!reg.dir("l1").exists());
    }

    /// `.done` wins over liveness in the verdict, but the runner group can
    /// still be mid-exit: no ESRCH proof yet → refuse.
    #[test]
    fn collect_done_lane_group_alive_refuses() {
        let tmp = tempfile::tempdir().unwrap();
        let fake = FakeProcfs::new();
        let cfg = seeded(&tmp, &fake, "l1", 900_026, 10);
        let reg = Registry::new(cfg.paths.registry.clone());
        std::fs::write(reg.dir("l1").join(".done"), "0\n").unwrap();
        let rc = collect(&cfg, &fake, Some("l1")).unwrap();
        assert_eq!(rc, exit::BAD);
        assert!(reg.dir("l1").exists(), "runner still exiting: record kept");
    }

    /// O-4: a record without a pgid cannot be proven dead by ANY read —
    /// refused, kept, loud (the audit keeps reporting it).
    #[test]
    fn collect_record_without_pid_refuses() {
        let tmp = tempfile::tempdir().unwrap();
        let fake = FakeProcfs::new();
        let cfg = test_cfg(tmp.path().join("reg"));
        let reg = Registry::new(cfg.paths.registry.clone());
        std::fs::create_dir_all(reg.dir("l1")).unwrap();
        reg.write_meta("l1", &[("name".to_owned(), "l1".to_owned())])
            .unwrap();
        let rc = collect(&cfg, &fake, Some("l1")).unwrap();
        assert_eq!(rc, exit::BAD);
        assert!(reg.dir("l1").exists(), "unanchored record must be kept");
    }

    /// A malformed record naming pgid 0 (which would probe OUR own group
    /// on kill -0) is refused by the exact-field check before any probe.
    #[test]
    fn collect_bogus_pgid_refuses_before_any_probe() {
        let tmp = tempfile::tempdir().unwrap();
        let fake = FakeProcfs::new();
        let cfg = test_cfg(tmp.path().join("reg"));
        let reg = Registry::new(cfg.paths.registry.clone());
        std::fs::create_dir_all(reg.dir("l1")).unwrap();
        reg.write_pid("l1", 0, Some(1)).unwrap();
        let rc = collect(&cfg, &fake, Some("l1")).unwrap();
        assert_eq!(rc, exit::BAD);
        assert!(reg.dir("l1").exists());
        assert!(fake.sent.borrow().is_empty());
    }

    /// --all shape: only proven-dead records go; live and unprovable ones
    /// stay; the refusal surfaces in the exit code.
    #[test]
    fn collect_all_gathers_only_proven_dead() {
        let tmp = tempfile::tempdir().unwrap();
        let fake = FakeProcfs::new();
        let cfg = test_cfg(tmp.path().join("reg"));
        let reg = Registry::new(cfg.paths.registry.clone());
        // live
        std::fs::create_dir_all(reg.dir("live")).unwrap();
        reg.write_pid("live", 900_031, Some(10)).unwrap();
        fake.add(900_031, 1, 900_031, 10, "sleep", "sleep 31");
        // dead orphan
        std::fs::create_dir_all(reg.dir("dead")).unwrap();
        reg.write_pid("dead", 900_032, Some(10)).unwrap();
        // stale record
        std::fs::create_dir_all(reg.dir("stale")).unwrap();
        reg.write_pid("stale", 900_033, Some(10)).unwrap();
        fake.add(900_033, 1, 900_033, 99, "other", "someone else");
        // done with group gone
        std::fs::create_dir_all(reg.dir("fin")).unwrap();
        reg.write_pid("fin", 900_034, Some(10)).unwrap();
        std::fs::write(reg.dir("fin").join(".done"), "0\n").unwrap();
        fake.add(900_034, 1, 900_034, 10, "bash", "runner");
        fake.expire(900_034);

        let rc = collect(&cfg, &fake, None).unwrap();
        assert_eq!(rc, exit::BAD, "refusals must surface in the code");
        assert!(reg.dir("live").exists(), "live kept");
        assert!(!reg.dir("dead").exists(), "dead collected");
        assert!(reg.dir("stale").exists(), "unprovable kept");
        assert!(!reg.dir("fin").exists(), "done-and-gone collected");
        assert!(fake.sent.borrow().is_empty(), "collect never signals");
    }

    /// O-7 cell: the recorded worktree directory survives a collect —
    /// scratch ownership stays with git/hygiene, never this verb.
    #[test]
    fn collect_keeps_scratch_worktree_dir() {
        let tmp = tempfile::tempdir().unwrap();
        let fake = FakeProcfs::new();
        let cfg = test_cfg(tmp.path().join("reg"));
        let reg = Registry::new(cfg.paths.registry.clone());
        std::fs::create_dir_all(reg.dir("l1")).unwrap();
        let wt = tmp.path().join("wt-scratch");
        std::fs::create_dir_all(&wt).unwrap();
        reg.write_pid("l1", 900_040, Some(10)).unwrap();
        reg.write_meta(
            "l1",
            &[("worktree".to_owned(), wt.display().to_string())],
        )
        .unwrap();
        fake.add(900_040, 1, 900_040, 10, "sleep", "sleep 31");
        fake.expire(900_040);
        let rc = collect(&cfg, &fake, Some("l1")).unwrap();
        assert_eq!(rc, exit::OK);
        assert!(!reg.dir("l1").exists(), "record collected");
        assert!(wt.exists(), "scratch dir must never be collected");
    }

    /// The named form on an absent lane is a loud error, not a silent 0.
    #[test]
    fn collect_named_absent_lane_bails() {
        let tmp = tempfile::tempdir().unwrap();
        let fake = FakeProcfs::new();
        let cfg = test_cfg(tmp.path().join("reg"));
        let r = collect(&cfg, &fake, Some("ghost"));
        assert!(r.is_err(), "absent named lane must be loud");
    }

    // --- collect carrier removal: the guard set --------------------------

    fn git_in(dir: &Path, args: &[&str]) {
        let out = Command::new("git")
            .arg("-C")
            .arg(dir)
            .args(args)
            .env("GIT_AUTHOR_NAME", "t")
            .env("GIT_AUTHOR_EMAIL", "t@t")
            .env("GIT_COMMITTER_NAME", "t")
            .env("GIT_COMMITTER_EMAIL", "t@t")
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
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
        std::fs::write(dir.join("f"), "1\n").unwrap();
        git_in(dir, &["add", "-A"]);
        git_in(dir, &["commit", "-q", "-m", "one"]);
        git_in(dir, &["remote", "add", "origin", origin.to_str().unwrap()]);
        git_in(dir, &["push", "-q", "-u", "origin", "main"]);
    }

    fn add_worktree(work: &Path, wt: &Path) {
        git_in(work, &["worktree", "add", "--detach", wt.to_str().unwrap(), "HEAD"]);
    }

    /// A DONE record (rc=0, pgid recorded but absent from the fake table —
    /// the ESRCH proof) with launch metadata.
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

    /// A RUNNING record claiming the same worktree path.
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

    /// The happy arm: DONE + proven-dead + clean + contained carrier —
    /// the record goes AND the worktree goes.
    #[test]
    fn collect_removes_done_contained_carrier_worktree() {
        let tmp = tempfile::tempdir().unwrap();
        let fake = FakeProcfs::new();
        let work = tmp.path().join("work");
        std::fs::create_dir(&work).unwrap();
        repo_with_origin(&work);
        let wt = tmp.path().join("cwt-wt");
        add_worktree(&work, &wt);
        let cfg = test_cfg(tmp.path().join("reg"));
        let reg = Registry::new(cfg.paths.registry.clone());
        done_lane(&reg, "l1", Some(&wt), "2026-11-01T00:00:00Z", 900_140);
        let rc = collect(&cfg, &fake, Some("l1")).unwrap();
        assert_eq!(rc, exit::OK);
        assert!(!reg.dir("l1").exists(), "record collected");
        assert!(!wt.exists(), "every guard held — the carrier worktree is removed");
    }

    /// The path-reuse cell: an OLD done record must never kill a NEWER
    /// lane's live worktree — path reuse refuses by name.
    #[test]
    fn collect_refuses_newer_record_claiming_same_path() {
        let tmp = tempfile::tempdir().unwrap();
        let fake = FakeProcfs::new();
        let work = tmp.path().join("work");
        std::fs::create_dir(&work).unwrap();
        repo_with_origin(&work);
        let wt = tmp.path().join("cwt-wt");
        add_worktree(&work, &wt);
        let cfg = test_cfg(tmp.path().join("reg"));
        let reg = Registry::new(cfg.paths.registry.clone());
        done_lane(&reg, "old", Some(&wt), "2026-11-01T00:00:00Z", 900_141);
        live_lane(&reg, &fake, "new", &wt, "2026-11-02T00:00:00Z", 900_142);
        let rc = collect(&cfg, &fake, Some("old")).unwrap();
        assert_eq!(rc, exit::OK, "the record is collected; a prune refusal is a named line, not an exit code");
        assert!(!reg.dir("old").exists(), "done record collected");
        assert!(reg.dir("new").exists(), "live record untouched");
        assert!(wt.exists(), "a newer record claims the path — worktree must survive");
        let lines = carrier_prune(&reg, &fake, "old", Some("2026-11-01T00:00:00Z"), &wt);
        assert_eq!(lines.len(), 1, "{}", lines.join("\n"));
        assert!(lines[0].contains("newer-record"), "{}", lines[0]);
    }

    /// An OLD but still-LIVE record on the same path also refuses: its
    /// process could commit into the check→remove window.
    #[test]
    fn collect_refuses_older_live_record_on_same_path() {
        let tmp = tempfile::tempdir().unwrap();
        let fake = FakeProcfs::new();
        let work = tmp.path().join("work");
        std::fs::create_dir(&work).unwrap();
        repo_with_origin(&work);
        let wt = tmp.path().join("cwt-wt");
        add_worktree(&work, &wt);
        let cfg = test_cfg(tmp.path().join("reg"));
        let reg = Registry::new(cfg.paths.registry.clone());
        live_lane(&reg, &fake, "elder", &wt, "2026-10-31T00:00:00Z", 900_143);
        done_lane(&reg, "fin", Some(&wt), "2026-11-01T00:00:00Z", 900_144);
        let rc = collect(&cfg, &fake, Some("fin")).unwrap();
        assert_eq!(rc, exit::OK);
        assert!(wt.exists(), "a live sibling runs on the path — worktree must survive");
        let lines = carrier_prune(&reg, &fake, "fin", Some("2026-11-01T00:00:00Z"), &wt);
        assert_eq!(lines.len(), 1, "{}", lines.join("\n"));
        assert!(lines[0].contains("live-record"), "{}", lines[0]);
    }

    /// Dirty carrier: the record is still collected (its death is proven),
    /// but the worktree survives — dirty is a named refusal, never --force.
    #[test]
    fn collect_refuses_dirty_carrier_keeps_worktree() {
        let tmp = tempfile::tempdir().unwrap();
        let fake = FakeProcfs::new();
        let work = tmp.path().join("work");
        std::fs::create_dir(&work).unwrap();
        repo_with_origin(&work);
        let wt = tmp.path().join("cwt-wt");
        add_worktree(&work, &wt);
        std::fs::write(wt.join("uncommitted"), "wip\n").unwrap();
        let cfg = test_cfg(tmp.path().join("reg"));
        let reg = Registry::new(cfg.paths.registry.clone());
        done_lane(&reg, "l1", Some(&wt), "2026-11-01T00:00:00Z", 900_145);
        let rc = collect(&cfg, &fake, Some("l1")).unwrap();
        assert_eq!(rc, exit::OK);
        assert!(!reg.dir("l1").exists(), "record collected");
        assert!(wt.exists(), "dirty worktree must survive");
        let lines = carrier_prune(&reg, &fake, "l1", Some("2026-11-01T00:00:00Z"), &wt);
        assert_eq!(lines.len(), 1, "{}", lines.join("\n"));
        assert!(lines[0].starts_with("PRUNE-REFUSE dirty"), "{}", lines[0]);
    }

    /// Unmerged lane: HEAD is ahead of origin/main — containment refuses
    /// and nothing is removed.
    #[test]
    fn collect_refuses_not_contained_carrier_keeps_worktree() {
        let tmp = tempfile::tempdir().unwrap();
        let fake = FakeProcfs::new();
        let work = tmp.path().join("work");
        std::fs::create_dir(&work).unwrap();
        repo_with_origin(&work);
        let wt = tmp.path().join("cwt-wt");
        add_worktree(&work, &wt);
        std::fs::write(wt.join("lane-only"), "unmerged\n").unwrap();
        git_in(&wt, &["add", "-A"]);
        git_in(&wt, &["commit", "-q", "-m", "lane-only"]);
        let cfg = test_cfg(tmp.path().join("reg"));
        let reg = Registry::new(cfg.paths.registry.clone());
        done_lane(&reg, "l1", Some(&wt), "2026-11-01T00:00:00Z", 900_146);
        let rc = collect(&cfg, &fake, Some("l1")).unwrap();
        assert_eq!(rc, exit::OK);
        assert!(!reg.dir("l1").exists(), "record collected");
        assert!(wt.exists(), "unmerged worktree must survive");
    }

    /// Vanished-but-registered carrier: the record collects, the run is
    /// green, and the direct guard names the VANISHED prune class (the
    /// registration is pruned, the filesystem is never touched).
    #[test]
    fn collect_vanished_carrier_prunes_without_error() {
        let tmp = tempfile::tempdir().unwrap();
        let fake = FakeProcfs::new();
        let work = tmp.path().join("work");
        std::fs::create_dir(&work).unwrap();
        repo_with_origin(&work);
        let wt = tmp.path().join("cwt-wt");
        add_worktree(&work, &wt);
        std::fs::remove_dir_all(&wt).unwrap();
        let lines = worktree::prune_carrier(&wt, Some(&work));
        assert_eq!(lines.len(), 1, "{}", lines.join("\n"));
        assert!(lines[0].starts_with("PRUNE-VANISHED"), "{}", lines[0]);
        let cfg = test_cfg(tmp.path().join("reg"));
        let reg = Registry::new(cfg.paths.registry.clone());
        done_lane(&reg, "l1", Some(&wt), "2026-11-01T00:00:00Z", 900_147);
        let rc = collect(&cfg, &fake, Some("l1")).unwrap();
        assert_eq!(rc, exit::OK, "the vanished class is the prune class, not an error");
        assert!(!reg.dir("l1").exists(), "record collected");
    }

    /// A record that never names a worktree is untouched by the whole
    /// guard machinery: no scan, no git, no PRUNE line — record only.
    #[test]
    fn collect_record_without_worktree_gets_no_carrier_lines() {
        let tmp = tempfile::tempdir().unwrap();
        let fake = FakeProcfs::new();
        let cfg = test_cfg(tmp.path().join("reg"));
        let reg = Registry::new(cfg.paths.registry.clone());
        done_lane(&reg, "l1", None, "2026-11-01T00:00:00Z", 900_148);
        let rc = collect(&cfg, &fake, Some("l1")).unwrap();
        assert_eq!(rc, exit::OK);
        assert!(!reg.dir("l1").exists(), "record collected, nothing else touched");
    }
}
