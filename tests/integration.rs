//! Hermetic integration tests: real `setsid` processes, the real process
//! table, real flock. Each test owns a private fixture root under TMPDIR
//! and a unique namespace token, so parallel tests never see (or kill)
//! each other's processes. Every sweep/audit bound names that token —
//! a nameless sweep is refused by contract anyway.

use std::fs;
use std::os::unix::io::AsRawFd;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant, SystemTime};

const BIN: &str = env!("CARGO_BIN_EXE_lanespec");

/// Private fixture: root dir + unique namespace token.
struct Fixture {
    root: PathBuf,
    ns: String,
}

impl Fixture {
    fn new(tag: &str) -> Self {
        let nanos = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let ns = format!("it{tag}x{}x{nanos:x}", std::process::id());
        let root = std::env::temp_dir().join(format!("lanespec-it-{ns}"));
        fs::create_dir_all(root.join("lanes")).unwrap();
        Self { root, ns }
    }

    /// Write a config file with the given extra TOML (classes, sentinels).
    fn config(&self, extra: &str) -> PathBuf {
        let p = self.root.join("config.toml");
        fs::write(
            &p,
            format!(
                "[paths]\nregistry = \"{r}/lanes\"\nscratch = \"{r}\"\n[lock]\npath = \"{r}/gate.lock\"\n{extra}",
                r = self.root.display()
            ),
        )
        .unwrap();
        p
    }

    fn lane_dir(&self, name: &str) -> PathBuf {
        self.root.join("lanes").join(name)
    }

    fn script(&self, file: &str, body: &str) -> PathBuf {
        let p = self.root.join(file);
        fs::write(&p, body).unwrap();
        p
    }

    /// Write a sentinel file with an epoch mtime (mtime is never evidence
    /// — the audit must report it as a hint only).
    fn old_sentinel(&self, name: &str) -> PathBuf {
        let p = self.root.join(name);
        fs::write(&p, "x\n").unwrap();
        let st = Command::new("touch")
            .args(["-d", "@0"])
            .arg(&p)
            .status()
            .unwrap();
        assert!(st.success(), "touch failed");
        p
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

struct Run {
    code: i32,
    out: String,
    err: String,
}

fn lanespec(cfg: &Path, args: &[&str]) -> Run {
    let out = Command::new(BIN)
        .arg("--config")
        .arg(cfg)
        .args(args)
        .output()
        .expect("run lanespec");
    Run {
        code: out.status.code().unwrap_or(-1),
        out: String::from_utf8_lossy(&out.stdout).into_owned(),
        err: String::from_utf8_lossy(&out.stderr).into_owned(),
    }
}

fn lanespec_ns(cfg: &Path, ns: &str, args: &[&str]) -> Run {
    let mut all = vec!["--namespace".to_owned(), ns.to_owned()];
    all.extend(args.iter().map(|s| (*s).to_owned()));
    let refs: Vec<&str> = all.iter().map(String::as_str).collect();
    lanespec(cfg, &refs)
}

fn pgid_from(out: &str) -> u32 {
    let tail = out
        .split("pgid=")
        .nth(1)
        .unwrap_or_else(|| panic!("no pgid in launch output: {out}"));
    tail.chars()
        .take_while(|c| c.is_ascii_digit())
        .collect::<String>()
        .parse()
        .expect("pgid digits")
}

fn alive(pid: u32) -> bool {
    Path::new("/proc").join(pid.to_string()).exists()
}

/// `kill -0 -PGID`: true while ANY member keeps the group alive — no
/// leader needed (this is why leader-dead groups are killable).
/// Uses the syscall directly: procps `kill(1)` parses `-PGID` after a
/// signal option differently per distro (in the build image it probes
/// nothing — or worse, signals the CALLER's group), and the syscall is
/// exactly what `src/procfs.rs` runs in production.
fn pgid_alive(pgid: u32) -> bool {
    // SAFETY: signal 0 performs error checking only; no memory is touched.
    unsafe { libc::kill(-(pgid as libc::pid_t), 0) == 0 }
}

/// Signal a whole process group via the syscall (see `pgid_alive` for why
/// not `kill(1)`). ESRCH simply means the group is already gone.
fn kill_pgid(pgid: u32, sig: i32) {
    // SAFETY: signalling a process group; no memory is touched.
    unsafe { libc::kill(-(pgid as libc::pid_t), sig) };
}

fn cmdline_of(pid: u32) -> Option<String> {
    let raw = fs::read(Path::new("/proc").join(pid.to_string()).join("cmdline")).ok()?;
    Some(
        raw.split(|b| *b == 0)
            .map(|s| String::from_utf8_lossy(s).into_owned())
            .collect::<Vec<_>>()
            .join(" "),
    )
}

fn ppid_of(pid: u32) -> Option<u32> {
    let raw = fs::read_to_string(Path::new("/proc").join(pid.to_string()).join("stat")).ok()?;
    let close = raw.rfind(')')?;
    raw[close + 2..]
        .split_whitespace()
        .nth(1) // field 4 = ppid
        .and_then(|s| s.parse().ok())
}

fn direct_children(pid: u32) -> Vec<u32> {
    let mut out = Vec::new();
    let Ok(rd) = fs::read_dir("/proc") else {
        return out;
    };
    for e in rd.flatten() {
        let Ok(p) = e.file_name().to_string_lossy().parse::<u32>() else {
            continue;
        };
        if ppid_of(p) == Some(pid) {
            out.push(p);
        }
    }
    out
}

/// Wait for a condition; every wait has a deadline (long-drill law).
fn wait_until(what: &str, timeout: Duration, mut cond: impl FnMut() -> bool) {
    let started = Instant::now();
    while !cond() {
        if started.elapsed() >= timeout {
            panic!("TIMEOUT waiting for {what} after {}s", timeout.as_secs());
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

/// True while SOME process holds an flock on the file: a non-blocking
/// LOCK_EX attempt is refused (EWOULDBLOCK) exactly while held. This is
/// namespace-portable: /proc/locks lists no FLOCK rows outside the init
/// pid namespace (measured), but flock(2) answers the same question
/// everywhere — and it is what `lanespec unlock` itself asks first.
fn lock_held_via_flock(path: &Path) -> bool {
    let Ok(f) = std::fs::File::open(path) else {
        return false;
    };
    // SAFETY: plain flock(2) probe on an owned fd; no memory is touched.
    !unsafe { libc::flock(f.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) == 0 }
}

/// Reparented = the spawner (CLI) died and the kernel handed the runner
/// to the host's reparent target (pid 1, or the nearest subreaper whose
/// comm is configured in `reparent_targets` — under a harness like an
/// agent server that is that process, not init).
fn wait_reparented(pgid: u32, target_comm: &str) {
    let label = if target_comm.is_empty() {
        "init"
    } else {
        target_comm
    };
    wait_until(
        &format!("pgid {pgid} reparented to {label}"),
        Duration::from_secs(15),
        || {
            ppid_of(pgid)
                .is_some_and(|p| p <= 1 || (!target_comm.is_empty() && comm_of(p) == target_comm))
        },
    );
}

fn comm_of(pid: u32) -> String {
    fs::read_to_string(Path::new("/proc").join(pid.to_string()).join("comm"))
        .unwrap_or_default()
        .trim()
        .to_owned()
}

/// Discover this host's reparent target empirically: a setsid child of a
/// dying intermediate lands on the nearest live subreaper (or pid 1).
/// Returns its comm (empty for pid 1). The value goes into the test
/// config's `reparent_targets`, mirroring the production profile.
fn probe_reparent_target() -> String {
    let token = format!("lp-probe-{}-{:x}", std::process::id(), {
        SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    });
    // The intermediate bash execs setsid in the background and exits
    // right away; the kernel then reparents the grandchild. NOTE: use
    // spawn+wait, NOT output() — the output pipes make the wrapper's
    // background job exit with the pipe lifetime instead of surviving.
    let mut child = Command::new("bash")
        .arg("-c")
        .arg(format!(
            "setsid bash -c 'trap \"\" HUP; sleep 20 & wait' {token} &"
        ))
        .stdin(std::process::Stdio::null())
        .spawn()
        .expect("spawn probe intermediate");
    let st = child.wait().expect("wait probe intermediate");
    assert!(st.success(), "probe intermediate failed: {st}");
    let finder = |token: &str| {
        let Ok(rd) = fs::read_dir("/proc") else {
            return None;
        };
        rd.flatten().find_map(|e| {
            let p = e.file_name().to_string_lossy().parse::<u32>().ok()?;
            let c = cmdline_of(p)?;
            // The wrapper bash carries the token too — it execs/awaits
            // `setsid`; the adopted grandchild's cmdline never does.
            (c.contains(token) && !c.contains("setsid")).then_some(p)
        })
    };
    let mut child = None;
    wait_until("probe grandchild spawned", Duration::from_secs(10), || {
        child = finder(&token);
        child.is_some()
    });
    let child = child.unwrap();
    let ppid = ppid_of(child).expect("probe grandchild ppid");
    // Kill the probe's whole group (bash + its sleep) — its own session.
    kill_pgid(child, libc::SIGKILL);
    if ppid <= 1 {
        return String::new(); // init reparents: the pid-1 rule suffices
    }
    comm_of(ppid)
}

/// TOML for [parent-rule] with the discovered reparent target comm.
fn parent_rule_toml(target_comm: &str) -> String {
    if target_comm.is_empty() {
        String::new() // pid 1 is always a target
    } else {
        format!("[parent-rule]\nreparent_targets = [\"{target_comm}\"]\n")
    }
}

/// Best-effort cleanup at test end. The lane group is killed only while
/// its leader's cmdline still carries the fixture token — the pid-reuse
/// law: never signal a recycled pid.
struct Guard {
    lane_pgid: Option<u32>,
    token: String,
    children: Vec<Child>,
}

impl Guard {
    fn new(token: &str) -> Self {
        Self {
            lane_pgid: None,
            token: token.to_owned(),
            children: Vec::new(),
        }
    }
}

impl Drop for Guard {
    fn drop(&mut self) {
        if let Some(pgid) = self.lane_pgid
            && cmdline_of(pgid).is_some_and(|c| c.contains(&self.token))
        {
            kill_pgid(pgid, libc::SIGKILL);
        }
        for c in &mut self.children {
            let kids = direct_children(c.id());
            let _ = c.kill();
            let _ = c.wait();
            for k in kids {
                let _ = Command::new("kill").args(["-9", &k.to_string()]).status();
            }
        }
    }
}

/// Launch a lane that runs `body` and stays alive (ignores HUP).
fn launch_alive(fx: &Fixture, cfg: &Path, name: &str, body: &str, g: &mut Guard) -> u32 {
    let r = lanespec_ns(cfg, &fx.ns, &["launch", name, "--", "bash", "-c", body]);
    assert_eq!(r.code, 0, "launch failed: {}{}", r.out, r.err);
    let pgid = pgid_from(&r.out);
    g.lane_pgid = Some(pgid);
    pgid
}

/// Tagged decoy whose parent is THIS live test process — sweep must keep it.
fn spawn_live_decoy(fx: &Fixture, g: &mut Guard) -> u32 {
    // NOTE the trailing `:` — bash -c execs the last command, which would
    // drop the tag from the cmdline; the no-op keeps bash itself alive.
    let decoy = Command::new("bash")
        .arg("-c")
        .arg("trap '' HUP; sleep 30; :")
        .arg(format!("lanespec:{}:liveagent", fx.ns))
        .stdin(Stdio::null())
        .spawn()
        .unwrap();
    let pid = decoy.id();
    g.children.push(decoy);
    pid
}

#[test]
fn launch_status_wait_happy_path() {
    let fx = Fixture::new("happy");
    let cfg = fx.config("");
    let mut g = Guard::new(&fx.ns);
    let script = fx.script("work.sh", "echo hello-lane\nsleep 0.4\necho FINISHED\n");
    let r = lanespec_ns(
        &cfg,
        &fx.ns,
        &["launch", "happy", "--", "bash", script.to_str().unwrap()],
    );
    assert_eq!(r.code, 0, "{}{}", r.out, r.err);
    assert!(r.out.contains("launched lane happy"), "{}", r.out);
    g.lane_pgid = Some(pgid_from(&r.out));
    let s = lanespec_ns(&cfg, &fx.ns, &["status", "happy"]);
    assert_eq!(s.code, 0);
    assert!(s.out.contains("running"), "{}", s.out);
    let w = lanespec_ns(&cfg, &fx.ns, &["wait", "happy", "15"]);
    assert_eq!(w.code, 0, "wait rc={} out={}", w.code, w.out);
    assert!(w.out.contains("lane happy: done rc=0"), "{}", w.out);
    assert_eq!(
        fs::read_to_string(fx.lane_dir("happy").join(".done"))
            .unwrap()
            .trim(),
        "0"
    );
    let s = lanespec_ns(&cfg, &fx.ns, &["status", "happy"]);
    assert!(s.out.contains("done rc=0"), "{}", s.out);
    // The log captured the lane stdout.
    let log = fs::read_to_string(fx.lane_dir("happy").join("log")).unwrap();
    assert!(log.contains("hello-lane"), "{log}");
}

#[test]
fn wait_propagates_lane_exit_code() {
    let fx = Fixture::new("rc7");
    let cfg = fx.config("");
    let mut g = Guard::new(&fx.ns);
    let _pgid = launch_alive(&fx, &cfg, "rc7lane", "sleep 0.3; exit 7", &mut g);
    let w = lanespec_ns(&cfg, &fx.ns, &["wait", "rc7lane", "15"]);
    assert_eq!(w.code, 7, "expected lane rc 7, got {} — {}", w.code, w.out);
    assert!(w.out.contains("done rc=7"), "{}", w.out);
}

#[test]
fn launch_refuses_live_lane_and_wait_times_out() {
    let fx = Fixture::new("live");
    let cfg = fx.config("");
    let mut g = Guard::new(&fx.ns);
    let _pgid = launch_alive(&fx, &cfg, "busy", "trap '' HUP; sleep 30", &mut g);
    let r2 = lanespec_ns(
        &cfg,
        &fx.ns,
        &["launch", "busy", "--", "bash", "-c", "true"],
    );
    assert_eq!(
        r2.code, 4,
        "already-live must exit 4: {}{}",
        r2.code, r2.out
    );
    assert!(r2.err.contains("already exists"), "{}", r2.err);
    let w = lanespec_ns(&cfg, &fx.ns, &["wait", "busy", "1"]);
    assert_eq!(w.code, 124, "wait must exit 124 at deadline: {}", w.out);
    assert!(w.out.contains("TIMEOUT"), "{}", w.out);
}

#[test]
fn audit_plan_and_reap_on_reparented_runner() {
    let fx = Fixture::new("audit");
    let target = probe_reparent_target();
    let cfg = fx.config(&format!(
        "{}[[class]]\nname = \"fleet\"\ncmdline-anchor = 'lanespec:{ns}:'\n[[sentinel]]\nglob = \"{r}/*.final\"\nage-hint-hours = 6\n",
        parent_rule_toml(&target),
        ns = fx.ns,
        r = fx.root.display()
    ));
    let mut g = Guard::new(&fx.ns);
    let old = fx.old_sentinel("stale.final");
    let pgid = launch_alive(&fx, &cfg, "gone", "trap '' HUP; sleep 30", &mut g);
    wait_reparented(pgid, &target);

    let a = lanespec_ns(&cfg, &fx.ns, &["audit"]);
    assert_eq!(a.code, 3, "audit must exit 3 on debris: {}{}", a.out, a.err);
    assert!(a.out.contains("ORPHAN (reparented"), "{}", a.out);
    assert!(a.out.contains(&format!("pid {pgid}")), "{}", a.out);
    assert!(
        a.out.contains("stale.final"),
        "sentinel hint missing:\n{}",
        a.out
    );
    let j = lanespec_ns(&cfg, &fx.ns, &["audit", "--json"]);
    assert_eq!(j.code, 3);
    assert!(j.out.contains("\"orphan\": true"), "{}", j.out);

    let p = lanespec_ns(&cfg, &fx.ns, &["plan"]);
    assert_eq!(p.code, 0);
    assert!(p.out.contains("class fleet has orphan pids"), "{}", p.out);
    assert!(p.out.contains("lanespec sweep --class fleet"), "{}", p.out);
    assert!(p.out.contains("end plan"), "{}", p.out);

    let r = lanespec_ns(&cfg, &fx.ns, &["reap", "gone"]);
    assert_eq!(r.code, 0, "{}{}", r.out, r.err);
    assert!(r.out.contains("reaped pgid"), "{}", r.out);
    wait_until("reaped pgid gone", Duration::from_secs(15), || !alive(pgid));

    // Parity with the bash supervisor: reap does not clear the registry,
    // so the audit still reports the lane — now as dead-uncollected.
    let a2 = lanespec_ns(&cfg, &fx.ns, &["audit"]);
    assert_eq!(a2.code, 3);
    assert!(a2.out.contains("orphan dead-uncollected"), "{}", a2.out);

    // The collect verb closes the loop: the record's pgid is proven dead
    // (ESRCH on the group), so the record is removed and the debris goes.
    let c = lanespec_ns(&cfg, &fx.ns, &["collect", "gone"]);
    assert_eq!(c.code, 0, "{}{}", c.out, c.err);
    assert!(!fx.lane_dir("gone").exists(), "record must be gone: {}", c.out);
    let a3 = lanespec_ns(&cfg, &fx.ns, &["audit"]);
    assert_eq!(a3.code, 0, "collected debris must leave the audit: {}{}", a3.out, a3.err);
    let _ = old;
}

#[test]
fn sweep_refuses_unbounded_kills_reparented_keeps_live() {
    let fx = Fixture::new("sweep");
    let target = probe_reparent_target();
    let cfg = fx.config(&parent_rule_toml(&target));
    let mut g = Guard::new(&fx.ns);

    let u = lanespec(&cfg, &["sweep"]);
    assert_eq!(u.code, 5, "nameless sweep must exit 5: {}{}", u.code, u.err);

    // B1 regression: `--namespace ""` is a nameless sweep by another name.
    let e = lanespec_ns(&cfg, "", &["sweep"]);
    assert_eq!(
        e.code, 5,
        "empty-namespace sweep must exit 5: {}{}",
        e.code, e.err
    );

    // (a) A lane whose spawner died → reparented → must be killed.
    let pgid = launch_alive(&fx, &cfg, "gone", "trap '' HUP; sleep 30", &mut g);
    wait_reparented(pgid, &target);
    // (b) A tagged process with THIS live test process as parent → kept.
    let decoy_pid = spawn_live_decoy(&fx, &mut g);

    let s = lanespec_ns(&cfg, &fx.ns, &["sweep"]);
    assert_eq!(s.code, 0, "{}{}", s.out, s.err);
    assert!(s.out.contains("killed pgid"), "{}", s.out);
    assert!(s.out.contains("KEPT — live parent"), "{}", s.out);
    wait_until("killed lane gone", Duration::from_secs(15), || !alive(pgid));
    assert!(alive(decoy_pid), "live-parent decoy must survive the sweep");
}

#[test]
fn reap_kills_whole_group_including_grandchildren() {
    let fx = Fixture::new("group");
    let cfg = fx.config("");
    let mut g = Guard::new(&fx.ns);
    let pgid = launch_alive(&fx, &cfg, "grp", "sleep 300 & wait", &mut g);
    // The grandchild is the `sleep` whose ppid is the runner bash (pgid).
    wait_until("grandchild spawned", Duration::from_secs(10), || {
        !direct_children(pgid).is_empty()
    });
    let gc = direct_children(pgid)[0];
    let r = lanespec_ns(&cfg, &fx.ns, &["reap", "grp"]);
    assert_eq!(r.code, 0, "{}{}", r.out, r.err);
    assert!(r.out.contains("reaped pgid"), "{}", r.out);
    wait_until("runner group gone", Duration::from_secs(15), || {
        !alive(pgid)
    });
    wait_until("grandchild gone", Duration::from_secs(15), || !alive(gc));
}

#[test]
fn retry_detached_ladder_lands_then_fails() {
    let fx = Fixture::new("retry");
    let cfg = fx.config("");
    let landed = fx.root.join("landed");
    let token = format!("ready-{}", fx.ns);
    let r = lanespec_ns(
        &cfg,
        &fx.ns,
        &[
            "retry",
            "gate",
            "--cmd",
            &format!("echo landed >> {}", landed.display()),
            "--success-cmd",
            &format!("sleep 0.2; echo {token}"),
            "--attempts",
            "2",
            "--space",
            "0",
        ],
    );
    assert_eq!(r.code, 0, "{}{}", r.out, r.err);
    assert!(r.out.contains("launched detached"), "{}", r.out);
    let final_path = fx.lane_dir("gate").join(".final");
    wait_until(".final LANDED", Duration::from_secs(30), || {
        fs::read_to_string(&final_path).is_ok_and(|s| s.starts_with("LANDED "))
    });
    assert_eq!(
        fs::read_to_string(&final_path).unwrap().trim(),
        format!("LANDED {token}")
    );
    assert!(landed.exists(), "ladder cmd must have run");

    // A failing ladder lands FAILED.
    let r2 = lanespec_ns(
        &cfg,
        &fx.ns,
        &[
            "retry",
            "doomed",
            "--cmd",
            "exit 1",
            "--attempts",
            "2",
            "--space",
            "0",
        ],
    );
    assert_eq!(r2.code, 0, "{}{}", r2.out, r2.err);
    let final2 = fx.lane_dir("doomed").join(".final");
    wait_until(".final FAILED", Duration::from_secs(30), || {
        fs::read_to_string(&final2).is_ok_and(|s| s.trim() == "FAILED")
    });
}

/// M1 regression (real processes): leader runs `bash -c "sleep 20 & kill
/// $$"` in its own session — the group outlives the leader. The lane must
/// NOT be reported "stale-record — NOT killed": wait keeps waiting while
/// the group lives, and reap KILLS the group (fd-heir mission).
#[test]
fn leader_dead_group_alive_waits_then_reap_kills_group() {
    let fx = Fixture::new("ldga");
    let cfg = fx.config("");
    let pidfile = fx.root.join("leader.pid");
    let tag = format!("lanespec:{}:runner", fx.ns);
    let mut child = Command::new("setsid")
        .arg("bash")
        .arg("-c")
        .arg(format!(
            "echo $$ > '{}'; sleep 20 & kill $$",
            pidfile.display()
        ))
        .arg(&tag)
        .stdin(Stdio::null())
        .spawn()
        .expect("spawn setsid leader");
    let _ = child.wait(); // the leader kills itself almost immediately
    wait_until("leader pid recorded", Duration::from_secs(10), || {
        pidfile.exists()
    });
    let leader: u32 = fs::read_to_string(&pidfile)
        .unwrap()
        .trim()
        .parse()
        .expect("leader pid");
    wait_until("leader gone", Duration::from_secs(15), || !alive(leader));
    assert!(
        pgid_alive(leader),
        "group {leader} must still be alive via its sleep member"
    );

    // Register the lane with the (now dead) leader as recorded pgid.
    fs::create_dir_all(fx.lane_dir("grp")).unwrap();
    fs::write(
        fx.lane_dir("grp").join("meta"),
        format!("name=grp\nns={}\nkind=lane\nlauncher=999999999\n", fx.ns),
    )
    .unwrap();
    fs::write(fx.lane_dir("grp").join("pid"), format!("{leader}\n")).unwrap();

    let w = lanespec_ns(&cfg, &fx.ns, &["wait", "grp", "1"]);
    assert_eq!(
        w.code, 124,
        "leader-dead group-alive lane still RUNS — wait must not declare it DEAD: {}{}",
        w.out, w.err
    );

    let r = lanespec_ns(&cfg, &fx.ns, &["reap", "grp"]);
    assert_eq!(r.code, 0, "{}{}", r.out, r.err);
    assert!(
        r.out.contains("leader dead, group alive"),
        "reap must name the fd-heir kill: {}",
        r.out
    );
    wait_until("group killed", Duration::from_secs(15), || {
        !pgid_alive(leader)
    });
}

#[test]
fn unlock_waits_for_live_holder_then_frees() {
    let fx = Fixture::new("lock");
    let target = probe_reparent_target();
    let cfg = fx.config(&parent_rule_toml(&target));
    let lock = fx.root.join("gate.lock");
    fs::write(&lock, "").unwrap();
    let mut g = Guard::new(&fx.ns);
    // The holder is bash itself (fd 9 via redirect + flock); its sleep
    // child inherits the fd — exactly the flock-heir shape unlock must
    // classify. (flock(1) -c forwards signals, which is not what the
    // gate lock looks like when a session dies.)
    let holder = Command::new("bash")
        .arg("-c")
        .arg(format!(
            "exec 9>'{}'; flock 9; sleep 30 & wait",
            lock.display()
        ))
        .spawn()
        .unwrap();
    let hp = holder.id();
    g.children.push(holder);
    // Give the holder a moment to take the lock before the first probe.
    // Sync via a non-blocking flock(2) attempt: it observes the same fact
    // the /proc/locks table would, without depending on that table being
    // visible from this pid namespace (containers see none).
    wait_until("holder took the lock", Duration::from_secs(10), || {
        lock_held_via_flock(&lock)
    });

    // Live holder (our own child) → wait with deadline → refuse at 1s.
    let u = lanespec(&cfg, &["unlock", "1"]);
    assert_eq!(u.code, 1, "must refuse at deadline: {}{}", u.out, u.err);
    assert!(u.out.contains("held LIVE"), "{}", u.out);
    assert!(u.err.contains("TIMEOUT"), "{}", u.err);

    // Killing the holder bash leaves its sleep as a reparented fd heir:
    // unlock must then classify it by the parent-gone proof and free.
    let _ = Command::new("kill")
        .args(["-TERM", &hp.to_string()])
        .status();
    wait_until("lock freed", Duration::from_secs(30), || {
        lanespec(&cfg, &["unlock", "1"]).code == 0
    });
}

#[test]
fn hook_proof_command_runs_and_gates_debris() {
    let fx = Fixture::new("hook");
    let target = probe_reparent_target();
    let proof = fx.script(
        "proof.sh",
        &format!(
            "#!/usr/bin/env bash\necho \"ran $1\" >> \"{r}/proof-ran\"\npp=$(awk '{{ i=index($0,\")\"); split(substr($0,i+2),a,\" \"); print a[2]; exit }}' \"/proc/$1/stat\" 2>/dev/null)\nif [ \"$pp\" = 1 ]; then exit 0; fi\nif [ -n \"{t}\" ] && [ \"$(cat \"/proc/$pp/comm\" 2>/dev/null)\" = \"{t}\" ]; then exit 0; fi\nexit 1\n",
            r = fx.root.display(),
            t = target
        ),
    );
    let cfg = fx.config(&format!(
        "{}[[class]]\nname = \"hooked\"\ncmdline-anchor = 'lanespec:{ns}:'\nproof-command = [\"/bin/bash\", \"{p}\", \"{{pid}}\"]\nrecovery-step = \"report hooked pid {{pid}} to the orchestrator\"\n",
        parent_rule_toml(&target),
        ns = fx.ns,
        p = proof.display()
    ));
    let mut g = Guard::new(&fx.ns);
    // A: reparented runner — proof (reparent target) must hold → debris.
    let pgid = launch_alive(&fx, &cfg, "orph", "trap '' HUP; sleep 30", &mut g);
    wait_reparented(pgid, &target);
    // B: same tag, live parent — proof must NOT hold.
    let decoy_pid = spawn_live_decoy(&fx, &mut g);

    let a = lanespec_ns(&cfg, &fx.ns, &["audit"]);
    assert_eq!(a.code, 3, "{}{}", a.out, a.err);
    assert!(a.out.contains(&format!("pid {pgid}: ORPHAN")), "{}", a.out);
    assert!(a.out.contains("live parent"), "{}", a.out);
    let ran = fs::read_to_string(fx.root.join("proof-ran")).expect("proof hook must have run");
    assert!(ran.contains(&format!("ran {pgid}")), "{ran}");
    assert!(ran.contains(&format!("ran {decoy_pid}")), "{ran}");

    let p = lanespec_ns(&cfg, &fx.ns, &["plan"]);
    assert!(p.out.contains("report hooked pid"), "{}", p.out);
    assert!(p.out.contains(&format!("pid {pgid}")), "{}", p.out);
}

/// N1 regression (real processes): two concurrent `retry` invocations with
/// the SAME lane name must produce exactly ONE ladder — the loser yields.
/// A second ladder must never start under the first, and the running
/// ladder's `.final` ownership is never reclaimed.
#[test]
fn retry_same_name_concurrent_exactly_one_ladder() {
    let fx = Fixture::new("retryrace");
    let cfg = fx.config("");
    let started = fx.root.join("started");
    let cmd = format!("touch {}; sleep 30", started.display());
    let mut g = Guard::new(&fx.ns);
    let launch = || {
        Command::new(BIN)
            .arg("--config")
            .arg(&cfg)
            .args(["--namespace", &fx.ns])
            .args([
                "retry",
                "race",
                "--cmd",
                &cmd,
                "--attempts",
                "2",
                "--space",
                "0",
            ])
            .output()
            .unwrap()
    };
    // Two processes racing for the same lane name at the same time.
    let (o1, o2) = std::thread::scope(|s| {
        let h1 = s.spawn(launch);
        let h2 = s.spawn(launch);
        (h1.join().unwrap(), h2.join().unwrap())
    });
    let s1 = String::from_utf8_lossy(&o1.stdout).into_owned();
    let s2 = String::from_utf8_lossy(&o2.stdout).into_owned();
    assert!(o1.status.success() && o2.status.success(), "{s1}\n{s2}");
    let outs = [s1.clone(), s2.clone()];
    let launched = outs
        .iter()
        .filter(|s| s.contains("launched detached"))
        .count();
    let yielded = outs
        .iter()
        .filter(|s| s.contains("yielding to live retry"))
        .count();
    assert_eq!(
        (launched, yielded),
        (1, 1),
        "exactly one ladder owner and one yielder expected, got: {outs:?}"
    );

    // The ladder started, and exactly ONE --inline ladder process exists.
    wait_until("ladder attempt started", Duration::from_secs(20), || {
        started.exists()
    });
    let inline_procs = || {
        let Ok(rd) = fs::read_dir("/proc") else {
            return 0;
        };
        rd.flatten()
            .filter(|e| {
                e.file_name()
                    .to_string_lossy()
                    .chars()
                    .all(|c| c.is_ascii_digit())
                    && cmdline_of(e.file_name().to_string_lossy().parse().unwrap_or(0))
                        .is_some_and(|c| c.contains("--inline") && c.contains(&fx.ns))
            })
            .count()
    };
    assert_eq!(
        inline_procs(),
        1,
        "exactly one inline ladder process must exist"
    );

    // A third invocation while the ladder lives: yields (same lane), rc 0.
    let r3 = lanespec_ns(
        &cfg,
        &fx.ns,
        &[
            "retry",
            "race",
            "--cmd",
            &cmd,
            "--attempts",
            "2",
            "--space",
            "0",
        ],
    );
    assert_eq!(r3.code, 0, "{}{}", r3.out, r3.err);
    assert!(r3.out.contains("yielding to live retry race"), "{}", r3.out);
    assert_eq!(
        inline_procs(),
        1,
        "the third invocation must not spawn a ladder"
    );

    // Cleanup: kill the ladder's own session (its cmdline carries our token).
    let pidfile = fs::read_to_string(fx.lane_dir("race").join("pid")).unwrap();
    let pgid: u32 = pidfile.split_whitespace().next().unwrap().parse().unwrap();
    g.lane_pgid = Some(pgid);
}

/// N2 regression (real processes): `retry --inline` records the CALLER's
/// pgid. A `reap` invoked INSIDE that same session must REFUSE — the
/// recorded group contains the caller's own lineage — and signal nothing:
/// the ladder must survive to land its `.final`.
#[test]
fn reap_refuses_inline_pgid_inside_callers_session() {
    let fx = Fixture::new("inlreap");
    let cfg = fx.config("");
    let script = fx.script(
        "session.sh",
        &format!(
            r#"BIN="$1"; CFG="$2"
d={r}/lanes/inl
"$BIN" --config "$CFG" retry inl --cmd "sleep 3; echo tok" --attempts 1 --space 0 --inline > "{r}/ladder.log" 2>&1 &
lp=$!
i=0
while [ ! -f "$d/pid" ]; do
  i=$((i+1))
  if [ "$i" -gt 200 ]; then echo TIMEOUT > "{r}/reap.out"; echo 99 > "{r}/reap.rc"; wait $lp; exit 1; fi
  sleep 0.05
done
"$BIN" --config "$CFG" reap inl > "{r}/reap.out" 2>&1
echo $? > "{r}/reap.rc"
wait $lp
echo done > "{r}/ladder.done"
"#,
            r = fx.root.display()
        ),
    );
    let mut g = Guard::new(&fx.ns);
    let child = Command::new("setsid")
        .arg("bash")
        .arg(&script)
        .arg(BIN)
        .arg(&cfg)
        .stdin(Stdio::null())
        .spawn()
        .expect("spawn session wrapper");
    g.children.push(child);
    wait_until("session script finished", Duration::from_secs(60), || {
        fx.root.join("ladder.done").exists()
    });
    g.children
        .last_mut()
        .expect("child present")
        .wait()
        .expect("wait session wrapper");
    let rc = fs::read_to_string(fx.root.join("reap.rc")).unwrap();
    let out = fs::read_to_string(fx.root.join("reap.out")).unwrap();
    assert_eq!(
        rc.trim(),
        "1",
        "reap inside the recorded lineage must refuse, out: {out}"
    );
    assert!(
        out.contains("refusing to reap") && out.contains("our own process group or an ancestor's"),
        "loud lineage refusal expected, got: {out}"
    );
    assert_eq!(
        fs::read_to_string(fx.lane_dir("inl").join(".final"))
            .unwrap()
            .trim(),
        "LANDED rc=0",
        "the refused reap must leave the ladder alive to land .final"
    );
}

/// The built-in manual: every known topic prints text and exits 0; the index
/// prints with no topic and with the `topics` alias; an unknown topic exits 64
/// (usage, never the debris code 3). No run reads config, opens the registry,
/// or touches the process table — they run with no `--config`, and a bogus
/// `--config` is never opened.
#[test]
fn help_topics_exit_zero_unknown_exits_usage() {
    for topic in ["commands", "exit-codes", "configuration", "diagnostics"] {
        let o = Command::new(BIN).args(["help", topic]).output().unwrap();
        assert_eq!(o.status.code(), Some(0), "help {topic} must exit 0");
        assert!(!o.stdout.is_empty(), "help {topic} must print text");
    }
    for args in [vec!["help"], vec!["help", "topics"]] {
        let o = Command::new(BIN).args(&args).output().unwrap();
        assert_eq!(o.status.code(), Some(0), "help index must exit 0");
        assert!(
            String::from_utf8_lossy(&o.stdout).contains("topics:"),
            "index must list topics"
        );
    }
    // A bogus --config must not be opened by help: a known topic still exits 0.
    let o = Command::new(BIN)
        .args(["--config", "/nonexistent/lanespec.toml", "help", "commands"])
        .output()
        .unwrap();
    assert_eq!(o.status.code(), Some(0), "help must ignore config");
    // An unknown topic is a usage error, never a verdict code: 64, not 3.
    // The debris code keeps exactly one meaning for every consumer,
    // including a `wait` that re-surfaces a lane's recorded rc.
    let o = Command::new(BIN)
        .args(["help", "nonexistent-topic"])
        .output()
        .unwrap();
    assert_eq!(o.status.code(), Some(64), "unknown help topic must exit 64");
    assert!(
        String::from_utf8_lossy(&o.stderr).contains("unknown help topic"),
        "unknown topic must name the problem on stderr"
    );
}

/// F-1 of the decision-check (a wrong command line exited clap's own,
/// undocumented 2): every parser rejection exits the documented USAGE code 64
/// with advice on stderr, while --help and --version still print and exit 0.
#[test]
fn unknown_command_line_exits_usage_64() {
    for args in [
        vec!["audit", "--bogus-flag"],
        vec!["--bogus-global"],
        vec!["no-such-command"],
        vec!["wait"], // missing required value
    ] {
        let o = Command::new(BIN).args(&args).output().unwrap();
        assert_eq!(
            o.status.code(),
            Some(64),
            "{args:?} must exit usage 64, stderr: {}",
            String::from_utf8_lossy(&o.stderr)
        );
        assert!(
            !o.stderr.is_empty(),
            "{args:?} must explain the mistake on stderr"
        );
    }
    // The parser's own help and version print on stdout and exit 0.
    for args in [vec!["--help"], vec!["--version"]] {
        let o = Command::new(BIN).args(&args).output().unwrap();
        assert_eq!(o.status.code(), Some(0), "{args:?} must exit 0");
        assert!(!o.stdout.is_empty(), "{args:?} must print on stdout");
    }
}

/// Taxonomy retrofit (family exit class 70): a named config file that
/// cannot be read is an operational-precondition failure — exit 70, never a
/// verdict code. A missing `--config` file and a missing `LANESPEC_CONFIG`
/// file answer alike for every command that resolves config (`help` resolves
/// none). The generic refusal code 1 stays what it always was: a refusal
/// while working, not "the environment is not there".
#[test]
fn missing_named_config_exits_operational_70() {
    let missing = "/nonexistent-conformance-missing.lanespec.toml";
    for args in [
        vec!["--config", missing, "status"],
        vec!["--config", missing, "audit"],
    ] {
        let o = Command::new(BIN).args(&args).output().unwrap();
        assert_eq!(
            o.status.code(),
            Some(70),
            "{args:?} must exit operational 70, stderr: {}",
            String::from_utf8_lossy(&o.stderr)
        );
        assert!(
            String::from_utf8_lossy(&o.stderr).contains("nonexistent-conformance-missing"),
            "{args:?} must name the unreadable config on stderr"
        );
    }
    // A LANESPEC_CONFIG pointing at a missing file is the same refusal.
    let o = Command::new(BIN)
        .args(["status"])
        .env("LANESPEC_CONFIG", missing)
        .output()
        .unwrap();
    assert_eq!(
        o.status.code(),
        Some(70),
        "env-named missing config must exit 70, stderr: {}",
        String::from_utf8_lossy(&o.stderr)
    );
}

/// F-2 of the decision-check (the manual can lie): the `exit-codes` topic must
/// enumerate exactly the codes `lanespec::exit` defines — every constant
/// present, no phantom code documented.
#[test]
fn exit_codes_topic_enumerates_the_contract() {
    let documented: Vec<i32> = lanespec::help::EXIT_CODES
        .lines()
        .filter_map(|line| {
            let head: String = line.chars().take_while(|c| !c.is_alphabetic()).collect();
            head.trim().parse().ok()
        })
        .collect();
    let contract = [
        lanespec::exit::OK,
        lanespec::exit::BAD,
        lanespec::exit::DEBRIS,
        lanespec::exit::USAGE,
        lanespec::exit::OPERATIONAL,
        lanespec::exit::ALREADY_LIVE,
        lanespec::exit::MISSING_BOUND,
        lanespec::exit::TIMEOUT,
    ];
    for code in contract {
        assert!(
            documented.contains(&code),
            "exit-codes topic omits contract code {code}"
        );
    }
    for code in &documented {
        assert!(
            contract.contains(code),
            "exit-codes topic documents code {code} that exit.rs does not define"
        );
    }
}

// --- collect: registry-record collection for proven-dead lanes -------------

/// The gap this verb closes: after the group is proven dead, the record
/// row used to stay forever. collect removes it; status then shows no row.
#[test]
fn collect_removes_dead_record_and_status_shows_no_row() {
    let fx = Fixture::new("col1");
    let cfg = fx.config("");
    let mut g = Guard::new(&fx.ns);
    let pgid = launch_alive(&fx, &cfg, "deadl", "trap '' HUP; sleep 30", &mut g);
    let r = lanespec_ns(&cfg, &fx.ns, &["reap", "deadl"]);
    assert_eq!(r.code, 0, "{}{}", r.out, r.err);
    wait_until("reaped pgid gone", Duration::from_secs(15), || !pgid_alive(pgid));

    // Before collect: the forever-row the fix removes.
    let s = lanespec_ns(&cfg, &fx.ns, &["status"]);
    assert!(
        s.out.contains("lane deadl:") && s.out.contains("orphan dead-uncollected"),
        "pre-collect status must show the row: {}",
        s.out
    );

    let c = lanespec_ns(&cfg, &fx.ns, &["collect", "deadl"]);
    assert_eq!(c.code, 0, "{}{}", c.out, c.err);
    assert!(!fx.lane_dir("deadl").exists(), "record must be collected");

    // No row in the listing; the named form reports the lane absent.
    let s2 = lanespec_ns(&cfg, &fx.ns, &["status"]);
    assert!(!s2.out.contains("lane deadl"), "status after collect: {}", s2.out);
    let s3 = lanespec_ns(&cfg, &fx.ns, &["status", "deadl"]);
    assert_eq!(s3.code, 1, "collected lane must answer as absent: {}{}", s3.out, s3.err);
}

/// A live lane's record is NEVER collected: refusal, record kept, nonzero.
#[test]
fn collect_refuses_live_lane_and_keeps_record() {
    let fx = Fixture::new("col2");
    let cfg = fx.config("");
    let mut g = Guard::new(&fx.ns);
    let pgid = launch_alive(&fx, &cfg, "busy", "trap '' HUP; sleep 30", &mut g);
    let c = lanespec_ns(&cfg, &fx.ns, &["collect", "busy"]);
    assert_ne!(c.code, 0, "live lane must be refused, got 0: {}", c.out);
    assert!(c.out.contains("refus") || c.err.contains("refus"), "{}{}", c.out, c.err);
    assert!(fx.lane_dir("busy").exists(), "live record must survive");
    assert!(pgid_alive(pgid), "collect must never signal the lane");
}

/// --all collects ONLY the proven-dead: the done-and-gone lane goes, the
/// live lane stays, and the refusal is visible in the exit code.
#[test]
fn collect_all_gathers_only_proven_dead() {
    let fx = Fixture::new("col3");
    let cfg = fx.config("");
    let mut g = Guard::new(&fx.ns);
    // A lane that finished: .done landed and the runner's group is gone.
    let fpgid = launch_alive(&fx, &cfg, "fin", "sleep 0.3", &mut g);
    wait_until("fin .done", Duration::from_secs(20), || {
        fx.lane_dir("fin").join(".done").exists()
    });
    wait_until("fin group gone", Duration::from_secs(20), || !pgid_alive(fpgid));
    let _bpgid = launch_alive(&fx, &cfg, "busy", "trap '' HUP; sleep 30", &mut g);

    let c = lanespec_ns(&cfg, &fx.ns, &["collect", "--all"]);
    assert_ne!(c.code, 0, "the live refusal must surface in the code: {}", c.out);
    assert!(!fx.lane_dir("fin").exists(), "done-and-gone record must be collected");
    assert!(fx.lane_dir("busy").exists(), "live record must be kept");
}

/// Scratch is never collected: the recorded worktree dir survives the
/// collect (its removal belongs to git worktree + the hygiene tool, whose
/// rules need live-reference proofs — mtime is never evidence).
#[test]
fn collect_never_touches_scratch_worktree() {
    let fx = Fixture::new("col4");
    let cfg = fx.config("");
    let mut g = Guard::new(&fx.ns);
    let wt = fx.root.join("wt-collect-scratch");
    fs::create_dir_all(&wt).unwrap();
    let r = lanespec_ns(
        &cfg,
        &fx.ns,
        &["launch", "scr", "--worktree", wt.to_str().unwrap(), "--", "bash", "-c", "trap '' HUP; sleep 30"],
    );
    assert_eq!(r.code, 0, "{}{}", r.out, r.err);
    let pgid = pgid_from(&r.out);
    g.lane_pgid = Some(pgid);
    let r = lanespec_ns(&cfg, &fx.ns, &["reap", "scr"]);
    assert_eq!(r.code, 0, "{}{}", r.out, r.err);
    wait_until("reaped pgid gone", Duration::from_secs(15), || !pgid_alive(pgid));

    let c = lanespec_ns(&cfg, &fx.ns, &["collect", "scr"]);
    assert_eq!(c.code, 0, "{}{}", c.out, c.err);
    assert!(!fx.lane_dir("scr").exists(), "record collected");
    assert!(wt.exists(), "scratch dir must never be collected");
}

/// Usage shape: exactly one of <name> or --all — anything else is 64,
/// never a verdict code.
#[test]
fn collect_usage_shapes_exit_64() {
    let fx = Fixture::new("col5");
    let cfg = fx.config("");
    let a = lanespec_ns(&cfg, &fx.ns, &["collect"]);
    assert_eq!(a.code, 64, "{}{}", a.out, a.err);
    let b = lanespec_ns(&cfg, &fx.ns, &["collect", "x", "--all"]);
    assert_eq!(b.code, 64, "{}{}", b.out, b.err);
}
