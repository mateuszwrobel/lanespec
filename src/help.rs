//! The built-in manual: `lanespec help [topic]`.
//!
//! Pure output only. This module reads no config file, opens no registry or
//! lock, inspects no process table, and makes no network request. The caller
//! dispatches `help` before any configuration is resolved, so a help run has
//! no side effects. A topic that exists prints its text and exits 0; an unknown
//! topic is an error the caller maps to `exit::USAGE` (64) — a topic typo is a
//! usage error, never a verdict code.

/// The topic index printed by `lanespec help` with no topic, and by
/// `lanespec help topics`.
pub const HELP: &str = "\
usage: lanespec help [topic]
lanespec built-in manual: the commands, the exit-code contract, the
lanespec.toml configuration, and the diagnostics catalog.

topics:
  commands       every command with its purpose and flags
  exit-codes     what every exit code means and which command emits it
  configuration  the lanespec.toml file and its sections
  diagnostics    every failure notice: meaning, cause, and the fix

run 'lanespec help <topic>' for a topic
";

/// The commands topic: every subcommand with its purpose and flags.
pub const COMMANDS: &str = "\
# lanespec help commands — the command surface
usage: lanespec [global flags] <command> [args]

global flags:
  --config PATH     Config file (lanespec.toml); also LANESPEC_CONFIG env.
  --namespace NS    Namespace tag for registry lanes and sweep bounds.

commands:
  launch <name> [--worktree PATH] -- CMD...
             Start CMD detached in its own process group with a registry entry.
  status [name]
             Liveness per lane: running | done rc=N | stale-record | orphan.
  wait <name> [timeout]
             Poll the .done sentinel with a deadline; exit with the lane rc, 124
             on timeout.
  reap <name>
             TERM, bounded settle, then KILL the whole group; print the worktree
             verdict.
  collect <name> | collect --all
             Remove the registry record of a lane whose death the process table
             proves (group answered ESRCH, or .done with the group gone). Live,
             leader-dead-group-alive and stale records are refused and kept; the
             exit code shows a refusal. collect signals nothing. When the record
             names a registered carrier worktree and every guard holds — no
             newer or live record claims the path, the worktree is clean, and
             its HEAD is contained in origin/main — collect also removes that
             worktree: plain `git worktree remove`, never --force, one named
             PRUNE-* line per removal or refusal. Scratch dirs are never touched.
  audit [--json] [--repo PATH]
             Dump debris: orphan lanes, class fleets, lock holders, ahead-count,
             stale worktrees, sentinel age hints. Exit 3 on debris.
  plan [--json] [--repo PATH]
             Ordered recovery steps for the debris the audit finds. Exit 0.
  sweep [--class NAME]
             Kill only parent-gone-proven processes; --namespace/--class required.
  unlock [deadline]
             Resolve gate-lock holders: await live, kill orphan chains, refuse races.
  retry <name> --cmd CMD [--success-cmd CMD] [--attempts N] [--space S] [--inline]
             Detached retry ladder: yield-guard, spaced attempts, .final sentinel.
  help [topic]
             Print this built-in manual. 'help <topic>' prints one topic.
";

/// The exit-codes topic: the contract every command obeys.
pub const EXIT_CODES: &str = "\
# lanespec help exit-codes — the exit-code contract
Scripts branch on these numbers.

   0   Success, or nothing to report. Also: status and plan exit 0 even when
       they REPORT debris; only audit encodes debris in the code.
   1   Generic failure or refusal: bad input, unknown lane or class, a
       wait-timeout while a live holder refused, a collect refusal (the
       record is kept), or an unreadable process table.
   3   audit found debris (an orphan lane, class fleet, lock holder, or stale
       worktree). Only audit emits this code; it has exactly one meaning.
   4   launch refused: the lane already exists (live or done). Reap it first.
   5   sweep refused: no --namespace or --class bound was given, or a given
       bound was empty.
  64   Usage error: the command line itself is wrong (unknown command, unknown
       flag, missing value), help named a topic the manual does not have, or
       collect was given <name> and --all together or neither. A usage mistake
       is never a verdict code. --help and --version print and exit 0.
  70   Operational precondition: a config file named by --config or
       LANESPEC_CONFIG could not be read (missing or unreadable), so the run
       never started. This is not a verdict: no lane was examined, nothing
       was refused while working. A wrapper must never read 70 as drift.
 124   Deadline reached: wait while the lane still runs, or sweep while matched
       candidates still survived their kills.

wait also exits with the lane's recorded .done code when the lane finished.
";

/// The configuration topic: the lanespec.toml file.
pub const CONFIGURATION: &str = "\
# lanespec help configuration — the lanespec.toml file
The config is TOML with a closed schema: unknown keys are refused. Resolution
order: the --config flag, then the LANESPEC_CONFIG environment variable, then
built-in defaults. Every section is optional.

  [paths]
    registry = \"...\"   One directory per lane. Default: /var/tmp/lanes.
    scratch = \"...\"    Scratch space for detached launches and ladder logs.
                       Default: /var/tmp.

  [lock]
    path = \"...\"       The gate lock whose holders audit reports and unlock
                       resolves. Default: /var/tmp/lanespec.lock.

  [parent-rule]
    reparent-targets = [...]   Names a dead spawner's children get reparented
                       to, besides pid 1 (always a target). Default: [\"systemd\"].
    max-ancestry-depth = N     Ancestry chain length the orphan proof walks.
                       Default: 8.

  [[class]]
    name = \"...\"             Class id used by sweep --class and audit output.
    cmdline-anchor = \"...\"    A regex matched against the cmdline, anchored by
                       the tool. A match-everything anchor (empty or bare '.*')
                       is refused at load, so a sweep can never fan out to all.
    proof-command = [...]      Optional external proof (argv, no shell) with
                       {pid} and {cmdline} placeholders; exit 0 means it holds.
    recovery_step = \"...\"      Optional plan step with {pid}, {pgid}, {name}.

  [[sentinel]]
    glob = \"...\"             Sentinel glob reported as an age HINT by audit.
    age-hint-hours = N         Age past which audit prints a hint (never proof).

mtime is never evidence for a kill, so no section can declare it.
";

/// The diagnostics topic: what each failure notice means and the fix.
pub const DIAGNOSTICS: &str = "\
# lanespec help diagnostics — what each failure notice means and the fix
  launch refused: lane already exists        (exit 4)
      A lane with this name is live or recorded done. Run 'lanespec reap <name>'
      first, then launch again.
  audit reports debris                       (exit 3)
      The audit found an orphan lane, an orphan class fleet, an orphan lock
      holder, or a stale worktree. Run 'lanespec plan' for ordered steps, then
      reap or sweep as they name.
  wait: lane died without .done              (exit 1, DEAD notice)
      The lane's process is gone but left no .done sentinel. Run 'lanespec reap'
      or 'lanespec audit'; once the group is proven gone, 'lanespec collect
      <name>' removes the record so the row stops showing.
  wait: deadline reached                     (exit 124)
      The deadline passed while the lane still ran. Raise the timeout or reap.
  sweep refused: no bound                    (exit 5)
      A nameless sweep is refused by contract. Pass --namespace or --class.
  reap refused: recorded pgid is my own group (exit 1)
      The lane's process group IS the caller's group or an ancestor's (the shape
      an inline retry record has). Reap it from outside that session.
  collect refused: lane still alive          (exit 1)
      The record's process group is alive (or its leader is dead but fd-heir
      members hold the group). Run 'lanespec reap <name>' first; collect never
      signals anything itself.
  collect refused: death not proven          (exit 1)
      The record is stale (pid recycled, or a legacy record without a start_time)
      or names no pgid at all. Nothing in the process table can prove this lane
      died, so the record stays for inspection — mtime and age are never proof.
  config could not be read                   (exit 70)
      --config or LANESPEC_CONFIG names a file that cannot be read: missing,
      a directory, or no permission. Point it at a real lanespec.toml, or
      unset it to take the built-in defaults. Nothing ran: 70 is never a
      verdict about a lane.
  config refuses to load: match-everything anchor
      A class cmdline-anchor is empty, whitespace-only, or a bare '.*'. Declare a
      specific, anchored pattern so a sweep cannot fan out to every process.
  retry detached returns 0 (yielded)
      The ladder yielded to a live sibling lane or a ladder already running
      under the same name. The running ladder owns the .final sentinel.
";

/// The topics the manual has, in index order. `help topics` and `help` with no
/// argument print the index; every name here prints its own page.
pub const TOPICS: [&str; 4] = ["commands", "exit-codes", "configuration", "diagnostics"];

/// Print one topic. `None` prints the index. An unknown name is an error the
/// caller maps to `exit::USAGE`. This function only writes to stdout.
pub fn run(topic: Option<&str>) -> Result<(), String> {
    let Some(topic) = topic else {
        print!("{HELP}");
        return Ok(());
    };
    match topic {
        "topics" => print!("{HELP}"),
        "commands" => print!("{COMMANDS}"),
        "exit-codes" => print!("{EXIT_CODES}"),
        "configuration" => print!("{CONFIGURATION}"),
        "diagnostics" => print!("{DIAGNOSTICS}"),
        other => {
            return Err(format!(
                "unknown help topic: {other}\nvalid topics: {}\nrun 'lanespec help'",
                TOPICS.join(", ")
            ));
        }
    }
    Ok(())
}
