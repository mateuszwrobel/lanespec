# lanespec capability matrix

Every command, the exit code it produces, and the test that proves it. This
page is a map of the contract, not a restatement of behavior: the binary owns
each claim (`lanespec help commands`, `lanespec help exit-codes`), and this
table points at the golden test that pins it.

## Commands

| Command | What it does |
|---------|--------------|
| `launch NAME -- CMD` | Start CMD detached in its own session with a registry entry. |
| `status [NAME]` | Liveness per lane: `running`, `done rc=N`, `stale-record`, `orphan`. |
| `wait NAME [SECS]` | Poll `.done` with a deadline; exit with the lane rc, 124 on timeout. |
| `reap NAME` | TERM, bounded settle, KILL the whole group; print the worktree verdict. |
| `collect NAME \| --all` | Remove the registry record of a lane whose death the process table proves; live, leader-dead-group-alive and stale records are refused and kept. Never signals. A collected record's registered carrier worktree is also removed when every guard holds — no newer or live record claims the path, the worktree is clean, its HEAD is contained in `origin/main` — via plain `git worktree remove` (never `--force`), one named `PRUNE-*` line per removal or refusal. Unregistered scratch dirs are never touched. |
| `audit [--json]` | Dump debris: orphan lanes, class fleets, lock holders, stale worktrees. Exit 3 on debris. |
| `plan [--json]` | Ordered recovery steps for the debris the audit finds. |
| `sweep [--class C]` | Kill only parent-gone-proven processes; a bound is required. |
| `unlock [DEADLINE]` | Resolve gate-lock holders: await live, kill orphan chains, refuse races. |
| `retry NAME --cmd CMD` | Detached retry ladder: yield-guard, spaced attempts, `.final` sentinel. |
| `help [topic]` | Print the built-in manual (`commands`, `exit-codes`, `configuration`, `diagnostics`). |

## Command × exit code × tested-in

| Command | Exit | Meaning | Proven by |
|---------|-----:|---------|-----------|
| `launch` (fresh) | 0 | Lane started, registry entry written. | `launch_status_wait_happy_path` |
| `launch` (taken name) | 4 | The lane name already exists (live or done). | `launch_refuses_live_lane_and_wait_times_out`, `retry_same_name_concurrent_exactly_one_ladder` |
| `status` | 0 | Liveness printed, debris report does not encode in the exit code. | `launch_status_wait_happy_path` |
| `wait` (lane rc) | lane rc | `.done` reached; the recorded code propagates. | `wait_propagates_lane_exit_code` |
| `wait` (deadline) | 124 | Deadline reached while the lane still runs. | `launch_refuses_live_lane_and_wait_times_out`, `leader_dead_group_alive_waits_then_reap_kills_group` |
| `reap` (group gone) | 0 | Whole group killed, verdict printed. | `reap_kills_whole_group_including_grandchildren`, `audit_plan_and_reap_on_reparented_runner` |
| `reap` (own lineage) | 1 | Refused: the recorded pgid is the caller's own or an ancestor group. | `reap_refuses_inline_pgid_inside_callers_session` |
| `collect` (proven dead) | 0 | Record removed; the row leaves `status` and the audit stops finding it. | `collect_removes_dead_record_and_status_shows_no_row`, `audit_plan_and_reap_on_reparented_runner` |
| `collect` (refused) | 1 | Live, leader-dead-group-alive, stale or unanchored record: kept, nothing signalled, nothing removed. | `collect_refuses_live_lane_and_keeps_record`, `collect_all_gathers_only_proven_dead` |
| `collect` (scratch) | 0 | A proven-dead lane's recorded dir that is not a registered worktree survives the collect (`PRUNE-SKIP unregistered`) — git/hygiene own it. | `collect_never_touches_scratch_worktree`, `prune_skips_plain_dir_as_unregistered` |
| `collect` (carrier removed) | 0 | A done lane's registered carrier worktree — clean, contained in `origin/main`, no newer or live record claiming the path — is removed (`PRUNE-REMOVED`, never `--force`). | `collect_removes_done_contained_carrier_worktree`, `prune_clean_contained_carrier_removed_and_unpinned` |
| `collect` (carrier refused) | 0 | A failing guard keeps the worktree with one named refusal line: newer/live record on the path, dirty, not contained, main checkout. | `collect_refuses_newer_record_claiming_same_path`, `collect_refuses_older_live_record_on_same_path`, `collect_refuses_dirty_carrier_keeps_worktree`, `collect_refuses_not_contained_carrier_keeps_worktree`, `prune_refuses_main_checkout` |
| `collect` (carrier vanished) | 0 | Recorded path absent: registration pruned, named `PRUNE-VANISHED` line, never the filesystem. | `collect_vanished_carrier_prunes_without_error`, `prune_vanished_carrier_prunes_registration` |
| `collect` (usage shape) | 64 | `<name>` and `--all` given together or neither. | `collect_usage_shapes_exit_64` |
| `audit` (clean) | 0 | No debris. | `launch_status_wait_happy_path` |
| `audit` (debris) | 3 | Orphan lane/fleet/lock holder or stale worktree found. | `audit_plan_and_reap_on_reparented_runner`, `hook_proof_command_runs_and_gates_debris` |
| `plan` | 0 | Ordered steps printed; debris is reported, not encoded. | `audit_plan_and_reap_on_reparented_runner` |
| `sweep` (unbounded) | 5 | No `--class`/`--namespace` bound, or an empty bound. | `sweep_refuses_unbounded_kills_reparented_keeps_live` |
| `sweep` (bounded) | 0 or 124 | Proven orphans killed; 124 when candidates survived the kill loop. | `sweep_refuses_unbounded_kills_reparented_keeps_live` |
| `unlock` | 0 | Lock freed: live holder awaited, orphan chain killed. | `unlock_waits_for_live_holder_then_frees` |
| `retry` (lands) | 0 | Attempt verified; `.final` carries the landed token. | `retry_detached_ladder_lands_then_fails` |
| `retry` (yield) | 0 | A live sibling ladder owns the lane; this run yields. | `retry_same_name_concurrent_exactly_one_ladder` |
| `help <topic>` | 0 | A known topic printed its page; the index prints with no topic. | `help_topics_exit_zero_unknown_exits_usage` |
| `help <unknown>` | 64 | The named topic is not in the manual — a usage error, never a verdict code. | `help_topics_exit_zero_unknown_exits_usage` |
| (wrong command line) | 64 | Unknown command, unknown flag, or missing value; the parser's advice goes to stderr. | `unknown_command_line_exits_usage_64` |
| (config unreadable) | 70 | `--config` / `LANESPEC_CONFIG` names a file that cannot be read — an operational precondition, answered before any command runs; never a verdict. | `missing_named_config_exits_operational_70` |

## Lifecycle family

The lifecycle verbs carry kill-safety codes of their own. They are verdicts
about signalling, not taxonomy classes, and stay distinct so a wrapper can
never read a safety refusal or a timeout as drift or constraint:

| Code | Meaning | Emitted by |
|-----:|---------|------------|
| 3    | Debris found: an orphan lane, class fleet, lock holder, or stale worktree. | `audit` |
| 4    | Launch refused: the lane already exists — a safety refusal, not a usage error. | `launch` |
| 5    | Sweep refused: no namespace/class bound — nothing was signalled. | `sweep` |
| 124  | Deadline reached while processes still ran. | `wait`, `sweep` |

The family conformance suite drives only the pure surfaces (`help`,
`--version`, the verdict reads `status` and `audit`) and skips the lifecycle
verbs by name: their kill-safety proofs are this tool's own suite in
`tests/integration.rs`. `status` and `audit` answer operational **70** when a
named config cannot be read — a precondition failure, not drift.

## Exit-code contract

Exit codes are defined once in `lanespec::exit` (`OK`, `BAD`, `DEBRIS`,
`USAGE`, `OPERATIONAL`, `ALREADY_LIVE`, `MISSING_BOUND`, `TIMEOUT`) and
returned by `cli::run`. See `lanespec help exit-codes` for the same contract
from the binary itself and `docs/exit-codes.md` for the full notes.

Family note: an unknown `help` topic exits **64** here and — since each
family tool's P2 exit-taxonomy retrofit — **64** everywhere: the universal
usage code (dbgraph retired its dedicated `EXIT_NO_TOPIC` 3; archspec moved
off 1). stderr always names the fault, and no tool lets a topic typo
imitate a verdict code.
