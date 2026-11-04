# Exit-code contract

Every command obeys one contract. Scripts may branch on these numbers.

| Code | Meaning | Emitted by |
|-----:|---------|------------|
| 0    | Success, or nothing to report | all commands |
| 1    | Generic failure or refusal: bad input, unknown lane/class, wait-timeout while a live holder refused, a collect refusal (record kept, nothing removed), a live surfacer during unlock | all commands |
| 3    | Debris found: by `audit` — an orphan lane, an orphan class fleet, an orphan lock holder, or a stale worktree; by `prune-orphans` — an operator-visible `PROTECT-*` line (unattributable checkout, dirty-unlanded, ahead-unlanded). Only these two emit this code; it has exactly one meaning. | `audit`, `prune-orphans` |
| 4    | Launch refused: the lane already exists (live or done) — reap it first | `launch` |
| 5    | Sweep refused: no `--namespace` / `--class` bound was given, or a given bound was empty/whitespace-only | `sweep` |
| 64   | Usage error: the command line itself is wrong (unknown command, unknown flag, missing value), `help` named a topic the manual does not have, or `collect` was given `<name>` and `--all` together or neither. `--help` and `--version` print and exit 0 | parser, `help`, `collect` |
| 70   | Operational precondition: a config file named by `--config` or `LANESPEC_CONFIG` could not be read (missing, a directory, or no permission). Not a verdict: no lane state was examined. A wrapper must never read 70 as drift | config resolution, all commands except `help` |
| 124  | Deadline reached: `wait` while the lane still runs, or `sweep` while matched candidates still survived their kills (kill-loop bound) | `wait`, `sweep` |
| lane rc | `wait` exits with the lane's recorded `.done` code on success | `wait` |

Notes:

- 70 is answered BEFORE any command runs and covers both config sources
  (`--config` wins over `LANESPEC_CONFIG`, then built-in defaults). A config
  that READS but is then refused — bad TOML, unknown keys, a match-everything
  class anchor — stays a refusal while working: exit 1.
- `status` and `plan` exit 0 even when they REPORT debris; only `audit`
  and `prune-orphans` encode debris in the exit code. A live owner the
  oracle skips (`PROTECT-LIVE`) is a printed skip, not debris: exit 0.
- A `prune-orphans` guard refusal — mount holder, unreadable mount table,
  busy gate lock — is exit 1 with one named line: a removal was due and
  the guard kept the worktree. `--dry-run` never reaches a guard.
- A `wait` on a lane that died without `.done` exits 1 with a DEAD notice:
  run `reap` or `audit`.
- An unreadable process fd table makes `audit`/`unlock` fail with 1 —
  silence never reads as "free".
- `retry` detached returns 0 when it yields to a live ladder: a sibling
  lane running the same command, or a ladder already running under the
  SAME lane name. A live lane's `.final` sentinel is never reset by a
  second `retry` — the running ladder owns it.
- `reap` refuses with 1 when the recorded pgid IS the caller's own process
  group or an ancestor's group (the shape an inline `retry` record has):
  lanespec never signals its own lineage. Reap the lane from outside that
  session, or after the session has moved on.
- A wrong command line (unknown command, unknown flag, missing value) and a
  `help` topic that is not in the manual both exit 64: a usage mistake is
  never a verdict code. `audit` and `prune-orphans` are the only emitters
  of `3`, so a `3` reaching a
  script always means debris — including a `3` recorded by a lane and
  re-surfaced through `wait`.
