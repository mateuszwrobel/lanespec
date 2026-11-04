# lanespec

Lane lifecycle CLI: launch, supervise, audit and recover detached process
lanes.

`lanespec` runs a command in its own session, records it in a registry, and
answers the only questions that matter after a worker process dies: what is
still running, what is orphaned debris, and in which order to recover it.

## Laws the tool enforces

- Every wait has a deadline; a timeout prints loud and exits nonzero.
- Liveness is a process-group check plus a pid-reuse guard: the recorded
  start_time must match before any kill. A recycled pid is reported as
  `stale-record` and NEVER killed.
- Orphans are proven from the process tree (reparent to init/systemd or a
  dead parent). mtime is NEVER evidence; sentinel ages are hints only.
- A live parent is NEVER touched. Sweeps require a `--namespace` or
  `--class` bound; without one they refuse.
- Pattern scans exclude own pid and ancestors, so the tool can never match
  its own lineage.

## Install

From a checkout of this repository:

```sh
cargo install --path .
```

Or fetch a released binary through npm:

```sh
npm install "@<scope>/lanespec"    # <scope> is the scope the release announces
npx "@<scope>/lanespec" status     # or run it without installing
```

See [npm/README.md](npm/README.md) for how the npm package fetches and
verifies the binary.

## Usage

```text
lanespec [--config PATH] [--namespace NS] <command>

launch <name> [--worktree PATH] -- CMD...   start CMD detached, own pgid
status [name]                               per-lane verdict
wait <name> [timeout-s]                     poll .done, propagate rc
reap <name>                                 TERM, settle, KILL the group
collect <name> | --all                      remove a PROVEN-dead lane's record
                                            and its guarded carrier worktree
                                            (never signals, never touches scratch)
audit [--json] [--repo DIR]                 debris report (exit 3 on debris)
plan [--json] [--repo DIR]                  ordered recovery steps
sweep [--class NAME]                        kill proven orphans (bound required)
unlock [deadline-s]                         free the gate lock safely
prune-orphans [--dry-run] [--repo DIR]      classify worktrees by owner; remove
        only carriers attributed to lane records whose owner is proven dead
        (never automatic, never --force, one named line per action)
retry <name> --cmd CMD [--success-cmd CMD]  detached retry ladder
        [--attempts N] [--space S] [--inline]
```

Lane names match `[A-Za-z0-9._-]+` and start alphanumeric.

Registry layout per lane: `pid`, `meta`, `log`, `.done`. The `pid` file
holds `<pgid> <start_time>`. `.done` holds the lane's exit code and is
written atomically (temp+rename under the registry lock) by the runner.
Retry lanes additionally carry `push*.log` and the `.final` sentinel:
`LANDED <token>` or `FAILED`.

See [docs/exit-codes.md](docs/exit-codes.md) for the exit-code contract and
[docs/configuration.md](docs/configuration.md) for the config file.
