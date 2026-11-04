# Configuration

`lanespec` reads one TOML file: `--config PATH`, else `LANESPEC_CONFIG`,
else built-in defaults. A named file that cannot be read (missing, a
directory, no permission) is refused with exit 70 before any command runs —
an operational precondition, never a verdict (see
[docs/exit-codes.md](exit-codes.md)). The schema is closed: unknown fields
are rejected, so an unusable proof kind (for example "mtime") cannot be
expressed at all.

```toml
[paths]
registry = "/var/tmp/lanes"   # one directory per lane
scratch  = "/var/tmp"         # wt-* dirs are checked here for staleness

[lock]
path = "/var/tmp/lanespec.lock"   # gate lock the audit reports / unlock frees

[parent-rule]
reparent_targets = ["systemd"]  # comm names of reparent daemons (besides pid 1)
max-ancestry-depth = 8          # cap of ancestry walks

[[class]]                       # process classes the audit/sweep can bound
name = "fleet-daemon"
cmdline-anchor = '^/usr/lib/fleetd fleet-'   # regex over /proc cmdline
proof-command = ["/bin/true", "{pid}"]       # optional argv proof, exit 0 = holds
recovery-step = "sweep --class fleet-daemon" # optional plan step template

[[sentinel]]                    # age HINTS only — age is never evidence
glob = "/var/tmp/*.final"
age-hint-hours = 6
```

## Field notes

- `cmdline-anchor` must compile as a regex; validation fails fast
  otherwise. An anchor that matches EVERYTHING — empty/whitespace-only,
  or a bare `.*` — is refused AT LOAD: a config file can never rebuild
  the match-everything pattern a nameless sweep is refused for.
- `proof-command` placeholders: `{pid}`, `{cmdline}`. It runs argv-style
  (no shell). A failed proof downgrades the audit verdict to
  "PROOF FAILED — inspect" and never counts as killable debris. `sweep`
  consults the same proof BEFORE any kill: a nonzero verdict refuses that
  candidate and prints the refusal.
- `recovery-step` placeholders: `{pid}`. `plan` prints the template instead
  of the generic sweep line.
- There is deliberately NO `mtime`-style proof kind: the laws forbid killing
  by age, so the schema cannot express it.
- Registry mutations (launch, `.done` landing, final sentinels) take an
  exclusive `flock` on `<registry>/.lock`.
