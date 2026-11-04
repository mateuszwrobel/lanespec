//! Exit-code contract shared by every command.
//!
//! ```text
//!   0    success / nothing to report
//!   1    generic failure or refusal (bad input, timeout while refusing)
//!   3    audit found debris (orphan lanes / fleets / holders / stale worktrees)
//!   4    launch refused: lane already exists and is live or done (reap first)
//!   5    sweep refused: no --namespace / --class bound, or an empty one
//!  64    usage error: the command line is wrong, or help named an absent topic
//!  70    operational precondition: a named config file cannot be read
//! 124    deadline exceeded: wait timed out, or sweep's kill loop hit its bound
//! ```

/// Success.
pub const OK: i32 = 0;
/// Generic failure or refusal.
pub const BAD: i32 = 1;
/// Audit found debris. Only `audit` emits this code: a `help` topic typo is a
/// usage error (`USAGE`, 64), never a verdict code, so `3` has one meaning.
pub const DEBRIS: i32 = 3;
/// Usage error: the command line itself is wrong (unknown command, unknown
/// flag, missing value), or `help` named a topic the manual does not have.
/// Kept apart from every verdict code so a usage mistake can never be read
/// as a finding. `--help` and `--version` print and exit `OK`.
pub const USAGE: i32 = 64;
/// Operational precondition failure: the run could not start because a named
/// input is not there — today a `--config` / `LANESPEC_CONFIG` file that
/// cannot be read. Kept out of the verdict codes so a wrapper can tell
/// "the environment is not there" from a verdict: a missing config is never
/// drift (1) and never a refusal while working (also 1).
pub const OPERATIONAL: i32 = 70;
/// Launch refused: lane already exists.
pub const ALREADY_LIVE: i32 = 4;
/// Sweep refused: no namespace/class bound.
pub const MISSING_BOUND: i32 = 5;
/// Wait timed out at the deadline.
pub const TIMEOUT: i32 = 124;
