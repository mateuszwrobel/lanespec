//! lanespec — process/lane lifecycle CLI.
//!
//! lanespec supervises detached process lanes: it launches them in their own
//! process group, tracks them in a registry, waits with deadlines, audits
//! debris, and recovers orphaned fleets by parent-gone proof.

pub mod audit;
pub mod cli;
pub mod config;
pub mod exit;
#[cfg(test)]
pub mod fake;
pub mod glob;
pub mod help;
pub mod lifecycle;
pub mod orphan;
pub mod plan;
pub mod procfs;
pub mod prune;
pub mod registry;
pub mod retry;
pub mod sweep;
pub mod unlock;
pub mod worktree;
