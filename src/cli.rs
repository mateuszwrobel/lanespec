//! Command-line surface and dispatch.

use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};

use crate::audit;
use crate::config::{Config, ConfigUnreadable};
use crate::exit;
use crate::help;
use crate::lifecycle;
use crate::plan;
use crate::procfs::RealProcfs;
use crate::retry;
use crate::sweep;
use crate::unlock;

#[derive(Parser)]
#[command(
    name = "lanespec",
    version,
    about = "Lane lifecycle CLI: launch, supervise, audit and recover detached process lanes.",
    // `help` is this tool's own manual subcommand below, not clap's generated
    // one, so the built-in manual owns the name. clap's --help/--version stay.
    disable_help_subcommand = true
)]
pub struct Cli {
    /// Config file (lanespec.toml); also LANESPEC_CONFIG env.
    #[arg(long, global = true)]
    config: Option<PathBuf>,
    /// Namespace tag for registry lanes and sweep bounds.
    #[arg(long, global = true)]
    namespace: Option<String>,
    #[command(subcommand)]
    command: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Start CMD detached in its own process group with a registry entry.
    Launch {
        /// Lane name ([A-Za-z0-9._-]+).
        name: String,
        /// Worktree path recorded in the lane meta.
        #[arg(long)]
        worktree: Option<PathBuf>,
        /// Command to run (after --).
        #[arg(last = true)]
        cmd: Vec<String>,
    },
    /// Liveness per lane (running | done rc=N | stale-record | orphan).
    Status {
        /// One lane only.
        name: Option<String>,
    },
    /// Poll .done with a deadline; exit with the lane rc, 124 on timeout.
    Wait {
        /// Lane name.
        name: String,
        /// Deadline in seconds.
        timeout: Option<u64>,
    },
    /// TERM, bounded settle, KILL the whole group; print the worktree verdict.
    Reap {
        /// Lane name.
        name: String,
    },
    /// Remove the registry record of a PROVEN-dead lane; live and
    /// unprovable records are refused and kept. Never signals; a guarded
    /// carrier worktree removal is reported with PRUNE-* lines.
    Collect {
        /// Lane name; give this or --all, never both.
        name: Option<String>,
        /// Collect every proven-dead record; refuse every other lane.
        #[arg(long)]
        all: bool,
    },
    /// Dump debris: orphan lanes, class fleets, lock holders, ahead-count,
    /// stale worktrees, sentinel age hints. Exit 3 on debris.
    Audit {
        /// Machine-readable report.
        #[arg(long)]
        json: bool,
        /// Repo for ahead-count and worktree registration (default: cwd).
        #[arg(long)]
        repo: Option<PathBuf>,
    },
    /// Ordered recovery steps for the debris the audit finds.
    Plan {
        /// Machine-readable plan.
        #[arg(long)]
        json: bool,
        /// Repo (default: cwd).
        #[arg(long)]
        repo: Option<PathBuf>,
    },
    /// Kill only parent-gone-proven processes; --namespace/--class required.
    Sweep {
        /// Class name from config to bound the sweep.
        #[arg(long)]
        class: Option<String>,
    },
    /// Resolve gate-lock holders: await live, kill orphan chains, refuse races.
    Unlock {
        /// Wait deadline for a live holder, seconds.
        deadline: Option<u64>,
    },
    /// Detached retry ladder: yield-guard, spaced attempts, .final sentinel.
    Retry {
        /// Lane name for the ladder.
        name: String,
        /// Command to run each attempt (shell).
        #[arg(long)]
        cmd: String,
        /// Success verifier; its last stdout line becomes the LANDED token.
        #[arg(long)]
        success_cmd: Option<String>,
        /// Attempt count.
        #[arg(long, default_value_t = 5)]
        attempts: u32,
        /// Seconds between attempts.
        #[arg(long, default_value_t = 600)]
        space: u64,
        /// Run the ladder in this process instead of detached.
        #[arg(long)]
        inline: bool,
    },
    /// Print the built-in manual. Without a topic, print the topic index.
    Help {
        /// One of: commands, exit-codes, configuration, diagnostics.
        topic: Option<String>,
    },
}

/// Run the CLI; returns the process exit code.
pub fn run() -> i32 {
    // try_parse, not parse: clap's parse exits with clap's own number (2),
    // which this contract does not own. A parser error prints its advice on
    // stderr and exits USAGE (64); --help and --version print on stdout and
    // exit OK, exactly as the exit-code topic declares.
    let cli = match Cli::try_parse() {
        Ok(cli) => cli,
        Err(err) => {
            let _ = err.print();
            return if err.use_stderr() { exit::USAGE } else { exit::OK };
        }
    };
    match dispatch(cli) {
        Ok(code) => code,
        Err(e) => {
            eprintln!("lanespec: {e:#}");
            // A named config file that cannot be read is an operational
            // precondition failure (70), not a verdict refusal (1). Every
            // other error keeps the generic code.
            if e.downcast_ref::<ConfigUnreadable>().is_some() {
                exit::OPERATIONAL
            } else {
                exit::BAD
            }
        }
    }
}

fn dispatch(cli: Cli) -> Result<i32> {
    // The manual is pure output. Answer it before any config, registry, or
    // process-table access, so a `help` run has no side effects.
    if let Cmd::Help { topic } = &cli.command {
        return match help::run(topic.as_deref()) {
            Ok(()) => Ok(exit::OK),
            Err(msg) => {
                eprintln!("lanespec: {msg}");
                Ok(exit::USAGE)
            }
        };
    }
    let (cfg, used) = Config::resolve(cli.config.as_deref())?;
    let ns_opt = cli.namespace;
    let proc = RealProcfs::new();
    match cli.command {
        // Handled above, before configuration is resolved.
        Cmd::Help { .. } => Ok(exit::OK),
        Cmd::Launch { name, worktree, cmd } => lifecycle::launch(
            &cfg,
            &proc,
            ns_opt.as_deref().unwrap_or("default"),
            &name,
            worktree.as_deref(),
            &cmd,
        ),
        Cmd::Status { name } => lifecycle::status(&cfg, &proc, name.as_deref()),
        Cmd::Wait { name, timeout } => {
            lifecycle::wait(&cfg, &proc, &name, timeout.unwrap_or(3_600))
        }
        Cmd::Reap { name } => {
            lifecycle::reap(&cfg, &proc, &name, std::time::Duration::from_secs(5))
        }
        Cmd::Collect { name, all } => {
            // Exactly one of <name> or --all: both or neither is a wrong
            // command line (USAGE), never a verdict code.
            if name.is_some() == all {
                eprintln!("collect: pass exactly one of <name> or --all");
                return Ok(exit::USAGE);
            }
            lifecycle::collect(&cfg, &proc, name.as_deref())
        }
        Cmd::Audit { json, repo } => audit::run(&cfg, &proc, &repo_path(repo)?, json),
        Cmd::Plan { json, repo } => plan::run(&cfg, &proc, &repo_path(repo)?, json),
        Cmd::Sweep { class } => sweep::sweep(
            &cfg,
            &proc,
            ns_opt.as_deref(),
            class.as_deref(),
            std::time::Duration::from_secs(5),
            1_000,
            std::time::Duration::from_secs(120),
        ),
        Cmd::Unlock { deadline } => unlock::unlock(&cfg, &proc, deadline.unwrap_or(60)),
        Cmd::Retry {
            name,
            cmd,
            success_cmd,
            attempts,
            space,
            inline,
        } => retry::retry(
            &cfg,
            &proc,
            ns_opt.as_deref().unwrap_or("default"),
            &name,
            retry::RetrySpec {
                cmd,
                success_cmd,
                attempts,
                space,
            },
            inline,
            used.as_deref(),
        ),
    }
}

fn repo_path(repo: Option<PathBuf>) -> Result<PathBuf> {
    match repo {
        Some(p) => Ok(p),
        None => std::env::current_dir().context("resolve cwd for --repo"),
    }
}
