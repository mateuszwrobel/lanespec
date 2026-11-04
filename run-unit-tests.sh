#!/usr/bin/env bash
# Run the lanespec test suite plus the clippy gate.
#
# Safe to run from inside a git hook: we strip inherited GIT_* env so any
# `git` subprocess spawned during the run uses the test fixture's repo,
# not the enclosing repo's GIT_DIR.
set -euo pipefail

unset GIT_DIR GIT_WORK_TREE GIT_INDEX_FILE GIT_PREFIX \
      GIT_COMMON_DIR GIT_NAMESPACE GIT_OBJECT_DIRECTORY \
      GIT_ALTERNATE_OBJECT_DIRECTORIES

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

# Test scratch lives on disk, not tmpfs (repo TMPDIR law); build output goes
# to the per-lane cache, never into the worktree tree.
export TMPDIR="${TMPDIR:-/var/tmp}"
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$HOME/.cache/lanespec-target}"

echo "Running lanespec tests..."
# nextest (hardening lane A): per-test timeouts (see .config/nextest.toml).
# Doctest parity: doc tests stay on cargo test (nextest does not run them).
cargo nextest run --no-tests=pass --config-file "$SCRIPT_DIR/.config/nextest.toml" --manifest-path "$SCRIPT_DIR/Cargo.toml" "$@"
cargo test --doc --manifest-path "$SCRIPT_DIR/Cargo.toml"

echo "Running lanespec clippy gate..."
cargo clippy --manifest-path "$SCRIPT_DIR/Cargo.toml" --all-targets -- -D warnings

# Family-binary resolution law (speckit wave 3): ARCHSPEC env -> PATH ->
# fail closed, naming the binary. The binaries come from the global
# install: specs/install/install-spec-tools.sh (no relative target/ builds).
ARCHSPEC="${ARCHSPEC:-}"
if [ -z "$ARCHSPEC" ]; then
    ARCHSPEC="$(command -v archspec 2>/dev/null || true)"
fi
if [ -z "$ARCHSPEC" ] || [ ! -x "$ARCHSPEC" ]; then
    echo "archspec binary not found — set ARCHSPEC=/path/to/archspec or install the family binaries globally: specs/install/install-spec-tools.sh" >&2
    exit 1
fi

echo "Running archspec verify --strict for lanespec..."
"$ARCHSPEC" verify "$SCRIPT_DIR" --strict

echo "lanespec unit lane green"
