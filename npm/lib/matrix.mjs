// The exact two-key matrix law: every npm package version pins exactly these
// two release-asset names. No globs: the release carries more installables per
// target than one (linux-x64 ships tarball and deb), so name matching must be
// exact and the map is built from this table alone. deb, pkg and zst names are
// excluded by construction — they appear nowhere.
// lanespec ships Linux-only until the cross-platform port lands: this table is
// the single source of truth, and the generator, the workflow asset lists and
// the shim's unsupported-platform message all derive from it.

/// The release tag prefix this crate's releases carry (the tag-shape
/// gate, the generator's releaseTag and the install path's fallback all
/// derive the tag from this one constant).
export const TAG_PREFIX = Object.freeze("lanespec-v");

export const MATRIX_KEYS = Object.freeze([
  "linux-x64",
  "linux-arm64",
]);

/// version -> { "<platform>-<arch>": "<release asset name>" }
export function matrix(version) {
  return {
    "linux-x64": `lanespec-${version}-x86_64-unknown-linux-musl.tar.gz`,
    "linux-arm64": `lanespec-${version}-aarch64-unknown-linux-gnu.tar.gz`,
  };
}

/// The binary member name inside the archive for one platform-arch key.
/// Every key in MATRIX_KEYS ships a POSIX archive with this member name.
export function binaryName(_key) {
  return "lanespec";
}
