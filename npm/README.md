# lanespec (npm downloader package)

`lanespec` is a lane lifecycle CLI: launch, supervise, audit and recover
detached process lanes. It runs a command in its own session, records it in
a registry, and answers the questions that matter after a worker process
dies: what is still running, what is orphaned debris, and in which order to
recover it.

This package is a downloader: it does not contain the binary. It pins the
release assets of the matching version, downloads the one built for your
platform and architecture, verifies it against the pinned SHA-256 hash,
caches it, and runs it. The npm channel ships from this repository's
GitHub releases: every release carries the platform binaries this package
downloads.

Availability today: released binaries ship for Linux only — `linux-x64`
and `linux-arm64`. macOS and Windows support is planned; on those hosts the
install prints the supported keys and the first run fails there, loudly.

## Install

```sh
npm install "@<scope>/lanespec"        # <scope> is the scope the release announces
npx "@<scope>/lanespec" status         # or run it without installing
```

On a supported host (`linux`; `x64` or `arm64`) the install script fetches
the binary immediately. If lifecycle scripts are skipped (`npm install
--ignore-scripts`, or a package-manager script policy), nothing is lost: the
first run fetches the binary then.

## What gets downloaded

`assets.json` in this package maps your `platform-arch` to exactly one
release asset name and its SHA-256 hash, pinned at publish time from the
bytes of that release's assets. The download uses the plain release-download
URL — no API calls, no rate wall. The binary is cached under
`~/.cache/lanespec-npm`, named by version and platform, written via a
temporary file and an atomic rename under a lock, so concurrent first runs
share one complete binary.

If a download or cached file ever fails hash verification, the tool fails and
names the mismatch. There is no warn-and-continue path.

## Honest signing note

The release binaries carry no signature. Verification rests on the pinned
SHA-256 hash: npm provenance attests that the published tarball came from
this repository's published release pipeline — it attests the tarball's
origin, not a signed binary inside it. Verify a release asset yourself with
its `.sha256` sidecar and `sha256sum -c` at any time.

## Failure messages

Every failure names the platform, architecture, version, the exact download
URL, and (when relevant) the `--ignore-scripts` hint. If the release has no
asset for your `platform-arch`, the tool prints
`lanespec@<version>: no release asset for <platform>-<arch>` and exits
nonzero. You will never see a bare ENOENT.

## Version policy

One package version per release tag. Once a version is published here, its
release assets are frozen: the distribution of a published version never
changes, and the only recovery path is the next version.
