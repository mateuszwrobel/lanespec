// Finding B3 (exact two-key matrix law): the generator maps the release's
// full asset name list to EXACTLY two keys — no globs, no deb names
// anywhere in the map — and a name list missing any target fails closed.

import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import test from "node:test";
import { matrix, MATRIX_KEYS } from "../lib/matrix.mjs";
import { mkTmp, sha256Hex } from "./helpers.mjs";

const VER = "7.7.7";

function releaseDirWithAllNames(dir) {
  const v = VER;
  const installables = [
    `lanespec-${v}-x86_64-unknown-linux-musl.tar.gz`,
    `lanespec-${v}-aarch64-unknown-linux-gnu.tar.gz`,
    `lanespec_${v}_amd64.deb`,
    `lanespec_${v}_arm64.deb`,
  ];
  for (const name of installables) {
    fs.writeFileSync(path.join(dir, name), `payload-bytes-${name}`);
    fs.writeFileSync(path.join(dir, `${name}.sha256`), `${"0".repeat(64)}  ${name}\n`);
  }
  return installables;
}

function generate(dir, out, omit = null) {
  const args = [GEN, "--dir", dir, "--version", VER];
  if (omit) fs.rmSync(path.join(dir, matrix(VER)[omit]));
  if (out) args.push("--out", out);
  return spawnSync(process.execPath, args, { encoding: "utf8" });
}

const GEN = new URL("../scripts/gen-assets.mjs", import.meta.url).pathname;

test("matrix law: exactly two keys with the exact names", () => {
  assert.deepEqual(Object.keys(matrix(VER)).sort(), [...MATRIX_KEYS].sort());
  const m = matrix(VER);
  assert.equal(m["linux-x64"], `lanespec-${VER}-x86_64-unknown-linux-musl.tar.gz`);
  assert.equal(m["linux-arm64"], `lanespec-${VER}-aarch64-unknown-linux-gnu.tar.gz`);
  for (const name of Object.values(m)) {
    assert.ok(!name.endsWith(".deb"), `no deb in the map: ${name}`);
  }
});

test("full 8-name release list generates exactly two hashed keys", () => {
  const dir = mkTmp("npm-matrix-");
  releaseDirWithAllNames(dir);
  const out = path.join(dir, "assets.json");
  const res = generate(dir, out);
  assert.equal(res.status, 0, res.stderr);
  const doc = JSON.parse(fs.readFileSync(out, "utf8"));
  assert.deepEqual(Object.keys(doc.assets).sort(), [...MATRIX_KEYS].sort());
  // Finding M1 (half): hashes are sha256 of the DOWNLOADED ASSET BYTES —
  // the fixture sidecars above all carry the all-zeros decoy hash; a
  // sidecar-parsing generator would record that and fail here.
  for (const [key, entry] of Object.entries(doc.assets)) {
    const bytes = fs.readFileSync(path.join(dir, entry.name));
    assert.equal(entry.sha256, sha256Hex(bytes), `hash for ${key} must come from the bytes`);
    assert.notEqual(entry.sha256, "0".repeat(64));
  }
  // no deb name appears anywhere in the map bytes.
  const mapBytes = JSON.stringify(doc.assets);
  assert.ok(!mapBytes.includes(".deb"), "no .deb name in the map");
});

test("minus-one-platform fails closed naming the missing key", () => {
  const dir = mkTmp("npm-matrix-");
  releaseDirWithAllNames(dir);
  const out = path.join(dir, "assets.json");
  const res = generate(dir, out, "linux-arm64");
  assert.notEqual(res.status, 0);
  assert.match(res.stderr, /linux-arm64/);
  assert.match(res.stderr, new RegExp(`lanespec-${VER}-aarch64-unknown-linux-gnu\\.tar\\.gz`));
  assert.ok(!fs.existsSync(out), "no assets.json on a missing key");
});
