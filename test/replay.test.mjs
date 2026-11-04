// SPDX-License-Identifier: Apache-2.0
// Replay checks for the shipped packets. Each run is killed if it
// does not finish, so a whitespace-skip hang fails the test instead
// of stalling the suite.
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const verifier = join(root, "froga-verify.mjs");
const TIMEOUT_MS = 5000;

function verify(packetPath) {
  return spawnSync(process.execPath, [verifier, "--packet", packetPath], {
    encoding: "utf8",
    timeout: TIMEOUT_MS,
    killSignal: "SIGKILL"
  });
}

function finished(result, label) {
  assert.equal(
    result.signal,
    null,
    `${label} did not finish within ${TIMEOUT_MS}ms (signal ${result.signal})`
  );
}

test("csv packet replays", { timeout: 15000 }, () => {
  const result = verify(join(root, "examples/proof-packet.json"));
  finished(result, "csv packet");
  assert.equal(result.status, 0, result.stderr);
  const body = JSON.parse(result.stdout);
  assert.equal(body.valid, true);
  assert.equal(body.replayed, true);
  assert.equal(body.replay, "match");
});

test("csv one-digit tamper exits 2", { timeout: 15000 }, () => {
  const result = verify(join(root, "examples/proof-packet-tampered.json"));
  finished(result, "csv tamper");
  assert.equal(result.status, 2, result.stdout);
});

test("jsonl packet replays", { timeout: 15000 }, () => {
  const result = verify(join(root, "examples/proof-packet-jsonl.json"));
  finished(result, "jsonl packet");
  assert.equal(result.status, 0, result.stderr);
  const body = JSON.parse(result.stdout);
  assert.equal(body.valid, true);
  assert.equal(body.replayed, true);
  assert.equal(body.replay, "match");
});

test("jsonl one-byte tamper exits 2", { timeout: 15000 }, () => {
  const src = readFileSync(join(root, "examples/proof-packet-jsonl.json"), "utf8");
  const needle = '"value":"139970.29"';
  const at = src.indexOf(needle);
  assert.notEqual(at, -1);
  const digit = src.indexOf("139970.29", at);
  const tampered = `${src.slice(0, digit + "139970.2".length)}8${src.slice(digit + "139970.29".length)}`;
  assert.equal(tampered.length, src.length);
  assert.notEqual(tampered, src);
  const dir = mkdtempSync(join(tmpdir(), "froga-jsonl-tamper-"));
  const packetPath = join(dir, "packet.json");
  writeFileSync(packetPath, tampered);
  const result = verify(packetPath);
  finished(result, "jsonl tamper");
  assert.equal(result.status, 2, result.stdout);
});
