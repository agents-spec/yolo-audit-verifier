// exit-parity.test.ts — the two trustless CLIs (yolo-verify.ts / yolo-verify.py) must exit the SAME
// code for the SAME verdict, or a script keying off exit codes silently behaves differently depending
// on which CLI ran. This guards that axis: it reads both source files, extracts each EXIT map, and
// asserts every verdict they share maps to the same number — plus pins the canonical values so a
// silent change in either surfaces here. Two Python-only verdicts are documented (the TS CLI cannot
// emit them); any NEW divergence fails.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

// Extract a { key: int } map from source: from the first "{" after `anchor` to the next "}", then
// pick every `key: number` pair (quoted or bare; comments after values are ignored by the regex).
function exitMap(src: string, anchor: string): Record<string, number> {
  const i = src.indexOf(anchor);
  assert.ok(i >= 0, `anchor not found: ${anchor}`);
  const open = src.indexOf("{", i);
  const close = src.indexOf("}", open);
  const block = src.slice(open + 1, close);
  const out: Record<string, number> = {};
  for (const m of block.matchAll(/["']?([A-Za-z_]+)["']?\s*:\s*(\d+)/g)) out[m[1]] = Number(m[2]);
  return out;
}

const PY = exitMap(readFileSync(new URL("../yolo-verify.py", import.meta.url), "utf8"), "EXIT = {");
const TS = exitMap(readFileSync(new URL("../yolo-verify.ts", import.meta.url), "utf8"), "const EXIT");

// Canonical exit codes — the single source of truth both CLIs must match.
const CANONICAL: Record<string, number> = {
  verified: 0, error: 1, pending_anchor: 2, anchored_payload_anomaly: 3, rpc_unreachable: 4,
  anchor_root_mismatch: 5, payload_hash_mismatch: 6, reference_seed: 7, anchor_absent: 8,
  anchor_mismatch: 9, receipt_unconfirmed: 10,
};
// Verdicts the TS CLI cannot emit (so they are legitimately absent from its EXIT map):
//   error — a CLI-level failure exit, not a VerificationView state.
// NOTE: anchor_mismatch (9) IS now mapped in yolo-verify.ts (added to the state union for the exhibit),
// so it is no longer TS-absent even though this Approach-A CLI never emits it at runtime — its exit
// code must still agree with Python's, which this fixture enforces.
const TS_CANNOT_EMIT = new Set(["error"]);

test("exit-parity: every verdict shared by both CLIs maps to the same code", () => {
  for (const k of Object.keys(PY)) {
    if (k in TS) assert.equal(TS[k], PY[k], `exit code drift for "${k}": ts=${TS[k]} py=${PY[k]}`);
  }
});

test("exit-parity: both CLIs match the canonical exit codes", () => {
  for (const [k, code] of Object.entries(PY)) assert.equal(code, CANONICAL[k], `python EXIT["${k}"]=${code} != canonical ${CANONICAL[k]}`);
  for (const [k, code] of Object.entries(TS)) assert.equal(code, CANONICAL[k], `ts EXIT["${k}"]=${code} != canonical ${CANONICAL[k]}`);
});

test("exit-parity: the only verdicts missing from the TS CLI are the documented ones", () => {
  const missingFromTs = Object.keys(PY).filter((k) => !(k in TS));
  assert.deepEqual(new Set(missingFromTs), TS_CANNOT_EMIT, `unexpected TS-absent verdict(s) — a shared verdict must be mapped in both CLIs: ${missingFromTs.join(", ")}`);
});

test("exit-parity: receipt_unconfirmed is 10 in both (the fifth state)", () => {
  assert.equal(PY.receipt_unconfirmed, 10);
  assert.equal(TS.receipt_unconfirmed, 10);
});
