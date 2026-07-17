// calldata-parity.test.ts — the anchorBatch calldata PARSE lives ONCE in verify-core.js and must
// stay byte-identical to yolo-verify.py::_decode_anchor_tx (the Python control). Both languages
// assert against the SAME fixtures (verifier/test/calldata-fixtures.json), so a divergence in the
// highest-stakes step fails here rather than silently in an exhibit. Transport is substituted with
// static tx/receipt objects; the pure parse is the unit under test.
import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { parseAnchorBatchCalldata } from "../verify-core.js";

const FIX = JSON.parse(
  readFileSync(fileURLToPath(new URL("./calldata-fixtures.json", import.meta.url)), "utf8"),
);

for (const c of FIX.cases) {
  test(`calldata parse (core): ${c.name}`, () => {
    const got = parseAnchorBatchCalldata(
      c.tx, c.receipt, FIX.anchor_address, c.txHash, c.expFirst, c.expLast,
    );
    assert.equal(got.status, c.expect.status, `${c.name}: status ${got.status} != ${c.expect.status} (${got.note})`);
    assert.equal(got.root, c.expect.root, `${c.name}: root mismatch`);
  });
}
