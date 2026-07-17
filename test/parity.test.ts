import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { recomputeAndAssess, type ProofBundle } from "../verify-client";

type ParityFixture = {
  name: string; assert: "verdict" | "merkle_step"; expectedVerdict?: string;
  expectedMerkleResult: "pass" | "fail"; expectMerkleReasonContains?: string;
  onChainRoot: string | null; onChainReachable: boolean; onChainStatus?: string | null; bundle: ProofBundle;
};
const FIXTURES: ParityFixture[] = JSON.parse(readFileSync(new URL("./parity-fixtures.json", import.meta.url), "utf8"));
const MERKLE_CHECK = 2; // checks order: [payload, chain, merkle, onchain]

for (const fx of FIXTURES) {
  test(`parity (TS): ${fx.name}`, async () => {
    const view = await recomputeAndAssess(fx.bundle, fx.onChainRoot, fx.onChainReachable, fx.onChainStatus ?? null);
    const merkle = view.checks[MERKLE_CHECK];
    assert.equal(merkle.result, fx.expectedMerkleResult, `merkle should be ${fx.expectedMerkleResult} (got ${merkle.result}: ${merkle.detail ?? "—"})`);
    if (fx.expectMerkleReasonContains)
      assert.ok((merkle.detail ?? "").toLowerCase().includes(fx.expectMerkleReasonContains.toLowerCase()), `merkle-fail detail should name '${fx.expectMerkleReasonContains}' (got: ${merkle.detail ?? "—"})`);
    if (fx.assert === "verdict") {
      assert.equal(view.state, fx.expectedVerdict, `TS verdict should be ${fx.expectedVerdict} (got ${view.state})`);
      assert.equal(view.verified, false, "a leaf-not-bound bundle must never read verified");
    }
  });
}
