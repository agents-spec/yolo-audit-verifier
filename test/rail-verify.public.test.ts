// Public, self-contained rail-verification demo test — runnable by anyone who clones the verifier.
// Imports ONLY ./rail-verify (flat layout); uses STATIC pre-signed receipt fixtures (rail-fixtures.json)
// and CANNED rail RPC responses — no live network, no emit-path builder, no monorepo deps, no ethers.
// Mirrors the existing test/rejection.test.ts style.
//
// Run:  node --import tsx --test test/rail-verify.public.test.ts   (deps: tsx + viem only)
//
// "Verify it yourself" demonstrations of the 3-rail per-rail settlement confirm + its honesty rules.

import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import {
  assessRailSettlement, parseXrplSettlement, parseSolanaSettlement,
  type SettlementReceipt, type RailRead,
} from "../rail-verify";

type Fixture = {
  name: string;
  receipt: SettlementReceipt;
  railInput: RailRead | { chain: "xrpl"; legResults: Array<{ reachable: boolean; tx: unknown }> } | { chain: "solana"; getTx: { reachable: boolean; tx: unknown } };
  expected: { railVerdict: string; attestation: string; protocolEnforced1pct: boolean };
};

const FIXTURES: Fixture[] = JSON.parse(readFileSync(new URL("./rail-fixtures.json", import.meta.url), "utf8"));

// resolve a fixture's railInput into a RailRead: chain-raw inputs run through the REAL parser
// (parseXrplSettlement / parseSolanaSettlement); a ready RailRead is used directly.
function toRead(receipt: SettlementReceipt, railInput: Fixture["railInput"]): RailRead {
  if ("chain" in railInput && railInput.chain === "xrpl") return parseXrplSettlement(receipt, railInput.legResults as any);
  if ("chain" in railInput && railInput.chain === "solana") return parseSolanaSettlement(receipt, railInput.getTx as any);
  return railInput as RailRead;
}

describe("rail-verify — public 3-rail settlement confirm demos (static fixtures, offline)", () => {
  for (const fx of FIXTURES) {
    it(fx.name, async () => {
      const a = await assessRailSettlement(fx.receipt, toRead(fx.receipt, fx.railInput));
      assert.equal(a.railVerdict, fx.expected.railVerdict, `railVerdict for ${fx.name}`);
      assert.equal(a.attestation, fx.expected.attestation, `attestation for ${fx.name}`);
      assert.equal(a.protocolEnforced1pct, fx.expected.protocolEnforced1pct, `protocolEnforced1pct for ${fx.name}`);
      // honesty invariants that hold for EVERY verdict:
      assert.match(a.note, /tamper-evident, NOT omission-evident/);             // omission caveat always present
      if (fx.receipt.enforcement === "attested_off_ledger") assert.equal(a.protocolEnforced1pct, false); // off-ledger never enforced
      console.log(`  ✓ ${fx.name}: ${a.railVerdict} / ${a.attestation} / protocolEnforced1pct=${a.protocolEnforced1pct}`);
    });
  }
});
