// Standalone test for the verifier's SELF-ENFORCED reference/seed allowlist (forensic-audit fix #2).
// Imports ONLY ./verify-client.ts (no monorepo / no Supabase deps). Proves the headline: a
// NON-allowlisted id that CLAIMS reference/seed has its payload RE-HASHED and FAILS — the server
// cannot grant the membership-only skip on say-so. Also shows an allowlisted id IS granted the skip.
//
// Run: `npm test` (node --test via tsx). Offline/pure — the on-chain root is injected.

import { test } from "node:test";
import assert from "node:assert/strict";
import {
  recomputePayloadHash,
  recomputeChainHash,
  recomputeRootFromProof,
  recomputeAndAssess,
  type ProofBundle,
} from "../verify-client.ts";

const ARGUS = "4fbe49c2-89f5-44e4-a995-89115f767217";

// A bundle whose SERVED payload is withheld (_redacted) while the stored hashes are those of the REAL
// payload — so if the verifier re-hashes the redaction marker it will NOT match the stored hash.
async function redactedBundleWithId(id: number): Promise<{ bundle: ProofBundle; root: string }> {
  const realPayload = { tool: "atxp", amount_usdc: 1 };
  const payload_hash = await recomputePayloadHash(realPayload, "v1");
  const chain_hash = await recomputeChainHash(ARGUS, 0, "genesis", payload_hash);
  const root = await recomputeRootFromProof(chain_hash, [], true);
  const bundle = {
    entry: {
      id, agent_id: ARGUS, seq: 0, action_type: "decision_consequential",
      prev_hash: "genesis", canon_version: "v1", payload: { _redacted: true, _reason: "withheld" },
    },
    hashes: { payload_hash, chain_hash },
    status: "reference_seed", verified: false, anchored: true,
    anchor: { status: "onchain", root, tx: "0xabc", basescan_url: "x", batch: { first_seq: 0, last_seq: 0, log_count: 1, ipfs_cid: null } },
    merkle_proof: { leaf: chain_hash, steps: [], single_leaf_batch: true },
    classification: { kind: "reference_seed", label: "REFERENCE / SEED ENTRY", redacted: true, reason: "claims reference/seed" },
  } as unknown as ProofBundle;
  return { bundle, root };
}

test("NON-allowlisted id (999) claiming reference/seed → REJECTED (payload re-hashed, fails)", async () => {
  const { bundle, root } = await redactedBundleWithId(999);
  const v = await recomputeAndAssess(bundle, root);
  assert.equal(v.verified, false, "a server-only reference/seed claim must NOT be verified");
  assert.equal(v.state, "payload_hash_mismatch", "payload was re-hashed and did not match");
  assert.equal(v.checks[0].result, "fail", "payload-hash check failed (not skipped)");
});

test("allowlisted id (27) claiming reference/seed → granted the membership-only skip", async () => {
  const { bundle, root } = await redactedBundleWithId(27);
  const v = await recomputeAndAssess(bundle, root);
  assert.equal(v.state, "reference_seed", "allowlisted id classified reference_seed");
  assert.equal(v.checks[0].result, "skip", "payload-hash recompute skipped for allowlisted id");
});
