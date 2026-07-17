// verify-client.ts — the standalone Yolo audit verifier's client-side verification (no app dependency).
// The verification CORE is verify-core.js (co-located, shared, ZERO deps): the recompute primitives,
// the anchorBatch calldata parse, and recomputeAndAssess. This file re-attaches the TypeScript types
// dropped to make the core browser-runnable, and keeps ONLY its own Node/viem on-chain read transport.
//
// recomputeAndAssess stays PURE given (bundle, onChainRoot); readOnChainRoot does the actual Base read.

import { createPublicClient, http, parseAbi } from "viem";
import { base } from "viem/chains";
import {
  recomputePayloadHash as _recomputePayloadHash,
  recomputeChainHash as _recomputeChainHash,
  recomputeRootFromProof as _recomputeRootFromProof,
  recomputeAndAssess as _recomputeAndAssess,
  checkpointFor as _checkpointFor,
  REFERENCE_SEED_IDS as _REFERENCE_SEED_IDS,
  LAST_KNOWN_ANCHORS as _LAST_KNOWN_ANCHORS,
} from "./verify-core.js";

// ── Shared types (mirror /api/verify/[auditId]/proof response) ──────────────────

export type ProofBundle = {
  entry: {
    id: number; agent_id: string; seq: number; action_type: string;
    prev_hash: string; canon_version: "v1" | "v2" | null; payload: Record<string, unknown>;
  };
  hashes: { payload_hash: string; chain_hash: string };
  status: string;
  verified: boolean;
  anchored: boolean;
  anchor?: {
    status: string; root: string; tx: string | null; basescan_url: string | null;
    batch: { first_seq: number; last_seq: number; log_count: number; ipfs_cid: string | null };
  };
  merkle_proof?: { leaf: string; steps: Array<{ sibling: string; position: "left" | "right" }>; single_leaf_batch: boolean };
  checks?: { root_reconciles?: boolean; payload_hash?: { status: string; recomputed: boolean; canon_version: string; reason: string } };
  note?: string;
  // Present only for ids on the frozen reference/seed allowlist (lib/audit-proof.ts). `redacted`
  // means the readable payload was withheld → the client skips payload-hash recompute (membership only).
  classification?: { kind: string; label: string; redacted: boolean; reason: string };
};

export type ClientCheck = { label: string; result: "pass" | "fail" | "skip"; detail?: string };

export type VerificationView = {
  state: "verified" | "pending_anchor" | "anchor_root_mismatch" | "anchored_payload_anomaly" | "payload_hash_mismatch" | "rpc_unreachable" | "anchor_absent" | "reference_seed" | "receipt_unconfirmed" | "anchor_mismatch";
  verified: boolean;  // true ONLY when fully sound — the green state
  tone: "ok" | "warn" | "bad" | "neutral";
  headline: string;
  // Attestation scope — what the verdict actually bound. Never a bare "verified" with no scope:
  //   "full payload bound" (v2) | "top-level only — nested keys not bound" (v1) |
  //   "Merkle-membership only — payload not re-hashed" (reference/seed).
  scope: string;
  note: string;
  checks: ClientCheck[];
  serverClassification?: string; // server's payload_hash.reason, shown as context (never as the verdict)
};

export type AnchorCheckpoint = { agentId: string; anchorIndex: number; lastSeq: number; block: number; root: string; tx: string };

// ── Verification core, re-exported from the shared browser core (verify-core.js) ──
//
// The pure logic lives ONCE in verify-core.js (also inlined VERBATIM by the offline exhibit and
// vendored byte-identical into verifier/). Here we only re-attach the TypeScript types dropped when
// the core was made browser-runnable — the casts are PACKAGING, not logic. Behavior is proven
// unchanged by the (untouched) parity/rail fixtures and the Python control verifier.

export const recomputePayloadHash = _recomputePayloadHash as (payload: Record<string, unknown>, canon: "v1" | "v2") => Promise<string>;
export const recomputeChainHash = _recomputeChainHash as (agentId: string, seq: number, prevHash: string, payloadHash: string) => Promise<string>;
export const recomputeRootFromProof = _recomputeRootFromProof as (leaf: string, steps: Array<{ sibling: string; position: "left" | "right" }>, singleLeafBatch: boolean) => Promise<string>;
export const recomputeAndAssess = _recomputeAndAssess as unknown as (bundle: ProofBundle, onChainRoot: string | null, onChainReachable?: boolean, onChainStatus?: string | null) => Promise<VerificationView>;
export const checkpointFor = _checkpointFor as (agentId: string) => AnchorCheckpoint | undefined;
export const REFERENCE_SEED_IDS = _REFERENCE_SEED_IDS as Set<number>;
export const LAST_KNOWN_ANCHORS = _LAST_KNOWN_ANCHORS as ReadonlyArray<AnchorCheckpoint>;

// ── On-chain read (Base mainnet, public RPC) — TRANSPORT, stays per-consumer ─────
//
// Reads the anchored root straight from YoloAuditAnchor via a public Base RPC, matched by
// seq RANGE (never index — on-chain count != DB count after the RLS re-anchor incident).
// Returns the on-chain root (64-hex lowercase) or null if no matching on-chain anchor.

const ANCHOR_ABI = parseAbi([
  "function getAnchorCount(string agentId) view returns (uint256)",
  "function getAnchor(string agentId, uint256 index) view returns (bytes32 merkleRoot, string ipfsCid, uint32 logCount, uint64 firstSeq, uint64 lastSeq, uint32 anchoredAt)",
]);

export async function readOnChainRoot(agentId: string, firstSeq: number, lastSeq: number): Promise<string | null> {
  const address = process.env.NEXT_PUBLIC_AUDIT_ANCHOR_ADDRESS as `0x${string}` | undefined;
  if (!address) throw new Error("NEXT_PUBLIC_AUDIT_ANCHOR_ADDRESS not set");

  // Default public Base RPC is heavily rate-limited (iterating getAnchor trips it). Allow a
  // reliable public endpoint via NEXT_PUBLIC_BASE_RPC_URL; still client-side, still Base.
  const rpcUrl = process.env.NEXT_PUBLIC_BASE_RPC_URL || "https://mainnet.base.org";
  const client = createPublicClient({ chain: base, transport: http(rpcUrl) });
  const count = (await client.readContract({ address, abi: ANCHOR_ABI, functionName: "getAnchorCount", args: [agentId] })) as bigint;

  for (let i = 0n; i < count; i++) {
    const res = (await client.readContract({ address, abi: ANCHOR_ABI, functionName: "getAnchor", args: [agentId, i] })) as readonly [string, string, number, bigint, bigint, number];
    const [merkleRoot, , , fSeq, lSeq] = res;
    if (Number(fSeq) === firstSeq && Number(lSeq) === lastSeq) {
      return merkleRoot.replace(/^0x/i, "").toLowerCase();
    }
  }
  return null;
}
