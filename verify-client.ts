// verify-client.ts — the exact verification logic the Yolo /verify page runs in-browser.
// (Vendored from the Yolo web app so this verifier is fully self-contained; the Python CLI
//  reimplements the same logic independently — the two agreeing is the cross-language proof.)
//
// The whole point: your own machine does the SHA-256 work and reads the anchored root from
// Base — trusting your runtime + Base, not Yolo's say-so. Uses Web Crypto
// (globalThis.crypto.subtle, available in browsers over HTTPS and in Node 20+) and viem for a
// public Base RPC read. The canonicalizers reproduce the Yolo server's payload_hash exactly.
//
// recomputeAndAssess is PURE given (bundle, onChainRoot) — the on-chain root is injected so
// the verdict logic is unit-testable offline; readOnChainRoot does the actual Base read.

import { createPublicClient, http, parseAbi } from "viem";
import { base } from "viem/chains";

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
};

export type ClientCheck = { label: string; result: "pass" | "fail" | "skip"; detail?: string };

export type VerificationView = {
  state: "verified" | "pending_anchor" | "anchor_root_mismatch" | "anchored_payload_anomaly" | "payload_hash_mismatch" | "onchain_unconfirmed";
  verified: boolean;  // true ONLY when fully sound — the green state
  tone: "ok" | "warn" | "bad" | "neutral";
  headline: string;
  note: string;
  checks: ClientCheck[];
  serverClassification?: string; // server's payload_hash.reason, shown as context (never as the verdict)
};

// ── Primitives (Web Crypto + canonicalizers copied verbatim from audit-chain.ts) ─

async function sha256Hex(input: string): Promise<string> {
  const data = new TextEncoder().encode(input);
  const digest = await globalThis.crypto.subtle.digest("SHA-256", data);
  return Array.from(new Uint8Array(digest)).map((b) => b.toString(16).padStart(2, "0")).join("");
}

function legacyCanonicalize(payload: Record<string, unknown>): string {
  return JSON.stringify(payload, Object.keys(payload).sort());
}

function jcsCanonicalize(value: unknown): string {
  if (Array.isArray(value)) return "[" + value.map(jcsCanonicalize).join(",") + "]";
  if (value !== null && typeof value === "object") {
    const obj = value as Record<string, unknown>;
    const keys = Object.keys(obj).sort();
    return "{" + keys.map((k) => JSON.stringify(k) + ":" + jcsCanonicalize(obj[k])).join(",") + "}";
  }
  return JSON.stringify(value);
}

export async function recomputePayloadHash(payload: Record<string, unknown>, canon: "v1" | "v2"): Promise<string> {
  return sha256Hex(canon === "v2" ? jcsCanonicalize(payload) : legacyCanonicalize(payload));
}

export async function recomputeChainHash(agentId: string, seq: number, prevHash: string, payloadHash: string): Promise<string> {
  return sha256Hex(`${agentId}:${seq}:${prevHash}:${payloadHash}`);
}

// Mirrors computeMerkleRoot/verifyMerkleProof but RETURNS the recomputed root so it can be
// compared to both the bundle's claimed root and the on-chain root. Single-leaf asymmetry:
// root = sha256(leaf), not leaf.
export async function recomputeRootFromProof(
  leaf: string,
  steps: Array<{ sibling: string; position: "left" | "right" }>,
  singleLeafBatch: boolean,
): Promise<string> {
  if (singleLeafBatch) return sha256Hex(leaf);
  let acc = leaf;
  for (const step of steps) {
    acc = step.position === "left" ? await sha256Hex(step.sibling + acc) : await sha256Hex(acc + step.sibling);
  }
  return acc;
}

// ── On-chain read (Base mainnet, public RPC) ────────────────────────────────────
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

// ── Verdict ─────────────────────────────────────────────────────────────────────
//
// PURE given (bundle, onChainRoot). onChainRoot: 64-hex string if read from Base, or null
// if the entry isn't anchored OR the Base read was unavailable (distinguished by anchored).

export async function recomputeAndAssess(bundle: ProofBundle, onChainRoot: string | null): Promise<VerificationView> {
  const canon = (bundle.entry.canon_version ?? "v1") as "v1" | "v2";
  const payloadOk = (await recomputePayloadHash(bundle.entry.payload, canon)) === bundle.hashes.payload_hash;
  const chainOk   = (await recomputeChainHash(bundle.entry.agent_id, bundle.entry.seq, bundle.entry.prev_hash, bundle.hashes.payload_hash)) === bundle.hashes.chain_hash;

  // PENDING — no anchor yet. We can still confirm the payload binding in-browser.
  if (!bundle.anchored || !bundle.anchor || !bundle.merkle_proof) {
    return {
      state: "pending_anchor",
      verified: false,
      tone: "neutral",
      headline: "Recorded — not yet anchored on-chain",
      note: "This entry is in the append-only log but has not been anchored on Base yet. Your browser confirmed the payload hashes below; a Merkle anchor will exist after the next nightly anchor. Do not treat this entry as anchored.",
      checks: [
        { label: "Payload re-hashes to its payload_hash", result: payloadOk ? "pass" : "fail" },
        { label: "Chain hash binds the payload to this entry", result: chainOk ? "pass" : "fail" },
        { label: "Merkle proof reconciles to an anchored root", result: "skip", detail: "no anchor yet" },
        { label: "Anchored root matches Base mainnet", result: "skip", detail: "no anchor yet" },
      ],
    };
  }

  const recomputedRoot  = await recomputeRootFromProof(bundle.merkle_proof.leaf, bundle.merkle_proof.steps, bundle.merkle_proof.single_leaf_batch);
  const apiRoot         = bundle.anchor.root.toLowerCase();
  const merkleMatchesApi = recomputedRoot === apiRoot;
  const onChainOk        = onChainRoot !== null ? recomputedRoot === onChainRoot.toLowerCase() : null;
  const serverClassification = bundle.checks?.payload_hash?.reason;

  const checks: ClientCheck[] = [
    { label: "Payload re-hashes to its payload_hash", result: payloadOk ? "pass" : "fail" },
    { label: "Chain hash binds the payload to this entry", result: chainOk ? "pass" : "fail" },
    {
      label: "Merkle proof reconciles to the proof's root",
      result: merkleMatchesApi ? "pass" : "fail",
      detail: merkleMatchesApi ? undefined : `recomputed ${recomputedRoot.slice(0, 12)}… ≠ claimed ${apiRoot.slice(0, 12)}…`,
    },
    {
      label: "Recomputed root matches the root anchored on Base",
      result: onChainOk === null ? "skip" : onChainOk ? "pass" : "fail",
      detail: onChainOk === null ? "could not reach a Base RPC" : onChainOk ? undefined : "recomputed root is NOT the one anchored on Base",
    },
  ];

  // (1) Structurally invalid: the proof doesn't reconcile to the claimed root, OR the
  // claimed root isn't the one on Base. Either way, NOT verifiably anchored.
  if (!merkleMatchesApi || onChainOk === false) {
    return {
      state: "anchor_root_mismatch",
      verified: false,
      tone: "bad",
      headline: "Anchor proof INVALID — do not trust",
      note: !merkleMatchesApi
        ? "Your browser recomputed the Merkle root from this proof and it does NOT match the root in the bundle. The anchor data is inconsistent — this entry is NOT verifiably anchored."
        : "Your browser recomputed the Merkle root and it does NOT match the root anchored on Base mainnet. Do not trust this proof.",
      checks,
    };
  }

  // (2) Root is sound, but the payload does not bind to it.
  if (!payloadOk || !chainOk) {
    const known = bundle.checks?.payload_hash?.status === "known_legacy_anomaly";
    return {
      state: known ? "anchored_payload_anomaly" : "payload_hash_mismatch",
      verified: false,
      tone: known ? "warn" : "bad",
      headline: known
        ? "Anchored, but payload integrity NOT confirmed (documented legacy anomaly)"
        : "INTEGRITY FAILURE — payload does not match its hash",
      note: known
        ? "Your browser confirmed this entry's chain hash is anchored on Base, but the stored payload does NOT re-hash to its recorded payload_hash. The operator classifies this as a documented legacy anomaly (BUG-SEQ0) — NOT tampering — but it cannot be shown as fully verified."
        : "Your browser confirmed the Merkle anchor, but the stored payload does NOT re-hash to its recorded payload_hash and this is not a known legacy anomaly. Treat as a potential integrity issue.",
      checks,
      serverClassification,
    };
  }

  // (3) All in-browser checks pass but Base was unreachable — cannot claim "verified".
  if (onChainOk === null) {
    return {
      state: "onchain_unconfirmed",
      verified: false,
      tone: "warn",
      headline: "Recomputed in your browser ✓ — Base confirmation unavailable",
      note: "Your browser independently recomputed the payload hash, chain hash, and Merkle root, and they all match the proof. It could not reach a Base RPC to confirm the root is the one anchored on-chain — retry, or open the transaction on Basescan.",
      checks,
    };
  }

  // (4) Fully sound: payload binds, Merkle reconciles, and the root is the one on Base.
  return {
    state: "verified",
    verified: true,
    tone: "ok",
    headline: "VERIFIED — independently recomputed in your browser",
    note: "Your browser recomputed the payload hash, the chain hash, and the Merkle root from the proof bundle, and confirmed that root is the one anchored on Base mainnet. This required no trust in Yolo's servers.",
    checks,
  };
}
