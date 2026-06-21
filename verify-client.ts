// verify-client.ts — vendored copy for the standalone Yolo audit verifier (no app dependency).
// Byte-for-byte the BODY of the Yolo app's client-side verification logic; a drift-guard test in
// the main repo keeps the two in lockstep. Recomputes payload_hash -> chain_hash -> Merkle root
// with Web Crypto and reads the anchored root from Base via viem — trusting your runtime + Base,
// never Yolo. Reference/seed entries may have their payload withheld (_redacted): the payload-hash
// recompute is then skipped and the entry is confirmed by Merkle membership alone.

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
  // Present only for ids on the frozen reference/seed allowlist (lib/audit-proof.ts). `redacted`
  // means the readable payload was withheld → the client skips payload-hash recompute (membership only).
  classification?: { kind: string; label: string; redacted: boolean; reason: string };
};

export type ClientCheck = { label: string; result: "pass" | "fail" | "skip"; detail?: string };

export type VerificationView = {
  state: "verified" | "pending_anchor" | "anchor_root_mismatch" | "anchored_payload_anomaly" | "payload_hash_mismatch" | "rpc_unreachable" | "anchor_absent" | "reference_seed";
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

// ── Reference/seed allowlist (verifier self-enforced) ───────────────────────────
//
// Frozen mirror of the REFERENCE_SEED_ENTRIES ids in lib/audit-proof.ts. The Merkle-membership-only
// skip (no payload re-hash) is granted ONLY when the server bundle classifies an entry reference_seed
// AND its id is on THIS list — so a server cannot grant the payload-skip for an arbitrary id. Kept in
// lockstep with lib/audit-proof.ts and verifier/reference-seed-allowlist.json by
// test/verifier-reference-seed-sync.test.ts.
export const REFERENCE_SEED_IDS = new Set<number>([
  2, 3, 4, 5, 6, 9, 10, 11, 14, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33,
]);

// ── Last-known-anchor checkpoints (zero-dependency floor, per agent) ────────────
//
// One committed checkpoint per agent: that agent's highest confirmed on-chain anchor, taken from the
// immutable anchorBatch tx's own calldata (agentId/root/lastSeq), cross-checked against the anchor
// record, with tx.to = YoloAuditAnchor and receipt status = success. Real, independently-verifiable
// (decode each tx on Basescan) — so "anchor absent" can be told apart from "RPC unreachable" WITHOUT
// trusting any single RPC. When a REACHABLE RPC reports no matching anchor for an entry whose agent has
// a checkpoint here and whose seq is at/below that checkpoint's lastSeq, the absence is corroborated
// (the contract demonstrably anchored that agent past it) — a HARD anchor_absent, not RPC lag. Mirror
// of verifier/last-known-anchor.json (`checkpoints`), tied by test/verifier-reference-seed-sync.test.ts.
export type AnchorCheckpoint = { agentId: string; anchorIndex: number; lastSeq: number; block: number; root: string; tx: string };
export const LAST_KNOWN_ANCHORS: ReadonlyArray<AnchorCheckpoint> = [
  { agentId: "48e7d993-5534-4f01-ad03-fbcdb4b8afd2", anchorIndex: 0,  lastSeq: 0,  block: 46016574, root: "7bfd8da730d693bff67dc36f97c173ba3a523f0eba9dedc3dea28ad5077d3332", tx: "0x7b99ee4d1159ba45d252a489e5ec705511263bf936ee085c450f325bf044479a" },
  { agentId: "4fbe49c2-89f5-44e4-a995-89115f767217", anchorIndex: 22, lastSeq: 51, block: 47523729, root: "e61f3317e2628bcf5448a92dc65b251fdea42e232b71b23be177f25b81acae82", tx: "0x9a5e17bff77aef2483c79c1c383169bb200a990a18a080c79a603eb3c8b8d099" },
  { agentId: "62181681-4007-4252-9b9c-7e537fa0e785", anchorIndex: 0,  lastSeq: 0,  block: 46016579, root: "ffb31ce73f4ef3f3341000c79d8eb4cb3afb32105650cf049c3703f7975fd799", tx: "0xe8b0ffb73698555de219dfc18af277c59c240e398b9971b51f2dd15b48583b1f" },
  { agentId: "78dfb9a0-35c8-49d3-8ea3-127bb359260f", anchorIndex: 0,  lastSeq: 0,  block: 46016582, root: "d2ef81e884532729bb8a2cd5aeab9cda217186247292465e8f5835c3596788dd", tx: "0x345912d33cd5982cc97e3a3b4cb55a2cf5d1aede2a9c1cd48c78e20f30178f12" },
  { agentId: "9251890e-3a04-4082-bfff-59170cc59da1", anchorIndex: 0,  lastSeq: 0,  block: 46016584, root: "10622df66014dedf64c5d22217567eb64eec1ab257e2a364fd6f3c1d4d64f519", tx: "0x7235559d48e0aaf2714089dbe9f25e84872296c5d405043e21324d9a722f45cf" },
  { agentId: "c8bf3f0e-8b63-400a-b1cf-c3144c6a04a3", anchorIndex: 0,  lastSeq: 1,  block: 46016587, root: "91a917fb1caeadbbdd897e56a268592734f21c6dedf28e96885061ac0d3d70b7", tx: "0xce63b5c5d04459bbb7945da431abdd24276f559ca6e62859b44226970862a694" },
  { agentId: "d54d8310-96f3-446c-b141-08a0db7d7093", anchorIndex: 0,  lastSeq: 0,  block: 47512821, root: "2b5af082d9bdd2f184908d8f2de3db454ee9c72faa1b56813926e70dd258fe35", tx: "0x36b3df17d7b87ab1e294b4f54a9bb399230d3a2af51c8492ccf314d61d76a3f3" },
];

// Returns the committed checkpoint for an agent, or undefined if none.
export function checkpointFor(agentId: string): AnchorCheckpoint | undefined {
  return LAST_KNOWN_ANCHORS.find((c) => c.agentId === agentId);
}

// ── Verdict ─────────────────────────────────────────────────────────────────────
//
// PURE given (bundle, onChainRoot). onChainRoot: 64-hex string if read from Base, or null
// if the entry isn't anchored OR the Base read was unavailable (distinguished by anchored).

// onChainReachable distinguishes the two null-root causes: false = no RPC answered (transport
// failure, "unreachable"); true = a reachable RPC gave a definitive answer but no matching anchor was
// found ("absent"). The read layer (browser/Node/Python) sets it; the verdict logic stays pure.
export async function recomputeAndAssess(bundle: ProofBundle, onChainRoot: string | null, onChainReachable = false): Promise<VerificationView> {
  const canon = (bundle.entry.canon_version ?? "v1") as "v1" | "v2";
  // Reference/seed entries may have their readable payload WITHHELD (`_redacted`). When withheld
  // there is nothing to recompute: payload + chain-hash checks are SKIPPED (null) and the entry is
  // confirmed by Merkle membership alone. Non-redacted entries get the full unchanged recompute.
  // Self-enforced: the server SAYING reference_seed is necessary but NOT sufficient — the id must also
  // be on the verifier's own frozen allowlist. A non-allowlisted id claiming reference_seed is verified
  // as a NORMAL entry (payload re-hashed); the membership-only skip is never granted on server say-so.
  const localRefSeed = REFERENCE_SEED_IDS.has(bundle.entry.id);
  const isRefSeed = bundle.classification?.kind === "reference_seed" && localRefSeed;
  // The withheld-payload skip is honored ONLY for an allowlisted id. If the server withheld the payload
  // for a non-allowlisted id, do NOT skip: the redaction marker won't re-hash → payload_hash_mismatch.
  const redacted  = ((bundle.entry.payload as { _redacted?: unknown })?._redacted === true) && localRefSeed;
  const serverClassification = bundle.classification?.reason ?? bundle.checks?.payload_hash?.reason;

  // Attestation scope — derived from canon_version + reference/seed, surfaced in EVERY verdict so an
  // auditor sees how much was actually bound. v1 binds only top-level keys (nested keys collapse), v2
  // binds the full payload, reference/seed is membership-only (payload not re-hashed).
  const canonScope = canon === "v2" ? "full payload bound" : "top-level only — nested keys not bound";
  const scope = isRefSeed ? "Merkle-membership only — payload not re-hashed" : canonScope;

  const payloadOk = redacted ? null : (await recomputePayloadHash(bundle.entry.payload, canon)) === bundle.hashes.payload_hash;
  const chainOk   = redacted ? null : (await recomputeChainHash(bundle.entry.agent_id, bundle.entry.seq, bundle.entry.prev_hash, bundle.hashes.payload_hash)) === bundle.hashes.chain_hash;

  const payloadCheck: ClientCheck = redacted
    ? { label: "Payload re-hashes to its payload_hash", result: "skip", detail: "payload withheld (reference/seed) — membership only" }
    : { label: "Payload re-hashes to its payload_hash", result: payloadOk ? "pass" : "fail", detail: payloadOk ? canonScope : undefined };
  const chainCheck: ClientCheck = redacted
    ? { label: "Chain hash binds the payload to this entry", result: "skip", detail: "payload withheld (reference/seed)" }
    : { label: "Chain hash binds the payload to this entry", result: chainOk ? "pass" : "fail" };

  // PENDING — no anchor yet. We can still confirm the payload binding in-browser (when served).
  if (!bundle.anchored || !bundle.anchor || !bundle.merkle_proof) {
    return {
      state: "pending_anchor",
      scope,
      verified: false,
      tone: "neutral",
      headline: "Recorded — not yet anchored on-chain",
      note: "This entry is in the append-only log but has not been anchored on Base yet. A Merkle anchor will exist after the next nightly anchor. Do not treat this entry as anchored.",
      checks: [
        payloadCheck,
        chainCheck,
        { label: "Merkle proof reconciles to an anchored root", result: "skip", detail: "no anchor yet" },
        { label: "Anchored root matches Base mainnet", result: "skip", detail: "no anchor yet" },
      ],
      serverClassification,
    };
  }

  const recomputedRoot  = await recomputeRootFromProof(bundle.merkle_proof.leaf, bundle.merkle_proof.steps, bundle.merkle_proof.single_leaf_batch);
  const apiRoot         = bundle.anchor.root.toLowerCase();
  const merkleMatchesApi = recomputedRoot === apiRoot;
  const onChainOk        = onChainRoot !== null ? recomputedRoot === onChainRoot.toLowerCase() : null;

  const checks: ClientCheck[] = [
    payloadCheck,
    chainCheck,
    {
      label: "Merkle proof reconciles to the proof's root",
      result: merkleMatchesApi ? "pass" : "fail",
      detail: merkleMatchesApi ? undefined : `recomputed ${recomputedRoot.slice(0, 12)}… ≠ claimed ${apiRoot.slice(0, 12)}…`,
    },
    {
      label: "Recomputed root matches the root anchored on Base",
      result: onChainOk === null ? "skip" : onChainOk ? "pass" : "fail",
      detail: onChainOk === null
        ? (onChainReachable ? "no matching anchor found on Base for this seq range" : "could not reach a Base RPC")
        : onChainOk ? undefined : "recomputed root is NOT the one anchored on Base",
    },
  ];

  // (1) Structurally invalid: the proof doesn't reconcile to the claimed root, OR the claimed root
  // isn't the one on Base. A GENUINE failure — surfaced even for reference/seed entries (a label
  // never hides a real integrity problem; this is how id 14's corrupt anchor still reads "bad").
  if (!merkleMatchesApi || onChainOk === false) {
    return {
      state: "anchor_root_mismatch",
      scope,
      verified: false,
      tone: "bad",
      headline: "Anchor proof INVALID — do not trust",
      note: !merkleMatchesApi
        ? "Your browser recomputed the Merkle root from this proof and it does NOT match the root in the bundle. The anchor data is inconsistent — this entry is NOT verifiably anchored."
        : "Your browser recomputed the Merkle root and it does NOT match the root anchored on Base mainnet. Do not trust this proof.",
      checks,
      serverClassification,
    };
  }

  // (2) Root is sound, but the payload does not bind to it. Only meaningful when the payload is
  // SERVED — skipped for redacted reference/seed entries (there is no payload to bind).
  if (!redacted && (!payloadOk || !chainOk)) {
    const known = bundle.checks?.payload_hash?.status === "known_legacy_anomaly";
    return {
      state: known ? "anchored_payload_anomaly" : "payload_hash_mismatch",
      scope,
      verified: false,
      tone: known ? "warn" : "bad",
      headline: known
        ? "Anchored, but payload integrity NOT confirmed (documented legacy anomaly)"
        : "INTEGRITY FAILURE — payload does not match its hash",
      note: known
        ? "Your browser confirmed this entry's chain hash is anchored on Base, but the stored payload does NOT re-hash to its recorded payload_hash. The operator classifies this as a documented legacy anomaly — NOT tampering — but it cannot be shown as fully verified."
        : "Your browser confirmed the Merkle anchor, but the stored payload does NOT re-hash to its recorded payload_hash and this is not a known legacy anomaly. Treat as a potential integrity issue.",
      checks,
      serverClassification,
    };
  }

  // (R) Reference/seed: Merkle membership is sound (and, when served, the payload binds too). This
  // is real anchored chain history but NOT a production decision — shown NEUTRAL, never green.
  if (isRefSeed) {
    const onChainConfirmed = onChainOk === true;
    return {
      state: "reference_seed",
      scope,
      verified: false,
      tone: "neutral",
      headline: "REFERENCE / SEED ENTRY — not a production decision",
      note:
        (redacted
          ? "A pre-Strict-B substrate-test entry from Yolo's development phase; its readable payload is withheld. "
          : "A development-phase reference/seed entry, not a production decision. ") +
        (onChainConfirmed
          ? "Your browser confirmed its chain hash is anchored on Base mainnet — Merkle membership verified" +
            (redacted ? "; the payload-hash recompute is skipped because the payload is withheld." : ".")
          : (onChainReachable
            ? "The Merkle proof reconciles to the bundle's root, but a reachable Base RPC found no matching anchor on-chain for this seq range."
            : "The Merkle proof reconciles to the bundle's root, but no Base RPC was reachable to confirm it on-chain — retry, or open the tx on Basescan.")) +
        " It is labeled reference/seed so it is never mistaken for a production record.",
      checks,
      serverClassification,
    };
  }

  // (3) All in-browser checks pass but the anchored root could not be CONFIRMED on Base. Split the two
  // genuinely different causes — never collapse "couldn't look" with "looked, nothing there":
  if (onChainOk === null) {
    // (3a) rpc_unreachable — every RPC transport failed. A connectivity problem, NOT evidence of absence.
    if (!onChainReachable) {
      return {
        state: "rpc_unreachable",
        scope,
        verified: false,
        tone: "warn",
        headline: "Recomputed in your browser ✓ — Base RPC unreachable",
        note: "Your browser independently recomputed the payload hash, chain hash, and Merkle root, and they all match the proof. No Base RPC was reachable to confirm the root on-chain — this is a connectivity problem, NOT evidence the anchor is missing. Retry, or pass a reliable RPC.",
        checks,
      };
    }
    // (3b) anchor_absent — a REACHABLE RPC returned no matching anchor for this seq range. The claimed
    // anchor is not on Base. Hardened by THIS agent's committed checkpoint when the entry's seq is
    // at/below it (so the absence cannot be RPC lag behind a known anchored head). An agent with no
    // checkpoint falls back to the honest single-RPC label.
    const floor = checkpointFor(bundle.entry.agent_id);
    const floorHard = floor !== undefined && bundle.anchor.batch.last_seq <= floor.lastSeq;
    return {
      state: "anchor_absent",
      scope,
      verified: false,
      tone: "bad",
      headline: "NO ANCHOR ON BASE — the claimed anchor is not on-chain",
      note:
        "Your browser recomputed the payload hash, chain hash, and Merkle root from the bundle, but a reachable Base RPC returned NO matching anchor for this entry's seq range. The proof claims an anchor that is not on Base mainnet — do not treat this entry as anchored." +
        (floorHard
          ? ` Corroborated by this agent's committed last-known-anchor checkpoint (${floor!.agentId.slice(0, 8)}… anchored through seq ${floor!.lastSeq} at block ${floor!.block}), so this absence is not RPC lag behind a known anchored head.`
          : " (Confirmed against a single reachable RPC; not covered by the committed checkpoint floor.)"),
      checks,
    };
  }

  // (4) Fully sound production entry: payload binds, Merkle reconciles, root is the one on Base.
  return {
    state: "verified",
    scope,
    verified: true,
    tone: "ok",
    headline: `VERIFIED — ${scope} — independently recomputed in your browser`,
    note: "Your browser recomputed the payload hash, the chain hash, and the Merkle root from the proof bundle, and confirmed that root is the one anchored on Base mainnet. This required no trust in Yolo's servers.",
    checks,
  };
}
