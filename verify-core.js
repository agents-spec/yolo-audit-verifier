// verify-core.js — SHARED, browser-runnable verification CORE for the Yolo audit verifier.
// Single source of truth for the pure verification logic: recompute payload_hash -> chain_hash
// -> Merkle root with Web Crypto, fold the verdict, and PARSE the on-chain anchorBatch calldata.
// Contains NO transport: the RPC read (viem/fetch in a JS consumer, urllib in the Python verifier)
// lives in each consumer and hands its result to parseAnchorBatchCalldata / recomputeAndAssess.
//
// recomputeAndAssess + the recompute primitives run in a bare browser <script> with no build step
// (only TypeScript annotations/`as`-casts were dropped from the source). verify-client.ts re-attaches
// those types and adds its own transport; the Python verifier (yolo-verify.py) mirrors this logic
// exactly, held in lockstep by shared parity fixtures.
//
// Uses globalThis.crypto.subtle (browsers over HTTPS, Node 20+). Zero dependencies.

// ── Primitives (Web Crypto + canonicalizers copied verbatim from audit-chain.ts) ─

async function sha256Hex(input) {
  const data = new TextEncoder().encode(input);
  const digest = await globalThis.crypto.subtle.digest("SHA-256", data);
  return Array.from(new Uint8Array(digest)).map((b) => b.toString(16).padStart(2, "0")).join("");
}

function legacyCanonicalize(payload) {
  return JSON.stringify(payload, Object.keys(payload).sort());
}

function jcsCanonicalize(value) {
  if (Array.isArray(value)) return "[" + value.map(jcsCanonicalize).join(",") + "]";
  if (value !== null && typeof value === "object") {
    const obj = value;
    const keys = Object.keys(obj).sort();
    return "{" + keys.map((k) => JSON.stringify(k) + ":" + jcsCanonicalize(obj[k])).join(",") + "}";
  }
  return JSON.stringify(value);
}

export async function recomputePayloadHash(payload, canon) {
  return sha256Hex(canon === "v2" ? jcsCanonicalize(payload) : legacyCanonicalize(payload));
}

export async function recomputeChainHash(agentId, seq, prevHash, payloadHash) {
  return sha256Hex(`${agentId}:${seq}:${prevHash}:${payloadHash}`);
}

// Mirrors computeMerkleRoot/verifyMerkleProof but RETURNS the recomputed root so it can be
// compared to both the bundle's claimed root and the on-chain root. Single-leaf asymmetry:
// root = sha256(leaf), not leaf.
export async function recomputeRootFromProof(
  leaf,
  steps,
  singleLeafBatch,
) {
  if (singleLeafBatch) return sha256Hex(leaf);
  let acc = leaf;
  for (const step of steps) {
    acc = step.position === "left" ? await sha256Hex(step.sibling + acc) : await sha256Hex(acc + step.sibling);
  }
  return acc;
}

// ── On-chain anchorBatch calldata PARSE (Approach B, transport-free) ─────────────
//
// Public, auditor-confirmable constants (Base mainnet, chain 8453). Identical to the Python
// verifier's (yolo-verify.py): YoloAuditAnchor address + the anchorBatch() 4-byte selector.
export const ANCHOR_ADDRESS = "0xdf5e1c1e82880c0e9dce3758a58e62189ca365fd"; // YoloAuditAnchor (lowercased)
export const ANCHOR_BATCH_SELECTOR = "0x370dd8ba"; // keccak256("anchorBatch(string,bytes32,string,uint32,uint64,uint64)")[:4]

// Pure parse of the anchoring tx's PUBLIC calldata — the highest-stakes step, shared so no
// consumer reimplements it. Transport fetches the tx + receipt; this decodes them. Byte-for-byte
// the logic of yolo-verify.py::_decode_anchor_tx (proven by the Python parity fixture).
//   anchorBatch(string agentId, bytes32 merkleRoot, string ipfsCid, uint32 logCount,
//               uint64 firstSeq, uint64 lastSeq); merkleRoot = word 1; firstSeq/lastSeq = words 4/5.
// Returns { root, status, note } where status is:
//   "found"    — a valid anchorBatch tx for THIS exact batch; root is its merkleRoot.
//   "absent"   — the source answered but there is no such tx (a reachable "no match").
//   "mismatch" — a tx exists but is NOT a valid anchor of this batch (wrong to / selector / seq /
//                failed receipt). Transport failures are the caller's concern (treated "unreachable").
export function parseAnchorBatchCalldata(tx, receipt, anchorAddr, txHash, expFirst, expLast) {
  if (tx === null || tx === undefined) return { root: null, status: "absent", note: "no such anchor tx (reachable source returned no tx)" };
  const to = (tx.to || "").toLowerCase();
  if (to !== anchorAddr) return { root: null, status: "mismatch", note: `tx.to ${to} != anchor ${anchorAddr}` };
  const data = tx.input;
  if (!data.startsWith(ANCHOR_BATCH_SELECTOR)) return { root: null, status: "mismatch", note: `selector ${data.slice(0, 10)} != anchorBatch ${ANCHOR_BATCH_SELECTOR}` };
  const body = data.slice(10); // strip "0x" + 8-hex selector
  const word = (i) => body.slice(i * 64, (i + 1) * 64);
  const root = word(1).toLowerCase();
  const firstSeq = parseInt(word(4), 16), lastSeq = parseInt(word(5), 16);
  if (firstSeq !== expFirst || lastSeq !== expLast) return { root: null, status: "mismatch", note: `tx batch seq[${firstSeq}-${lastSeq}] != bundle seq[${expFirst}-${expLast}]` };
  // Receipt gate — the ONLY thing separating "someone CLAIMED this root" from "this root was
  // ANCHORED". A reverted tx still carries well-formed calldata (anyone can send an anchorBatch call
  // with any root and let it revert), so an unconfirmed root must NEVER reach a comparison: return a
  // root iff the receipt confirms success. Three distinct outcomes, never collapsed:
  //   receipt null / indeterminate status -> "unconfirmed" (reachable, read calldata, receipt not
  //       confirmed) — unreachable-CLASS, NOT evidence against the anchor. root stays null.
  //   receipt.status === "0x0" (or any confirmed non-0x1) -> "mismatch" — a confirmed revert, a real
  //       negative, stays red. root stays null.
  //   receipt.status === "0x1" -> "found" — confirmed; only NOW is a root returned.
  const status = receipt ? receipt.status : null;
  if (status === null || status === undefined) {
    return { root: null, status: "unconfirmed", note: `read tx ${txHash.slice(0, 10)}… and its calldata, but the receipt is missing/indeterminate — the tx's success could not be confirmed. Unconfirmed calldata proves nothing (a failed tx still carries calldata); NOT evidence against the anchor.` };
  }
  if (status !== "0x1") return { root: null, status: "mismatch", note: `tx not successful (status=${status})` };
  return { root, status: "found", note: `tx ${txHash.slice(0, 10)}…` };
}

// ── Reference/seed allowlist (verifier self-enforced) ───────────────────────────
//
// Frozen mirror of the REFERENCE_SEED_ENTRIES ids in lib/audit-proof.ts. The Merkle-membership-only
// skip (no payload re-hash) is granted ONLY when the server bundle classifies an entry reference_seed
// AND its id is on THIS list — so a server cannot grant the payload-skip for an arbitrary id. Kept in
// lockstep with lib/audit-proof.ts and verifier/reference-seed-allowlist.json by
// test/verifier-reference-seed-sync.test.ts.
export const REFERENCE_SEED_IDS = new Set([
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
export const LAST_KNOWN_ANCHORS = [
  { agentId: "48e7d993-5534-4f01-ad03-fbcdb4b8afd2", anchorIndex: 0,  lastSeq: 0,  block: 46016574, root: "7bfd8da730d693bff67dc36f97c173ba3a523f0eba9dedc3dea28ad5077d3332", tx: "0x7b99ee4d1159ba45d252a489e5ec705511263bf936ee085c450f325bf044479a" },
  { agentId: "4fbe49c2-89f5-44e4-a995-89115f767217", anchorIndex: 22, lastSeq: 51, block: 47523729, root: "e61f3317e2628bcf5448a92dc65b251fdea42e232b71b23be177f25b81acae82", tx: "0x9a5e17bff77aef2483c79c1c383169bb200a990a18a080c79a603eb3c8b8d099" },
  { agentId: "62181681-4007-4252-9b9c-7e537fa0e785", anchorIndex: 0,  lastSeq: 0,  block: 46016579, root: "ffb31ce73f4ef3f3341000c79d8eb4cb3afb32105650cf049c3703f7975fd799", tx: "0xe8b0ffb73698555de219dfc18af277c59c240e398b9971b51f2dd15b48583b1f" },
  { agentId: "78dfb9a0-35c8-49d3-8ea3-127bb359260f", anchorIndex: 0,  lastSeq: 0,  block: 46016582, root: "d2ef81e884532729bb8a2cd5aeab9cda217186247292465e8f5835c3596788dd", tx: "0x345912d33cd5982cc97e3a3b4cb55a2cf5d1aede2a9c1cd48c78e20f30178f12" },
  { agentId: "9251890e-3a04-4082-bfff-59170cc59da1", anchorIndex: 0,  lastSeq: 0,  block: 46016584, root: "10622df66014dedf64c5d22217567eb64eec1ab257e2a364fd6f3c1d4d64f519", tx: "0x7235559d48e0aaf2714089dbe9f25e84872296c5d405043e21324d9a722f45cf" },
  { agentId: "c8bf3f0e-8b63-400a-b1cf-c3144c6a04a3", anchorIndex: 0,  lastSeq: 1,  block: 46016587, root: "91a917fb1caeadbbdd897e56a268592734f21c6dedf28e96885061ac0d3d70b7", tx: "0xce63b5c5d04459bbb7945da431abdd24276f559ca6e62859b44226970862a694" },
  { agentId: "d54d8310-96f3-446c-b141-08a0db7d7093", anchorIndex: 0,  lastSeq: 0,  block: 47512821, root: "2b5af082d9bdd2f184908d8f2de3db454ee9c72faa1b56813926e70dd258fe35", tx: "0x36b3df17d7b87ab1e294b4f54a9bb399230d3a2af51c8492ccf314d61d76a3f3" },
];

// Returns the committed checkpoint for an agent, or undefined if none.
export function checkpointFor(agentId) {
  return LAST_KNOWN_ANCHORS.find((c) => c.agentId === agentId);
}

// ── Verdict ─────────────────────────────────────────────────────────────────────
//
// PURE given (bundle, onChainRoot). onChainRoot: 64-hex string if read from Base, or null
// if the entry isn't anchored OR the Base read was unavailable (distinguished by anchored).

// onChainReachable distinguishes the two null-root causes: false = no RPC answered (transport
// failure, "unreachable"); true = a reachable RPC gave a definitive answer but no matching anchor was
// found ("absent"). The read layer (browser/Node/Python) sets it; the verdict logic stays pure.
export async function recomputeAndAssess(bundle, onChainRoot, onChainReachable = false, onChainStatus = null) {
  const canon = (bundle.entry.canon_version ?? "v1");
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
  const redacted  = ((bundle.entry.payload)?._redacted === true) && localRefSeed;
  const serverClassification = bundle.classification?.reason ?? bundle.checks?.payload_hash?.reason;

  // Attestation scope — derived from canon_version + reference/seed, surfaced in EVERY verdict so an
  // auditor sees how much was actually bound. v1 binds only top-level keys (nested keys collapse), v2
  // binds the full payload, reference/seed is membership-only (payload not re-hashed).
  const canonScope = canon === "v2" ? "full payload bound" : "top-level only — nested keys not bound";
  const scope = redacted ? "Merkle-membership only — payload not re-hashed" : canonScope;

  const payloadOk = redacted ? null : (await recomputePayloadHash(bundle.entry.payload, canon)) === bundle.hashes.payload_hash;
  const chainOk   = redacted ? null : (await recomputeChainHash(bundle.entry.agent_id, bundle.entry.seq, bundle.entry.prev_hash, bundle.hashes.payload_hash)) === bundle.hashes.chain_hash;

  const payloadCheck = redacted
    ? { label: "Payload re-hashes to its payload_hash", result: "skip", detail: "payload withheld (reference/seed) — membership only" }
    : { label: "Payload re-hashes to its payload_hash", result: payloadOk ? "pass" : "fail", detail: payloadOk ? canonScope : undefined };
  const chainCheck = redacted
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
  const rootReconciles  = recomputedRoot === apiRoot;
  // PARITY with yolo-verify.py L232 (leaf_ok): the proof's leaf must be THIS entry's chain_hash.
  // Without this, a bundle whose leaf is disconnected from the payload but whose leaf-derived root
  // matches the anchor folds an UNRELATED leaf to a real root — the Merkle step would read "pass"
  // while proving nothing about this payload. Fold leaf-binding in exactly as Python does
  // (merkle_ok = leaf_ok AND recomputed_root == anchor.root).
  const leafOk          = bundle.merkle_proof.leaf === bundle.hashes.chain_hash;
  const merkleMatchesApi = leafOk && rootReconciles;
  const onChainOk        = onChainRoot !== null ? (leafOk && recomputedRoot === onChainRoot.toLowerCase()) : null;

  const checks = [
    payloadCheck,
    chainCheck,
    {
      label: "Merkle proof reconciles to the proof's root",
      result: merkleMatchesApi ? "pass" : "fail",
      detail: merkleMatchesApi
        ? undefined
        : !leafOk
          ? `proof leaf ${bundle.merkle_proof.leaf.slice(0, 12)}… ≠ this entry's chain_hash ${bundle.hashes.chain_hash.slice(0, 12)}… — leaf not bound to the payload`
          : `recomputed ${recomputedRoot.slice(0, 12)}… ≠ claimed ${apiRoot.slice(0, 12)}…`,
    },
    {
      label: "Recomputed root matches the root anchored on Base",
      result: onChainStatus === "mismatch" ? "fail" : onChainOk === null ? "skip" : onChainOk ? "pass" : "fail",
      detail: onChainStatus === "mismatch"
        ? "the referenced tx is not a valid anchorBatch of this batch — do not trust"
        : onChainOk === null
        ? (onChainStatus === "unconfirmed" ? "reached Base and read the calldata, but the tx receipt could not be confirmed — not evidence against the anchor"
          : onChainReachable ? "no matching anchor found on Base for this seq range"
          : "could not reach a Base RPC")
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
        ? (!leafOk
            ? "The Merkle proof's leaf is NOT this entry's chain_hash. The proof folds an unrelated leaf to the anchored root, so it proves nothing about THIS entry's payload — do not trust this proof."
            : "Your browser recomputed the Merkle root from this proof and it does NOT match the root in the bundle. The anchor data is inconsistent — this entry is NOT verifiably anchored.")
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

  // (3) All in-browser checks pass (payload binds, Merkle reconciles) but the anchored root could not
  // be CONFIRMED on Base. THREE genuinely different causes, never collapsed — ranked (mirroring
  // yolo-verify.py's verdict precedence): anchor_absent > receipt_unconfirmed > rpc_unreachable. All
  // rank BELOW the structural/payload negatives that already returned above, so an unconfirmed receipt
  // can NEVER soften a real failure (a payload_hash_mismatch / anchor_root_mismatch stays red even
  // when the receipt is also unconfirmed). This is why the fifth state lives HERE, in the core, once —
  // not in a consumer that could re-order it.
  if (onChainOk === null) {
    // (3a) anchor_mismatch — reachable; the referenced tx is a CONFIRMED non-anchor of this batch
    // (wrong target/selector/seq, or a confirmed 0x0 revert). "Looked, and what's there is WRONG" —
    // a DIFFERENT fact from anchor_absent ("looked, nothing there"). Ranked above anchor_absent, below
    // the payload/merkle negatives (which already returned). Mirrors yolo-verify.py's precedence.
    if (onChainStatus === "mismatch") {
      return {
        state: "anchor_mismatch",
        scope,
        verified: false,
        tone: "bad",
        headline: "ANCHOR MISMATCH — the referenced tx is not a valid anchor of this batch",
        note: "Your browser recomputed the payload hash, chain hash, and Merkle root from the bundle, but the transaction this proof points to is NOT a valid anchorBatch of this entry's batch (wrong target, selector, or seq range, or a failed/reverted tx). The claimed anchor is invalid — do not trust this proof. This is NOT the same as 'no anchor found': an invalid anchor tx exists, it just does not anchor this entry.",
        checks,
      };
    }
    // (3b) anchor_absent — a REACHABLE RPC returned no matching anchor for this seq range (and not the
    // unconfirmed-receipt case). The claimed anchor is not on Base. Hardened by THIS agent's committed
    // checkpoint when the entry's seq is at/below it (so the absence cannot be RPC lag behind a known
    // anchored head). An agent with no checkpoint falls back to the honest single-RPC label.
    if (onChainReachable && onChainStatus !== "unconfirmed") {
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
            ? ` Corroborated by this agent's committed last-known-anchor checkpoint (${floor.agentId.slice(0, 8)}… anchored through seq ${floor.lastSeq} at block ${floor.block}), so this absence is not RPC lag behind a known anchored head.`
            : " (Confirmed against a single reachable RPC; not covered by the committed checkpoint floor.)"),
        checks,
      };
    }
    // (3b) receipt_unconfirmed — reachable, read the tx calldata, but the receipt is missing/indeterminate
    // so the tx's success is unconfirmed. Unconfirmed calldata proves nothing (a failed tx still carries
    // calldata): NOT evidence against the anchor. Ranked below anchor_absent, above rpc_unreachable.
    if (onChainStatus === "unconfirmed") {
      return {
        state: "receipt_unconfirmed",
        scope,
        verified: false,
        tone: "warn",
        headline: "Recomputed in your browser ✓ — anchor receipt unconfirmed",
        note: "Your browser recomputed the payload hash, chain hash, and Merkle root, and they all match the proof. It reached Base and read the anchor transaction and its calldata — but could NOT confirm the transaction receipt, so it cannot say the tx succeeded. Unconfirmed calldata proves nothing (a failed transaction still carries calldata); this is NOT evidence against the anchor. Retry, use another Base RPC, or open the tx on Basescan.",
        checks,
      };
    }
    // (3c) rpc_unreachable — every RPC transport failed. A connectivity problem, NOT evidence of absence.
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
