/**
 * yolo-verify.ts — Node CLI using the bundled verify-client.ts (the EXACT logic the Yolo
 * /verify page runs). Independent of the Python verifier; the two agreeing on real data is the
 * cross-language trust proof. On-chain read here is Approach A (getAnchor by seq-range) —
 * distinct from the Python tool's Approach B (read the anchoring tx). Two methods, same root.
 *
 * RPC resilience: the on-chain read tries your --rpc (if given) first, then falls back through a
 * curated list of public Base RPCs on rate-limit/transport errors. The zero-flag command verifies
 * clean without you supplying an endpoint; RPC_UNREACHABLE is returned ONLY when every
 * candidate genuinely fails — a confirmation is never faked.
 *
 * Run: npm install && npx tsx yolo-verify.ts <audit_id> [--source URL] [--rpc URL] [--bundle file] [--json]
 */
import * as fs from "fs";

import {
  recomputeAndAssess,
  readOnChainRoot,
  type ProofBundle,
  type VerificationView,
} from "./verify-client";

const PUBLISHED_ANCHOR = "0xDf5e1c1e82880C0E9dce3758A58e62189Ca365FD";

// Curated public Base RPCs, ordered by observed reliability for iterating getAnchor (Approach A).
// publicnode first (handles the iteration without tripping rate limits); mainnet.base.org last as
// the canonical fallback. A --rpc / NEXT_PUBLIC_BASE_RPC_URL value is prepended and tried first.
const PUBLIC_BASE_RPCS = [
  "https://base-rpc.publicnode.com",
  "https://base.llamarpc.com",
  "https://base.drpc.org",
  "https://1rpc.io/base",
  "https://mainnet.base.org",
];

const hostOf = (u: string): string => { try { return new URL(u).host; } catch { return u; } };
const EXIT: Record<VerificationView["state"], number> = {
  verified: 0, pending_anchor: 2, anchored_payload_anomaly: 3,
  rpc_unreachable: 4, anchor_root_mismatch: 5, payload_hash_mismatch: 6,
  reference_seed: 7, // pre-Strict-B / development reference-seed entry — chain membership only, not a production decision
  anchor_absent: 8,  // a reachable RPC found no matching anchor on-chain — the claimed anchor is not on Base
};

const flag = (name: string): string | undefined => {
  const i = process.argv.indexOf(name);
  return i >= 0 ? process.argv[i + 1] : undefined;
};

async function main() {
  // RPC candidates: a --rpc / NEXT_PUBLIC_BASE_RPC_URL value (if given) is tried FIRST, then the
  // curated public fallbacks (deduped, order preserved). Public endpoints rate-limit Approach A's
  // getAnchor iteration, so a single endpoint is fragile — the fallback makes the zero-flag path
  // verify clean while staying honest (RPC_UNREACHABLE only when EVERY candidate fails).
  const rpcOverride = flag("--rpc") ?? process.env.NEXT_PUBLIC_BASE_RPC_URL;
  const rpcCandidates = [...new Set([rpcOverride, ...PUBLIC_BASE_RPCS].filter(Boolean) as string[])];
  if (!process.env.NEXT_PUBLIC_AUDIT_ANCHOR_ADDRESS) process.env.NEXT_PUBLIC_AUDIT_ANCHOR_ADDRESS = PUBLISHED_ANCHOR;

  const source = flag("--source") ?? "https://yolo.solutions";
  const bundleFile = flag("--bundle");
  const asJson = process.argv.includes("--json");
  const idArg = process.argv[2] && !process.argv[2].startsWith("--") ? process.argv[2] : undefined;

  let bundle: ProofBundle;
  if (bundleFile) {
    bundle = JSON.parse(fs.readFileSync(bundleFile, "utf8"));
  } else if (idArg) {
    const res = await fetch(`${source.replace(/\/$/, "")}/api/verify/${idArg}/proof`);
    if (res.status === 404) { console.error(`error: no audit entry with id ${idArg} (404)`); process.exit(1); }
    bundle = (await res.json()) as ProofBundle;
  } else {
    console.error("usage: yolo-verify.ts <audit_id> | --bundle file.json"); process.exit(1); return;
  }

  // Read the anchored root, falling back through the candidate RPCs on transport/rate-limit errors.
  // A reachable RPC returning a definitive answer (a root OR a genuine null) stops the loop — chain
  // state is global, so another RPC would not change it. Only transport failures fall through; if
  // they all fail, onChainRoot stays null and the verdict is the honest RPC_UNREACHABLE.
  let onChainRoot: string | null = null;
  let onChainReachable = false;
  let rpcUsed: string | undefined;
  const rpcErrors: string[] = [];
  if (bundle.anchored && bundle.anchor) {
    for (const candidate of rpcCandidates) {
      process.env.NEXT_PUBLIC_BASE_RPC_URL = candidate;
      try {
        onChainRoot = await readOnChainRoot(bundle.entry.agent_id, bundle.anchor.batch.first_seq, bundle.anchor.batch.last_seq);
        onChainReachable = true; // a reachable RPC answered — a root, or a definitive "no match"
        rpcUsed = candidate;
        break;
      } catch (e) {
        rpcErrors.push(`${hostOf(candidate)} — ${e instanceof Error ? e.message.split("\n")[0] : String(e)}`);
      }
    }
  }
  // onChainReachable=false ⇒ no RPC answered (rpc_unreachable); =true with null root ⇒ a reachable RPC
  // found no matching anchor (anchor_absent). The committed last-known-anchor floor hardens the latter.
  const view = await recomputeAndAssess(bundle, onChainRoot, onChainReachable);

  if (asJson) {
    console.log(JSON.stringify({ id: bundle.entry.id, verdict: view.state, verified: view.verified, rpc: rpcUsed ?? null, checks: view.checks }, null, 2));
    process.exit(EXIT[view.state]);
  }

  const rpcLabel = rpcUsed
    ? `${hostOf(rpcUsed)}${rpcErrors.length ? ` (fell back past ${rpcErrors.length})` : ""}`
    : !bundle.anchored ? "(not queried — entry not anchored)"
    : `(all ${rpcCandidates.length} candidates unreachable)`;
  console.log(`\nYolo audit verifier (Node/verify-client) — entry #${bundle.entry.id}`);
  console.log(`RPC: ${rpcLabel}\n`);
  for (const c of view.checks) {
    const mark = c.result === "pass" ? "PASS" : c.result === "fail" ? "FAIL" : " -- ";
    console.log(`  [${mark}] ${c.label}${c.detail ? `  (${c.detail})` : ""}`);
  }
  if (view.serverClassification) console.log(`\n  operator classification: ${view.serverClassification}`);
  console.log(`\nVERDICT: ${view.state.toUpperCase()} ${view.verified ? "✓" : ""}`);
  console.log(`  ${view.headline}`);
  if (view.state === "rpc_unreachable" && rpcErrors.length) {
    console.log(`\n  every Base RPC was unreachable — tried:`);
    for (const e of rpcErrors) console.log(`    · ${e}`);
    console.log(`  retry later or pass a reliable --rpc; the in-browser recompute above still holds.`);
  }
  process.exit(EXIT[view.state]);
}

main().catch((e) => { console.error("error:", e instanceof Error ? e.message : e); process.exit(1); });
