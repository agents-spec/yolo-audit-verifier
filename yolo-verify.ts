/**
 * yolo-verify.ts — Node CLI using the bundled verify-client.ts (the EXACT logic the Yolo
 * /verify page runs). Independent of the Python verifier; the two agreeing on real data is the
 * cross-language trust proof. On-chain read here is Approach A (getAnchor by seq-range) —
 * distinct from the Python tool's Approach B (read the anchoring tx). Two methods, same root.
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
const EXIT: Record<VerificationView["state"], number> = {
  verified: 0, pending_anchor: 2, anchored_payload_anomaly: 3,
  onchain_unconfirmed: 4, anchor_root_mismatch: 5, payload_hash_mismatch: 6,
  reference_seed: 7, // pre-Strict-B / development reference-seed entry — chain membership only, not a production decision
};

const flag = (name: string): string | undefined => {
  const i = process.argv.indexOf(name);
  return i >= 0 ? process.argv[i + 1] : undefined;
};

async function main() {
  // RPC precedence: --rpc > NEXT_PUBLIC_BASE_RPC_URL > public default (mainnet.base.org).
  // Public RPCs are rate-limited; pass --rpc for reliability (Approach A iterates getAnchor).
  const rpc = flag("--rpc");
  if (rpc) process.env.NEXT_PUBLIC_BASE_RPC_URL = rpc;
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

  let onChainRoot: string | null = null;
  if (bundle.anchored && bundle.anchor) {
    try {
      onChainRoot = await readOnChainRoot(bundle.entry.agent_id, bundle.anchor.batch.first_seq, bundle.anchor.batch.last_seq);
    } catch { onChainRoot = null; }
  }
  const view = await recomputeAndAssess(bundle, onChainRoot);

  if (asJson) {
    console.log(JSON.stringify({ id: bundle.entry.id, verdict: view.state, verified: view.verified, checks: view.checks }, null, 2));
    process.exit(EXIT[view.state]);
  }

  const host = (() => { try { return new URL(process.env.NEXT_PUBLIC_BASE_RPC_URL!).host; } catch { return "(default)"; } })();
  console.log(`\nYolo audit verifier (Node/verify-client) — entry #${bundle.entry.id}`);
  console.log(`RPC: ${host}\n`);
  for (const c of view.checks) {
    const mark = c.result === "pass" ? "PASS" : c.result === "fail" ? "FAIL" : " -- ";
    console.log(`  [${mark}] ${c.label}${c.detail ? `  (${c.detail})` : ""}`);
  }
  if (view.serverClassification) console.log(`\n  operator classification: ${view.serverClassification}`);
  console.log(`\nVERDICT: ${view.state.toUpperCase()} ${view.verified ? "✓" : ""}`);
  console.log(`  ${view.headline}`);
  process.exit(EXIT[view.state]);
}

main().catch((e) => { console.error("error:", e instanceof Error ? e.message : e); process.exit(1); });
