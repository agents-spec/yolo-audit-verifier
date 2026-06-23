// rail-verify.ts — Rail-agnostic Stage 1, slice 2: the verifier's per-rail confirm step.
//
// ADDITIVE and ORTHOGONAL to the existing Base-anchor verify (verify-client.ts is UNTOUCHED). A
// settlement_receipt entry still gets the normal tamper-evidence verdict from recomputeAndAssess
// first; this module ALSO, independently, confirms the receipt's claimed settlement against the
// foreign rail's ledger and checks the agent's EIP-191 attestation.
//
// HONESTY CONSTRAINT (the whole point — enforced in every verdict + note):
//   This confirms ONLY that the declared settlement tx exists on the rail, succeeded, and that the
//   declared split legs (asset/amount/dest) match the actual on-chain transfers. It does NOT, and
//   must never appear to, assert:
//     (a) protocol-level 1% enforcement on off-ledger rails (proven-and-audited != chain-enforced),
//     (b) completeness — the chain is tamper-evident, NOT omission-evident (cannot prove no other
//         settlements were omitted),
//     (c) anything about transfers outside the declared legs.
//   A stub for an un-wired rail returns rail_unsupported — NEVER a false rail_settlement_confirmed.

import { createPublicClient, http, recoverMessageAddress, type Chain } from "viem";
import { base, baseSepolia } from "viem/chains";
import type { ProofBundle } from "./verify-client";

export const SETTLEMENT_RECEIPT_ACTION_TYPE = "settlement_receipt";

// ── receipt shape (mirrors lib/rail-receipt.ts payload; the receipt IS the hashed entry.payload) ─
export type Enforcement = "chain_enforced" | "attested_off_ledger";
export interface SplitLeg { role: string; dest: string; amount: string; proof?: unknown }
export interface SettlementReceipt {
  schema: string;
  home: { chain: string; nft: string; self_wallet: string };
  rail: string;
  asset: { symbol: string; rail_address: string; decimals: number };
  amount: string;
  counterparty: string;
  proof: { kind: string; tx_hash?: string; ledger_index?: number; signature?: string; slot?: number };
  split: { model: string; rule: { agent_bps: number; treasury_bps: number; owner_bps: number }; legs: SplitLeg[] };
  enforcement: Enforcement;
  settled_at: string;
  attestation: { scheme: string; signer_role: string; signature: string; recovered_signer: string };
  // Stage 2 / x402 (OPTIONAL): the x402 payment that FUNDED this split. Confirmed additively + orthogonally
  // (the funding-leg check below) — it never changes the split verdict or protocolEnforced1pct.
  funding_proof?: {
    source: string; x402_version: number; scheme: string; rail: string; tx_hash: string;
    payer: string; payee: string; asset: { symbol: string; rail_address: string; decimals: number };
    amount: string; invoice_id?: string; facilitator?: string;
  };
}

// The receipt is read FROM the hashed entry.payload (never a copy outside the hash, so the
// rail-checked data is exactly what the Base-anchor verify already bound). Returns null otherwise.
export function getReceiptFromBundle(bundle: ProofBundle): SettlementReceipt | null {
  if (bundle.entry.action_type !== SETTLEMENT_RECEIPT_ACTION_TYPE) return null;
  return bundle.entry.payload as unknown as SettlementReceipt;
}

// JCS canonicalization — copied verbatim from verify-client.ts (vendored verifier duplicates canon,
// keeping this module self-contained; it must reproduce the builder's signing preimage byte-for-byte).
function jcsCanonicalize(value: unknown): string {
  if (Array.isArray(value)) return "[" + value.map(jcsCanonicalize).join(",") + "]";
  if (value !== null && typeof value === "object") {
    const obj = value as Record<string, unknown>;
    const keys = Object.keys(obj).sort();
    return "{" + keys.map((k) => JSON.stringify(k) + ":" + jcsCanonicalize(obj[k])).join(",") + "}";
  }
  return JSON.stringify(value);
}

// ── attestation (EIP-191 over JCS(signed_core); recovered must == home.self_wallet) ─────────────
export type AttestationVerdict = "attestation_valid" | "attestation_invalid";
export async function verifyAttestation(receipt: SettlementReceipt): Promise<{ verdict: AttestationVerdict; recovered: string | null; detail: string }> {
  const { attestation, ...core } = receipt; // signed_core = everything except the attestation block
  const preimage = jcsCanonicalize(core);
  try {
    const recovered = await recoverMessageAddress({ message: preimage, signature: attestation.signature as `0x${string}` });
    const ok = recovered.toLowerCase() === receipt.home.self_wallet.toLowerCase();
    return {
      verdict: ok ? "attestation_valid" : "attestation_invalid",
      recovered,
      detail: ok ? "agent home self_wallet signed this receipt" : `recovered ${recovered} != home.self_wallet ${receipt.home.self_wallet}`,
    };
  } catch (e) {
    return { verdict: "attestation_invalid", recovered: null, detail: `signature malformed: ${(e as Error).message}` };
  }
}

// ── split internal consistency — pure integer re-check, identical to on-chain AgentShareCore ─────
const BPS = 10_000n;
export function checkSplitConsistency(receipt: SettlementReceipt): { ok: boolean; detail: string } {
  try {
    const amount = BigInt(receipt.amount);
    const leg = (role: string) => receipt.split.legs.find((l) => l.role === role);
    const a = leg("agent"), t = leg("treasury"), o = leg("owner");
    if (!a || !t || !o) return { ok: false, detail: "missing a required split leg (agent/treasury/owner)" };
    const expA = (amount * 100n + (BPS - 1n)) / BPS; // ceil-1%, exactly AgentShareCore.agentShare
    const expT = (amount * 200n) / BPS;              // floor-2%
    const expO = amount - expA - expT;               // remainder
    if (BigInt(a.amount) !== expA) return { ok: false, detail: `agent leg ${a.amount} != ceil(1%) ${expA}` };
    if (BigInt(t.amount) !== expT) return { ok: false, detail: `treasury leg ${t.amount} != floor(2%) ${expT}` };
    if (BigInt(o.amount) !== expO) return { ok: false, detail: `owner leg ${o.amount} != remainder ${expO}` };
    if (BigInt(a.amount) + BigInt(t.amount) + BigInt(o.amount) !== amount) return { ok: false, detail: "legs do not sum to amount" };
    return { ok: true, detail: "legs sum to amount; agent == ceil(1%) (AgentShareCore rule)" };
  } catch {
    return { ok: false, detail: "non-integer amount or leg amount" };
  }
}

// ── per-rail reader (mirrors the existing viem on-chain reader; stubs un-wired rails) ────────────
const TRANSFER_TOPIC = "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"; // keccak256("Transfer(address,address,uint256)")
export type RailTransfer = { token: string; to: string; amount: string }; // lowercased; amount in base-units
export type RailRead =
  | { kind: "unsupported"; detail: string }
  | { kind: "unreachable"; detail: string }
  | { kind: "absent"; detail: string }          // reachable, but tx not found / not successful
  | { kind: "found"; transfers: RailTransfer[] }; // tx succeeded; its ERC-20 Transfer events

// viem chains for the EVM rails we can confirm today; extend as more EVM rails are needed.
const EVM_CHAINS: Record<string, Chain> = { "eip155:8453": base, "eip155:84532": baseSepolia };
const DEFAULT_RPCS: Record<string, string> = { "eip155:8453": "https://mainnet.base.org", "eip155:84532": "https://sepolia.base.org" };

function railRpc(rail: string, override?: string): string | undefined {
  if (override) return override;
  try { const m = JSON.parse(process.env.RAIL_RPCS ?? "{}"); if (m[rail]) return m[rail]; } catch { /* ignore */ }
  return DEFAULT_RPCS[rail];
}

export async function readEvmSettlement(receipt: SettlementReceipt, opts?: { rpcUrl?: string }): Promise<RailRead> {
  const chain = EVM_CHAINS[receipt.rail];
  if (!chain) return { kind: "unsupported", detail: `no EVM client registered for rail ${receipt.rail}` };
  if (receipt.proof.kind !== "evm_tx" || !receipt.proof.tx_hash) return { kind: "absent", detail: "receipt proof is not an evm_tx with a tx_hash" };
  const rpcUrl = railRpc(receipt.rail, opts?.rpcUrl);
  try {
    const client = createPublicClient({ chain, transport: http(rpcUrl) });
    const rc = await client.getTransactionReceipt({ hash: receipt.proof.tx_hash as `0x${string}` });
    if (!rc) return { kind: "absent", detail: "tx not found on rail" };
    if (rc.status !== "success") return { kind: "absent", detail: `tx not successful (status=${rc.status})` };
    const transfers: RailTransfer[] = rc.logs
      .filter((l) => (l.topics[0]?.toLowerCase() === TRANSFER_TOPIC) && l.topics.length === 3)
      .map((l) => ({
        token: l.address.toLowerCase(),
        to: ("0x" + (l.topics[2] as string).slice(-40)).toLowerCase(),
        amount: BigInt(l.data).toString(),
      }));
    return { kind: "found", transfers };
  } catch (e) {
    return { kind: "unreachable", detail: `rail RPC error: ${(e as Error).message}` };
  }
}

// ── shared parity-critical helpers (MUST be byte-identical to rail-verify.py) ───────────────────
// XRPL currency code → canonical 40-hex (UPPER). 3-char ASCII codes and 40-hex both normalize here so
// the on-ledger currency and the receipt's symbol compare regardless of representation.
export function xrplCurrencyTo40Hex(code: string): string {
  if (/^[0-9a-fA-F]{40}$/.test(code)) return code.toUpperCase();
  let hex = "";
  for (let i = 0; i < code.length; i++) hex += code.charCodeAt(i).toString(16).padStart(2, "0");
  return (hex + "0".repeat(40)).slice(0, 40).toUpperCase(); // ASCII bytes left-justified in 20 bytes
}
// Exact decimal-string → integer base-units (no floats). null if it does NOT scale cleanly (more
// fractional digits than the asset's decimals, or not a plain decimal) → caller must NOT confirm.
export function scaleDecimalToBaseUnits(decimalStr: string, decimals: number): bigint | null {
  if (!/^\d+(\.\d+)?$/.test(decimalStr)) return null; // plain decimals only (rejects sci-notation etc.)
  const dot = decimalStr.indexOf(".");
  const intPart = dot === -1 ? decimalStr : decimalStr.slice(0, dot);
  const fracPart = dot === -1 ? "" : decimalStr.slice(dot + 1);
  if (fracPart.length > decimals) return null; // more precision than the asset allows → not exact
  return BigInt(intPart + fracPart.padEnd(decimals, "0"));
}

// Rail-aware address normalization for matching: EVM (eip155:*) is case-INSENSITIVE hex (lowercase
// both sides); XRPL r-addresses and Solana base58 are case-SENSITIVE → exact (NO lowercasing), so two
// distinct non-EVM addresses differing only by case can never collide. MUST match rail-verify.py.
function normAddr(rail: string, s: string): string {
  return rail.startsWith("eip155:") ? s.toLowerCase() : s;
}

function railRpcList(rail: string, override: string | undefined, defaults: string[]): string[] {
  if (override) return [override, ...defaults];
  try { const m = JSON.parse(process.env.RAIL_RPCS ?? "{}"); if (m[rail]) return [m[rail], ...defaults]; } catch { /* ignore */ }
  return defaults;
}

// ── XRPL reader — per-leg `tx` lookup (each leg = its own settled Payment) ──────────────────────
const XRPL_RPCS = ["https://xrplcluster.com", "https://s1.ripple.com:51234", "https://s2.ripple.com:51234"];
type XrplLegResult = { reachable: boolean; tx: any | null };

// PURE: given each leg's `tx` result (the rippled `result` object, or null=not-found), produce a
// RailRead the existing assessor consumes. Gates the chain-specifics the {token,to,amount} shape can't
// carry (validated/tesSUCCESS → absent; currency+issuer+ledger+clean-scale → suppress the leg's
// transfer so the assessor yields mismatch). Emits the ACTUAL on-chain destination + delivered amount
// (so destination/amount disagreements are caught genuinely by the assessor, not echoed).
export function parseXrplSettlement(receipt: SettlementReceipt, legResults: XrplLegResult[]): RailRead {
  if (legResults.some((r) => !r.reachable)) return { kind: "unreachable", detail: "an XRPL endpoint was unreachable for a leg" };
  for (let i = 0; i < receipt.split.legs.length; i++) {
    const tx = legResults[i]?.tx;
    if (!tx || tx.validated !== true || tx?.meta?.TransactionResult !== "tesSUCCESS") {
      return { kind: "absent", detail: `leg ${receipt.split.legs[i].role}: tx missing / not validated / not tesSUCCESS` };
    }
  }
  const transfers: RailTransfer[] = [];
  for (let i = 0; i < receipt.split.legs.length; i++) {
    const leg = receipt.split.legs[i];
    const tx = legResults[i].tx;
    if (tx.ledger_index !== (leg.proof as { ledger_index?: number } | undefined)?.ledger_index) continue; // ledger mismatch → suppress → assessor mismatch
    const delivered = tx?.meta?.delivered_amount;
    if (delivered === undefined || delivered === null) continue; // must use delivered_amount; absent → suppress
    let amount: bigint | null = null;
    if (typeof delivered === "string") {
      if (receipt.asset.symbol.toUpperCase() !== "XRP") continue;       // string delivered == native XRP drops
      amount = /^\d+$/.test(delivered) ? BigInt(delivered) : null;       // drops are already integer base-units
    } else if (typeof delivered === "object") {
      const currencyOk = xrplCurrencyTo40Hex(String(delivered.currency)) === xrplCurrencyTo40Hex(receipt.asset.symbol);
      const issuerOk = normAddr(receipt.rail, String(delivered.issuer ?? "")) === normAddr(receipt.rail, receipt.asset.rail_address); // r-address: exact
      if (!currencyOk || !issuerOk) continue;                            // asset mismatch → suppress
      amount = scaleDecimalToBaseUnits(String(delivered.value), receipt.asset.decimals); // null if not exact
    }
    if (amount === null) continue;
    transfers.push({ token: normAddr(receipt.rail, receipt.asset.rail_address), to: normAddr(receipt.rail, String(tx.Destination ?? "")), amount: amount.toString() });
  }
  return { kind: "found", transfers };
}

async function xrplTx(endpoints: string[], txHash: string): Promise<XrplLegResult> {
  for (const url of endpoints) {
    try {
      const res = await fetch(url, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ method: "tx", params: [{ transaction: txHash, binary: false }] }) });
      if (!res.ok) continue;
      const r = (await res.json())?.result;
      if (!r) continue;
      if (r.error || r.status === "error") return { reachable: true, tx: null }; // reachable, definitively not a settled tx
      return { reachable: true, tx: r };
    } catch { continue; }
  }
  return { reachable: false, tx: null };
}

export async function readXrplSettlement(receipt: SettlementReceipt, opts?: { rpcUrl?: string }): Promise<RailRead> {
  const endpoints = railRpcList(receipt.rail, opts?.rpcUrl, XRPL_RPCS);
  const legResults: XrplLegResult[] = [];
  for (const leg of receipt.split.legs) {
    const h = (leg.proof as { tx_hash?: string } | undefined)?.tx_hash;
    legResults.push(h ? await xrplTx(endpoints, h) : { reachable: true, tx: null }); // missing per-leg proof → absent cause
  }
  return parseXrplSettlement(receipt, legResults);
}

// ── Solana reader — one getTransaction; balance-delta matching with ambiguity guard ─────────────
const SOLANA_RPCS = ["https://api.mainnet-beta.solana.com"];
type SolanaTxResult = { reachable: boolean; tx: any | null };

// PURE: given the getTransaction result, build per-(owner,mint) NET balance deltas from
// pre/postTokenBalances (owner = the WALLET, not the ATA; mint explicit) and emit one transfer per
// (owner,mint) with a positive net delta. Two legs sharing (owner,mint) → their net delta != either
// leg's amount → the assessor matches neither → mismatch (the ambiguity guard, for free).
export function parseSolanaSettlement(receipt: SettlementReceipt, g: SolanaTxResult): RailRead {
  if (!g.reachable) return { kind: "unreachable", detail: "Solana RPC unreachable" };
  if (!g.tx) return { kind: "absent", detail: "tx not found" };
  if (g.tx?.meta?.err != null) return { kind: "absent", detail: "tx failed (meta.err != null)" };
  const mint = receipt.asset.rail_address;
  const deltas = new Map<string, bigint>(); // key = owner (for this mint)
  const apply = (arr: any[], sign: bigint) => {
    for (const b of arr ?? []) {
      if (b?.mint !== mint) continue;
      const k = String(b.owner);
      deltas.set(k, (deltas.get(k) ?? 0n) + sign * BigInt(b.uiTokenAmount.amount));
    }
  };
  apply(g.tx?.meta?.preTokenBalances, -1n);
  apply(g.tx?.meta?.postTokenBalances, 1n);
  const transfers: RailTransfer[] = [];
  for (const [owner, delta] of deltas) {
    if (delta > 0n) transfers.push({ token: normAddr(receipt.rail, mint), to: normAddr(receipt.rail, owner), amount: delta.toString() });
  }
  return { kind: "found", transfers };
}

async function solanaGetTx(endpoints: string[], sig: string): Promise<SolanaTxResult> {
  for (const url of endpoints) {
    try {
      const res = await fetch(url, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "getTransaction", params: [sig, { encoding: "jsonParsed", maxSupportedTransactionVersion: 0, commitment: "finalized" }] }) });
      if (!res.ok) continue;
      const j = await res.json();
      if (j.error) continue;
      return { reachable: true, tx: j.result ?? null }; // result null = not found
    } catch { continue; }
  }
  return { reachable: false, tx: null };
}

export async function readSolanaSettlement(receipt: SettlementReceipt, opts?: { rpcUrl?: string }): Promise<RailRead> {
  const sig = (receipt.proof as { signature?: string } | undefined)?.signature;
  if (!sig) return { kind: "absent", detail: "receipt proof has no Solana signature" };
  const endpoints = railRpcList(receipt.rail, opts?.rpcUrl, SOLANA_RPCS);
  return parseSolanaSettlement(receipt, await solanaGetTx(endpoints, sig));
}

// Dispatch by CAIP-2 family. EVM/XRPL/Solana all wired; unknown families → rail_unsupported (NOT a
// false pass). Each reader returns the SAME RailRead union consumed by assessRailSettlement (unchanged).
export async function readRailSettlement(receipt: SettlementReceipt, opts?: { rpcUrl?: string }): Promise<RailRead> {
  const family = receipt.rail.split(":")[0];
  if (family === "eip155") return readEvmSettlement(receipt, opts);
  if (family === "xrpl") return readXrplSettlement(receipt, opts);
  if (family === "solana") return readSolanaSettlement(receipt, opts);
  return { kind: "unsupported", detail: `unknown rail family: ${family}` };
}

// ── verdict (PURE given the rail read; mirrors recomputeAndAssess's pure-given-reads design) ─────
export type RailVerdict =
  | "rail_settlement_confirmed" | "rail_settlement_mismatch" | "rail_settlement_absent"
  | "rail_unreachable" | "rail_unsupported";
export type RailCheck = { label: string; result: "pass" | "fail" | "skip"; detail?: string };
// Stage 2 / x402 — funding-leg facet (ADDITIVE + ORTHOGONAL to the split verdict). OQ-10 gating:
// funding_mismatch DOWNGRADES the overall tone (a provably-false funding claim); funding_unreachable is
// INFORMATIONAL (a connectivity blip is not a lie); funding_confirmed/funding_absent_field do not downgrade.
export type FundingVerdict = "funding_confirmed" | "funding_unreachable" | "funding_mismatch" | "funding_absent_field";
export interface RailAssessment {
  railVerdict: RailVerdict;
  attestation: AttestationVerdict;
  splitConsistent: boolean;
  enforcementClaim: Enforcement;
  protocolEnforced1pct: boolean; // TRUE only: chain_enforced + confirmed + agent-1%-leg→self_wallet on-chain + attestation valid
  tone: "ok" | "warn" | "bad" | "neutral";
  headline: string;
  note: string;
  checks: RailCheck[];
  fundingVerdict: FundingVerdict; // x402 funding-leg facet (orthogonal; see OQ-10 gating above)
}
// The split assessment WITHOUT the funding facet — computed independently, never touched by funding.
export type RailAssessmentCore = Omit<RailAssessment, "fundingVerdict">;

// Appended to EVERY verdict — the omission/off-receipt honesty caveat.
const OMISSION_NOTE =
  " Scope: this confirms only THIS declared settlement. The audit chain is tamper-evident, NOT omission-evident — it cannot prove the agent had no other, unsealed settlements, and it cannot prove that transfers outside the declared legs did not occur.";

// Split assessment — UNCHANGED logic, now returning the funding-free core. The funding facet is applied
// in the exported assessRailSettlement wrapper below; this core never sees it (computed independently).
async function assessRailCore(receipt: SettlementReceipt, read: RailRead): Promise<RailAssessmentCore> {
  const att = await verifyAttestation(receipt);
  const split = checkSplitConsistency(receipt);
  const checks: RailCheck[] = [
    { label: "Receipt attestation recovers to home.self_wallet", result: att.verdict === "attestation_valid" ? "pass" : "fail", detail: att.detail },
    { label: "Split legs sum to amount; agent == ceil(1%) (AgentShareCore rule)", result: split.ok ? "pass" : "fail", detail: split.detail },
  ];

  const finalize = (railVerdict: RailVerdict, tone: RailAssessment["tone"], headline: string, note: string, protocolEnforced1pct: boolean): RailAssessmentCore => {
    let t = tone, n = note;
    if (att.verdict === "attestation_invalid") {
      if (railVerdict === "rail_settlement_confirmed" && t === "ok") t = "warn"; // payments real but receipt unsigned → not green
      n = `ATTESTATION INVALID — this receipt is NOT signed by the agent's home self_wallet (${att.detail}). ` + n;
    }
    return {
      railVerdict,
      attestation: att.verdict,
      splitConsistent: split.ok,
      enforcementClaim: receipt.enforcement,
      protocolEnforced1pct: protocolEnforced1pct && att.verdict === "attestation_valid",
      tone: t,
      headline,
      note: n + OMISSION_NOTE,
      checks,
    };
  };

  // rail read → verdict (each non-found case adds the corresponding rail check)
  if (read.kind === "unsupported") {
    checks.push({ label: "Settlement confirmed on the rail", result: "skip", detail: `rail_unsupported: ${read.detail}` });
    return finalize("rail_unsupported", "neutral", "Rail not independently confirmable yet (NOT a pass)",
      `The rail ${receipt.rail} has no wired reader, so the declared on-chain settlement was NOT independently checked. This is explicitly NOT a confirmation. ${read.detail}.`, false);
  }
  if (read.kind === "unreachable") {
    checks.push({ label: "Settlement confirmed on the rail", result: "skip", detail: `rail_unreachable: ${read.detail}` });
    return finalize("rail_unreachable", "warn", "Rail RPC unreachable — not confirmed",
      `Could not reach an RPC for ${receipt.rail}; this is a connectivity problem, NOT evidence the settlement is missing. ${read.detail}.`, false);
  }
  if (read.kind === "absent") {
    checks.push({ label: "Settlement confirmed on the rail", result: "fail", detail: `rail_settlement_absent: ${read.detail}` });
    return finalize("rail_settlement_absent", "bad", "Declared settlement NOT found on the rail",
      `A reachable rail read found no successful settlement matching the receipt's proof: ${read.detail}. Do not trust this receipt's settlement claim.`, false);
  }

  // found → match each declared leg (asset/dest/amount) against the actual on-chain transfers.
  // Rail-aware casing: EVM lowercased, XRPL/Solana exact (normAddr) — no case-fold collisions.
  const token = normAddr(receipt.rail, receipt.asset.rail_address);
  let allLegsFound = true;
  for (const leg of receipt.split.legs) {
    const matched = read.transfers.some((tr) => tr.token === token && tr.to === normAddr(receipt.rail, leg.dest) && tr.amount === leg.amount);
    if (!matched) allLegsFound = false;
    checks.push({ label: `Leg ${leg.role} ${leg.amount} → ${leg.dest.slice(0, 12)}… present on-chain`, result: matched ? "pass" : "fail", detail: matched ? undefined : "no matching on-chain transfer (asset/dest/amount)" });
  }

  if (!allLegsFound) {
    return finalize("rail_settlement_mismatch", "bad", "Settlement found, but the declared split does NOT match on-chain transfers",
      "The proof tx exists and succeeded, but one or more declared split legs (asset/amount/dest) do NOT match the actual on-chain transfers. The receipt misstates the settlement — do not trust it.", false);
  }

  // all legs confirmed on-chain → the declared payments occurred. Now the enforcement nuance:
  const agentLeg = receipt.split.legs.find((l) => l.role === "agent");
  const agentToSelf = !!agentLeg && agentLeg.dest.toLowerCase() === receipt.home.self_wallet.toLowerCase();
  const isEvm = receipt.rail.startsWith("eip155:");

  if (receipt.enforcement === "chain_enforced" && isEvm && agentToSelf && split.ok) {
    return finalize("rail_settlement_confirmed", "ok", "Settlement CONFIRMED on-chain — inviolable-1% independently verified",
      `Every declared split leg matches an on-chain transfer in the proof tx, INCLUDING the agent's 1% (${agentLeg!.amount}) to home.self_wallet — so the inviolable-1% is independently confirmed from the chain itself, not merely asserted.`, true);
  }

  // confirmed payments, but NOT protocol-enforced (off-ledger, or a chain_enforced claim we can't tie to the 1%-leg)
  const why = receipt.enforcement === "attested_off_ledger"
    ? "enforcement=attested_off_ledger: the 1% is PROVEN-AND-AUDITED (the declared payments exist and follow the 97/1/2 ratio) but was NOT enforced by an on-chain protocol — this tool does NOT and cannot assert protocol-level 1% enforcement on this rail."
    : "the agent-1%-to-self_wallet leg could not be tied to an on-chain transfer in a way that proves protocol enforcement — treat the 1% as proven-and-audited, not protocol-enforced.";
  return finalize("rail_settlement_confirmed", "ok", "Declared payments CONFIRMED on the rail — NOT protocol-enforced",
    `Every declared split leg matches an on-chain transfer, so the declared payments occurred. ${why}`, false);
}

// ── x402 funding-leg confirm (Stage 2) ──────────────────────────────────────────────────────────
// REUSES the existing rail readers to confirm the funding_proof's tx — the SAME "confirm a transfer on a
// rail" machinery the split legs use, pointed at the single funding transfer (→ funding_proof.payee).
// Same rail as the split (OQ-6), so it uses the same RAIL_RPCS/reader — no new RPC config.
export async function readFundingSettlement(receipt: SettlementReceipt, opts?: { rpcUrl?: string }): Promise<RailRead> {
  const fp = receipt.funding_proof;
  if (!fp) return { kind: "absent", detail: "no funding_proof on receipt" };
  const family = fp.rail.split(":")[0];
  if (family === "eip155") {
    const synthetic = { rail: fp.rail, proof: { kind: "evm_tx", tx_hash: fp.tx_hash }, asset: fp.asset, split: { legs: [] } } as unknown as SettlementReceipt;
    return readEvmSettlement(synthetic, opts);
  }
  if (family === "solana") {
    const synthetic = { rail: fp.rail, proof: { kind: "solana_tx", signature: fp.tx_hash }, asset: fp.asset, split: { legs: [] } } as unknown as SettlementReceipt;
    return readSolanaSettlement(synthetic, opts);
  }
  if (family === "xrpl") {
    // funding_proof declares no ledger_index (the per-leg ledger gate is N/A for a single funding tx) —
    // so we set the synthetic leg's ledger_index FROM the fetched tx and reuse parseXrplSettlement verbatim.
    const endpoints = railRpcList(fp.rail, opts?.rpcUrl, XRPL_RPCS);
    const legResult = await xrplTx(endpoints, fp.tx_hash);
    const synthetic = {
      rail: fp.rail, asset: fp.asset,
      split: { legs: [{ role: "funding", dest: fp.payee, amount: fp.amount, proof: { kind: "xrpl_tx", tx_hash: fp.tx_hash, ledger_index: (legResult.tx as { ledger_index?: number } | null)?.ledger_index } }] },
    } as unknown as SettlementReceipt;
    return parseXrplSettlement(synthetic, [legResult]);
  }
  return { kind: "unsupported", detail: `no reader for funding rail family ${family}` };
}

// PURE: funding_proof + its (pre-fetched) rail read → funding verdict. unreachable/unsupported = can't
// confirm (informational); absent = claimed funding tx missing/failed (contradiction); found = match the
// single funding transfer (asset/payee/amount). No funding_proof → N/A.
export function assessFundingVerdict(receipt: SettlementReceipt, fundingRead: RailRead | null | undefined): FundingVerdict {
  const fp = receipt.funding_proof;
  if (!fp) return "funding_absent_field";
  if (!fundingRead) return "funding_unreachable"; // has funding_proof but not checked → can't confirm (informational)
  if (fundingRead.kind === "unreachable" || fundingRead.kind === "unsupported") return "funding_unreachable";
  if (fundingRead.kind === "absent") return "funding_mismatch"; // claimed funding tx not found/failed → contradicts
  const token = normAddr(fp.rail, fp.asset.rail_address);
  const to = normAddr(fp.rail, fp.payee);
  const matched = fundingRead.transfers.some((tr) => tr.token === token && tr.to === to && tr.amount === fp.amount);
  return matched ? "funding_confirmed" : "funding_mismatch";
}

// The exported assessor: the split assessment (computed INDEPENDENTLY by assessRailCore — railVerdict,
// splitConsistent, protocolEnforced1pct unchanged) PLUS the orthogonal funding facet with OQ-10 gating.
export async function assessRailSettlement(receipt: SettlementReceipt, read: RailRead, fundingRead?: RailRead | null): Promise<RailAssessment> {
  const a = await assessRailCore(receipt, read);
  const fundingVerdict = assessFundingVerdict(receipt, fundingRead);
  let tone = a.tone, note = a.note;
  const checks = a.checks.slice();
  if (fundingVerdict === "funding_confirmed") {
    checks.push({ label: "x402 funding tx confirmed on rail", result: "pass", detail: `funding ${receipt.funding_proof!.amount} → ${receipt.funding_proof!.payee} confirmed on ${receipt.funding_proof!.rail}` });
  } else if (fundingVerdict === "funding_mismatch") {
    checks.push({ label: "x402 funding tx confirmed on rail", result: "fail", detail: "funding tx contradicts the claim (amount/payee/asset, or absent when it must exist)" });
    tone = "bad"; // OQ-10: a provably-false funding claim DOWNGRADES the overall tone (even if the split confirms)
    note = "FUNDING MISMATCH — the receipt's x402 funding_proof does NOT match the rail (provably-false funding claim). " + note;
  } else if (fundingVerdict === "funding_unreachable") {
    checks.push({ label: "x402 funding tx confirmed on rail", result: "skip", detail: "funding rail RPC unreachable / not checked — informational, does NOT downgrade the split verdict" });
  }
  // funding_absent_field (non-x402 receipt) → no check, no change (behaves exactly as before)
  return { ...a, tone, note, checks, fundingVerdict };
}
