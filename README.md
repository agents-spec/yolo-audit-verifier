# Yolo — an accountability layer for AI agents

Yolo is a **tamper-evident, independently verifiable record of what an AI agent decided and settled.** Every consequential action an agent takes is sealed into an append-only audit chain, anchored to **Base mainnet**, and **recomputable from public data by anyone** — no trust in Yolo required.

**This repo is the open-source verifier.** It reads an agent's sealed audit entry / settlement receipt plus the on-chain data, recomputes every claim, and reports honestly. Two independent implementations ship here — **Python and Node** — and the same entry producing the same verdict in both is the cross-language trust proof.

→ **[yolo.solutions](https://yolo.solutions)**

---

## What the verifier does

Given a public proof bundle + public chain data, it independently recomputes:

1. **The hash chain** — each entry's `payload_hash` (RFC-8785 JCS → SHA-256) and its link to the previous entry (`chain_hash`), so the history can't be reordered or edited.
2. **The Merkle proof** — that the entry is in the batch whose root was anchored on Base mainnet (`YoloAuditAnchor`, a public constant you confirm once).
3. **The rail settlement** — that the money actually moved as the receipt claims, read straight from the chain (Base / XRPL / Solana).

And it **reports honestly per rail:**

- **protocol-enforced** — a pinned on-chain contract performed the split, and every leg is bound to that contract. The verifier grants this **only** when the binding holds.
- **attested** — the agent sealed the settlement and it verifies on-rail, but a contract did not enforce the split (e.g. off-ledger rails). A label alone never buys the stronger verdict.

If anything doesn't recompute — a tampered amount, a wrong payee, a broken chain link, an unbound split — the verifier **rejects it**. Forged inputs are caught, not trusted.

---

## The stack at a glance

The verifier is the open-source slice of a larger system. What Yolo builds:

| Layer | What it is |
|---|---|
| **Identity** | Each agent is an ERC-721 token; settlement destinations and operational signers resolve from on-chain identity. |
| **Bounded-autonomy runtime** | A deterministic enforcer **outside the model**: the agent *proposes*, the enforcer *permits or escalates* against a fixed box (per-action ceiling, recipient allow-list, rails). Clockless and fail-safe — an unbounded model never moves money on its own. |
| **The seal** | Canonicalize (JCS) → SHA-256 → hash-chain → Merkle root → **anchored on Base mainnet**, append-only. Once anchored, no vendor — including Yolo — can edit it. |
| **Three rails, one verifier** | Base, XRPL, and Solana settlements all seal into the same chain and verify through the same TS/Python verifier *(this repo)*. |
| **Standards bindings** | The seal is the evidence underneath the agent-economy standards: **AP2** mandates (authorization), **x402** payments (funding proof), and **ERC-8004** (the seal as a Validation method *and* as evidence-backed Reputation). |

---

## Run it

Everything recomputes from a public proof bundle + a public Base RPC. Files are at the repo root.

```sh
# ── Node (the browser's exact logic) ──────────────────────────────
npm install
npx tsx yolo-verify.ts 49          # recompute a live anchored entry straight from Base
npm test                           # the rail-verifier + rejection suite (TS verdicts)

# ── Python (an independent reimplementation) ──────────────────────
python3 -m venv .venv && .venv/bin/pip install -r requirements.txt
.venv/bin/python yolo-verify.py 49
.venv/bin/python test/rail_verify_public_test.py   # Python verdicts on the same fixtures

# Same fixtures, same verdicts in both languages = the cross-language trust proof.
# Emit the per-rail verdicts as JSON for a manual diff:
.venv/bin/python rail-verify.py --parity test/rail-fixtures.json
```

The Node tool auto-selects a public Base RPC (override with `--rpc`); the Python tool reads the anchor from public calldata. Neither relies on Yolo's servers to compute anything.

---

## Trust model — what you rely on
- The **public proof bundle** (`https://yolo.solutions/api/verify/{id}/proof`, or any copy you already hold).
- A **public Base RPC** — the Node tool auto-selects one (and falls back across several); override with `--rpc` if you want to pin your own.
- The **published `YoloAuditAnchor` address** (`0xDf5e1c1e82880C0E9dce3758A58e62189Ca365FD`) — a public constant you confirm once (Basescan / `/methodology`).

You do **not** rely on Yolo's servers to compute anything: both tools recompute every hash locally and read the root from Base themselves.

## The five steps (anchor tamper-evidence)
1. **payload → payload_hash** — canonicalize the payload (by `canon_version`) and SHA-256 it.
2. **chain_hash binding** — `sha256("{agent_id}:{seq}:{prev_hash}:{payload_hash}") == chain_hash`.
3. **Merkle proof → root** — fold the sibling path (single-leaf ⇒ `sha256(leaf)`) `== proof root`.
4. **root anchored on Base** — read the anchored root from Base; `== recomputed root`.
5. **payload-integrity classification** — the operator's anomaly/tampering label, echoed as *their* claim.

Verdicts: `verified | pending_anchor | anchor_root_mismatch | anchored_payload_anomaly | payload_hash_mismatch | reference_seed | rpc_unreachable | anchor_absent | anchor_mismatch`. Exit codes: `0 / 2 / 5 / 3 / 6 / 7 / 4 / 8 / 9` (1 = error). `rpc_unreachable` (no RPC answered) and `anchor_absent` (a reachable RPC found no matching anchor) are kept distinct — only the latter is evidence the anchor is missing; a committed last-known-anchor floor (`last-known-anchor.json`) hardens it, and an optional Basescan key (`--basescan`/`BASESCAN_API_KEY`) adds a non-RPC cross-check.

## Canonicalization (the subtle part)
`payload_hash` is SHA-256 over a **canonical** serialization:
- **v2 = RFC 8785** (JSON Canonicalization Scheme). The Python tool uses the **`rfc8785`** library — **not** `json.dumps(sort_keys=True)`, which is not JCS-conformant (sorts by Unicode code *point*, not UTF-16 code *unit*; wrong number formatting) and would mismatch v2 entries.
- **v1 = legacy** (pre-2026-05-24): the original canonicalizer dropped nested-object keys; reproduced exactly so historical entries still verify. `NULL`/absent `canon_version` ⇒ v1.

On-chain read: **Node = Approach A** (`getAnchor(agentId, i)` matched by seq-range — the same `verify-client.ts` the `/verify` page runs, with automatic fallback across public Base RPCs). **Python = Approach B** (reads the anchoring tx's public calldata and slices the `bytes32 merkleRoot`; no ABI library, no web3; selector `0x370dd8ba`).

## Rail-agnostic settlement verification (`rail-verify.ts` / `rail-verify.py`)

Beyond the Base-anchor tamper-evidence check above, the verifier can independently confirm a `settlement_receipt` entry's *declared settlement* against the **foreign rail's own ledger** — **EVM (`eip155:*`), XRPL, and Solana** — over **raw public RPC, no chain SDKs**, with **byte-for-byte TS↔Python parity**. This is additive and **orthogonal** to the anchor verdict.

**Verdicts:** `rail_settlement_confirmed | rail_settlement_mismatch | rail_settlement_absent | rail_unreachable | rail_unsupported`, plus the receipt's signature check `attestation_valid | attestation_invalid` (the home `self_wallet` must EIP-191-sign the receipt).

**What it proves.** The declared transaction exists and settled on the named rail, and each split leg's **amount → destination** matches the actual on-chain transfers (asset included). For an EVM `chain_enforced` receipt it additionally confirms the inviolable **1%** from the transaction itself — the agent leg's `ceil(1%)` to the home `self_wallet` is an on-chain transfer in the proof tx, not merely asserted — **and** that the split was performed by the pinned `SettlementSplit` contract, so `protocolEnforced1pct = true` means contract-enforced, not just correctly-proportioned.

### What it does NOT claim (read this)
- **Off-ledger rails are proven-and-audited, NOT protocol-enforced.** On XRPL / non-programmable rails the split is separate native payments, so the 1% is *verified to have occurred*, not *enforced by a contract*. `protocolEnforced1pct` is **true only** for a confirmed EVM `chain_enforced` receipt bound to the pinned contract; **false** for every off-ledger confirmation, even a fully matched one.
- **`chain_enforced` is bound to a KNOWN contract — not just the right amounts.** `protocolEnforced1pct = true` additionally requires the proof tx to **(1)** emit `SettlementRouted` from the **pinned** `SettlementSplit` **and (2)** have every split leg sent **by** that contract (`Transfer.from`). The correct 97/1/2 ratio from any other source does **not** qualify (fixture `f_evm_chain_enforced_unbound` → `false`). The verifier **carries** the pinned addresses and never trusts one from the receipt:
  - **Base Sepolia (`eip155:84532`) → `0xe7680c1B6132DEC06CcDf6a863D09037EcBe03Af`**
  - **Base mainnet is intentionally absent** until a mainnet `SettlementSplit` is deployed and pinned — so a mainnet `chain_enforced` claim returns `protocolEnforced1pct = false` (honest by construction).
- **Tamper-evident, NOT omission-evident.** A confirmed receipt proves *this* settlement is real and unaltered; it cannot prove the agent had no other, unsealed settlements.

### Exactness
- **Integer base-units only** — no floating point anywhere; a value that doesn't scale cleanly is a `mismatch`, never a pass.
- **Rail-aware address casing** — EVM compares case-insensitively (hex); XRPL r-addresses and Solana base58 compare case-sensitively (exact).
- **Solana matching uses `postTokenBalances.owner`** (the wallet, not the ATA) with an ambiguity guard: if two legs share one `(owner, mint)` the net delta can't be attributed per leg → `mismatch`, never a false confirm. XRPL confirms each leg's own `tx_hash` + `ledger_index` via `meta.delivered_amount`.

### Verify it yourself (offline, static fixtures)
Self-contained demos — no network, no monorepo — covering EVM confirmed-and-1%-enforced (bound to the pinned `SettlementSplit`), an EVM `chain_enforced` claim with the right ratio but **NOT** from the pinned contract → `protocolEnforced1pct = false`, XRPL off-ledger confirmed-but-NOT-enforced, wrong-issuer / Solana ATA-not-owner mismatches, and an unsupported rail.
```sh
node --import tsx --test test/rail-verify.public.test.ts   # Node (tsx + viem)
python3 test/rail_verify_public_test.py                    # Python (rfc8785 + eth-account)
```
The same fixtures producing the same verdicts in both languages is the cross-language trust proof.

---

## Honest status
- **Live on Base mainnet:** the audit chain and its anchoring — settlements are sealed and Merkle roots are anchored on-chain today.
- **Proven on testnet + fixtures:** the 97/1/2 settlement split, the three-rail verifier (with TS↔Python parity), the bounded-autonomy runtime, and the standards bindings (AP2 / x402 / ERC-8004) are demonstrated end-to-end on Base Sepolia, other testnets, and committed fixtures — including a live ERC-8004 round-trip on Base Sepolia.
- **Gated next step:** production mainnet settlement (moving real value through the enforced split) and live standards writes — designed and dry-run-proven, deliberately not yet run with real funds.

Nothing here claims more than the code does. Where something is a fixture or a testnet proof, it says so — and the verifier itself is built to refuse the stronger verdict whenever the binding isn't there.

## Notes
- Public Base RPCs are rate-limited and Approach A iterates `getAnchor`, so any single endpoint is fragile. The Node tool auto-falls-back across several; only if **every** candidate is rate-limited at once does it return `rpc_unreachable` (the in-browser recompute still holds). The Python tool reads a single tx (Approach B) and isn't affected.
- **Integer bound:** payload numbers must be within ±(2⁵³−1) (the I-JSON safe-integer range); `rfc8785` enforces this.

## License
MIT — see [LICENSE](./LICENSE). Fork it, run it, audit it.

---

Yolo is the verification layer for any AI making decisions that matter — agent commerce today, decisional logging (clinical, moderation, underwriting) next. Full context at **[yolo.solutions](https://yolo.solutions)**.
