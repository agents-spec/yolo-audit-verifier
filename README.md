# Yolo audit verifier

Independently verify any Yolo audit entry against **Base mainnet** — without trusting Yolo or
`yolo.solutions`. The tool fetches the public proof bundle and reads the anchored Merkle root
straight from Base. Two independent implementations ship here (**Python** and **Node**); the
same entry producing the same verdict in both is the cross-language trust proof.

## Trust model — what you rely on
- The **public proof bundle** (`https://yolo.solutions/api/verify/{id}/proof`, or any copy you already hold).
- A **public Base RPC** — the Node tool auto-selects one (and falls back across several); override with `--rpc` if you want to pin your own.
- The **published `YoloAuditAnchor` address** (`0xDf5e1c1e82880C0E9dce3758A58e62189Ca365FD`) — a public constant you confirm once (Basescan / `/methodology`).

You do **not** rely on Yolo's servers to compute anything: both tools recompute every hash locally and read the root from Base themselves.

## The five steps
1. **payload → payload_hash** — canonicalize the payload (by `canon_version`) and SHA-256 it.
2. **chain_hash binding** — `sha256("{agent_id}:{seq}:{prev_hash}:{payload_hash}") == chain_hash`.
3. **Merkle proof → root** — fold the sibling path (single-leaf ⇒ `sha256(leaf)`) `== proof root`.
4. **root anchored on Base** — read the anchored root from Base; `== recomputed root`.
5. **payload-integrity classification** — the operator's anomaly/tampering label, echoed as *their* claim.

Verdicts: `verified | pending_anchor | anchor_root_mismatch | anchored_payload_anomaly | payload_hash_mismatch | onchain_unconfirmed`. Exit codes: `0 / 2 / 5 / 3 / 6 / 4` (1 = error).

## Canonicalization (the subtle part)
`payload_hash` is SHA-256 over a **canonical** serialization:
- **v2 = RFC 8785** (JSON Canonicalization Scheme). The Python tool uses the **`rfc8785`** library — **not** `json.dumps(sort_keys=True)`, which is not JCS-conformant (sorts by Unicode code *point*, not UTF-16 code *unit*; wrong number formatting) and would mismatch v2 entries.
- **v1 = legacy** (pre-2026-05-24): the original canonicalizer dropped nested-object keys; reproduced exactly so historical entries still verify. `NULL`/absent `canon_version` ⇒ v1.

## Python — independent reimplementation
```sh
python3 -m venv .venv && .venv/bin/pip install -r requirements.txt
.venv/bin/python yolo-verify.py 35 --rpc https://your-base-rpc
.venv/bin/python yolo-verify.py --bundle bundle.json
```
On-chain read = **Approach B**: reads the anchoring tx's **public calldata** and slices the
`bytes32 merkleRoot` (word 1) — no ABI library, no web3. The `anchorBatch` calldata layout is
documented inline in `yolo-verify.py` (`read_onchain_root`). Selector: `0x370dd8ba`.

## Node — the browser's exact logic
```sh
npm install
npx tsx yolo-verify.ts 49                                # zero-flag: auto-selects a reliable public Base RPC
npx tsx yolo-verify.ts 49 --rpc https://your-base-rpc    # or pin your own endpoint
```
On-chain read = **Approach A**: `getAnchor(agentId, i)` matched by seq-range — the same code the
`/verify` page runs, bundled here as `verify-client.ts`. The CLI tries your `--rpc` (if given)
first, then **automatically falls back** through a curated list of public Base RPCs on any
rate-limit/transport error — so the zero-flag command reaches the green `verified` state without
tripping a single endpoint's rate limit.

## Notes
- Public Base RPCs (e.g. `mainnet.base.org`) are rate-limited and Approach A iterates `getAnchor`,
  so any single endpoint is fragile. The Node tool auto-falls-back across several public RPCs, so
  the zero-flag command normally reaches the green `verified` state on its own. Only if **every**
  candidate is rate-limited at once does it return `onchain_unconfirmed` (the in-browser recompute
  still holds) — pass your own `--rpc` to force a clean confirmation. The Python tool reads a single
  tx (Approach B) and isn't affected by getAnchor iteration limits.
- **Integer bound:** payload numbers must be within ±(2⁵³−1) (the I-JSON safe-integer range);
  `rfc8785` enforces this. No Yolo payload exceeds it, by design.

## License
MIT — see [LICENSE](./LICENSE). Fork it, run it, audit it.
