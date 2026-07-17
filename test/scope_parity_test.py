#!/usr/bin/env python3
"""
scope_parity_test.py — Python-side attestation-scope assertions, MIRRORING the TypeScript
suite at test/verify-client.test.ts:197-242 ("attestation scope is declared in the verdict").
Both verifiers are now tested on the SAME axis: every verdict declares how much the seal
actually bound (derived from canon_version + reference/seed), and NO verdict emits without one.

  v2        -> "full payload bound"
  v1        -> "top-level only — nested keys not bound"
  null      -> v1 scope (top-level only) — NULL/absent canon_version reads as v1
  redacted  -> "Merkle-membership only — payload not re-hashed" (reference/seed, allowlisted id)
  invariant -> every verify() result carries a non-empty scope, on every verdict path

The TS suite injects the on-chain root directly (recomputeAndAssess is pure). yolo-verify.py
reads the root inside verify(), so for the "verified"/"reference_seed" cases we force the
on-chain read to return the recomputed root (the transport, not the parse) — the same
separation of concerns. No network is used.

Run:  .venv/bin/python test/scope_parity_test.py
Exit: 0 all passed · 1 any assertion failed
"""
import importlib.util
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.join(HERE, "..")
sys.path.insert(0, ROOT)
spec = importlib.util.spec_from_file_location("yolo_verify", os.path.join(ROOT, "yolo-verify.py"))
yv = importlib.util.module_from_spec(spec)
spec.loader.exec_module(yv)

ARGUS = "4fbe49c2-89f5-44e4-a995-89115f767217"
FULL = "full payload bound"
TOPLEVEL = "top-level only — nested keys not bound"
MEMBERSHIP = "Merkle-membership only — payload not re-hashed"

# One allow-listed reference/seed id (mirror of REFERENCE_SEED_IDS / reference-seed-allowlist.json);
# the withheld-payload -> membership-only scope is granted ONLY for an id on this list.
REDACTED_ID = 25


def _sound_bundle(canon, *, redacted=False, entry_id=100):
    """Build a bundle whose payload/chain/merkle all reconcile, so verify() can reach a green
    verdict once the on-chain read is forced. Mirrors soundBundle() in the TS suite.
    Single-leaf batch: root = sha256(leaf), leaf = chain_hash. Returns (bundle, recomputed_root)."""
    if redacted:
        payload = {"_redacted": True, "_reason": "withheld"}
        classification = {"kind": "reference_seed", "label": "REFERENCE / SEED ENTRY",
                          "redacted": True, "reason": "pre-Strict-B substrate-test decision"}
        # payload is withheld -> steps 1&2 skipped; chain_hash is asserted only via the merkle leaf.
        chain_hash = yv.sha256_hex("redacted-leaf-fixture")
        payload_hash = "00" * 32  # unused (recompute skipped for a redacted allow-listed id)
    else:
        payload = {"a": 1, "b": "x", "nested": {"z": 9}}  # has a nested object, as the TS fixture does
        classification = None
        payload_hash = yv.canon_payload_hash(payload, canon)  # canon.py — the server's exact bytes
        chain_hash = yv.sha256_hex(f"{ARGUS}:0:genesis:{payload_hash}")

    root = yv.sha256_hex(chain_hash)  # single-leaf asymmetry: root = sha256(leaf)
    bundle = {
        "entry": {"id": entry_id, "agent_id": ARGUS, "seq": 0, "action_type": "decision_routine",
                  "prev_hash": "genesis", "canon_version": canon, "payload": payload},
        "hashes": {"payload_hash": payload_hash, "chain_hash": chain_hash},
        "status": "verified", "verified": True, "anchored": True,
        "anchor": {"status": "onchain", "root": root, "tx": "0x" + "ab" * 32, "basescan_url": "x",
                   "batch": {"first_seq": 0, "last_seq": 0, "log_count": 1, "ipfs_cid": None}},
        "merkle_proof": {"leaf": chain_hash, "steps": [], "single_leaf_batch": True},
    }
    if classification:
        bundle["classification"] = classification
    return bundle, root


def _verify_forcing_onchain(bundle, forced_root):
    """Run verify() with the on-chain read forced to return forced_root as a confirmed anchor —
    substituting the TRANSPORT only (viem/urllib), never the calldata parse or the verdict logic."""
    orig = yv.read_onchain_root
    yv.read_onchain_root = lambda rpc, addr, tx, first, last: (forced_root, "found", "forced")
    try:
        return yv.verify(bundle, yv.DEFAULT_RPC, yv.ANCHOR_ADDRESS)
    finally:
        yv.read_onchain_root = orig


failures = 0


def check(name, got, expected):
    global failures
    if got == expected:
        print(f"ok   {name}: {got!r}")
    else:
        print(f"FAIL {name}: expected {expected!r}, got {got!r}")
        failures += 1


# ── scope values on a fully-resolved verdict (mirrors the TS "verified" assertions) ──
b, root = _sound_bundle("v2")
r = _verify_forcing_onchain(b, root)
check("v2 verified -> scope 'full payload bound'", r["scope"], FULL)
check("  (and verdict is verified)", r["verdict"], "verified")

b, root = _sound_bundle("v1")
r = _verify_forcing_onchain(b, root)
check("v1 verified -> scope 'top-level only — nested keys not bound'", r["scope"], TOPLEVEL)
check("  (and verdict is verified)", r["verdict"], "verified")

b, root = _sound_bundle(None)
r = _verify_forcing_onchain(b, root)
check("null canon_version -> v1 scope (top-level only)", r["scope"], TOPLEVEL)

b, root = _sound_bundle("v1", redacted=True, entry_id=REDACTED_ID)
r = _verify_forcing_onchain(b, root)
check("redacted allow-listed -> scope 'Merkle-membership only'", r["scope"], MEMBERSHIP)
check("  (and verdict is reference_seed)", r["verdict"], "reference_seed")

# ── invariant: NEVER a verdict without a scope, across canon versions AND verdict paths ──
inv_ok = True
cases = []
# forced-onchain (verified / reference_seed) paths
for canon in ("v1", "v2", None):
    bb, rr = _sound_bundle(canon)
    cases.append(_verify_forcing_onchain(bb, rr))
bb, rr = _sound_bundle("v1", redacted=True, entry_id=REDACTED_ID)
cases.append(_verify_forcing_onchain(bb, rr))
# non-forced paths (no network: tx=None -> anchor absent; and a pending bundle)
for canon in ("v1", "v2", None):
    bb, _ = _sound_bundle(canon)
    bb["anchor"]["tx"] = None          # -> anchor_absent, no RPC hit
    cases.append(yv.verify(bb, yv.DEFAULT_RPC, yv.ANCHOR_ADDRESS))
    pend = {"entry": {"id": 1, "agent_id": ARGUS, "seq": 0, "action_type": "x",
                      "prev_hash": "genesis", "canon_version": canon, "payload": {"k": 1}},
            "hashes": {"payload_hash": "00" * 32, "chain_hash": "11" * 32},
            "status": "pending_anchor", "verified": False, "anchored": False}
    cases.append(yv.verify(pend, yv.DEFAULT_RPC, yv.ANCHOR_ADDRESS))  # -> pending_anchor

for res in cases:
    s = res.get("scope")
    if not (isinstance(s, str) and len(s) > 0):
        print(f"FAIL invariant: verdict {res.get('verdict')!r} emitted with empty scope {s!r}")
        inv_ok = False
        failures += 1
if inv_ok:
    print(f"ok   invariant: all {len(cases)} verdict paths carry a non-empty scope")

if failures:
    print(f"\n{failures} scope parity assertion(s) failed")
    sys.exit(1)
print("\nall Python scope parity assertions passed")
