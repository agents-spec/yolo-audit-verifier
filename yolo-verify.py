#!/usr/bin/env python3
"""
yolo-verify.py — independent, trustless verifier for a single Yolo audit entry.

Verifies an entry against Base mainnet WITHOUT trusting Yolo: it fetches the public proof
bundle and reads the anchored Merkle root straight from Base via a public RPC of your choice.
The only embedded constants are public and auditor-confirmable (the YoloAuditAnchor address and
the anchorBatch() selector). Canonicalization is byte-for-byte the server's (canon.py / rfc8785).

FIVE STEPS:
  1. payload -> payload_hash    canon by canon_version (v2 = RFC 8785 JCS, v1 = legacy filter)
  2. chain_hash binding         sha256("{agent_id}:{seq}:{prev_hash}:{payload_hash}") == chain_hash
  3. Merkle proof -> root        fold the sibling path (single-leaf => sha256(leaf)) == proof root
  4. root anchored on Base       read the anchoring tx; root in its calldata == recomputed root
  5. payload-integrity class.    echo the operator's anomaly/tampering label (their claim, not ours)

VERDICT mirrors the /verify page:
  verified | pending_anchor | anchor_root_mismatch | anchored_payload_anomaly |
  payload_hash_mismatch | reference_seed | rpc_unreachable | anchor_absent | anchor_mismatch
  (rpc_unreachable = no RPC answered; anchor_absent = a reachable RPC found no matching anchor;
   anchor_mismatch = the referenced tx is not a valid anchorBatch of this batch)

REFERENCE/SEED: some ids on a frozen allowlist are pre-Strict-B / development entries, not
production decisions. Their readable payload may be WITHHELD (_redacted) by the proof API; this
tool then SKIPS steps 1-2 and confirms the entry by Merkle membership alone — never a false
"payload mismatch". Behaviour for every other id is unchanged (full five-step check).

USAGE:
  python3 yolo-verify.py <audit_id> [--source https://yolo.solutions] [--rpc URL] [--json]
  python3 yolo-verify.py --bundle bundle.json [--rpc URL] [--json]
EXIT: 0 verified · 2 pending_anchor · 3 anchored_payload_anomaly · 4 rpc_unreachable ·
      5 anchor_root_mismatch · 6 payload_hash_mismatch · 7 reference_seed · 8 anchor_absent ·
      9 anchor_mismatch · 1 error
"""
import argparse
import hashlib
import json
import os
import sys
import urllib.error
import urllib.parse
import urllib.request

try:
    from canon import payload_hash as canon_payload_hash
except ModuleNotFoundError as exc:
    # First-run UX: a missing canonicalization dependency should explain itself, not dump a
    # traceback — an external auditor must not be lost before they see a verdict.
    if exc.name == "rfc8785":
        sys.exit(
            "error: missing dependency 'rfc8785' — the RFC 8785 JSON Canonicalization library.\n"
            "It is REQUIRED and must not be substituted with json.dumps (not JCS-conformant).\n"
            "Install it (a virtualenv is cleanest), from the verifier/ directory:\n"
            "    python3 -m venv .venv && .venv/bin/pip install -r requirements.txt\n"
            "then run with that interpreter:\n"
            "    .venv/bin/python yolo-verify.py <audit_id>\n"
            "See verifier/README.md."
        )
    raise

# ── Public, auditor-confirmable constants (Base mainnet, chain 8453) ────────────
ANCHOR_ADDRESS = "0xdf5e1c1e82880c0e9dce3758a58e62189ca365fd"  # YoloAuditAnchor (lowercased)
# 4-byte selector of anchorBatch(string,bytes32,string,uint32,uint64,uint64) = keccak256(sig)[:4].
ANCHOR_BATCH_SELECTOR = "0x370dd8ba"
DEFAULT_SOURCE = "https://yolo.solutions"
DEFAULT_RPC = "https://mainnet.base.org"  # public; override with --rpc for reliability

# Verifier-self-enforced reference/seed allowlist — frozen mirror of REFERENCE_SEED_ENTRIES in
# lib/audit-proof.ts. The Merkle-membership-only skip is granted ONLY for an id on this list AND
# classified reference_seed by the bundle; a server cannot grant the payload-skip for an arbitrary id.
_ALLOWLIST_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "reference-seed-allowlist.json")
with open(_ALLOWLIST_PATH, encoding="utf-8") as _fh:
    REFERENCE_SEED_IDS = set(json.load(_fh)["ids"])

# Zero-dependency floor — one committed checkpoint per agent (highest confirmed on-chain anchor),
# used to tell a genuine 'anchor absent' (reachable RPC, no match, at/below this agent's checkpoint)
# from RPC lag. Keyed by agentId for lookup. See its _comment for derivation.
_FLOOR_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "last-known-anchor.json")
with open(_FLOOR_PATH, encoding="utf-8") as _fh:
    LAST_KNOWN_ANCHORS = {c["agentId"]: c for c in json.load(_fh)["checkpoints"]}

EXIT = {"verified": 0, "error": 1, "pending_anchor": 2, "anchored_payload_anomaly": 3,
        "rpc_unreachable": 4, "anchor_root_mismatch": 5, "payload_hash_mismatch": 6,
        "reference_seed": 7, "anchor_absent": 8, "anchor_mismatch": 9}


def sha256_hex(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()


def rpc_call(rpc_url: str, method: str, params: list):
    body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}).encode()
    req = urllib.request.Request(rpc_url, data=body,
                                 headers={"content-type": "application/json", "user-agent": "yolo-verify/1.0"})
    with urllib.request.urlopen(req, timeout=25) as resp:
        out = json.load(resp)
    if out.get("error"):
        raise RuntimeError(f"{method}: {out['error']}")
    return out["result"]


def recompute_merkle_root(leaf: str, steps: list, single_leaf: bool) -> str:
    # Plain SHA-256 over hex-string concat — language-trivial; mirrors the Yolo server's Merkle rules.
    if single_leaf:
        return sha256_hex(leaf)  # single-leaf batch: root = sha256(leaf), NOT leaf
    acc = leaf
    for st in steps:
        sib = st["sibling"]
        acc = sha256_hex(sib + acc) if st["position"] == "left" else sha256_hex(acc + sib)
    return acc


def _decode_anchor_tx(get_tx, get_receipt, anchor_addr, tx_hash, exp_first, exp_last):
    """APPROACH B — read the anchored root straight from the anchoring tx's PUBLIC calldata via the
    given (get_tx, get_receipt) source. No ABI library: pure slicing. Returns (root_hex|None, status,
    note) where status is:
       found    — a valid anchorBatch tx for THIS exact batch; root_hex is its merkleRoot.
       absent   — the source answered but there is no such tx (a reachable "no match").
       mismatch — a tx exists but is NOT a valid anchor of this batch (wrong to / selector / seq /
                  failed receipt) — distinct from a successful anchor of a DIFFERENT root.
    Transport failures are NOT caught here: the caller treats them as 'unreachable'.

    anchorBatch(string agentId, bytes32 merkleRoot, string ipfsCid, uint32 logCount,
                uint64 firstSeq, uint64 lastSeq); merkleRoot = calldata word 1; firstSeq/lastSeq = 4/5.
    """
    tx = get_tx(tx_hash)
    if tx is None:
        return None, "absent", "no such anchor tx (reachable source returned no tx)"
    to = (tx.get("to") or "").lower()
    if to != anchor_addr:
        return None, "mismatch", f"tx.to {to} != anchor {anchor_addr}"
    data = tx["input"]
    if not data.startswith(ANCHOR_BATCH_SELECTOR):
        return None, "mismatch", f"selector {data[:10]} != anchorBatch {ANCHOR_BATCH_SELECTOR}"
    body = data[10:]  # strip "0x" + 8-hex selector
    word = lambda i: body[i * 64:(i + 1) * 64]  # noqa: E731
    root = word(1).lower()
    first_seq, last_seq = int(word(4), 16), int(word(5), 16)
    if first_seq != exp_first or last_seq != exp_last:
        return None, "mismatch", f"tx batch seq[{first_seq}-{last_seq}] != bundle seq[{exp_first}-{exp_last}]"
    receipt = get_receipt(tx_hash)
    status = receipt.get("status") if receipt else None
    if status != "0x1":
        return None, "mismatch", f"tx not successful (status={status})"
    return root, "found", f"tx {tx_hash[:10]}…"


def read_onchain_root(rpc_url, anchor_addr, tx_hash, exp_first, exp_last):
    """Primary source: a Base JSON-RPC node."""
    return _decode_anchor_tx(
        lambda h: rpc_call(rpc_url, "eth_getTransactionByHash", [h]),
        lambda h: rpc_call(rpc_url, "eth_getTransactionReceipt", [h]),
        anchor_addr, tx_hash, exp_first, exp_last)


def read_onchain_root_basescan(api_key, anchor_addr, tx_hash, exp_first, exp_last):
    """Optional secondary, non-RPC cross-check: the Basescan API proxy. Used only when the primary RPC
    is unreachable AND a key is configured, so confirmation/absence doesn't hinge on one RPC layer."""
    def proxy(action, txhash):
        q = urllib.parse.urlencode({"module": "proxy", "action": action, "txhash": txhash, "apikey": api_key})
        with urllib.request.urlopen(f"https://api.basescan.org/api?{q}", timeout=25) as resp:
            return json.load(resp).get("result")
    return _decode_anchor_tx(
        lambda h: proxy("eth_getTransactionByHash", h),
        lambda h: proxy("eth_getTransactionReceipt", h),
        anchor_addr, tx_hash, exp_first, exp_last)


def fetch_bundle(source: str, audit_id: int) -> dict:
    url = f"{source.rstrip('/')}/api/verify/{audit_id}/proof"
    try:
        with urllib.request.urlopen(url, timeout=25) as resp:
            return json.load(resp)
    except urllib.error.HTTPError as e:
        if e.code == 404:
            raise SystemExit(f"error: no audit entry with id {audit_id} (404)")
        raise


def verify(bundle: dict, rpc_url: str, anchor_addr: str, basescan_key=None) -> dict:
    entry, hashes = bundle["entry"], bundle["hashes"]
    steps_out = []

    # Reference/seed entries may have their readable payload WITHHELD (_redacted): steps 1 & 2 are
    # then skipped (nothing to recompute) and the entry is confirmed by Merkle membership alone.
    payload = entry.get("payload") or {}
    classification = bundle.get("classification") or {}
    # Self-enforced: server say-so is necessary but NOT sufficient — the id must be on the verifier's
    # own allowlist. A non-allowlisted id claiming reference_seed is verified as a NORMAL entry.
    local_ref_seed = entry.get("id") in REFERENCE_SEED_IDS
    is_ref_seed = classification.get("kind") == "reference_seed" and local_ref_seed
    # Honor the withheld-payload skip ONLY for an allowlisted id; otherwise the redaction marker is
    # re-hashed like any payload and fails as payload_hash_mismatch.
    redacted = (isinstance(payload, dict) and payload.get("_redacted") is True) and local_ref_seed

    # Attestation scope — declared in EVERY verdict so canon binding is never hidden. v1 binds only
    # top-level keys (nested collapse); v2 binds the full payload; reference/seed is membership-only.
    _canon = entry.get("canon_version") or "v1"
    scope = ("Merkle-membership only — payload not re-hashed" if is_ref_seed
             else "full payload bound" if _canon == "v2"
             else "top-level only — nested keys not bound")

    # 1. payload -> payload_hash
    if redacted:
        payload_ok = None
        steps_out.append(("1. payload -> payload_hash", None, "payload withheld (reference/seed) — skipped"))
    else:
        recomputed_ph = canon_payload_hash(payload, entry.get("canon_version"))
        payload_ok = recomputed_ph == hashes["payload_hash"]
        cv = entry.get("canon_version") or "v1(null)"
        steps_out.append(("1. payload -> payload_hash", payload_ok,
                          f"({cv}) {recomputed_ph[:12]}… {'==' if payload_ok else '!='} stored"))

    # 2. chain_hash binding
    if redacted:
        chain_ok = None
        steps_out.append(("2. chain_hash binding", None, "payload withheld (reference/seed) — skipped"))
    else:
        recomputed_ch = sha256_hex(f"{entry['agent_id']}:{entry['seq']}:{entry['prev_hash']}:{hashes['payload_hash']}")
        chain_ok = recomputed_ch == hashes["chain_hash"]
        steps_out.append(("2. chain_hash binding", chain_ok,
                          f"{recomputed_ch[:12]}… {'==' if chain_ok else '!='} stored chain_hash"))

    anchored = bool(bundle.get("anchored") and bundle.get("anchor") and bundle.get("merkle_proof"))
    if not anchored:
        steps_out.append(("3. Merkle proof -> root", None, "no anchor yet"))
        steps_out.append(("4. root anchored on Base", None, "no anchor yet"))
        return {"verdict": "pending_anchor", "steps": steps_out, "scope": scope}

    # 3. Merkle proof -> root
    mp, anchor = bundle["merkle_proof"], bundle["anchor"]
    leaf_ok = mp["leaf"] == hashes["chain_hash"]
    recomputed_root = recompute_merkle_root(mp["leaf"], mp["steps"], mp["single_leaf_batch"])
    merkle_ok = leaf_ok and recomputed_root == anchor["root"].lower()
    steps_out.append(("3. Merkle proof -> root", merkle_ok,
                      f"{recomputed_root[:12]}… {'==' if recomputed_root == anchor['root'].lower() else '!='} proof root"
                      + ("" if leaf_ok else "  [leaf != chain_hash!]")))

    # 4. root anchored on Base (Approach B). Distinguish found / mismatch / absent / unreachable so the
    # verdict never collapses "couldn't reach an RPC" with "the anchor is genuinely not on-chain".
    onchain_root, onchain_ok, onchain_note, onchain_status = None, None, "no on-chain tx in bundle", "absent"
    if anchor.get("tx"):
        try:
            onchain_root, onchain_status, onchain_note = read_onchain_root(
                rpc_url, anchor_addr, anchor["tx"], anchor["batch"]["first_seq"], anchor["batch"]["last_seq"])
        except Exception as exc:  # transport failure → RPC UNREACHABLE (never echo the URL — it may carry a key)
            onchain_status, onchain_note = "unreachable", f"Base read failed: {type(exc).__name__}"
        # Optional non-RPC cross-check: if the RPC was unreachable and a Basescan key is configured,
        # retry via Basescan so absence/confirmation does not hinge on a single RPC layer.
        if onchain_status == "unreachable" and basescan_key:
            try:
                onchain_root, onchain_status, onchain_note = read_onchain_root_basescan(
                    basescan_key, anchor_addr, anchor["tx"], anchor["batch"]["first_seq"], anchor["batch"]["last_seq"])
                onchain_note = f"[basescan] {onchain_note}"
            except Exception:
                pass  # keep unreachable
        if onchain_status == "found":
            onchain_ok = (onchain_root == recomputed_root)
    step4 = onchain_ok if onchain_status == "found" else (False if onchain_status == "mismatch" else None)
    steps_out.append(("4. root anchored on Base", step4, f"{onchain_note} ({onchain_status})"))

    # 5. payload-integrity classification (operator's claim, echoed honestly)
    ph_class = (bundle.get("checks") or {}).get("payload_hash") or {}

    # Verdict precedence (mirrors the /verify panel + Node verifier): structural fail > payload-bind
    # fail (served only) > reference/seed > anchor_mismatch (found-but-wrong tx) > anchor_absent
    # (reachable, no matching anchor) > rpc_unreachable (no RPC answered) > verified.
    if not merkle_ok or onchain_ok is False:
        verdict = "anchor_root_mismatch"
    elif not redacted and not (payload_ok and chain_ok):
        verdict = "anchored_payload_anomaly" if ph_class.get("status") == "known_legacy_anomaly" else "payload_hash_mismatch"
    elif is_ref_seed:
        verdict = "reference_seed"
    elif onchain_status == "mismatch":
        verdict = "anchor_mismatch"
    elif onchain_status == "absent":
        verdict = "anchor_absent"
    elif onchain_status == "unreachable":
        verdict = "rpc_unreachable"
    else:
        verdict = "verified"
    return {"verdict": verdict, "steps": steps_out, "scope": scope,
            "operator_classification": classification.get("reason") or ph_class.get("reason")}


VERDICT_LINE = {
    "verified": "VERIFIED — independently verified against Base mainnet; no trust in Yolo.",
    "pending_anchor": "PENDING ANCHOR — recorded but not yet anchored on Base. Not verifiable yet.",
    "anchor_root_mismatch": "ANCHOR ROOT MISMATCH — the proof does NOT reconcile to an anchored root. Do not trust.",
    "anchored_payload_anomaly": "ANCHORED PAYLOAD ANOMALY — chain hash IS anchored, but the payload does not re-hash. Operator: documented legacy anomaly, not tampering.",
    "payload_hash_mismatch": "PAYLOAD HASH MISMATCH — payload does not re-hash and is not an allow-listed anomaly. Potential integrity issue.",
    "rpc_unreachable": "RPC UNREACHABLE — recomputed in this tool, but NO Base RPC answered. A connectivity problem, NOT evidence the anchor is missing. Retry with --rpc.",
    "anchor_absent": "ANCHOR ABSENT — a reachable Base RPC returned NO matching anchor for this seq range. The claimed anchor is not on-chain.",
    "anchor_mismatch": "ANCHOR MISMATCH — the referenced tx is not a valid anchorBatch of this batch (wrong target/selector/seq or failed). Do not trust.",
}


def main():
    ap = argparse.ArgumentParser(description="Independent trustless verifier for a Yolo audit entry.")
    ap.add_argument("audit_id", nargs="?", type=int, help="audit log id to fetch from --source")
    ap.add_argument("--bundle", help="verify a local proof-bundle JSON file instead of fetching")
    ap.add_argument("--source", default=DEFAULT_SOURCE, help=f"proof endpoint origin (default {DEFAULT_SOURCE})")
    ap.add_argument("--rpc", default=DEFAULT_RPC, help=f"Base JSON-RPC URL (default {DEFAULT_RPC})")
    ap.add_argument("--anchor-address", default=ANCHOR_ADDRESS, help="YoloAuditAnchor address override")
    ap.add_argument("--basescan", default=os.environ.get("BASESCAN_API_KEY"),
                    help="optional Basescan API key for a non-RPC cross-check when RPCs are unreachable (or set BASESCAN_API_KEY)")
    ap.add_argument("--json", action="store_true", help="machine-readable output")
    args = ap.parse_args()

    if args.bundle:
        with open(args.bundle, encoding="utf-8") as fh:
            bundle = json.load(fh)
    elif args.audit_id is not None:
        bundle = fetch_bundle(args.source, args.audit_id)
    else:
        ap.error("provide an audit_id or --bundle")

    res = verify(bundle, args.rpc, args.anchor_address.lower(), args.basescan)
    verdict = res["verdict"]
    eid = bundle["entry"]["id"]

    if args.json:
        print(json.dumps({"id": eid, "verdict": verdict, "verified": verdict == "verified",
                          "scope": res.get("scope"),
                          "steps": [{"step": s, "result": r, "detail": d} for s, r, d in res["steps"]]}, indent=2))
        return sys.exit(EXIT.get(verdict, 1))

    print(f"\nYolo audit verifier — entry #{eid}")
    print(f"RPC: {urllib.parse.urlparse(args.rpc).netloc}\n")
    for label, ok, detail in res["steps"]:
        mark = "PASS" if ok is True else "FAIL" if ok is False else " -- "
        print(f"  [{mark}] {label:<28} {detail}")
    if res.get("operator_classification"):
        print(f"\n  operator classification: {res['operator_classification']}")
    print(f"\nVERDICT: {verdict.upper()} {'✓' if verdict == 'verified' else ''}")
    print(f"  {VERDICT_LINE.get(verdict, '')}")
    print(f"  scope: {res.get('scope', '')}")
    if verdict == "anchor_absent":
        ab = (bundle.get("anchor") or {}).get("batch") or {}
        floor = LAST_KNOWN_ANCHORS.get(bundle["entry"].get("agent_id"))
        hard = floor is not None and ab.get("last_seq", 1 << 62) <= floor["lastSeq"]
        if hard:
            print(f"  corroborated by this agent's committed checkpoint (anchored through seq {floor['lastSeq']} at block {floor['block']}) — not RPC lag")
        else:
            print("  confirmed against a single reachable source; not covered by the committed checkpoint floor")
    sys.exit(EXIT.get(verdict, 1))


if __name__ == "__main__":
    main()
