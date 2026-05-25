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
  payload_hash_mismatch | onchain_unconfirmed

USAGE:
  python3 yolo-verify.py <audit_id> [--source https://yolo.solutions] [--rpc URL] [--json]
  python3 yolo-verify.py --bundle bundle.json [--rpc URL] [--json]
EXIT: 0 verified · 2 pending_anchor · 3 anchored_payload_anomaly · 4 onchain_unconfirmed ·
      5 anchor_root_mismatch · 6 payload_hash_mismatch · 1 error
"""
import argparse
import hashlib
import json
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

EXIT = {"verified": 0, "error": 1, "pending_anchor": 2, "anchored_payload_anomaly": 3,
        "onchain_unconfirmed": 4, "anchor_root_mismatch": 5, "payload_hash_mismatch": 6}


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


def read_onchain_root(rpc_url, anchor_addr, tx_hash, exp_first, exp_last):
    """APPROACH B — read the anchored root straight from the anchoring tx's PUBLIC calldata.
    No ABI library: pure slicing. Returns (root_hex|None, note).

    anchorBatch(string agentId, bytes32 merkleRoot, string ipfsCid,
                uint32 logCount, uint64 firstSeq, uint64 lastSeq)
    Calldata = 4-byte selector + ABI head (one 32-byte / 64-hex word per param, in order):
        word 0 : offset -> agentId   (dynamic string; pointer into the tail)
        word 1 : merkleRoot          (bytes32, stored INLINE)        <-- the anchored root
        word 2 : offset -> ipfsCid   (dynamic string; pointer)
        word 3 : logCount            (uint32,  right-aligned in the word)
        word 4 : firstSeq            (uint64,  right-aligned)
        word 5 : lastSeq             (uint64,  right-aligned)
    So merkleRoot = word 1; firstSeq/lastSeq = words 4/5 (used to confirm the tx anchors THIS
    batch). We additionally require tx.to == the published anchor address, the anchorBatch
    selector, and receipt.status == success — so the slice can only be read from a genuine,
    successful anchor of this exact batch.
    """
    tx = rpc_call(rpc_url, "eth_getTransactionByHash", [tx_hash])
    if tx is None:
        return None, "tx not found on this RPC"
    to = (tx.get("to") or "").lower()
    if to != anchor_addr:
        return None, f"tx.to {to} != anchor {anchor_addr}"
    data = tx["input"]
    if not data.startswith(ANCHOR_BATCH_SELECTOR):
        return None, f"selector {data[:10]} != anchorBatch {ANCHOR_BATCH_SELECTOR}"
    body = data[10:]  # strip "0x" + 8-hex selector
    word = lambda i: body[i * 64:(i + 1) * 64]  # noqa: E731
    root = word(1).lower()
    first_seq, last_seq = int(word(4), 16), int(word(5), 16)
    if first_seq != exp_first or last_seq != exp_last:
        return None, f"tx batch seq[{first_seq}-{last_seq}] != bundle seq[{exp_first}-{exp_last}]"
    receipt = rpc_call(rpc_url, "eth_getTransactionReceipt", [tx_hash])
    status = receipt.get("status") if receipt else None
    if status != "0x1":
        return None, f"tx not successful (status={status})"
    return root, f"tx {tx_hash[:10]}…"


def fetch_bundle(source: str, audit_id: int) -> dict:
    url = f"{source.rstrip('/')}/api/verify/{audit_id}/proof"
    try:
        with urllib.request.urlopen(url, timeout=25) as resp:
            return json.load(resp)
    except urllib.error.HTTPError as e:
        if e.code == 404:
            raise SystemExit(f"error: no audit entry with id {audit_id} (404)")
        raise


def verify(bundle: dict, rpc_url: str, anchor_addr: str) -> dict:
    entry, hashes = bundle["entry"], bundle["hashes"]
    steps_out = []

    # 1. payload -> payload_hash
    recomputed_ph = canon_payload_hash(entry["payload"], entry.get("canon_version"))
    payload_ok = recomputed_ph == hashes["payload_hash"]
    cv = entry.get("canon_version") or "v1(null)"
    steps_out.append(("1. payload -> payload_hash", payload_ok,
                      f"({cv}) {recomputed_ph[:12]}… {'==' if payload_ok else '!='} stored"))

    # 2. chain_hash binding
    recomputed_ch = sha256_hex(f"{entry['agent_id']}:{entry['seq']}:{entry['prev_hash']}:{hashes['payload_hash']}")
    chain_ok = recomputed_ch == hashes["chain_hash"]
    steps_out.append(("2. chain_hash binding", chain_ok,
                      f"{recomputed_ch[:12]}… {'==' if chain_ok else '!='} stored chain_hash"))

    anchored = bool(bundle.get("anchored") and bundle.get("anchor") and bundle.get("merkle_proof"))
    if not anchored:
        steps_out.append(("3. Merkle proof -> root", None, "no anchor yet"))
        steps_out.append(("4. root anchored on Base", None, "no anchor yet"))
        return {"verdict": "pending_anchor", "steps": steps_out}

    # 3. Merkle proof -> root
    mp, anchor = bundle["merkle_proof"], bundle["anchor"]
    leaf_ok = mp["leaf"] == hashes["chain_hash"]
    recomputed_root = recompute_merkle_root(mp["leaf"], mp["steps"], mp["single_leaf_batch"])
    merkle_ok = leaf_ok and recomputed_root == anchor["root"].lower()
    steps_out.append(("3. Merkle proof -> root", merkle_ok,
                      f"{recomputed_root[:12]}… {'==' if recomputed_root == anchor['root'].lower() else '!='} proof root"
                      + ("" if leaf_ok else "  [leaf != chain_hash!]")))

    # 4. root anchored on Base (Approach B)
    onchain_ok, onchain_note = None, "no on-chain tx in bundle"
    if anchor.get("tx"):
        try:
            onchain_root, onchain_note = read_onchain_root(
                rpc_url, anchor_addr, anchor["tx"], anchor["batch"]["first_seq"], anchor["batch"]["last_seq"])
            onchain_ok = (onchain_root == recomputed_root) if onchain_root else None
        except urllib.error.HTTPError as exc:
            onchain_ok, onchain_note = None, f"Base read failed: HTTP {exc.code}"
        except Exception as exc:  # never echo the RPC URL — it may carry an API key
            onchain_ok, onchain_note = None, f"Base read failed: {type(exc).__name__}"
    steps_out.append(("4. root anchored on Base",
                      onchain_ok,
                      (f"{onchain_note} root {'==' if onchain_ok else '!=' if onchain_ok is False else '?'} recomputed")))

    # 5. payload-integrity classification (operator's claim, echoed honestly)
    ph_class = (bundle.get("checks") or {}).get("payload_hash") or {}

    # Verdict — same precedence as the Yolo /verify panel (and the bundled Node verifier).
    if not merkle_ok or onchain_ok is False:
        verdict = "anchor_root_mismatch"
    elif not (payload_ok and chain_ok):
        verdict = "anchored_payload_anomaly" if ph_class.get("status") == "known_legacy_anomaly" else "payload_hash_mismatch"
    elif onchain_ok is None:
        verdict = "onchain_unconfirmed"
    else:
        verdict = "verified"
    return {"verdict": verdict, "steps": steps_out, "operator_classification": ph_class.get("reason")}


VERDICT_LINE = {
    "verified": "VERIFIED — independently verified against Base mainnet; no trust in Yolo.",
    "pending_anchor": "PENDING ANCHOR — recorded but not yet anchored on Base. Not verifiable yet.",
    "anchor_root_mismatch": "ANCHOR ROOT MISMATCH — the proof does NOT reconcile to an anchored root. Do not trust.",
    "anchored_payload_anomaly": "ANCHORED PAYLOAD ANOMALY — chain hash IS anchored, but the payload does not re-hash. Operator: documented legacy anomaly, not tampering.",
    "payload_hash_mismatch": "PAYLOAD HASH MISMATCH — payload does not re-hash and is not an allow-listed anomaly. Potential integrity issue.",
    "onchain_unconfirmed": "ONCHAIN UNCONFIRMED — recomputed in this tool, but could not read Base to confirm. Retry with --rpc.",
}


def main():
    ap = argparse.ArgumentParser(description="Independent trustless verifier for a Yolo audit entry.")
    ap.add_argument("audit_id", nargs="?", type=int, help="audit log id to fetch from --source")
    ap.add_argument("--bundle", help="verify a local proof-bundle JSON file instead of fetching")
    ap.add_argument("--source", default=DEFAULT_SOURCE, help=f"proof endpoint origin (default {DEFAULT_SOURCE})")
    ap.add_argument("--rpc", default=DEFAULT_RPC, help=f"Base JSON-RPC URL (default {DEFAULT_RPC})")
    ap.add_argument("--anchor-address", default=ANCHOR_ADDRESS, help="YoloAuditAnchor address override")
    ap.add_argument("--json", action="store_true", help="machine-readable output")
    args = ap.parse_args()

    if args.bundle:
        with open(args.bundle, encoding="utf-8") as fh:
            bundle = json.load(fh)
    elif args.audit_id is not None:
        bundle = fetch_bundle(args.source, args.audit_id)
    else:
        ap.error("provide an audit_id or --bundle")

    res = verify(bundle, args.rpc, args.anchor_address.lower())
    verdict = res["verdict"]
    eid = bundle["entry"]["id"]

    if args.json:
        print(json.dumps({"id": eid, "verdict": verdict, "verified": verdict == "verified",
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
    sys.exit(EXIT.get(verdict, 1))


if __name__ == "__main__":
    main()
