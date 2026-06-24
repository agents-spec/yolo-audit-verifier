"""
verifier/rail-verify.py — Python mirror of verifier/rail-verify.ts (the per-rail settlement confirm).

PARITY with the TS canonical is the whole point. This MUST agree with rail-verify.ts on every fixture:
  - JCS(signed_core): reuses the SAME rfc8785 library canon.py already uses for v2 payload_hash
    (byte-for-byte identical to the TS jcsCanonicalize for these ASCII/int/string/nested payloads).
  - integer split math: Python int (arbitrary precision) — agent=(amount*100+9999)//10000 (ceil-1%),
    treasury=amount*200//10000 (floor), owner=remainder — identical to the TS BigInt results.
  - EIP-191 recovery: eth_account recovers the SAME address as viem recoverMessageAddress over
    JCS(signed_core); attestation_valid iff recovered == home.self_wallet.
  - verdict NAMES identical; protocolEnforced1pct uses the SAME 4-condition rule.
  - honesty identical: off-ledger never reads as enforced; rail_unsupported never reads as confirmed;
    the unconditional omission caveat text is present.

Reuse: rfc8785 (canon.py), urllib JSON-RPC (yolo-verify.py). XRPL/Solana readers are stubbed →
rail_unsupported (NOT a false pass), exactly like the TS.

Run the parity emitter:  python3 rail-verify.py --parity fixtures.json   (emits per-fixture verdicts as JSON)
"""
import json
import re
import sys
import urllib.request

import rfc8785
from eth_account import Account
from eth_account.messages import encode_defunct

SETTLEMENT_RECEIPT_ACTION_TYPE = "settlement_receipt"
TRANSFER_TOPIC = "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"  # keccak256("Transfer(address,address,uint256)")
# keccak256("SettlementRouted(uint256,uint256,uint256,uint256,uint256,address,address,address)") — the event
# Block D's SettlementSplit emits on EVERY on-chain split. Its presence (from the pinned address) is the
# contract asserting "I routed this split"; it is what makes chain_enforced more than a forgeable string.
SETTLEMENT_ROUTED_TOPIC = "0xa339757253da7d5a07fa887dad737e505a084a8c182b5bffa32cc551fa355070"
# Pinned, audited SettlementSplit deployments per EVM rail (lowercased). The verifier CARRIES these (like
# the allowlist) and NEVER trusts a contract address from the receipt. A rail with no pinned deployment
# CANNOT have a chain_enforced claim confirmed -> protocolEnforced1pct=false (e.g. Base mainnet until deployed).
SETTLEMENT_SPLIT = {
    "eip155:84532": "0xe7680c1b6132dec06ccdf6a863d09037ecbe03af",  # Base Sepolia (scripts/sepolia/deployed.base-sepolia.json)
}
BPS = 10_000
EVM_RAILS = {"eip155:8453", "eip155:84532"}
DEFAULT_RPCS = {"eip155:8453": "https://mainnet.base.org", "eip155:84532": "https://sepolia.base.org"}

OMISSION_NOTE = (
    " Scope: this confirms only THIS declared settlement. The audit chain is tamper-evident, NOT "
    "omission-evident — it cannot prove the agent had no other, unsealed settlements, and it cannot "
    "prove that transfers outside the declared legs did not occur."
)


# ── JCS(signed_core) — the receipt minus its attestation, canonicalized via rfc8785 (== TS) ─────
def signed_core_preimage(receipt: dict) -> str:
    core = {k: v for k, v in receipt.items() if k != "attestation"}
    return rfc8785.dumps(core).decode("utf-8")


# ── attestation: EIP-191 recover over JCS(signed_core); must == home.self_wallet ────────────────
def verify_attestation(receipt: dict) -> dict:
    att = receipt.get("attestation") or {}
    preimage = signed_core_preimage(receipt)
    self_wallet = (receipt.get("home") or {}).get("self_wallet", "")
    try:
        recovered = Account.recover_message(encode_defunct(text=preimage), signature=att.get("signature"))
        ok = recovered.lower() == self_wallet.lower()
        return {
            "verdict": "attestation_valid" if ok else "attestation_invalid",
            "recovered": recovered,
            "detail": "agent home self_wallet signed this receipt" if ok
                      else f"recovered {recovered} != home.self_wallet {self_wallet}",
        }
    except Exception as e:  # malformed signature
        return {"verdict": "attestation_invalid", "recovered": None, "detail": f"signature malformed: {e}"}


# ── split internal consistency — pure integer re-check, identical to on-chain AgentShareCore ─────
def check_split_consistency(receipt: dict) -> dict:
    try:
        amount = int(receipt["amount"])
        legs = {l["role"]: l for l in receipt["split"]["legs"]}
        a, t, o = legs.get("agent"), legs.get("treasury"), legs.get("owner")
        if not (a and t and o):
            return {"ok": False, "detail": "missing a required split leg (agent/treasury/owner)"}
        exp_a = (amount * 100 + (BPS - 1)) // BPS  # ceil-1%, exactly AgentShareCore.agentShare
        exp_t = (amount * 200) // BPS              # floor-2%
        exp_o = amount - exp_a - exp_t             # remainder
        if int(a["amount"]) != exp_a:
            return {"ok": False, "detail": f"agent leg {a['amount']} != ceil(1%) {exp_a}"}
        if int(t["amount"]) != exp_t:
            return {"ok": False, "detail": f"treasury leg {t['amount']} != floor(2%) {exp_t}"}
        if int(o["amount"]) != exp_o:
            return {"ok": False, "detail": f"owner leg {o['amount']} != remainder {exp_o}"}
        if int(a["amount"]) + int(t["amount"]) + int(o["amount"]) != amount:
            return {"ok": False, "detail": "legs do not sum to amount"}
        return {"ok": True, "detail": "legs sum to amount; agent == ceil(1%) (AgentShareCore rule)"}
    except Exception:
        return {"ok": False, "detail": "non-integer amount or leg amount"}


# ── per-rail reader (raw JSON-RPC like yolo-verify.py; stubs un-wired rails) ─────────────────────
def _rpc_call(rpc_url: str, method: str, params: list):
    body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}).encode()
    # User-Agent: Cloudflare-fronted RPCs (e.g. sepolia.base.org) reject urllib's default UA with HTTP 403.
    # Transport-only — does not touch the verdict/assess logic or TS<->Python parity.
    req = urllib.request.Request(rpc_url, data=body, headers={"content-type": "application/json", "User-Agent": "yolo-audit-verifier"})
    with urllib.request.urlopen(req, timeout=25) as resp:
        return json.loads(resp.read()).get("result")


def read_evm_settlement(receipt: dict, rpc_url=None) -> dict:
    rail = receipt["rail"]
    if rail not in EVM_RAILS:
        return {"kind": "unsupported", "detail": f"no EVM client registered for rail {rail}"}
    proof = receipt.get("proof") or {}
    if proof.get("kind") != "evm_tx" or not proof.get("tx_hash"):
        return {"kind": "absent", "detail": "receipt proof is not an evm_tx with a tx_hash"}
    url = rpc_url or DEFAULT_RPCS.get(rail)
    try:
        rc = _rpc_call(url, "eth_getTransactionReceipt", [proof["tx_hash"]])
        if not rc:
            return {"kind": "absent", "detail": "tx not found on rail"}
        if rc.get("status") != "0x1":
            return {"kind": "absent", "detail": f"tx not successful (status={rc.get('status')})"}
        transfers = []
        for log in rc.get("logs", []):
            topics = log.get("topics", [])
            if len(topics) == 3 and topics[0].lower() == TRANSFER_TOPIC:
                transfers.append({
                    "token": log["address"].lower(),
                    "from": ("0x" + topics[1][-40:]).lower(),
                    "to": ("0x" + topics[2][-40:]).lower(),
                    "amount": str(int(log["data"], 16)),
                })
        # SettlementRouted emitters in the same tx (the EVM contract-enforcement signal; empty on most txs).
        split_events = [{"emitter": log["address"].lower()} for log in rc.get("logs", [])
                        if (log.get("topics") or [""])[0].lower() == SETTLEMENT_ROUTED_TOPIC]
        return {"kind": "found", "transfers": transfers, "splitEvents": split_events}
    except Exception as e:
        return {"kind": "unreachable", "detail": f"rail RPC error: {e}"}


# EVM chain-enforcement binding (MUST be byte-identical to rail-verify.ts). protocolEnforced1pct may be
# TRUE only if the split was performed by the PINNED SettlementSplit for this rail: (1) the tx emitted a
# SettlementRouted event FROM the pinned address (the contract's own assertion), AND (2) every declared
# leg was sent BY that pinned contract (Transfer.from == pinned). Both are required; missing either, or a
# rail with no pinned deployment, -> not bound (the chain_enforced claim cannot be independently confirmed).
def check_split_contract_binding(receipt, transfers, split_events):
    pinned = SETTLEMENT_SPLIT.get(receipt["rail"])
    if not pinned:
        return {"bound": False, "detail": f"no pinned SettlementSplit for rail {receipt['rail']} — chain enforcement cannot be confirmed"}
    event_from_pinned = any(e.get("emitter") == pinned for e in (split_events or []))
    token = norm_addr(receipt["rail"], receipt["asset"]["rail_address"])
    legs_from_pinned = all(
        any(tr["token"] == token and tr["to"] == norm_addr(receipt["rail"], leg["dest"]) and tr["amount"] == leg["amount"] and tr.get("from") == pinned
            for tr in transfers)
        for leg in receipt["split"]["legs"])
    if not event_from_pinned:
        return {"bound": False, "detail": f"no SettlementRouted event from the pinned SettlementSplit {pinned}"}
    if not legs_from_pinned:
        return {"bound": False, "detail": f"split legs were not all emitted by the pinned SettlementSplit {pinned} (Transfer.from mismatch)"}
    return {"bound": True, "detail": f"split bound to the pinned SettlementSplit {pinned} (SettlementRouted + all legs from the contract)"}


# ── shared parity-critical helpers (MUST be byte-identical to rail-verify.ts) ────────────────────
def xrpl_currency_to_40hex(code: str) -> str:
    if re.fullmatch(r"[0-9a-fA-F]{40}", code):
        return code.upper()
    hex_ = "".join(f"{ord(c):02x}" for c in code)
    return (hex_ + "0" * 40)[:40].upper()  # ASCII bytes left-justified in 20 bytes


def scale_decimal_to_base_units(decimal_str: str, decimals: int):
    """Exact decimal -> integer base-units; None if it does NOT scale cleanly (caller must not confirm)."""
    if not re.fullmatch(r"\d+(\.\d+)?", decimal_str):
        return None
    int_part, _, frac = decimal_str.partition(".")
    if len(frac) > decimals:
        return None
    return int(int_part + frac.ljust(decimals, "0"))


def norm_addr(rail: str, s: str) -> str:
    """Rail-aware: EVM case-insensitive (lowercase); XRPL/Solana case-SENSITIVE (exact). == rail-verify.ts."""
    return s.lower() if rail.startswith("eip155:") else s


def _rail_rpc_list(rail: str, override, defaults):
    if override:
        return [override] + defaults
    try:
        m = json.loads(__import__("os").environ.get("RAIL_RPCS", "{}"))
        if m.get(rail):
            return [m[rail]] + defaults
    except Exception:
        pass
    return defaults


# ── XRPL reader — per-leg `tx` lookup; PURE parser mirrors parseXrplSettlement ───────────────────
XRPL_RPCS = ["https://xrplcluster.com", "https://s1.ripple.com:51234", "https://s2.ripple.com:51234"]


def parse_xrpl_settlement(receipt: dict, leg_results: list) -> dict:
    if any(not r.get("reachable") for r in leg_results):
        return {"kind": "unreachable", "detail": "an XRPL endpoint was unreachable for a leg"}
    legs = receipt["split"]["legs"]
    for i, leg in enumerate(legs):
        tx = leg_results[i].get("tx") if i < len(leg_results) else None
        if not tx or tx.get("validated") is not True or (tx.get("meta") or {}).get("TransactionResult") != "tesSUCCESS":
            return {"kind": "absent", "detail": f"leg {leg['role']}: tx missing / not validated / not tesSUCCESS"}
    transfers = []
    for i, leg in enumerate(legs):
        tx = leg_results[i]["tx"]
        if tx.get("ledger_index") != (leg.get("proof") or {}).get("ledger_index"):
            continue  # ledger mismatch -> suppress -> assessor mismatch
        delivered = (tx.get("meta") or {}).get("delivered_amount")
        if delivered is None:
            continue  # must use delivered_amount
        amount = None
        if isinstance(delivered, str):
            if receipt["asset"]["symbol"].upper() != "XRP":
                continue
            amount = int(delivered) if re.fullmatch(r"\d+", delivered) else None
        elif isinstance(delivered, dict):
            currency_ok = xrpl_currency_to_40hex(str(delivered.get("currency"))) == xrpl_currency_to_40hex(receipt["asset"]["symbol"])
            issuer_ok = norm_addr(receipt["rail"], str(delivered.get("issuer") or "")) == norm_addr(receipt["rail"], receipt["asset"]["rail_address"])
            if not (currency_ok and issuer_ok):
                continue
            amount = scale_decimal_to_base_units(str(delivered.get("value")), receipt["asset"]["decimals"])
        if amount is None:
            continue
        transfers.append({"token": norm_addr(receipt["rail"], receipt["asset"]["rail_address"]), "to": norm_addr(receipt["rail"], str(tx.get("Destination") or "")), "amount": str(amount)})
    return {"kind": "found", "transfers": transfers}


def _xrpl_tx(endpoints, tx_hash):
    for url in endpoints:
        try:
            body = json.dumps({"method": "tx", "params": [{"transaction": tx_hash, "binary": False}]}).encode()
            req = urllib.request.Request(url, data=body, headers={"content-type": "application/json"})
            with urllib.request.urlopen(req, timeout=25) as resp:
                r = (json.loads(resp.read()) or {}).get("result")
            if not r:
                continue
            if r.get("error") or r.get("status") == "error":
                return {"reachable": True, "tx": None}
            return {"reachable": True, "tx": r}
        except Exception:
            continue
    return {"reachable": False, "tx": None}


def read_xrpl_settlement(receipt: dict, rpc_url=None) -> dict:
    endpoints = _rail_rpc_list(receipt["rail"], rpc_url, XRPL_RPCS)
    leg_results = []
    for leg in receipt["split"]["legs"]:
        h = (leg.get("proof") or {}).get("tx_hash")
        leg_results.append(_xrpl_tx(endpoints, h) if h else {"reachable": True, "tx": None})
    return parse_xrpl_settlement(receipt, leg_results)


# ── Solana reader — one getTransaction; balance-delta matching with ambiguity guard ──────────────
SOLANA_RPCS = ["https://api.mainnet-beta.solana.com"]


def parse_solana_settlement(receipt: dict, g: dict) -> dict:
    if not g.get("reachable"):
        return {"kind": "unreachable", "detail": "Solana RPC unreachable"}
    tx = g.get("tx")
    if not tx:
        return {"kind": "absent", "detail": "tx not found"}
    if (tx.get("meta") or {}).get("err") is not None:
        return {"kind": "absent", "detail": "tx failed (meta.err != null)"}
    mint = receipt["asset"]["rail_address"]
    deltas = {}

    def apply(arr, sign):
        for b in arr or []:
            if b.get("mint") != mint:
                continue
            owner = str(b.get("owner"))
            deltas[owner] = deltas.get(owner, 0) + sign * int(b["uiTokenAmount"]["amount"])

    meta = tx.get("meta") or {}
    apply(meta.get("preTokenBalances"), -1)
    apply(meta.get("postTokenBalances"), 1)
    transfers = [{"token": norm_addr(receipt["rail"], mint), "to": norm_addr(receipt["rail"], owner), "amount": str(delta)} for owner, delta in deltas.items() if delta > 0]
    return {"kind": "found", "transfers": transfers}


def _solana_get_tx(endpoints, sig):
    for url in endpoints:
        try:
            body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "getTransaction",
                               "params": [sig, {"encoding": "jsonParsed", "maxSupportedTransactionVersion": 0, "commitment": "finalized"}]}).encode()
            req = urllib.request.Request(url, data=body, headers={"content-type": "application/json"})
            with urllib.request.urlopen(req, timeout=25) as resp:
                j = json.loads(resp.read())
            if j.get("error"):
                continue
            return {"reachable": True, "tx": j.get("result")}
        except Exception:
            continue
    return {"reachable": False, "tx": None}


def read_solana_settlement(receipt: dict, rpc_url=None) -> dict:
    sig = (receipt.get("proof") or {}).get("signature")
    if not sig:
        return {"kind": "absent", "detail": "receipt proof has no Solana signature"}
    endpoints = _rail_rpc_list(receipt["rail"], rpc_url, SOLANA_RPCS)
    return parse_solana_settlement(receipt, _solana_get_tx(endpoints, sig))


def read_rail_settlement(receipt: dict, rpc_url=None) -> dict:
    family = receipt["rail"].split(":")[0]
    if family == "eip155":
        return read_evm_settlement(receipt, rpc_url)
    if family == "xrpl":
        return read_xrpl_settlement(receipt, rpc_url)
    if family == "solana":
        return read_solana_settlement(receipt, rpc_url)
    return {"kind": "unsupported", "detail": f"unknown rail family: {family}"}


# ── verdict (PURE given the rail read) — mirrors assessRailCore in rail-verify.ts ────────────────
# Split assessment — UNCHANGED logic, returns the funding-free core. The funding facet is applied in the
# assess_rail_settlement wrapper below; this core never sees it (computed independently).
def _assess_rail_core(receipt: dict, read: dict) -> dict:
    att = verify_attestation(receipt)
    split = check_split_consistency(receipt)
    checks = [
        {"label": "Receipt attestation recovers to home.self_wallet",
         "result": "pass" if att["verdict"] == "attestation_valid" else "fail", "detail": att["detail"]},
        {"label": "Split legs sum to amount; agent == ceil(1%) (AgentShareCore rule)",
         "result": "pass" if split["ok"] else "fail", "detail": split["detail"]},
    ]

    def finalize(rail_verdict, tone, headline, note, protocol_enforced):
        t, n = tone, note
        if att["verdict"] == "attestation_invalid":
            if rail_verdict == "rail_settlement_confirmed" and t == "ok":
                t = "warn"
            n = f"ATTESTATION INVALID — this receipt is NOT signed by the agent's home self_wallet ({att['detail']}). " + n
        return {
            "railVerdict": rail_verdict,
            "attestation": att["verdict"],
            "splitConsistent": split["ok"],
            "enforcementClaim": receipt.get("enforcement"),
            "protocolEnforced1pct": bool(protocol_enforced and att["verdict"] == "attestation_valid"),
            "tone": t,
            "headline": headline,
            "note": n + OMISSION_NOTE,
            "checks": checks,
        }

    kind = read.get("kind")
    if kind == "unsupported":
        checks.append({"label": "Settlement confirmed on the rail", "result": "skip", "detail": f"rail_unsupported: {read.get('detail')}"})
        return finalize("rail_unsupported", "neutral", "Rail not independently confirmable yet (NOT a pass)",
                        f"The rail {receipt['rail']} has no wired reader, so the declared on-chain settlement was NOT "
                        f"independently checked. This is explicitly NOT a confirmation. {read.get('detail')}.", False)
    if kind == "unreachable":
        checks.append({"label": "Settlement confirmed on the rail", "result": "skip", "detail": f"rail_unreachable: {read.get('detail')}"})
        return finalize("rail_unreachable", "warn", "Rail RPC unreachable — not confirmed",
                        f"Could not reach an RPC for {receipt['rail']}; this is a connectivity problem, NOT evidence the "
                        f"settlement is missing. {read.get('detail')}.", False)
    if kind == "absent":
        checks.append({"label": "Settlement confirmed on the rail", "result": "fail", "detail": f"rail_settlement_absent: {read.get('detail')}"})
        return finalize("rail_settlement_absent", "bad", "Declared settlement NOT found on the rail",
                        f"A reachable rail read found no successful settlement matching the receipt's proof: {read.get('detail')}. "
                        f"Do not trust this receipt's settlement claim.", False)

    # found → match each declared leg (asset/dest/amount) against the actual on-chain transfers
    token = norm_addr(receipt["rail"], receipt["asset"]["rail_address"])
    transfers = read.get("transfers", [])
    all_legs_found = True
    for leg in receipt["split"]["legs"]:
        matched = any(tr["token"] == token and tr["to"] == norm_addr(receipt["rail"], leg["dest"]) and tr["amount"] == leg["amount"] for tr in transfers)
        if not matched:
            all_legs_found = False
        checks.append({"label": f"Leg {leg['role']} {leg['amount']} -> {leg['dest'][:12]}... present on-chain",
                       "result": "pass" if matched else "fail",
                       "detail": None if matched else "no matching on-chain transfer (asset/dest/amount)"})

    if not all_legs_found:
        return finalize("rail_settlement_mismatch", "bad",
                        "Settlement found, but the declared split does NOT match on-chain transfers",
                        "The proof tx exists and succeeded, but one or more declared split legs (asset/amount/dest) do NOT "
                        "match the actual on-chain transfers. The receipt misstates the settlement — do not trust it.", False)

    agent_leg = next((l for l in receipt["split"]["legs"] if l["role"] == "agent"), None)
    agent_to_self = bool(agent_leg) and agent_leg["dest"].lower() == receipt["home"]["self_wallet"].lower()
    is_evm = receipt["rail"].startswith("eip155:")

    if receipt.get("enforcement") == "chain_enforced" and is_evm and agent_to_self and split["ok"]:
        # EVM contract-binding (the gap-closer): protocolEnforced1pct=true ONLY if the split was performed by
        # the PINNED SettlementSplit — its SettlementRouted event AND all legs sent by it (Transfer.from). Without
        # this, three transfers in the 97/1/2 ratio + a chain_enforced string would forge a "protocol-enforced" pass.
        binding = check_split_contract_binding(receipt, read.get("transfers", []), read.get("splitEvents"))
        checks.append({"label": "Split performed by the pinned SettlementSplit contract",
                       "result": "pass" if binding["bound"] else "fail", "detail": binding["detail"]})
        if binding["bound"]:
            return finalize("rail_settlement_confirmed", "ok",
                            "Settlement CONFIRMED on-chain — inviolable-1% independently verified",
                            f"Every declared split leg matches an on-chain transfer in the proof tx, INCLUDING the agent's 1% "
                            f"({agent_leg['amount']}) to home.self_wallet, and the split was performed by the pinned SettlementSplit "
                            f"contract — so the inviolable-1% is independently confirmed from the chain itself, not merely asserted.", True)
        return finalize("rail_settlement_confirmed", "ok",
                        "Declared payments CONFIRMED — chain_enforced claim NOT contract-verified",
                        f"Every declared split leg matches an on-chain transfer, but the split could NOT be bound to the pinned "
                        f"SettlementSplit contract ({binding['detail']}). The enforcement=\"chain_enforced\" claim is therefore NOT "
                        f"independently confirmed — treat the 1% as proven-and-audited, NOT protocol-enforced.", False)

    why = ("enforcement=attested_off_ledger: the 1% is PROVEN-AND-AUDITED (the declared payments exist and follow the "
           "97/1/2 ratio) but was NOT enforced by an on-chain protocol — this tool does NOT and cannot assert protocol-level "
           "1% enforcement on this rail."
           if receipt.get("enforcement") == "attested_off_ledger"
           else "the agent-1%-to-self_wallet leg could not be tied to an on-chain transfer in a way that proves protocol "
                "enforcement — treat the 1% as proven-and-audited, not protocol-enforced.")
    return finalize("rail_settlement_confirmed", "ok",
                    "Declared payments CONFIRMED on the rail — NOT protocol-enforced",
                    f"Every declared split leg matches an on-chain transfer, so the declared payments occurred. {why}", False)


# ── x402 funding-leg confirm (Stage 2) — mirrors readFundingSettlement/assessFundingVerdict in the TS ──
def read_funding_settlement(receipt: dict, rpc_url=None) -> dict:
    """REUSE the rail readers to confirm funding_proof's tx (same machinery as the split legs)."""
    fp = receipt.get("funding_proof")
    if not fp:
        return {"kind": "absent", "detail": "no funding_proof on receipt"}
    family = fp["rail"].split(":")[0]
    if family == "eip155":
        synthetic = {"rail": fp["rail"], "proof": {"kind": "evm_tx", "tx_hash": fp["tx_hash"]}, "asset": fp["asset"], "split": {"legs": []}}
        return read_evm_settlement(synthetic, rpc_url)
    if family == "solana":
        synthetic = {"rail": fp["rail"], "proof": {"kind": "solana_tx", "signature": fp["tx_hash"]}, "asset": fp["asset"], "split": {"legs": []}}
        return read_solana_settlement(synthetic, rpc_url)
    if family == "xrpl":
        # funding_proof declares no ledger_index → set the synthetic leg's from the fetched tx, reuse parser.
        endpoints = _rail_rpc_list(fp["rail"], rpc_url, XRPL_RPCS)
        leg_result = _xrpl_tx(endpoints, fp["tx_hash"])
        synthetic = {
            "rail": fp["rail"], "asset": fp["asset"],
            "split": {"legs": [{"role": "funding", "dest": fp["payee"], "amount": fp["amount"],
                                "proof": {"kind": "xrpl_tx", "tx_hash": fp["tx_hash"],
                                          "ledger_index": (leg_result.get("tx") or {}).get("ledger_index")}}]},
        }
        return parse_xrpl_settlement(synthetic, [leg_result])
    return {"kind": "unsupported", "detail": f"no reader for funding rail family {family}"}


def funding_verdict_from_read(receipt: dict, funding_read) -> str:
    """PURE: funding_proof + its pre-fetched rail read -> funding verdict. Mirrors assessFundingVerdict."""
    fp = receipt.get("funding_proof")
    if not fp:
        return "funding_absent_field"
    if funding_read is None:
        return "funding_unreachable"  # has funding_proof but not checked -> can't confirm (informational)
    kind = funding_read.get("kind")
    if kind in ("unreachable", "unsupported"):
        return "funding_unreachable"
    if kind == "absent":
        return "funding_mismatch"  # claimed funding tx missing/failed -> contradicts
    token = norm_addr(fp["rail"], fp["asset"]["rail_address"])
    to = norm_addr(fp["rail"], fp["payee"])
    matched = any(tr["token"] == token and tr["to"] == to and tr["amount"] == fp["amount"] for tr in funding_read.get("transfers", []))
    return "funding_confirmed" if matched else "funding_mismatch"


# The exported assessor: split assessment (computed INDEPENDENTLY by _assess_rail_core) PLUS the
# orthogonal funding facet with OQ-10 gating. railVerdict/splitConsistent/protocolEnforced1pct unchanged.
def assess_rail_settlement(receipt: dict, read: dict, funding_read=None) -> dict:
    a = _assess_rail_core(receipt, read)
    fv = funding_verdict_from_read(receipt, funding_read)
    tone, note, checks = a["tone"], a["note"], list(a["checks"])
    if fv == "funding_confirmed":
        checks.append({"label": "x402 funding tx confirmed on rail", "result": "pass",
                       "detail": f"funding {receipt['funding_proof']['amount']} -> {receipt['funding_proof']['payee']} confirmed on {receipt['funding_proof']['rail']}"})
    elif fv == "funding_mismatch":
        checks.append({"label": "x402 funding tx confirmed on rail", "result": "fail",
                       "detail": "funding tx contradicts the claim (amount/payee/asset, or absent when it must exist)"})
        tone = "bad"  # OQ-10: a provably-false funding claim DOWNGRADES the overall tone (even if the split confirms)
        note = "FUNDING MISMATCH — the receipt's x402 funding_proof does NOT match the rail (provably-false funding claim). " + note
    elif fv == "funding_unreachable":
        checks.append({"label": "x402 funding tx confirmed on rail", "result": "skip",
                       "detail": "funding rail RPC unreachable / not checked — informational, does NOT downgrade the split verdict"})
    # funding_absent_field (non-x402 receipt) -> no check, no change (behaves exactly as before)
    out = dict(a)
    out["tone"], out["note"], out["checks"], out["fundingVerdict"] = tone, note, checks, fv
    return out


# ── parity emitter: read fixtures [{name, receipt, railInput}], emit per-fixture verdicts as JSON ─
# railInput is EITHER a ready RailRead ({"kind":...}) OR chain-raw inputs to run through the PARSER:
#   {"chain":"xrpl","legResults":[...]}  |  {"chain":"solana","getTx":{...}}
def _resolve_read(receipt: dict, rail_input: dict) -> dict:
    if "chain" in rail_input:
        if rail_input["chain"] == "xrpl":
            return parse_xrpl_settlement(receipt, rail_input["legResults"])
        if rail_input["chain"] == "solana":
            return parse_solana_settlement(receipt, rail_input["getTx"])
    return rail_input  # already a RailRead


def _parity(path: str):
    with open(path) as f:
        fixtures = json.load(f)
    out = []
    for fx in fixtures:
        read = _resolve_read(fx["receipt"], fx.get("railInput", fx.get("read")))
        funding_read = None
        if fx.get("fundingRead") is not None:
            funding_read = _resolve_read(fx["receipt"], fx["fundingRead"])  # ready RailRead or chain-raw
        a = assess_rail_settlement(fx["receipt"], read, funding_read)
        out.append({
            "name": fx["name"],
            "railVerdict": a["railVerdict"],
            "attestation": a["attestation"],
            "splitConsistent": a["splitConsistent"],
            "protocolEnforced1pct": a["protocolEnforced1pct"],
            "fundingVerdict": a["fundingVerdict"],
            "tone": a["tone"],
        })
    print(json.dumps(out))


# ── helpers parity: emit the shared-helper outputs for direct TS<->Python comparison ─────────────
def _helpers(path: str):
    with open(path) as f:
        cases = json.load(f)
    out = {
        "currency": [xrpl_currency_to_40hex(c) for c in cases.get("currencyCases", [])],
        "scale": [(None if (v := scale_decimal_to_base_units(s, d)) is None else str(v)) for s, d in cases.get("scaleCases", [])],
    }
    print(json.dumps(out))


if __name__ == "__main__":
    if len(sys.argv) >= 3 and sys.argv[1] == "--parity":
        _parity(sys.argv[2])
    elif len(sys.argv) >= 3 and sys.argv[1] == "--helpers":
        _helpers(sys.argv[2])
    else:
        print("usage: python3 rail-verify.py [--parity|--helpers] <fixtures.json>", file=sys.stderr)
        sys.exit(2)
