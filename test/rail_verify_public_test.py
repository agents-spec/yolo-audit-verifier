"""
Public, self-contained Python rail-verification demo — runnable by anyone who clones the verifier.
Loads ONLY rail-verify.py (flat, via importlib since the filename is hyphenated); uses the SAME static
pre-signed fixtures (rail-fixtures.json) and CANNED rail responses — no live network, no emit-path
builder, no monorepo deps. Deps: rfc8785 + eth-account (requirements.txt).

Run:  pip install -r requirements.txt  &&  python3 test/rail_verify_public_test.py
"""
import importlib.util
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
spec = importlib.util.spec_from_file_location("rail_verify", os.path.join(HERE, "..", "rail-verify.py"))
rv = importlib.util.module_from_spec(spec)
spec.loader.exec_module(rv)

with open(os.path.join(HERE, "rail-fixtures.json")) as f:
    FIXTURES = json.load(f)


def to_read(receipt, rail_input):
    if rail_input.get("chain") == "xrpl":
        return rv.parse_xrpl_settlement(receipt, rail_input["legResults"])
    if rail_input.get("chain") == "solana":
        return rv.parse_solana_settlement(receipt, rail_input["getTx"])
    return rail_input  # already a RailRead


def main():
    failures = 0
    for fx in FIXTURES:
        a = rv.assess_rail_settlement(fx["receipt"], to_read(fx["receipt"], fx["railInput"]))
        exp = fx["expected"]
        checks = [
            ("railVerdict", a["railVerdict"], exp["railVerdict"]),
            ("attestation", a["attestation"], exp["attestation"]),
            ("protocolEnforced1pct", a["protocolEnforced1pct"], exp["protocolEnforced1pct"]),
        ]
        ok = all(got == want for _, got, want in checks)
        # honesty invariants (every verdict)
        ok = ok and ("tamper-evident, NOT omission-evident" in a["note"])
        if fx["receipt"]["enforcement"] == "attested_off_ledger":
            ok = ok and (a["protocolEnforced1pct"] is False)
        if ok:
            print(f"  OK  {fx['name']}: {a['railVerdict']} / {a['attestation']} / protocolEnforced1pct={a['protocolEnforced1pct']}")
        else:
            failures += 1
            print(f"  FAIL {fx['name']}: got {[ (n, g) for n, g, w in checks ]} expected {exp}")
    if failures:
        print(f"\n{failures} FAILED")
        sys.exit(1)
    print(f"\nall {len(FIXTURES)} public rail fixtures passed (Python)")


if __name__ == "__main__":
    main()
