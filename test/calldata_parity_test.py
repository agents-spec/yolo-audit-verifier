#!/usr/bin/env python3
"""
calldata_parity_test.py — Python side of the anchorBatch calldata-parse parity. yolo-verify.py's
_decode_anchor_tx (the CONTROL) must return the same (root, status) as verify-core.js's
parseAnchorBatchCalldata for every case in calldata-fixtures.json — proving the highest-stakes
step is identical across the JS core and the Python control, transport substituted with static
tx/receipt objects.

Run:  .venv/bin/python test/calldata_parity_test.py
Exit: 0 all passed · 1 any assertion failed
"""
import importlib.util
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.join(HERE, "..")
sys.path.insert(0, ROOT)
spec = importlib.util.spec_from_file_location("yolo_verify", os.path.join(ROOT, "yolo-verify.py"))
yv = importlib.util.module_from_spec(spec)
spec.loader.exec_module(yv)

with open(os.path.join(HERE, "calldata-fixtures.json"), encoding="utf-8") as fh:
    FIX = json.load(fh)
ADDR = FIX["anchor_address"]

failures = 0
for c in FIX["cases"]:
    # Substitute transport: callbacks return the static tx / receipt (or None), exactly what a real
    # eth_getTransactionByHash / eth_getTransactionReceipt would hand the parse.
    get_tx = lambda h, _tx=c["tx"]: _tx
    get_receipt = lambda h, _r=c["receipt"]: _r
    root, status, note = yv._decode_anchor_tx(get_tx, get_receipt, ADDR, c["txHash"], c["expFirst"], c["expLast"])
    exp = c["expect"]
    ok = (status == exp["status"]) and (root == exp["root"])
    if ok:
        print(f"ok   {c['name']}: status={status} root={(root or '')[:12]}")
    else:
        print(f"FAIL {c['name']}: got (status={status}, root={root}) != expected (status={exp['status']}, root={exp['root']})  [{note}]")
        failures += 1

if failures:
    print(f"\n{failures} calldata parity assertion(s) failed")
    sys.exit(1)
print(f"\nall {len(FIX['cases'])} calldata parity assertions passed (Python control == core fixtures)")
