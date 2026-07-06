import importlib.util, json, os, sys
HERE = os.path.dirname(os.path.abspath(__file__)); ROOT = os.path.join(HERE, "..")
sys.path.insert(0, ROOT)
spec = importlib.util.spec_from_file_location("yolo_verify", os.path.join(ROOT, "yolo-verify.py"))
yv = importlib.util.module_from_spec(spec); spec.loader.exec_module(yv)
with open(os.path.join(HERE, "parity-fixtures.json")) as f: FIXTURES = json.load(f)
MERKLE_STEP = 2  # steps: [1.payload, 2.chain, 3.merkle, 4.onchain]
failures = 0
for fx in FIXTURES:
    name = fx["name"]
    result = yv.verify(fx["bundle"], yv.DEFAULT_RPC, yv.ANCHOR_ADDRESS)  # anchor.tx null → no RPC hit
    merkle_ok = result["steps"][MERKLE_STEP][1]; merkle_detail = result["steps"][MERKLE_STEP][2]
    expect_pass = fx["expectedMerkleResult"] == "pass"
    if merkle_ok is not expect_pass:
        print(f"FAIL {name}: merkle expected {'pass' if expect_pass else 'fail'}, got ok={merkle_ok} ({merkle_detail})"); failures += 1; continue
    reason = fx.get("expectMerkleReasonContains")
    if reason and reason.lower() not in merkle_detail.lower():
        print(f"FAIL {name}: merkle detail should name '{reason}' (got: {merkle_detail})"); failures += 1; continue
    if fx["assert"] == "verdict" and result["verdict"] != fx["expectedVerdict"]:
        print(f"FAIL {name}: verdict expected {fx['expectedVerdict']}, got {result['verdict']}"); failures += 1; continue
    print(f"ok   {name}: merkle={'pass' if merkle_ok else 'fail'}" + (f", verdict={result['verdict']}" if fx['assert']=='verdict' else ""))
if failures: print(f"\n{failures} parity assertion(s) failed"); sys.exit(1)
print(f"\nall {len(FIXTURES)} Python parity assertions passed")
