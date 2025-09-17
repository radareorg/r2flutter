#!/usr/bin/env python3
import json, subprocess, sys, time, os

ROOT = os.path.dirname(os.path.dirname(__file__))
TEST_DIR = os.path.join(ROOT, 'test')
CUSTOM_DIR = os.path.join(TEST_DIR, 'custom')

def run_one(spec_path):
    with open(spec_path, 'r') as f:
        spec = json.load(f)
    name = spec.get('name') or os.path.basename(spec_path)
    cmd = spec['cmd']
    timeout = spec.get('timeout', 20)
    expect = spec.get('expect', {})
    cwd = spec.get('cwd', TEST_DIR)
    t0 = time.time()
    try:
        proc = subprocess.run(cmd, cwd=cwd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout, text=True)
    except subprocess.TimeoutExpired:
        print(f"[TIMEOUT] {name} exceeded {timeout}s", file=sys.stderr)
        return False
    dt = time.time() - t0
    out = proc.stdout
    err = proc.stderr
    ok = True
    # contains checks
    contains = expect.get('contains') or []
    for s in contains:
        if s not in out:
            print(f"[FAIL] {name}: missing substring: {s!r}", file=sys.stderr)
            ok = False
    # exact match
    eq = expect.get('equals')
    if eq is not None:
        if out.strip() != eq.strip():
            print(f"[FAIL] {name}: stdout mismatch", file=sys.stderr)
            ok = False
    # json validation (subset)
    jexp = expect.get('json')
    if jexp is not None:
        line = out.strip().splitlines()[0] if out.strip() else ''
        try:
            jobj = json.loads(line)
        except Exception as e:
            print(f"[FAIL] {name}: invalid JSON: {e}", file=sys.stderr)
            ok = False
        else:
            for k, v in jexp.items():
                if jobj.get(k) != v:
                    print(f"[FAIL] {name}: json field {k!r} expected {v!r} got {jobj.get(k)!r}", file=sys.stderr)
                    ok = False
    status = 'ok' if ok else 'FAIL'
    print(f"[{status}] {name} ({dt:.2f}s)")
    if not ok:
        # helpful context
        sys.stdout.write(out[:1000])
        sys.stderr.write(err[:1000])
    return ok

def main():
    if not os.path.isdir(CUSTOM_DIR):
        print(f"No custom tests found in {CUSTOM_DIR}")
        return 0
    specs = [os.path.join(CUSTOM_DIR, f) for f in os.listdir(CUSTOM_DIR) if f.endswith('.json')]
    specs.sort()
    if not specs:
        print(f"No test specs (*.json) in {CUSTOM_DIR}")
        return 0
    passed = 0
    for sp in specs:
        if run_one(sp):
            passed += 1
    total = len(specs)
    print(f"Summary: {passed}/{total} passed")
    return 0 if passed == total else 1

if __name__ == '__main__':
    sys.exit(main())

