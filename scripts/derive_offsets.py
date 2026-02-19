#!/usr/bin/env python3
import json, subprocess, sys, os, struct, re

def run(cmd, cwd=None):
    p = subprocess.run(cmd, cwd=cwd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    return p.returncode, p.stdout, p.stderr

def r2flutter_json(target):
    rc, out, err = run([os.path.join(os.path.dirname(__file__), '..', 'bin', 'r2flutter'), '--quiet', '--no-dump', '-j', '--dump-header', target])
    if rc != 0 or not out.strip():
        raise RuntimeError('r2flutter failed: %s' % err)
    return json.loads(out.strip().splitlines()[-1])

def round_up(x,a):
    return (x + (a-1)) & ~(a-1)

HEX_RE = re.compile(r"0x([0-9a-fA-F]+)")

def search_hex(target, start, end, hexpat):
    rc, out, err = run(['r2', '-nnq', '-c', f'e search.in=range; e search.from=0x{start:x}; e search.to=0x{end:x}; /x {hexpat}', target])
    addrs = []
    for line in out.splitlines():
        m = HEX_RE.search(line)
        if m:
            addrs.append(int(m.group(1), 16))
    return addrs

def read_qword(target, addr):
    rc, out, err = run(['r2', '-nnq', '-c', f'pxq 1 @ 0x{addr:x}', target])
    for line in out.splitlines():
        m = HEX_RE.search(line)
        if m:
            return int(m.group(1), 16)
    return 0

def le64(buf, off):
    if off < 0 or off+8 > len(buf):
        return 0
    return struct.unpack_from('<Q', bytes(buf), off)[0]

def read_cstr(buf, off, maxlen=128):
    if off < 0 or off >= len(buf):
        return ''
    end = off
    n = 0
    out = []
    while end < len(buf) and n < maxlen:
        b = buf[end]
        if b == 0:
            break
        if 32 <= b < 127 or b == 9:
            out.append(chr(b))
        else:
            return ''
        end += 1
        n += 1
    return ''.join(out)

def derive_offsets(target):
    j = r2flutter_json(target)
    iso_data = j['iso_data']
    iso_instr = j['iso_instr']
    total = j['cluster']['total']
    cws = j.get('cws', 4)
    align = 16
    base = iso_data + round_up(total, align)
    end = iso_instr if iso_instr > base else base + (1<<22)
    # Candidate offsets within Code and Function objects (64-bit typical)
    ep_cands = [0x10,0x18,0x20,0x28,0x30]
    owner_cands = [0x10,0x18,0x20,0x28,0x30]
    name_cands = [0x10,0x18,0x20,0x28,0x30]
    good_ep, good_owner, good_name = set(), set(), set()

    # Fast path: search for common prefixes in strings to get candidate name addresses
    names = []
    for pat in (b'package:', b'dart:'):
        hexpat = pat.hex()
        addrs = search_hex(target, base, end, hexpat)
        names.extend(addrs)

    # For each candidate String address, locate owner(Function) via pointers.
    # Consider both 64-bit and 32-bit compressed pointers.
    max_hits = 800
    for sa in names[:200]:  # cap initial string candidates
        le_name = sa.to_bytes(8, 'little').hex()
        owner_ptrs = search_hex(target, base, end, le_name)
        # also try 32-bit compressed encodings for (sa-base)
        rel = sa - base
        for sh in (0,1,2,3):
            enc = (rel >> sh) & 0xffffffff
            for tag in (0,1,3,7):
                val = (enc | tag) & 0xffffffff
                le4 = val.to_bytes(4, 'little').hex()
                owner_ptrs += search_hex(target, base, end, le4)
        # Each owner_ptr is at (owner + name_off)
        for owner_ptr in owner_ptrs[:12]:  # cap per-name refs
            for name_off in name_cands:
                owner = owner_ptr - name_off
                if owner < base or owner >= end:
                    continue
                # Find Code.owner refs: pointers to 'owner' within range (64-bit and 32-bit compressed)
                le_owner = owner.to_bytes(8, 'little').hex()
                code_owner_ptrs = search_hex(target, base, end, le_owner)
                rel_owner = owner - base
                for sh2 in (0,1,2,3):
                    enc2 = (rel_owner >> sh2) & 0xffffffff
                    for tag2 in (0,1,3,7):
                        val2 = (enc2 | tag2) & 0xffffffff
                        code_owner_ptrs += search_hex(target, base, end, val2.to_bytes(4, 'little').hex())
                for cop in code_owner_ptrs[:16]:
                    # cop == (code_base + owner_off)
                    for owner_off in owner_cands:
                        code_base = cop - owner_off
                        if code_base < base or code_base >= end:
                            continue
                        for ep_off in ep_cands:
                            ep = read_qword(target, code_base + ep_off)
                            if iso_instr <= ep < iso_instr + (1<<26) and (ep & 3) == 0:
                                good_owner.add(owner_off)
                                good_name.add(name_off)
                                good_ep.add(ep_off)
                                max_hits -= 1
                                break
                        if max_hits <= 0:
                            break
                    if max_hits <= 0:
                        break
                if max_hits <= 0:
                    break
            if max_hits <= 0:
                break
        if max_hits <= 0:
            break
    return {
        'hash': j['hash'],
        'compressed_word_size': cws,
        'heap_object_tag': 1,
        'max_alignment': align,
        'it_cap': 20000,
        'code_entry_point_offsets': sorted(good_ep),
        'code_owner_offsets': sorted(good_owner),
        'function_name_offsets': sorted(good_name),
    }

def merge_offsets(path, entry):
    if os.path.exists(path):
        with open(path, 'r') as f:
            obj = json.load(f)
    else:
        obj = {'arch': 'arm64', 'hashes': {}}
    h = entry['hash']
    obj.setdefault('hashes', {})
    obj['hashes'][h] = entry
    with open(path, 'w') as f:
        json.dump(obj, f, indent=2)

def main():
    if len(sys.argv) < 2:
        print('Usage: derive_offsets.py <path-to-libapp.so-or-.app>', file=sys.stderr)
        sys.exit(1)
    target = sys.argv[1]
    # resolve .app path to App binary
    if target.endswith('.app'):
        appbin = os.path.join(target, 'Frameworks', 'App.framework', 'App')
        if os.path.exists(appbin):
            target = appbin
    entry = derive_offsets(target)
    out = os.path.join(os.path.dirname(__file__), '..', 'offsets.json')
    merge_offsets(out, entry)
    print(json.dumps(entry, indent=2))

if __name__ == '__main__':
    main()
