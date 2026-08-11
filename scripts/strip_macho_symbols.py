#!/usr/bin/env python3
"""Write a copy of a Mach-O with its symbol table and dyld export trie removed.

Used to build symbol-less test fixtures: the four kDart*Snapshot* symbols are
external/global and load-bearing (the Flutter engine looks them up at runtime),
so strip(1)/llvm-strip cannot remove them. This neutralises LC_SYMTAB (nsyms=0),
LC_DYLD_INFO[_ONLY] (export_off/size=0) and LC_DYLD_EXPORTS_TRIE (datasize=0) in
every arm64 slice (or the thin Mach-O), which makes r2 report no symbols while
leaving the snapshot bytes intact. This exercises r2flutter's symbol-less
discovery path (structural instruction-image location).

Usage: strip_macho_symbols.py <input> <output>
"""
import struct, shutil, sys

CPU_ARM64 = 0x0100000C


def patch_macho(d, base):
    is64 = struct.unpack_from('<I', d, base)[0] == 0xfeedfacf
    ncmds = struct.unpack_from('<I', d, base + 16)[0]
    off = base + (32 if is64 else 28)
    acted = False
    for _ in range(ncmds):
        cmd, cmdsize = struct.unpack_from('<II', d, off)
        c = cmd & ~0x80000000
        if cmd == 0x2:  # LC_SYMTAB -> nsyms = 0
            struct.pack_into('<I', d, off + 12, 0)
            acted = True
        elif c == 0x22:  # LC_DYLD_INFO[_ONLY] -> export_off/size = 0
            struct.pack_into('<II', d, off + 40, 0, 0)
            acted = True
        elif c == 0x33:  # LC_DYLD_EXPORTS_TRIE -> datasize = 0
            struct.pack_into('<I', d, off + 12, 0)
            acted = True
        off += cmdsize
    return acted


def main(src, dst):
    shutil.copy(src, dst)
    d = bytearray(open(dst, 'rb').read())
    magic = struct.unpack_from('>I', d, 0)[0]
    ok = False
    if magic in (0xcafebabe, 0xcafebabf):  # fat
        b64 = magic == 0xcafebabf
        nfat = struct.unpack_from('>I', d, 4)[0]
        ao = 8
        for _ in range(nfat):
            if b64:
                ct, _cs, offset, _sz, _al, _res = struct.unpack_from('>IIQQII', d, ao)
                ao += 32
            else:
                ct, _cs, offset, _sz, _al = struct.unpack_from('>IIIII', d, ao)
                ao += 20
            if ct == CPU_ARM64:
                ok = patch_macho(d, offset) or ok
    else:
        ok = patch_macho(d, 0)
    if not ok:
        print("no symbol/export commands found to strip", file=sys.stderr)
        return 1
    open(dst, 'wb').write(d)
    return 0


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print(__doc__)
        sys.exit(2)
    sys.exit(main(sys.argv[1], sys.argv[2]))
