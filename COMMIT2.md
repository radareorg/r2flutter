# COMMIT 2 — Locate Dart instruction images without symbols (stripped Mach-O)

Follow-up to commit 1 (`Harden Dart snapshot discovery...`). Commit 1 removed the
junk-`iso_instr` risk and hardened `find_snapshots`, but on a genuinely
symbol-less binary it deliberately leaves `vm_instr`/`iso_instr = 0` (instruction
images carry no magic, so the scan cannot find them). This file records what
commit 2 must do and everything we learned so we don't re-derive it.

## Goal
When the four `kDart*Snapshot*` symbols are absent, still recover `vm_instr` and
`iso_instr` structurally so InstructionTable-based name recovery works (it is
gated behind `if (!ctx->iso_instr) return 0;` in `dart_pool_parse.c`).

## Key findings from the commit-1 investigation (don't redo these)
- **Only data snapshots carry the magic `0xf5f5dcdc`.** Instruction images do
  not, so magic-scanning can only ever locate `vm_data` / `iso_data`. Confirmed:
  `test/bins/ios/Runner.app/.../App` has exactly 2 magic hits (both data).
- **Layout (Runner.app, ground truth from the symbol table):**
  - `_kDartVmSnapshotInstructions`      @ `0x4000`   — start of `__TEXT.__text` (`r-x`)
  - `_kDartIsolateSnapshotInstructions` @ `0xe700`   — inside `__TEXT.__text`
  - `_kDartVmSnapshotData`              @ `0x1b0900` — start of `__TEXT.__const`
  - `_kDartIsolateSnapshotData`         @ `0x1b9600` — inside `__TEXT.__const`
  So instruction images live consecutively at the start of the first executable
  section: `[VmInstructions][IsolateInstructions]`.
- **The Dart snapshot symbols are load-bearing and survive `strip`.** They are
  external/global (the Flutter engine looks them up at runtime), so `llvm-strip`,
  `llvm-strip -x`, and `strip` all leave them in place (`strip` even returns rc=1).
  Consequence: a *functioning* Flutter app almost always keeps these symbols, so
  the symbol path already works for normal apps. The symbol-less case is an
  **edge case** (obfuscators, repackagers, hand-stripped LC_SYMTAB), which is why
  this is a lower-frequency follow-up, not urgent.

## Proposed approach
1. `vm_instr` = start (`vaddr`) of the first executable (`perm & R_PERM_X`) section
   that is not a segment. On the samples this is `__TEXT.__text`.
2. Read the Dart **instructions-image header** at `vm_instr` to get the VM
   instructions payload length, then `iso_instr = vm_instr + align_up(len, alignment)`.
   - Need to nail the instructions-image header format (`Image::kHeaderSize` /
     the leading length/size field) from `third_party/dart-sdk/runtime/vm/image_snapshot.{h,cc}`.
     Cross-check the computed `iso_instr` against the ground-truth `0x4000`→`0xe700`
     gap for Runner (i.e. VM-instructions length ≈ `0xe700 - 0x4000 = 0xa700`).
   - Fallback if the header can't be parsed: leave `iso_instr = 0` (current safe
     behavior) rather than guess.
3. Only run this when `vm_instr`/`iso_instr` are still 0 after symbols + data scan,
   so it never overrides symbol-derived values.

## Test / fixture strategy (the hard part)
- `strip`/`llvm-strip` do NOT remove the global Dart symbols, so we cannot make a
  fixture with the CLI strip tools. Options, in order of preference:
  1. Obtain a **real** obfuscated/stripped Flutter iOS `App` where the symbols are
     actually gone (best signal). **TODO: collect more iOS Flutter binaries** —
     especially release/obfuscated ones — into `test/bins/ios/` for coverage.
  2. Craft a fixture by rewriting a copy of an existing `App` to drop the four
     symbols from `LC_SYMTAB` (e.g. an r2 script that zeroes/removes the nlist
     entries), keeping the snapshot bytes intact.
- Regression assertion: on the symbol-less fixture, `-H -j` yields
  `vm_data`/`iso_data` from the scan AND `vm_instr=0x4000` / `iso_instr=0xe700`
  from structural location, and `-i`/`-f` recover IT entries/names.
- Also add a scan-path assertion for commit 1 itself once a fixture exists:
  data found, `instr` cleanly 0 (no junk), no crash.

## Also deferred here (small, separate robustness items from the audit §3.1)
- **Single-data-snapshot aliasing** (`pick_vm_iso_by_size`, count==1 sets
  `vm_data == iso_data`). Visible on the synthetic bin (`vm_data==iso_data==4`).
  The `sbom-synthetic` golden currently *encodes* this (`"vm_data":4,"iso_data":4`).
  Fixing it (assign the lone snapshot to `iso_data`, leave `vm_data=0`) requires
  updating that golden — do it alongside commit 2 and decide the correct semantics.
- Raw-file fallback scan (`find_snapshots`, the `r_io_size` branch) conflates
  physical offsets with IO addresses when a bin is loaded with maps but has
  zero/unnamed sections; only fully correct under `r2 -n`. Low priority.

## Files likely touched
- `src/lib/dart_pool_discovery.c` — structural instruction-image location.
- possibly a small helper to read the instructions-image header (new, or in
  `dart_pool_snapshot.c`).
- `test/bins/ios/...` — new stripped/obfuscated fixture(s).
- `test/db/cmd/` — new discovery test(s).
