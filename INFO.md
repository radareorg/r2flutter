Blutter/r2flutter: Standalone Dart AOT Name Extraction via Constant Pool

Overview
- Goal: Extract real Dart function names and entrypoints from Flutter/Dart AOT snapshots (libapp.so) without relying on afl/aflj or the Dart VM.
- Tools:
  - r2flutter: Small C utility that loads `libapp.so` with radare2, locates AOT snapshots, and decodes the ObjectPool to emit names + addresses.
  - scripts/gen_offsets.sh: Generates a per-snapshot-hash offsets file (`r2flutter/offsets.json`) to keep the decoder stable across Dart versions.
- Key property: r2flutter builds standalone (no Dart VM headers/libs) and does not parse afl output.

Repo Layout (relevant parts)
- r2flutter/
  - main.c: CLI entry, opens file with radare2 and kicks off name extraction.
  - dart_app.[ch]: Minimal app model; wires callback for extracted functions; emits addNames.r2/r2_dart_struct.h.
  - dart_pool_parse.c: Snapshot discovery (via r2), offsets loading (offsets.json), and clustered snapshot/ObjectPool decoder (constant pool → names).
  - dart_dumper.[ch]: Emits radare2 flags/comments, PP (x27) helper flags, and a basic struct header.
  - Makefile: Pure-C build; links against libr2 via pkg-config; no Dart VM linkage.
  - third_party/dartvm/: Vendored VM sources (headers only) to document snapshot/cluster formats used by the decoder (no linking).
  - arm64-v8a/: Example directory with libapp.so/libflutter.so for testing.
- scripts/
  - gen_offsets.sh: Generates `r2flutter/offsets.json` keyed by snapshot hash using only local binaries + curl (when needed for future enhancement).
- blutter/: Standalone C++ reference implementation (with VM linkage) used as conceptual reference. r2flutter must not depend on it.

Quick Start
- Requirements: radare2 development headers (pkg-config), make, a libapp.so and libflutter.so pair.
- Generate offsets for your libapp:
  - `./scripts/gen_offsets.sh r2flutter/arm64-v8a`
  - This produces `r2flutter/offsets.json` keyed by snapshot hash (read from VM snapshot data in libapp.so).
- Build and run r2flutter:
  - `make -C r2flutter`
  - `./r2flutter/blutter_r2 r2flutter/arm64-v8a r2flutter/out`
- Outputs:
  - `r2flutter/out/addNames.r2`: method flags with names + addresses.
  - `r2flutter/out/r2_dart_struct.h`: simple struct header.
  - PP/x27 pool-offset flags/comments to aid analysis (no afl required).

How It Works (High-level)
1) Snapshot discovery with radare2:
   - Queries `isj` to find these 4 symbols in libapp.so:
     - `_kDartVmSnapshotData`, `_kDartVmSnapshotInstructions`, `_kDartIsolateSnapshotData`, `_kDartIsolateSnapshotInstructions` (underscored and non-underscored names supported).
   - Reads the VM snapshot data to extract:
     - Snapshot hash (32 ASCII hex chars at offset +20)
     - Feature flags (following the hash; diagnostic)
2) Offsets selection:
   - Loads `r2flutter/offsets.json` keyed by snapshot hash.
   - Captures at least compressed pointer size and heap tag. Future entries can include structure offsets if needed.
3) Clustered snapshot decoding (AOT):
   - Parses the Isolate snapshot header (version + features) to locate the clustered section.
   - Reads `num_base_objects`, `num_objects`, `num_clusters`, `instructions_table_len`, etc.
   - Walks clusters of interest (ObjectPool, Code, Function, String, Array) and reconstructs:
     - Global ObjectPool
     - Strings for function names
     - Code entrypoints/sizes (reconstruct from AOT instructions table in bare instructions mode)
     - Function → Code relationships
   - Emits each function via callback with name, address, and size.

Usage in radare2 sessions (Android ELF and iOS Mach-O)
- After running `blutter_r2`, execute the script in radare2 to load names:
  - `radare2 -q r2flutter/arm64-v8a/libapp.so -c "e bin.cache=true; . r2flutter/out/addNames.r2"`
- You’ll see `method.*` flags and comments across the binary.

Maintaining for New Dart Versions
1) Generate/Update offsets.json:
   - Run: `./scripts/gen_offsets.sh <dir-with-libapp+libflutter>`
   - This produces a new `hash → { compressed_word_size, heap_object_tag }` entry in `r2flutter/offsets.json`.
   - For deeper stability (field offsets), enhance `gen_offsets.sh` to:
     - `curl` the VM sources for the detected Dart version/commit (e.g., class_id.h, object.h, app_snapshot.cc).
     - Parse constants and offsets to compute a richer layout JSON.
   - Commit the updated offsets.json.
2) Decoder tuning:
   - If the clustered snapshot changes (e.g., new EntryType or field order), adjust the decoder logic in `dart_pool_parse.c` referencing `third_party/dartvm/` sources.
   - Avoid adding a runtime dependency: keep vendored snapshots sources only as references (no linking).
3) Validation:
   - Confirm snapshot symbol detection:
     - `r2 -q -c 'isj~Dart' <libapp.so>` shows the 4 symbols.
   - Confirm snapshot hash in VM data:
     - Hash at vm_data + 20 matches the entry in offsets.json.
   - Run r2flutter and verify the number of functions found (sanity-check sizes, entrypoints, and names look plausible).

Gotchas / Notes
- AOT bare-instructions mode (typical on Android) stores only Code entrypoints/sizes in the instructions table in text; r2flutter reconstructs those values.
- Names: Function names are strings in the heap; decoder resolves String objects for full names.
- PP/x27 pool offsets: Emitted from disassembly (`pdfj`), independent of function enumeration (useful even before constant pool decoding is complete).
- Architecture: The sample targets arm64 (AArch64). Extend offsets generation and decoding paths as needed for x64/aarch32.

Troubleshooting
- “Dart snapshots not found”: Ensure `r2_core_bin_load` is called (r2flutter does this), and try `e bin.cache=true` in your r2 session. The binary must have the 4 symbols exported. On iOS/Mach-O with stripped symbols, r2flutter falls back to scanning sections (`iSj`) for the snapshot magic (0xdcdcf5f5) to locate VM/Isolate snapshot DATA blobs.
- “No layout for snapshot hash …”: Run `./scripts/gen_offsets.sh <libdir>` to populate `r2flutter/offsets.json`. Re-run the tool.
- Missing names/sizes: Verify `offsets.json` is present, and that the decoder has cluster coverage for your Dart version; if not, enhance offsets and update the decoder.

Roadmap / Extending
- Add more snapshot-hash entries (stable channels and popular Flutter engine versions).
- Auto-fetch VM sources for a given hash/version, precompute richer layout JSON (beyond compressed pointer + tag), and store it in-tree.
- Expand architecture coverage and add minimal tests to validate decoding of ObjectPool/Code/Function/String relationships.
