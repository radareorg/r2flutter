# r2flutter — Analysis & Correction Roadmap

Review of the library (`src/lib`), the r2 core plugin (`src/r2`), and the CLI
(`src/tool`) for inconsistent, confusing, duplicated, or wrong assumptions when
analyzing Flutter/Dart AOT snapshots on iOS and Android. Findings are verified
against the source, the sample binaries in `test/bins`, real Dart SDK sources in
`third_party/dart-sdk`, and a locally built Dart 3.12.2 AOT snapshot.

Maintainer priorities: **1) robust Dart-VM version identification** ·
**2) performance** · **3) iOS/Android correctness parity**.

Items are ranked **P0** (do next) → **P3** (nice to have). Severity is implied by
rank; each item states the concrete failure it causes.

---

## Status — what has been fixed (do not redo)

| Commit | What landed |
|--------|-------------|
| `d387c0b` | Unknown-hash **fingerprinting** replaces the blind hardcoded "v3.9.2 defaults" (`dart_newest_profile()` auto-tracks the profile table). `-H` reports **`version_source`** (`exact-hash`/`override`/`fingerprint`/`unknown`) and labels guessed layouts `~<ver>+ (fingerprint)`. Report and decode paths now share the same layout (previously decode used a degenerate zeroed struct). Test: `header-fingerprint`. |
| `2391781` | Explicit **3.7/3.8/3.10/3.11/3.12 CID + layout profiles** (parsed from each release's real `class_id.h`). Also **verified**: the floored tables were already byte-for-byte correct for *every* release 2.10.0–3.12.1, so no CID value changed — the rows are explicit coverage + a regression anchor. |
| `cd6b655` | Discovery hardening: removed the **bogus instruction-blob classification** (only data snapshots carry magic `0xf5f5dcdc`; a stray hit could poison `iso_instr`); symbol-derived addresses are no longer clobbered by scan guesses; `vaddr==0` duplicates can't erase a good address; magic hits deduped; Mach-O segments skipped. |
| `0716a95` | **Structural instruction-image location** for symbol-less Mach-O: `vm_instr` = first executable section, `iso_instr = align_up(vm_instr + ImageSize, 64)` from the Dart Image header, with cross-checks that fall back to `0` rather than emit junk. Verified on stripped Runner (`0x4000`/`0xe700`, full 7671 IT entries) and AuthPass (`0x5a80`/`0xfdc0`). Adds `scripts/strip_macho_symbols.py` + `discovery-stripped-ios`. |
| *(uncommitted)* | **P0.1**: `modern_get_fill_spec`'s fallback `rules[]` is keyed by `DartCidKind` and resolved through a per-layout `by_kind[]` table built once in `modern_cid_cache_init`, instead of literal 3.6-era CIDs. Fixes a whole-block off-by-one on 3.2–3.5 layouts (36 CIDs from `SENTINEL` upward got the neighbouring class's ref/scalar layout) and `MonomorphicSmiableCall`/`UnlinkedCall` on 3.9+, where the two swapped places. Abstract classes that never form a cluster (`CallSiteData`, `AbstractType`, `TypedDataBase`) no longer claim a spec. |

Corrections to earlier assumptions, worth remembering:
- **The CID tables are not the problem.** Flooring is exactly correct 2.10→3.12,
  verified against SDK sources. Only a *future* CID shift needs action, and the
  generator adds a profile automatically when one appears.
- **The `kDart*` snapshot symbols survive `strip`** — they are external/global and
  load-bearing (the engine resolves them at runtime). Symbol-less iOS is an edge
  case (obfuscators/repackagers), not the norm.

---

## The finding that reshapes priorities

**Only 1 of 5 sample binaries exercises the "modern" (good) cluster decoder.**
`dart_modern_is_supported_snapshot()` (`dart_pool_modern.c:207`) gates it on
`tag_style == OBJECT_HEADER && compressed_word_size == 4`:

| Sample | Dart | tag_style | cws | modern decoder? |
|--------|------|-----------|-----|-----------------|
| `android/mafia` | 3.9.2 | OBJECT_HEADER | 4 | **yes** |
| `android/first` | 2.18.2 | OBJECT_HEADER | 8 | no |
| `ios/Runner.app` | 3.4.3 | OBJECT_HEADER | 8 | no |
| `ios/AuthPass.app` | 3.2.5 | CID_SHIFT1 | 8 | no |
| `macos/hello.aot` | 3.11.5 | OBJECT_HEADER | 8 | no |

Two consequences drive the P0 items below:
1. The 4000-line modern decoder is **skipped for most binaries**, including
   modern-era ones that merely lack pointer compression (iOS Runner 3.4.3,
   hello 3.11.5). Those rely on the data-image scanners for names.
2. The single modern-path sample is 3.9.2, which **nearly matched** the CID table
   `modern_get_fill_spec` used to hardcode — which is why the P0.1 bug was
   invisible to CI, and why its fix still has no end-to-end test (P0.3).

---

## P0 — correctness bugs with no test coverage

### P0.2 Extend the modern decoder to uncompressed (`cws == 8`) snapshots
`dart_pool_modern.c:207`. The `cws == 4` half of the gate is an implementation
limit, not a format boundary: 2.18.2, 3.4.3 and 3.11.5 samples are all
OBJECT_HEADER but uncompressed, so they never reach the good decoder.
**Failure:** name/class recovery on those binaries falls back to heuristic
data-image scanning — i.e. most iOS apps and all macOS standalone builds get the
weaker path. **Fix:** parameterise the ref/pointer width in the modern reader
(the compressed-vs-native pointer read is already understood — see
`doc/learn.md` on `heap_base | stored32`) and drop `cws == 4` from the gate.
This is the single largest *quality* win available.

### P0.3 Test corpus does not cover the decoders we ship
Add samples that exercise the untested combinations, then wire them into the
suite:
- a **Dart 3.4/3.5-era compressed-pointer** app (P0.1 is fixed but still has no
  end-to-end regression test; it was verified only by resolving `rules[]` against
  each layout in isolation);
- an **uncompressed modern** app through the modern path (validates P0.2);
- more **iOS** binaries generally, ideally real obfuscated/stripped release
  `App`s (also broadens the `0716a95` structural path, per `COMMIT2.md`);
- a **32-bit ARM** app if one can be found (validates P1.2).
Buildable locally with the installed Dart SDK for the standalone cases; Flutter
app samples need collecting.

---

## P1 — correctness, lower prevalence or already-guarded

### P1.1 Tag-style CID decode applied inconsistently
`dart_object.c:88-99` honours all three `DartTagStyle` variants, but cluster/CID
decode hardcodes the OBJECT_HEADER form `(tags>>12)&0xFFFFF` in
`dart_pool_clusters.c:226`, `dart_pool_modern.c:2328/3160/3529/3688`,
`dart_pool_data_image.c:82`; and `dart_pool_it.c:158-160` routes **CID_INT32**
into the OBJECT_HEADER formula (should be `header & 0xffffffff`).
**Failure:** pre-2.14 (CID_INT32) and 2.14–3.3 (CID_SHIFT1) snapshots are
mis-decoded by every cluster walker. Mitigated today only because those eras also
fail the modern gate and fall back to scanners.
**Fix:** one tag-style-aware extractor, called everywhere.

### P1.2 Hardcoded 8-byte target word / arm64 assumptions
- `modern_target_word_size()` (`dart_pool_modern.c:1196-1199`) **ignores `ctx` and
  returns 8** — it takes `ctx` only to `(void)` it. All ObjectPool `pp_offset`
  math (`:1201-1208`) and the synthetic-PP builder (`:2243-2262`) are wrong on
  32-bit ARM, so `PP+N` lookups resolve to the wrong entry.
- Entry-point stride hardcodes `*4` (`dart_pool_clusters.c:164`,
  `dart_pool_classes.c:170`, `dart_pool_it.c:349,399`).
- `-AAA` (`src/r2/flutter_analysis.c:104-129`) is entirely arm64 (PP=`x27`,
  `x15/x29`, AAPCS64 clobber) with **no arch guard**; on arm32/x64 it emits wrong
  PP annotations instead of bailing. Neither frontend checks `asm.arch`/`bits`.
  **Fix:** gate on arch, derive the PP register, or refuse with a clear message.

### P1.3 Plugin/CLI frontend drift (AGENTS.md violations)
Two hand-maintained parsers: CLI getopt (`main.c:118`) vs plugin
(`core_flutter.c:192+`).
- **`-r` is missing in the plugin** (it only has `-*`), directly violating
  AGENTS.md ("-q, -j and -r flags are modifiers"). `r2flutter -f -r` errors.
- Plugin **silently no-ops under `r2 -n`** (`dart_app_new_from_core` returns NULL
  via `R_UNWRAP4(core,bin,cur,file)`), so `-f/-A/-R` do nothing while `-H/-z/-i`
  work — and `r2 -n` is the workflow AGENTS.md recommends.
- CLI help advertises `[jr*]`/`-c*` but `*` is not in the getopt string.
- Plugin help omits `-q` and `-f <N>`; `-C` is plugin-only; `-E` is CLI-only;
  `-f <N>` grammar differs (CLI treats the number as the path).
**Fix:** one shared parser/dispatch in the library so the modifier contract holds
once. Cheap, visible, and unblocks consistent `-q/-j/-r` everywhere.

### P1.4 iOS `LC_NOTE` (`__dart_app_snap`) container is CLI-only
`main.c:84-97` extracts the embedded inner Mach-O; the plugin has no equivalent,
so `r2flutter -H` inside r2 analyses the outer VM shell and fails, and
`dctx.container_*` stays empty. **Fix:** move detection/extraction into the
library so both frontends share it.

### P1.5 Single-data-snapshot aliasing
`pick_vm_iso_by_size` (`dart_pool_discovery.c:25-49`) with one snapshot assigns
the same address to both `vm_data` and `iso_data` (visible on the synthetic bin:
both `0x4`), so one is parsed as the other. The `sbom-synthetic` golden currently
*encodes* this, so fixing it means deciding the right semantics (probably: lone
snapshot is the isolate, leave `vm_data = 0`) and updating that test.

---

## P2 — duplication, dead code, structural debt

### P2.1 Two cluster decoders, both run on every enumeration
`decode_pool_and_emit` (`dart_pool_parse.c:323, :386`) runs the legacy
`deserialize_clusters` **and** the modern scanner over the same stream, then scans
the data image again (`scan_code_names`, `collect_data_names`, + optional r2 pass).
The legacy walker compares raw cluster CIDs against the **fake** `kXxxCid` enum
(P2.2), so it silently never decodes strings (`kStringCid=72` vs real ~92) and
misreads the cluster CID as a tagged `>>12` header.
**Fix:** once P0.2 widens the modern gate, delete the legacy walker (or reduce it
to a documented fallback). Also the biggest **perf** win — see P3.1.

### P2.2 Delete the fake `kXxxCid` enum
`dart_pool_parse_priv.h:20-52` hardcodes a CID set matching **no real Dart
version** (`kStringCid=72`, `kOneByteStringCid=73`, `kCodeCid=40`,
`kTypeCid=110`; real ≈ 92/94/17/48), plus `dart_pool_classes.c:51-52` adds
`kFieldCid_extract=10`, `kLibraryCid_extract=12`. Used ~35× in the legacy paths.
**Fix:** route every consumer through `dart_cid_get(layout, …)` and remove the enum.

### P2.3 Two different "newest" baselines (introduced by `d387c0b`)
`dart_pick_layout_by_hash` now fingerprints unknown hashes to
`dart_newest_profile()` = **3.12.0**, but `cid_table_for_layout`
(`dart_cid.c:147`) still falls back to `cid_table_for_version ("3.9.2")` when a
layout carries no version. Harmless today (3.9 and 3.12 CIDs are identical) but
they will diverge the moment a future release shifts CIDs. **Fix:** have the CID
fallback use the same newest-profile accessor instead of a literal string.

### P2.4 CID/layout data still lives in three places
`offsets.json` (source of truth, generated from SDK), `dart_cid.c` `cid_tables[]`
(generated ✔), and `dart_offsets.h` `dart_hash_entries[]` — which only carries
`hash → compressed_word_size`, a value already derivable from the profile and then
overridden by the feature flags anyway (cws is decided three times, flags win).
**Fix:** drop the hash→cws table or derive it.

### P2.5 alloc/fill cluster walk reimplemented 5× in the modern decoder
`modern_parse_cluster_meta` (`:2307`), `modern_load_vm_base_strings` (`:3131`),
`dart_modern_extract_classes_from_clusters` (`:3489`),
`dart_modern_scan_names_from_clusters` (`:3616`), resolver init (`:1609`) — each
re-runs tag→cid→alloc→fill with subtly different special-casing, so a layout fix
must be made in all five. **Fix:** one shared walker with callbacks. (Do this
*before* P0.2, which otherwise has to be applied five times.)

### P2.6 `data_image_base` recomputed in ≥3 places with a magic-16 fallback
`dart_object.c:304-305`, `dart_pool_classes.c:1646-1655`, plus IT callers each do
`snapshot + align_up(total_len, layout->max_alignment ?: 16)`. Extract one helper
and confirm alignment is genuinely derived (it can be raised to 64) rather than
silently defaulted.

### P2.7 Dead `-x`/`-z` special-case in both frontends
`core_flutter.c:343-345` and `main.c:207-208` set string-refs for *any* `-x`,
making the later `action == 'x'` check dead; help text implies otherwise.

---

## P3 — performance

Read caching (`read_mem`, `dart_pool_snapshot.c:10-44`) already turns per-byte
varint reads into a 1 MB sliding window. Remaining hotspots, largest first:

### P3.1 Redundant full passes over the same regions
Per P2.1 a single `-f`/`-A` walks the cluster stream twice and the data image 2–3
times. Collapsing to one cluster walk + one data-image scan is the biggest win on
large inputs (`mafia/libapp.so` ~15 MB, `AuthPass.app` ~38 MB). Falls out of P2.1.

### P3.2 Brute-force InstructionTable header search
`dart_pool_it.c:233-330` probes `{16,0,8,12} × delta -64..64 step 4`, then scans
the whole data image every 16 bytes (`:209-231`), then a third linear scan
`+0x40..+0x40000 step 8` (`:289-320`); `decode_pool_and_emit` additionally retries
`dart_it_emit_varint` across `delta -64..64`. O(image) per lookup because the
header location isn't derived. **Fix:** compute it from the layout — the Image
header format is now understood (see `COMMIT2.md`: word0 `ImageSize`, word1
`InstructionsSectionOffset`, 64-byte header), which should make the IT header
directly addressable.

### P3.3 Per-value snapshot-header re-parse
`dart_object.c:296-312` calls `dart_snapshot_header_read(ctx, ctx->iso_data, …)`
for *every* scalar value decode just to recompute `data_base`. Cache on the ctx.

### P3.4 Read-cache tail cliff + forward-only thrash
The 1 MB refill (`:37`) needs the whole range readable, so the last <1 MB of each
section degrades to one syscall per byte; the window is forward-only, so name
resolution alternating between the cluster stream and the string heap refills
repeatedly. Consider a small multi-window/LRU cache and a short-read-tolerant refill.

---

## P4 — test quality (beyond the corpus gaps in P0.3)

- **Obfuscation-map tests are tautological**: `test/db/cmd/obf-map`,
  `test/custom/obf-funcs-ios.json`, `obf-it-android.json` load a map whose keys
  match nothing in the sample, so output is identical to the no-`-m` run. They
  prove loading doesn't crash, never that renaming works. Add a fixture whose
  keys actually occur.
- `analyze-aaa-android.json` only greps `"Flutter analysis:"` — passes even if
  nothing is recovered. Assert a recovered count/name.
- Header tests pin entire JSON blobs incl. full CID tables: deterministic but
  brittle (one new field broke ~10 tests during `d387c0b`). Consider
  field-subset assertions like the `test/custom` specs already use.
- Missing behaviours: plugin `-r`, plugin under `r2 -n`, gapped-layout structural
  discovery (macOS, see `COMMIT2.md`), stripped **ELF**.
- Directory-form input only recognises Android `libapp.so` / iOS
  `App.framework/App` (`main.c:62-74`); `-H <dir-with-hello.aot>` errors "does
  not exist". Broaden the resolver or document it.

---

## Suggested execution order

1. **P2.5** — unify the modern alloc/fill walker (prerequisite: makes P0.2 a
   one-place change instead of five).
2. **P0.2** — widen the modern decoder to uncompressed snapshots. Biggest quality
   win; makes most iOS/macOS samples use the good path.
3. **P0.3** — grow the corpus alongside 2 so it is actually verified, and to give
   the landed P0.1 fix an end-to-end regression test.
4. **P2.1 + P3.1** — delete the legacy walker; one cluster walk, one data scan.
5. **P1.3** — shared frontend parser (fixes the `-r`/`r2 -n` AGENTS.md violations).
6. **P1.1, P1.2** — tag-style helper; arch gating.
7. **P3.2–P3.4**, remaining P1/P2 cleanups, test hardening.

`COMMIT2.md` tracks the narrower follow-ups left over from the discovery work
(gapped layouts, more iOS fixtures, stripped ELF, P1.5 semantics).
