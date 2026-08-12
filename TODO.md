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
| `d11ebc3` | **P0.1**: `modern_get_fill_spec`'s fallback `rules[]` is keyed by `DartCidKind` and resolved through a per-layout `by_kind[]` table built once in `modern_cid_cache_init`, instead of literal 3.6-era CIDs. Fixes a whole-block off-by-one on 3.2–3.5 layouts (36 CIDs from `SENTINEL` upward got the neighbouring class's ref/scalar layout) and `MonomorphicSmiableCall`/`UnlinkedCall` on 3.9+, where the two swapped places. Abstract classes that never form a cluster (`CallSiteData`, `AbstractType`, `TypedDataBase`) no longer claim a spec. |
| `33bb19b` | **P2.5**: one shared cluster walker (`ModernWalk`) replaces the five hand-rolled tag→cid→alloc→fill loops. Consumers register readers in a `DartCidKind`-keyed table and the walker skips every class they don't claim, so tag decoding, alloc/fill skipping, `start_ref` bookkeeping and the inline-string decision each exist **once** (were 4–5× each). `modern_walk_fill_recorded` serves the resolver, which reads each cluster from its own recorded offset. Verified behaviour-preserving: output byte-identical on 5 samples × 21 actions. |
| `e9fa905` | **Part of P0.2**: the read-only-data rule (`modern_walk_is_rodata`) — the six classes Dart moves into the data image when pointer compression is off (exactly `Serializer::ReadOnlyObjectType`) now correctly emit no fill records. Inert until the gate opens; see P0.2 for what still blocks it. |
| `897a98d` | **P1.1**: one `dart_cid_from_tags` helper now decodes `CID_INT32`, `CID_SHIFT1`, and `OBJECT_HEADER` tags for object inspection, modern and legacy cluster walks, data-image scanners, and InstructionTable discovery. This removes the duplicate decoders and fixes `CID_INT32` being treated as `OBJECT_HEADER` in two paths. |
| `833f89a` | **P2.1**: deleted the legacy cluster walker — `deserialize_clusters`, `decode_class_cluster`, `decode_function_cluster`, `resolve_names`, the `DartClass`/`DartPoolFunction` types and the `DartCtx.classes`/`.functions` fields that only it wrote (244 lines). It had been running on every `-f`/`-A` alongside the modern scanner while contributing nothing: verified before removal by stubbing it out (50/50 outputs identical), and after by diffing 95 sample×action outputs against the previous commit. `decode_string_cluster`/`skip_generic_cluster`/`free_dart_string` stay — the legacy **class** parser in `dart_pool_classes.c` still uses them for CID_SHIFT1 samples. |
| `f10d30d` | **P2.2**: the fake `kXxxCid` enum is gone. Only 3 of its 28 values (`Class`, `PatchClass`, `Function`) matched any real Dart release, so the legacy class parser decoded Class/Function clusters and silently skipped String/Array/Type/Mint/Double — the ones it needed for names. Its `switch` is now an `if` chain over `LegacyClusterCids`, resolved per layout via `dart_cid_get`. The two sites that fell back to a *fabricated* id when resolution failed (`dart_pool_data_image.c`, `dart_pool_it.c`) now fail closed, and a third raw `kFieldCid` comparison was resolved the same way. `builtin_type_name` keeps working on `Type.type_class_id` — a class id packed in the type flags, not a ref despite the field name — but against real ids. The `ti->kind` discriminator, which was never a snapshot id, became `DartTypeKind`. |
| `f10d30d` | **Perf, found via P2.2**: `cid_table_for_layout` resolved the CID table by comparing version *strings* against every row on **every** `dart_cid_get` call, and that call sits per-object on some paths. A one-entry memo keyed on the layout pointer makes it a pointer compare. Synthetic `-x` 4862 → **37 ms** (131×), mafia `-f` 1008 → 550 ms, mafia `-c` 756 → 312 ms. Output unchanged on all 95 comparisons. This was already the dominant cost *before* P2.2 — more evidence for the P3.1 note that the double cluster walk was the wrong suspect. |
| `251bec7` | **Initial `--dump-xrefs`**: real-binary `-x` tests (`xrefs-android`, `xrefs-ios`) land, so the ObjectPool-use scanner is no longer covered only by the synthetic blob. |
| `25dc49e` | **P3.5 + two `-x` correctness bugs**: `collect_pool_uses_from_entry` read JSON keys `pdj` does not emit. `offset` (real key: `addr`) always returned 0, so *every* pool use fell back to `entry->address` — the reported address was the function start, never the referencing instruction. `opstr` (real keys: `disasm`/`opcode`) was always NULL, making two of the three parser calls duplicates. The fixed 96-op window also ran past short functions (median Dart function is 28 instructions) into their neighbours; it is now bounded by the next entry's address. After the fix 100% of pool uses lie inside the function they are attributed to (before, 100% sat at a function start, which is why the attribution check could not fail). mafia `-x` 7783 → 4738 ms. Also hardens the `dart_cid_get` memo to key on a copy of the version text, not the (freeable) layout pointer. |
| `334c97b` | **P2.3**: `cid_table_for_layout`'s fallback for a layout with no usable version now goes through `dart_newest_profile()` instead of the literal `"3.9.2"`, so it agrees with the baseline the version fingerprinter picks for an unknown hash. Verified a no-op today (the two tables have zero differing CIDs); it stops being one the moment a release shifts the numbering. |
| `540efcf` | **P0.2 largely landed — the modern gate is now open.** `dart_modern_is_supported_snapshot` accepts `cws == 8` **and** `CID_SHIFT1`, not just `cws == 4` / OBJECT_HEADER. The fill desync that blocked this (the roadmap's cluster-12 failure on `hello.aot`) is resolved by `modern_skip_fill_instance` (version-dependent instance fill shape) and `modern_load_rodata_strings`, which reads the six RO-data string classes from the data image where uncompressed builds put them. **Result:** iOS Runner (3.4.3) recovers **6389 method names** where it emitted `func.<addr>` placeholders before; `hello.aot` (3.11.5) recovers 1130/1325. Tests `dump-funcs-ios-runner`/`-authpass`/`dump-it-ios-runner` updated to assert real names. **Still gated:** class/field extraction (`modern_can_extract_classes` keeps `cws == 4`), so `-c` on cws=8 still shows the weak `size=0` fallback — see the trimmed P0.2. |
| `b6ea0b8` | **Synthetic fixture reconciled** with the varint-tag switch. `6a7e01b` correctly made the legacy class parser read cluster tags as varints (Dart writes them with `Read<uint32_t>`, a varint), which broke `bins/synthetic/field_snapshot.bin` — it stores raw LE u32 tags. Rather than re-encode the blob, the parser branches on `synthetic_legacy_parse`: raw u32 for the fixture, varint for real snapshots. All tests green again. The fixture still has no generator (see P4). |
| `02efb30` | **String comments in `-AAA` disasm**: `PP+N` ObjectPool loads that resolve to a string now emit a `; dart: string "…"` comment at the referencing instruction. New test `analysis-string-comments`. |

Corrections to earlier assumptions, worth remembering:
- **The CID tables are not the problem.** Flooring is exactly correct 2.10→3.12,
  verified against SDK sources. Only a *future* CID shift needs action, and the
  generator adds a profile automatically when one appears.
- **The `kDart*` snapshot symbols survive `strip`** — they are external/global and
  load-bearing (the engine resolves them at runtime). Symbol-less iOS is an edge
  case (obfuscators/repackagers), not the norm.
- **The VM snapshot's canonical string cluster carries no canonical-set table**,
  unlike the isolate's. Measured on `android/mafia`: skipping one there consumes
  the next cluster's bytes and desynchronises the whole walk. This contradicts
  the SDK, where `StringDeserializationCluster::ReadAlloc` always calls
  `BuildCanonicalSetFromLayout` and both snapshots are read with
  `is_non_root_unit=false`. Unexplained; `modern_vm_strings_alloc` encodes the
  measured behaviour. Worth revisiting — it may mean the VM cluster range is
  being located slightly wrong and the strings we recover are a happy accident.

---

## The finding that reshaped priorities — now largely acted on

Historically **only 1 of 5 sample binaries** reached the "modern" (good) cluster
decoder, because `dart_modern_is_supported_snapshot()` gated on
`tag_style == OBJECT_HEADER && cws == 4`. `540efcf` opened that gate:

| Sample | Dart | tag_style | cws | modern **name** path | modern **class/field** path |
|--------|------|-----------|-----|-----------------|-----------------|
| `android/mafia` | 3.9.2 | OBJECT_HEADER | 4 | **yes** | **yes** |
| `android/first` | 2.18.2 | OBJECT_HEADER | 8 | **yes** (was no) | no (cws==4 gate) |
| `ios/Runner.app` | 3.4.3 | OBJECT_HEADER | 8 | **yes** (was no) | no |
| `ios/AuthPass.app` | 3.2.5 | CID_SHIFT1 | 8 | **yes** (was no) | no |
| `macos/hello.aot` | 3.11.5 | OBJECT_HEADER | 8 | **yes** (was no) | no |

So function/method **name** recovery now runs on all five; only class/field
extraction is still `cws == 4`-only. That is the remaining half of P0.2.

The single *class-path* sample is still 3.9.2, which **nearly matched** the CID
table `modern_get_fill_spec` used to hardcode — which is why the P0.1 bug was
invisible to CI, and why its fix still has no end-to-end test (P0.3).

---

## P0 — correctness bugs with no test coverage

### P0.2 (remaining half) Class/field extraction on `cws == 8` snapshots
The **name** path is done — `540efcf` opened `dart_modern_is_supported_snapshot`
to `cws == 8` and `CID_SHIFT1`, and iOS/macOS samples now recover real method
names (see status table). What is left is **class/field** extraction:
`modern_can_extract_classes` (`dart_pool_modern.c`) still returns
`cws == 4`. On a cws=8 snapshot `-c` falls back to the `size=0` string-scan
(`class extraction: ObjectHeader fill parser unavailable for cws=8, using string
fallback`), so fields, instance sizes and interfaces are not recovered.

**Do not re-derive — already established:**
- *Format delta is exactly `Serializer::ReadOnlyObjectType`*: six classes
  (`PcDescriptors`, `CodeSourceMap`, `CompressedStackMaps`, `String`,
  `OneByteString`, `TwoByteString`) move to the RO-data image with no fill
  records. Handled by `modern_walk_is_rodata` + `modern_load_rodata_strings`.
- *The fill desync is resolved.* The old cluster-12 failure on `hello.aot` came
  from a version-dependent instance fill shape; `modern_skip_fill_instance`
  fixes it, and the name-scan fill walk now completes on cws=8.
- *Instance/class fill reads target-word-sized fields.* This is where the
  remaining work is: `modern_read_class_fill`/`modern_read_field_fill` were
  written for the compressed layout. Extending them, then dropping the `cws == 4`
  in `modern_can_extract_classes`, is the task. Verify with `hello.aot -c`:
  today garbage, target is real class names + non-zero sizes.

### P0.3 Test corpus does not cover the decoders we ship
Progress: iOS **name** recovery on cws=8 is now asserted
(`dump-funcs-ios-runner`/`-authpass`, `dump-it-ios-runner`), and `-x` has
real-binary coverage (`xrefs-android`/`-ios`). Remaining gaps:
- a **Dart 3.4/3.5-era compressed-pointer** app (P0.1 is fixed but still has no
  end-to-end regression test; it was verified only by resolving `rules[]` against
  each layout in isolation);
- **cws=8 class/field** extraction has no positive test yet — it can't, until the
  remaining half of P0.2 lands and `hello.aot -c` produces real classes;
- more **iOS** binaries generally, ideally real obfuscated/stripped release
  `App`s (also broadens the `0716a95` structural path, per `COMMIT2.md`);
- a **32-bit ARM** app if one can be found (validates P1.2).
Buildable locally with the installed Dart SDK for the standalone cases; Flutter
app samples need collecting.

---

## P1 — correctness, lower prevalence or already-guarded

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

### P2.4 CID/layout data still lives in three places
`offsets.json` (source of truth, generated from SDK), `dart_cid.c` `cid_tables[]`
(generated ✔), and `dart_offsets.h` `dart_hash_entries[]` — which only carries
`hash → compressed_word_size`, a value already derivable from the profile and then
overridden by the feature flags anyway (cws is decided three times, flags win).
**Fix:** drop the hash→cws table or derive it.

### P2.6 `data_image_base` recomputed in ≥3 places with a magic-16 fallback
`dart_object.c:304-305`, `dart_pool_classes.c:1646-1655`, plus IT callers each do
`snapshot + align_up(total_len, layout->max_alignment ?: 16)`. Extract one helper
and confirm alignment is genuinely derived (it can be raised to 64) rather than
silently defaulted.

### P2.7 `-x`/`-z` special-case in both frontends (partly overtaken)
`core_flutter.c` (`case 'x'`) and `main.c` set `string_refs = true` for *any*
`-x`. The dispatch is now live (`case 'x' → dart_pool_dump_xrefs`), so the
"dead branch" framing no longer holds — but the unconditional `string_refs`
plus the `if (cmd->action != 'z')` guard still reads as accidental coupling
between `-x` and `-z`. Re-audit against current line numbers before acting;
lower priority than when first written.

---

## P3 — performance

Read caching (`read_mem`, `dart_pool_snapshot.c:10-44`) already turns per-byte
varint reads into a 1 MB sliding window. Remaining hotspots, largest first:

### P3.1 Redundant full passes over the same regions
A single `-f`/`-A` walks the cluster stream twice and the data image 2–3 times.

**This was claimed to be the biggest perf win; measured, it is not.** Removing
the whole legacy cluster walk changes runtime by ~1%, inside noise (mafia `-f`
993 → 1005 ms; AuthPass `-f` 616 → 618 ms) — it bails out early rather than
re-walking the stream.

The real cost was elsewhere, and profiling found it: `dart_cid_get` re-resolved
the CID table by version-string comparison on every call (see the status table).
Memoising it took mafia `-f` from 1008 → 550 ms and the synthetic `-x` from 4862
→ 37 ms — far more than P2.1 could ever have given. **Profile before spending
time here.**

`-x` was the next slowest; `25dc49e` fixed its correctness bugs and the window
bound cut mafia `-x` 7783 → 4738 ms. A further ~2× remains: it still round-trips
disassembly through `pdj` JSON text (`dart_pool_xrefs.c:527`) only to string-match
`disasm`, where decoding with `r_anal_op` and inspecting operands directly would
skip both the pretty-printer and the JSON. The 4096-entry scan cap also still
hides ~89% of mafia's 37259 IT entries.

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

- **The synthetic fixture has no generator and is fragile.** `bins/synthetic/field_snapshot.bin`
  is a hand-authored blob. It has already forced two special cases as the parser
  was corrected: P2.2 had to renumber its cluster tags to real CIDs, and `b6ea0b8`
  had to branch the tag reader on `synthetic_legacy_parse` because it stores raw
  LE u32 tags while real snapshots use varints. Every future layout/encoding fix
  risks a third. **Write a generator** so the fixture tracks the parser instead of
  pinning obsolete conventions; the `synthetic_legacy_parse` branch could then go.
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

1. **P0.2 (remaining half)** — class/field extraction on `cws == 8`. The name
   path already landed (`540efcf`); this finishes the largest quality win. Drop
   the `cws == 4` in `modern_can_extract_classes` once
   `modern_read_class_fill`/`modern_read_field_fill` handle the uncompressed
   layout. Verify with `hello.aot -c`.
2. **P0.3** — grow the corpus alongside 1: a real cws=8 class-extraction golden,
   and a 3.4/3.5-era compressed sample for the still-untested P0.1 fix.
3. **Finish `-x`**: replace the `pdj` JSON round-trip with `r_anal_op` decoding
   (~2× more), then reconsider the 4096-entry cap that hides ~89% of IT entries.
4. **P1.3** — shared frontend parser (fixes the `-r`/`r2 -n` AGENTS.md violations).
5. **P1.2** — arch gating.
6. **Write a synthetic-fixture generator** (see P4) so parser fixes stop needing
   blob special-cases.
7. **P3.2** — now a *lower* suspect than it looked; it never showed up in the
   `-x` profile. Remaining P2 cleanups and test hardening.

`COMMIT2.md` tracks the narrower follow-ups left over from the discovery work
(gapped layouts, more iOS fixtures, stripped ELF, P1.5 semantics).
