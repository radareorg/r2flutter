# Discoveries and Technical Findings

This document summarizes key technical findings discovered during the implementation of class extraction features in r2flutter.

## `-H` Text Output Is Markdown-Friendly

**Finding**: Human-readable `-H` output is intended to be pasted into markdown notes, so section titles should use ATX headings: `#` for the top-level title and `##` for subsections. Avoid setext underline separators such as `===` and `---`; they are less consistent with the rest of the CLI output and harder to regression-test cleanly.

## macOS `dart compile exe` Uses An `LC_NOTE` Inner Mach-O

**Finding**: Standalone macOS binaries produced by `dart compile exe` are a two-level container: the outer executable is the statically linked Dart VM, and the actual AOT app is an ARM64 Mach-O dylib stored as opaque bytes in an `LC_NOTE` named `__dart_app_snap`.

The note gives a raw file offset and size. The inner Mach-O then exposes the usual four Dart snapshot symbols:

- `_kDartVmSnapshotInstructions`
- `_kDartVmSnapshotData`
- `_kDartIsolateSnapshotInstructions`
- `_kDartIsolateSnapshotData`

Static tools that only map `LC_SEGMENT_64` commands will analyze the Dart VM shell and miss the app code entirely. `r2flutter` should therefore treat `__dart_app_snap` as a first-class snapshot container: detect the note in the outer Mach-O, extract or virtually map the inner Mach-O, and run the existing snapshot discovery on that inner image.

**Implementation implications**:

- add a Mach-O `LC_NOTE` scanner for `__dart_app_snap`
- expose a CLI/action that identifies standalone Dart executables and reports the embedded payload offset/size
- support transparent analysis of the inner Mach-O instead of requiring users to manually carve it out
- keep address reporting explicit: recovered app functions are relative to the inner Mach-O / isolate instructions, while outer-process runtime addresses need an extra mapping step
- add a regression fixture for an outer `dart compile exe` binary, not only the existing `test/bins/macos/hello/hello.aot` inner Mach-O

**Platform note**: The analyzed Dart `3.11.4_macos_arm64` standalone sample uses `no-compressed-pointers`, unlike Android Flutter AOT builds. The snapshot feature string should drive pointer-width decisions instead of assuming all modern non-iOS targets use compressed pointers.

## macOS Standalone Dart Has Useful Hunting Signals

**Finding**: The most reliable static indicator for standalone macOS Dart AOT executables is the `LC_NOTE` owner string `__dart_app_snap`. Secondary indicators are the Dart VM strings/symbols such as `kDartVmSnapshotData`, `kDartIsolateSnapshotData`, `Dart VM`, and `DART_VM_OPTIONS`.

Flutter macOS apps differ structurally: their Dart app snapshot lives in `App.framework`, and the outer app usually depends on `FlutterMacOS.framework`. A standalone `dart compile exe` binary has no Flutter framework dependency.

**Implementation implications**:

- `-H` JSON should include container metadata such as `container:"macho-lc-note"`, `note_owner:"__dart_app_snap"`, `payload_offset`, and `payload_size` when present
- a future `--triage` mode can report `standalone-dart-macos` vs `flutter-macos-app` based on `LC_NOTE`, snapshot symbols, and Flutter framework imports
- string triage should prioritize the inner Mach-O object pool; this is where hardcoded URLs, paths, and keys appear even when the outer VM binary looks uninteresting

## `LC_NOTE` Reflective Loading Affects Dynamic Assumptions

**Finding**: The macOS standalone Dart runtime loads the inner Mach-O manually from `LC_NOTE`, maps executable memory with `MAP_JIT`, and does not register the payload through dyld. As a result, the app code may not appear in normal module lists or dependency views.

**Implication**: `r2flutter` should not rely on dynamic module enumeration or loader-provided module boundaries for this format. The static file offset in `LC_NOTE` is the stable source of truth, and any Frida/r2 script output should document that hooks need to account for anonymous runtime mappings.

## Field Flags Can Reuse Raw `kind_bits`

**Finding**: `DartFieldInfo.flags` does not need a second packed enum layout.

The Dart VM already stores the field properties we care about in `Field.kind_bits_`, and the current snapshot layout in `third_party/sdk/runtime/vm/object.h` places them at:

- `const`: bit 0
- `static`: bit 1
- `final`: bit 2
- `late`: bit 6

Because r2flutter only tests those bits as booleans later, `fi->flags` can keep the raw `kind_bits` value directly as long as `DART_FIELD_*` mirrors the VM bit positions.

## Compressed Pointers Store Low 32 Bits Of The Tagged Pointer

**Finding**: The current Dart VM sources in `third_party/sdk` do not implement compressed pointers as `heap_base + (ref << alignment_shift)`.

The real model in this checkout is:

- store the low 32 bits of the already-tagged pointer
- reconstruct with `heap_base + stored32`
- keep Smis compressed to the same 32-bit slot width

This also means `PP` is not the heap-base register. `PP` is the object-pool register. On ARM64 the heap upper bits come from `HEAP_BITS`, and on x64 compressed loads add `Thread::heap_base_offset()`.

## Compressed-Pointer AOT Strings Are Packed Cluster Payloads, Not ROData C Strings

**Finding**: In code snapshots without compressed pointers, canonical strings can be emitted as direct ROData heap objects, which is why local iOS and `android/first` samples contain NUL-padded names such as `_Uint16List`.

With compressed pointers enabled, the serializer skips that direct ROData path and writes strings through `StringSerializationCluster` instead:

- alloc phase writes encoded length/type
- fill phase writes encoded length/type again
- then raw one-byte or UTF-16 payload bytes

This is why compressed-pointer Android samples such as `android/mafia` contain byte runs like:

```text
Handle 82 1a 82 34 MonomorphicSmiableCall ...
```

The printable text is still plain, but it is separated by cluster metadata bytes instead of `0x00`.

**Implication**: fuzzy `-zz` can recover some of these with non-NUL-delimited text scanning, but complete support should come from snapshot-aware string-cluster decoding rather than classic C-string assumptions.

## Snapshot `WriteUnsigned` Is Not Standard ULEB128

**Finding**: Dart clustered snapshots do not use plain ULEB128 for `WriteUnsigned` / `ReadUnsigned`.

The terminating byte is written as `value + 0x80`, so:

- `6` is encoded as `0x86`
- `12` is encoded as `0x8c`
- multi-byte values use low 7-bit chunks followed by a final byte with bit 7 set

This explains packed runs such as:

```text
9e "<optimized out>" 8c "Handle" ac "MonomorphicSmiableCall"
```

where `0x9e` is length `30` (`15 << 1`) and `0x8c` is length `12` (`6 << 1`) for one-byte strings.

**Implication**: snapshot-aware string recovery must use Dart's own unsigned decoding, not a generic LEB128 reader, otherwise string lengths and cluster metadata drift immediately.

## Reliable Compressed-String Recovery Comes From Packed Record Runs

**Finding**: A full cluster deserializer is not required just to recover meaningful strings from compressed-pointer snapshots.

In practice, scanning the snapshot cluster region for **runs** of valid Dart string records works well:

- decode a Dart `ReadUnsigned`
- interpret `encoded >> 1` as length and `encoded & 1` as one-byte vs two-byte
- require a sequence of several valid records, tolerating a few short non-text records between them
- emit payload addresses, not prefix-byte addresses, so results dedupe cleanly with classic section scans

This recovers structured packed strings from `android/mafia` while avoiding the need to fully model every non-string cluster.

## InstructionsTable Data Lives Inside A String Object In The RO Image

**Finding**: Modern AOT snapshots do not place `InstructionsTable::Data` directly at the `it_data_off` address inside the clustered blob.

For current Android samples, the read-only image after the clustered snapshot starts with an `Image` header (`0x40` bytes), and the instruction-table bytes are wrapped in a large `OneByteString` object. The usable table header starts at that string payload:

- object start: aligned `it_data` string in the RO image
- payload start: `object + 0x10` on current 64-bit `HASH_IN_OBJECT_HEADER` builds
- payload header: `canonical_stack_map_entries_offset`, `length`, `first_entry_with_code`, `padding`

**Implication**: probing `it_data_off` as if it were already the `InstructionsTable::Data` header can collapse the table to a bogus 3-entry decode. A robust parser should scan the RO image strings for a payload whose header and entry array look like a real instruction table.

## Sample `it_len` Does Not Equal The Real Code-Entry Count

**Finding**: On the `poc/app/libapp.so` Dart `3.8.1` sample, the clustered header reports `it_len=2953`, but the real RO-image `InstructionsTable::Data` payload found in the wrapped `OneByteString` has `length=26413`.

The recovered string object starts at `0x2e2fc0`, and its payload decodes the expected early entries:

- index `0` -> `0x396900`
- index `1` -> `0x3969c0`
- index `42` -> `0x3980fc`
- index `43` -> `0x398174`

Those addresses match the reference outputs from blutter and unflutter for `DateTime.compareTo`, its dynamic variant, `_runMain`, and the `_runMain` anonymous closure.

**Implication**: `cluster.it_len` is not a reliable upper bound for `-f` on this sample. Function dumping should trust the decoded RO-image table length and should not cap itself to the smaller clustered-header value.

## `-n` Must Stay Opt-In

**Finding**: The name-pool fallback is useful for exploratory reversing, but it is too weak to enable by default because it can silently mislabel functions.

Current behavior:

- `collect_data_names ()` scans the data image for `package:` and `dart:` strings and stores them in discovery order
- `resolve_it_entry_name ()` only consults that pool after exact symbol, entrypoint, and stack-map-based naming fails
- when enabled, unresolved code entries consume names sequentially via `name_pool_idx++`

Why this is risky:

- there is no proof that pool index `N` belongs to instruction-table entry `N`
- one early mismatch shifts all later fallback names
- the resulting names look plausible enough to be mistaken for confirmed metadata

Use `-n` for manual triage only. The default synthetic `method.fn_*` names are intentionally less informative, but more honest.

## Code-Slot Owner CID Must Gate The Name-Pool Fallback

**Finding**: The InstructionsTable lists one slot per AOT Code object, and a large fraction of those slots are not user methods but allocate stubs (`Code.owner` is a `Class`), type-test stubs (`Code.owner` is an `AbstractType`), or VM stubs (`Code.owner` is null). On the `poc/app` Dart 3.8.1 sample roughly 2,700 slots out of 26,413 are allocate stubs.

Prior behavior treated every un-named slot identically and consumed the next `name_pool` string, so each stub silently shifted every following name by one. Cross-checking against blutter's `addNames.py` showed about 54% of addresses had the wrong name for this reason alone.

Fix: the Code-cluster reader now records the cluster cid of each slot's owner ref in `code_owner_cid_by_index[]` and exposes it on `DartCtx.owner_kind_by_code_index[]`. During naming:

- owner cid equal to `Class` cid -> synthesize `stub.Allocate<ClassName>Stub`
- owner cid equal to `Function` cid -> existing class+method naming path
- owner ref of zero -> VM stub (no cluster provides a name on this pass)
- any other non-zero cid -> best-effort `stub.TypeTest_<name>`

`resolve_it_entry_name ()` then only advances `name_pool_idx` when the slot is `DART_OWNER_FUNCTION` or `DART_OWNER_UNKNOWN`. Stub slots emit stable synthetic names like `stub.vm_<index>` instead of stealing a pool entry.

**Implication**: names stay aligned across the full IT even when `-n` is enabled, and diffing the output against blutter's `ida_script/addNames.py` becomes meaningful again. Out-of-snapshot VM stubs (addresses before `iso_instr`) are still unnamed on this branch; matching them requires a separate per-version `OBJECT_STORE_STUB_CODE_LIST` / `VM_STUB_CODE_LIST` table and is intentionally left for a follow-up.

**Test invariant**: regression tests for this gate must run with `-n`. The default path intentionally leaves the name pool disabled, so tests without that flag do not exercise the bug where allocate and type-test stubs consumed pool entries.

## `dyn:` Trampolines Need A Better Signal Than Code Payload Info

**Finding**: The proposed unchecked-entry-offset fold is not proven by the mafia fixture.

On `test/bins/android/mafia`, the modern Code cluster payload for the early entries called out in `doc/functips.md` is only `0` or `1`, which decodes to `unchecked_offset = payload_info >> 1 == 0`. That does not explain `0x5b6b64` or `0x5b6c34`, even though both still look like dynamic-entry trampolines in the function listing.

**Implication**: do not suppress `dyn:` rows by name or adjacency alone. Keep `-i` raw, keep the visible `dyn:` entries in `-f` until a real Code-object relationship is recovered, and test the current behavior so future changes can prove they are improving it rather than hiding it.

## Parser Cleanup Should Delete Before It Wraps

Prefer direct `DartSnapshotHeader` use over wrappers that split the same fields into out-parameters. For duplicated formatters, reuse the existing formatter when output text is identical instead of adding another mode-specific helper.

## Enum Recovery In `-T` Is Heuristic But Useful

**Finding**: Production AOT samples still do not expose enough `Class` metadata to recover enum declarations directly, but enum names and variants often survive as qualified strings such as `AppLifecycleState.resumed` plus a matching `AppLifecycleState.` marker.

`-T` now supplements the existing type-name scanner with a conservative enum inference pass over extracted strings:

- require a trailing `EnumName.` marker
- require at least two lowercase `EnumName.value` strings
- score candidates so enum-shaped type names like `...State`, `...Action`, `...Mode`, `...Direction`, `...Alignment`, and `...Affinity` are preferred
- reject obvious factory-style false positives such as `Future.value`, `List.from`, and similar constructor-heavy APIs

This recovers real enums in the shipped fixtures on both platforms, for example `AppLifecycleState` on iOS and Android, and `TextInputAction` on the Android `mafia` sample.

## Dump Header JSON Superset

**Finding**: `-j -H` emits the same snapshot/cluster fields as the old dump-snapshot JSON, plus layout metadata (version, tag style, CID table).

This makes the legacy dump-snapshot flag redundant and keeps scripts relying on `cluster` and snapshot addresses intact.

## Direct-Ref Annotation Prefixes Are Better As Data Than Control Flow

**Finding**: `flutter_process_direct_ref ()` only dispatches across a fixed set of flag-name prefixes, so an open-coded chain of `flutter_annotate_flag_ref ()` calls adds noise without adding logic.

Keeping the prefixes in a tiny local table makes the supported mappings explicit:

- `dart.class.` -> `class ref`
- `dart.type.` -> `type ref`
- `dart.field.` -> `field ref`
- `dart.str.` and `str.` -> `string`

**Implication**: refactors to add or reorder supported direct-reference prefixes now touch one data block and one loop instead of duplicating another boolean clause.

## InstructionTable Dumping Is A Real Output Mode Now

**Finding**: `-i` should be treated like the other dump commands, not as a stderr-only debug side effect.

The command now:

- writes to stdout
- honors `-j` for JSON
- honors `-r` for radare2 flags
- honors `-l` for manageable output on large apps

The parser also needs a wider scan than the raw `it_off` hint on some iOS samples, because the offset can land inside the table payload rather than exactly on the `InstructionsTable::Data` header.

## String Dump Flag Matches `rabin2 -z`

**Finding**: The standalone CLI and radare2 plugin use `-z` for reliable
ObjectPool-backed string dumping, matching the familiar `rabin2 -z` shape while
keeping provenance stricter. Use `-j` with `-z` when JSON output is needed.
Use `-zz` when broad fuzzy/carved string triage is desired. Add `-x` to string
actions (`-xz`, `-xzz`) to include reverse reference metadata; without `-x`,
the text output stays focused on strings. `-q -z` prints only string values.

This leaves `-t` for r2 comment/script-style string output and keeps public examples/tests on the same strings flag users already know from rabin2.

## Standalone CLI Uses Short Flags Only

The standalone `bin/r2flutter` parser now uses `r_getopt`, so every option is a single-character flag. Keep CLI tests and examples on these action flags: `-A` analyze/apply, `-c` classes, `-f` functions, `-H` header, `-i` instruction table, `-R` r2 script, `-T` types, `-x` xrefs, and `-z` reliable strings. Shared modifiers are `-j`, `-q`, `-r`, `-n`, and `-v`; argument options are `-l` and `-m`. Use `-zz` for fuzzy/carved strings. Use `-m` for the Flutter obfuscation map because `-o` reads as output in common CLI conventions.

Bare `r2flutter` must be help-only in both the standalone CLI and core plugin. The analysis ladder is explicit under repeated `A` in both entrypoints: `-A` applies recovered method flags/comments, `-AA` enables the field-extraction analysis layer, and `-AAA` runs the Dart-aware code refs/comments pass.

`-q` is an output modifier, not an action. It keeps the selected action intact while compacting text/r2 dumps by dropping explanatory comments and nested detail where the dump has a shorter useful form.

## r2r Coverage Needs Short Cross-Platform Windows

**Finding**: The `test/db/cmd` suite is more maintainable when every dump mode is exercised on both Android and iOS using short deterministic windows instead of full dumps.

The current matrix covers `-H`, `-f`, `-i`, `-z`, `-zz`, `-c`, and `-T` against small Android/iOS fixtures and the Android `mafia` ObjectPool sample, using `-l` or `sed -n` to keep expectations stable and fast.

This avoids brittle megabyte-scale expectations while still checking platform-specific snapshot addresses, instruction table metadata, and representative function/class/type/string prefixes.

## Stub Symbols Should Stay With RBin

**Finding**: Loader-provided ELF/Mach-O stub symbols do not add useful Flutter-specific signal, because radare2 already exposes them through `RBin`.

`r2flutter` now skips those stubs by default in `-f` and analysis output, which keeps the plugin focused on Dart-derived names and makes function-dump tests line up with the augmented data we actually recover.

## Production AOT Snapshots Lack Class Metadata

**Finding**: Class definitions (kClassCid=5) are not serialized in production Flutter builds.

When parsing clusters in production AOT snapshots, all CIDs encountered (e.g., 1068, 790819) are >= kNumPredefinedCids (~128), indicating they are user-defined class instance clusters, not Class definition objects themselves.

**Implication**: Direct cluster parsing cannot recover class names from the Class cluster in release builds. Alternative approaches like string scanning are required.

## Cluster Tag Encoding (Dart 3.4.3+)

For Dart 3.4.3 and later, the cluster tag format uses `TAG_STYLE_OBJECT_HEADER`:

```
Bits 0-11:  Reserved flags (canonical, immutable, size tag)
Bits 12-31: ClassId (20 bits)
```

To extract the Class ID:
```c
uint32_t cid = (tag >> 12) & 0xFFFFF;
```

Earlier versions used different encoding:
- Dart 2.10-2.13: Raw int32 CID
- Dart 2.14-3.3: `(cid << 1) | canonical`

Reference: `third_party/sdk/runtime/vm/app_snapshot.cc` lines 912-920

## String-Based Type Name Extraction

**Finding**: Scanning the const/data section between `vm_data` and `iso_data` successfully extracts type-like strings.

CamelCase names matching the pattern `[A-Z][a-z]+[A-Za-z0-9]*` that contain at least one lowercase letter are likely type names. This approach successfully extracts ~250 type names from test binaries including:
- `ArgumentError`, `_Future`, `Widget`, `BuildContext`, etc.

This serves as a reliable fallback when cluster parsing yields no class definitions.

## Heuristic String Extraction & Classification

**Finding**: Production snapshots frequently omit usable string clusters, so scanning the read-only sections for raw ASCII/UTF-16 sequences is more reliable than walking snapshot metadata.

Implementation details:
1. Iterate every non-executable, readable section (covers `.rodata`, Mach-O `__DATA_CONST`, etc.).
2. Parse printable ASCII runs (length >= 4, <= 512) directly from the bytes.
3. Parse UTF-16LE runs by collapsing two-byte code units into UTF-8, which recovers user strings that are stored as wide characters.
4. Classify each recovered string:
   - `runtime`: values starting with `dart:`/containing `dartvm` internals
   - `library`: structural metadata (`package:` URIs, `.dart` paths, CamelCase type names)
   - `app`: anything containing whitespace or punctuation (typical user-facing strings)

This produces cleaner fuzzy string output even when the clustered snapshot contains compressed or stripped string objects, while also giving analysts a quick way to filter out VM noise and focus on app-facing literals like `"Hello, Dart!"`.

## Fuzzy Strings Must Stay Inside Dart Snapshot Windows

**Finding**: Letting the string dumper scan every readable section regresses badly on iOS once Mach-O `__text`, code stubs, cert blobs, and loader metadata are included in the candidate set.

## `R_STR_ISEMPTY` Only Applies To Real Strings

**Finding**: The repo style rule to prefer `R_STR_ISEMPTY` / `R_STR_ISNOTEMPTY` only applies to C string checks.

Cases like `char *value` should use `R_STR_ISEMPTY (value)` instead of open-coded `!value || !*value`, but guards for non-string pointers such as `ut64 *addrp` should stay as pointer/value checks because they are not string buffers.

The practical fix is:

- prefer snapshot-bounded windows (`vm_data` up to the next snapshot, and similarly for `iso_data` when applicable)
- keep the broad fallback limited to read-only constant sections such as Mach-O `__const` / `__cstring` and ELF `.rodata` / `.data.rel.ro`
- keep short-string heuristics strict enough to drop opcode-shaped junk like `_X;,` while preserving real Dart identifiers like `_Set`

This removes the worst false positives from fuzzy string scans without sacrificing the real Dart names stored in the const area of the shipped iOS and Android fixtures.

## Cross References Split Into Metadata, Data-Image, And Code Layers

**Finding**: Not all useful Dart snapshot xrefs come from the same place.

There are three distinct layers:

- **snapshot metadata xrefs**: serialized ref-id links such as `Class.name_ref`, `Class.library_ref`, `Class.super_class_ref`, `Class.interfaces_ref`, `Field.owner_ref`, `Field.name_ref`, and `Field.type_ref`
- **data-image object xrefs**: raw `Function` and `Field` objects that can still be scanned in release builds even when full class metadata is missing
- **code xrefs**: object-pool loads, field-offset accesses, and call edges that only appear in disassembly

Practical implication:

- `object -> name/owner/super/interface` style links are often dumpable from the binary without disassembly
- `function uses string/class/field/method` style links generally require code analysis

Current gaps:

- `DartStringInfo.references` is populated from decoded class/library/field/method metadata for fuzzy recovery and from ObjectPool entries for reliable `-z`, so string output can show reverse `string -> user` links when the metadata survives
- object-pool offsets can be collected from code, and `-x` can resolve some `PP+imm` slots into `code -> string/class/type/field/method` xrefs when `anal.gp` is set and the slot target is a readable string or an existing Dart flag
- library URI resolution works when metadata survives, and `Field.type_ref`
  links now resolve simple `Type` objects, `TypeArguments` for generic field
  types, `TypeParameter` placeholders like `X0`, and simple `FunctionType`
  signatures such as `(int) => String`
- class interface arrays now resolve through small `Array` and `Type` records
  when metadata survives, producing `implements` text/JSON and
  `class.interface` xrefs

The repo now exposes the currently recoverable subset through:

- CLI: `-x`
- radare2 plugin: `r2flutter -x`

The xref dumper is still conservative. It does not invent code-use edges without
an object-pool base, and it does not reconstruct indirect dispatch/call graphs.

## Object-Oriented Metadata Recovery Is Layered

**Finding**: The current OO recovery state is no longer "classes done, fields
missing, xrefs absent". The implemented surface is split across several
confidence layers:

- cluster metadata can recover class names, superclass/library/interface refs,
  flags, layout counters, and Field owner/name refs when those serialized
  objects survive
- data-image scans can attach raw Field and Function objects back to recovered
  classes by owner/name
- string fallback recovers many type-looking names but does not carry reliable
  hierarchy, library, field, or method ownership
- `-x` emits the metadata/data-image edge subset, while plugin `r2flutter -AAA`
  handles some disassembly-derived annotations

The most valuable next work is therefore not "add field extraction" from
scratch. It is production coverage for these metadata paths, recovering mixin
application chains when the VM metadata carries enough signal, and broadening
object-pool decoding beyond the current readable-string/live-flag targets. Field
attachment, generic field type rendering, type-parameter field types,
function-shaped field types, class interface edges, reverse string metadata
references, and cluster-backed method signatures now have direct synthetic
text/JSON/xref coverage.

## `r2flutter -AAA` Uses Live `RCore` Metadata But Keeps PP Resolution Conservative

**Finding**: The new plugin-side analysis pass now runs inside the already loaded `RCore` session, reuses the current function/flag state, normalizes tagged Dart entrypoints to executable addresses, and scans analyzed ARM64 ops to recover:

- direct call xrefs
- string/class/field/type refs when the target can be tied back to known metadata or live flags
- PP (`x27`) slot-use comments such as `dart: PP slot +0x530`

This closes part of the old "metadata only" gap for code xrefs without pretending we can fully decode every object-pool entry yet.

Important current limitation:

- the shipped CLI samples do not populate `anal.gp`; object-pool resolution in
  `-x` is therefore a live-r2-session feature, not a normal standalone CLI
  fixture result
- current pool decoding tries raw/tag-stripped pointers plus compressed
  `app.heap_base` candidates and stops at readable strings or existing Dart
  flags; broader Dart object decoding is still future work
- `-AAA` can reliably annotate PP-relative slot usage and indirect-call
  breadcrumbs, but still does not resolve dispatch-table targets or build a full
  call graph

## Recovering Methods Without Class Clusters

Production snapshots omit the `Class` cluster, but that does **not** mean current `r2flutter` can rely on direct cluster deserialization for methods. On the Dart `3.8.1` Android sample in `poc/app/libapp.so`, the current clustered walk yields `strings=0 classes=0 functions=0`, so method recovery has to be treated as a raw data-image / `Code` + `Function` reconstruction problem rather than a simple “parse the Function cluster” problem.

r2flutter does have a raw data-image method scan for objects whose CID equals `cid_function`, and that is the right direction. The intended extraction is:

- Entry point (validated against the isolate instructions region)
- Symbolic name strings
- Owning class pointers to recover class names
- `kind_tag` values to classify constructors/getters/stubs

In practice, this still needs more work on newer Android samples. The key lesson is that qualified function recovery should be built from raw `Function -> owner -> class/library` reconstruction and then joined with InstructionTable addresses, not from direct cluster metadata alone.

## Memory Layout Observations

For iOS test binaries (`App.framework/App`), the physical address (paddr) equals the virtual address (vaddr), both at 0x1b0900. This simplifies address translation.

For Android (`libapp.so`), standard ELF relocation rules apply with segment-based address translation.

## Snapshot Structure

### Binary Layout

**Android (libapp.so)**:
```
ELF Header
├── .rodata section
│   ├── _kDartVmSnapshotData        (VM isolate data, ~3KB)
│   ├── _kDartIsolateSnapshotData   (App isolate data - bulk)
│   └── _kDartIsolateSnapshotInstructions
└── .text section
    └── _kDartVmSnapshotInstructions
```

**iOS (App.framework/App)**:
```
Mach-O Header
├── __DATA segment
│   ├── _kDartVmSnapshotData
│   └── _kDartIsolateSnapshotData
└── __TEXT segment
    ├── _kDartVmSnapshotInstructions
    └── _kDartIsolateSnapshotInstructions
```

### Snapshot Header

```
Offset  Size    Field
──────────────────────────────────────────────────────
0x00    4       Magic number (0xf5f5dcdc, little-endian)
0x04    8       Length (total size minus magic, int64)
0x0C    8       Kind (snapshot type, int64)
0x14    32      Version hash (ASCII hex, NOT null-terminated)
0x34    N       Features string (null-terminated)
```

### Clustered Header (ULEB128 encoded)

After the features string's null terminator:
```
num_base_objects
num_objects
num_clusters
instructions_table_len
instruction_table_data_offset
```

## Two-Phase Deserialization

Dart uses Alloc/Fill phases:

1. **Alloc Phase**: Read cluster tags, allocate objects, assign reference IDs starting from `num_base_objects + 1`
2. **Fill Phase**: Read actual field values, resolve reference IDs to object pointers

This handles circular references since all objects are allocated before any fields are filled.

## Predefined Class IDs (CIDs)

**Important**: CID values change between Dart versions. The table below shows values for two common version ranges:

| Class | Dart 3.4.x | Dart 3.5-3.10.x |
|-------|------------|-----------------|
| kIllegalCid | 0 | 0 |
| kClassCid | 5 | 5 |
| kFunctionCid | 7 | 7 |
| kFieldCid | 10 | 10 |
| kLibraryCid | 12 | 12 |
| kCodeCid | 18 | 18 |
| kObjectPoolCid | 22 | 23 |
| kMintCid | 60 | 61 |
| kArrayCid | 89 | 90 |
| kStringCid | 92 | 93 |
| kOneByteStringCid | 93 | 94 |
| kTwoByteStringCid | 94 | 95 |
| kNumPredefinedCids | 174 | 175 |

CIDs >= kNumPredefinedCids are dynamically assigned to user-defined classes.

**Detection**: Use the 32-byte snapshot hash to look up the correct CID table from a version profile database.

## String Encoding in Snapshots

String length and type are combined in a single ULEB128:
```
encoded = (length << 1) | is_two_byte
```
- Bit 0: 0 = OneByteString (Latin-1), 1 = TwoByteString (UTF-16)
- Bits 1+: String length

**No compression** is applied to string content - they are plain UTF-8 or Latin-1.

## Compressed Pointers (Dart 2.18+)

Since Dart 2.18, object references use 32-bit compressed pointers:
```
Absolute = heap_base + (compressed_ref << alignment_shift)
```

The heap base is stored in register x27/PP on ARM64. String **content** remains uncompressed.

Detection: Check features string for `compressed-pointers` or `no-compressed-pointers`.

## Data Image Layout

```
Snapshot Base
├── Snapshot Stream (clusters, roots)
├── Padding (aligned to kMaxObjectAlignment, typically 16 bytes)
└── Data Image
    ├── InstructionsTable::Data
    ├── Object Pool entries
    ├── String contents
    └── Other read-only data
```

The `instruction_table_data_offset` field points into the Data Image.

## Version Identification

The 32-byte ASCII MD5 hash at offset 0x14 identifies the exact Dart VM version and snapshot format. This hash maps to a finite set of constraint profiles that can be statically defined.

r2flutter maintains 40+ known snapshot hashes from Flutter 1.22.x (Dart 2.10.0) to Flutter 3.38.x (Dart 3.10.7).

### Version Profiles Include:
- Tag encoding style (CID-Int32, CID-Shift1, ObjectHeader)
- Header field count (4-6 depending on version)
- CID table mapping
- Compressed pointer configuration
- Number of predefined CIDs

## What Survives Tree-Shaking

| Preserved | Removed |
|-----------|---------|
| All referenced class names | Unused classes and methods |
| All referenced field names | Unused fields |
| Method names (in snapshot) | Debug symbols (if stripped) |
| String literals used in code | Source code locations (release) |
| Global/static identifiers | Variable names (local scope) |

Class names, method names, and field names are not reliably exposed as standalone `Class` / `Function` / `String` clusters in production AOT snapshots. Enough metadata often still survives somewhere in the data image for tools like blutter and unflutter to recover names, but `r2flutter` must not assume that a direct clustered walk will expose those objects in a convenient form.

## Android vs iOS: Cluster Counts and String Encoding Differences

### Cluster Counts Vary Enormously by Platform

**Finding**: Android production AOT snapshots can have hundreds of thousands of clusters, while iOS snapshots typically have very few.

| Binary | Platform | num_clusters | num_objects |
|--------|----------|-------------|-------------|
| first/libapp.so | Android | 514,008 | 9,993 |
| mafia/libapp.so | Android | 65 | 9,993 |
| Runner.app | iOS | 17 | 13,577 |
| AuthPass.app | iOS | 17 | 16,008 |

The `num_clusters` field from the ULEB128 header is NOT bounded by a small constant. Android snapshots built without compressed pointers (`first`) can have cluster counts in the hundreds of thousands. Validation thresholds must accommodate this (at least up to 1M).

### String Null-Termination Depends on Pointer Compression

**Finding**: In the snapshot data region (between `vm_data` and `iso_data`), string encoding differs based on the `compressed-pointers` feature flag:

- **Without compressed pointers** (e.g., `first/libapp.so`): Type name strings are null-terminated with zero-padding (typically aligned to 4 or 8 bytes). Standard null-terminated string scanning works.
- **With compressed pointers** (e.g., `mafia/libapp.so`): Type name strings are tightly packed with binary length-prefix bytes between them and are NOT null-terminated. The byte following a string is typically a snapshot encoding byte (e.g., `\x82`, `\x8c`).

Example from `mafia/libapp.so`:
```
Handle\x82\x1a\x82\x34\xacMonomorphicSmiableCall\x82\x33...
```
vs `first/libapp.so`:
```
_Uint16List\x00\x00\x00\x00\x00...
```

**Implication**: The string-based type extraction fallback must accept strings delimited by any non-printable byte (not just null terminators) to work on compressed-pointer Android snapshots.

### Blutter Only Supports Android

Blutter (in `third_party/blutter`) currently only supports Android ELF (arm64). It compiles the actual Dart VM runtime for the target version and walks live ClassTable/ObjectPool structures via `Dart_Initialize`. iOS support is listed as a TODO. The key difference: Blutter's `ElfHelper::MapLibAppSo()` has incomplete Mach-O handling.

## String Object Storage in ROData Image (Dart 3.4.3+)

**Finding**: In AOT snapshots without compressed pointers, canonical strings are stored as raw Dart heap objects in the ROData image section, NOT as serialized cluster data.

### ROData String Object Format

```
Offset 0x00: [8 bytes] Object header
             - Bits 0-7:   GC flags (AlwaysSet, NotMarked, OldAndNotRemembered)
             - Bits 8-11:  SizeTag (object size / alignment, 0 if large)
             - Bits 12-31: ClassId (kOneByteStringCid=93 or kTwoByteStringCid=94)
             - Bits 32-63: Hash (cached string hash)
Offset 0x08: [8 bytes] Length (SMI-tagged: actual_length << 1)
Offset 0x10: [variable] String data (1 byte per char for OneByteString)
```

Objects are aligned to 8 bytes.

### RODataSerializationCluster

The `RODataSerializationCluster` in `app_snapshot.cc` (line 3638) handles canonical strings for the root loading unit. Its `WriteFill()` method is a **no-op** - the actual string content is written directly to the data image by `ImageWriter::WriteROData()`.

The cluster stream only stores **offsets** into the data image (via `WriteAlloc`), not the string content itself. At deserialization time, `RODataDeserializationCluster::ReadAlloc()` reconstructs pointers by adding offsets to the mmap'd data image base.

### Compressed Pointer Mode (Different Layout!)

With compressed pointers enabled (`compressed-pointer` in flags):
```
Offset 0x00: [8 bytes] Object header
Offset 0x08: [4 bytes] Length (compressed SMI)
Offset 0x0C: [variable] String data
```

Strings in compressed-pointer snapshots are serialized inline in the cluster stream via `StringSerializationCluster`, NOT stored in ROData. Reliable `-z` now reports strings reached through decoded ObjectPool entries; fuzzy `-zz` still handles broad carving/triage.

### ROData Location

The ROData image follows the isolate snapshot data, aligned to `kMaxObjectAlignment` (16 bytes):
```
rodata_start = iso_data + align16(iso_snapshot_length)
```

The ROData section extends to the end of the `.rodata` (Android) or `__TEXT.__const` (iOS) section.

### CID Values Vary by Dart Version

| Dart Version | kOneByteStringCid | kTwoByteStringCid |
|--------------|-------------------|-------------------|
| 3.4.x        | 93                | 94                |
| 3.5.x - 3.10.x | 94              | 95                |

The r2flutter ROData scanner tries both the layout-specified CID and CID-1 to handle version mismatches with unknown hashes.

## References

- Dart SDK: `runtime/vm/clustered_snapshot.cc`, `runtime/vm/raw_object.h`, `runtime/vm/class_id.h`
- Dart SDK snapshot format: `runtime/vm/app_snapshot.cc` (Serializer::Serialize at line 8836, Deserializer::Deserialize at line 9721)
- Dart SDK ROData serialization: `runtime/vm/app_snapshot.cc` (RODataSerializationCluster at line 3638)
- Dart SDK image writing: `runtime/vm/image_snapshot.cc` (WriteROData at line 590)
- Dart SDK class table: `runtime/vm/class_table.h` (ClassTable, UnboxedFieldBitmap)
- Vyacheslav Egorov's Dart VM internals: https://mrale.ph/dartvm/
- Third-party tools: blutter, unflutter, reFlutter

## Dumper API Cleanup

The pool and function dumpers are easier to maintain when the public entrypoints take a single `int fmt` mode, matching `dart_pool_dump_it ()`, instead of growing parallel `_json` and `_r2` exports. The extraction pass stays shared, while the format-specific rendering lives in small helpers behind one API per dumper:

- `dart_pool_dump_header (ctx, fmt)`
- `dart_pool_dump_classes (ctx, fmt)`
- `dart_pool_dump_strings (ctx, fmt)`
- `dart_dumper_dump_funcs (app, fmt)`

This keeps the CLI and plugin call sites on the same mode switch (`0`, `'j'`, `'r'`) and avoids triplicating traversal logic every time a dumper gains a new field.

## Obfuscation Maps

Flutter obfuscation maps use the VM `--save-obfuscation-map` format: one JSON array with alternating `original, obfuscated` strings. r2flutter has to reverse that relation during analysis because the snapshot only carries the obfuscated side. Applying the rename map at identifier materialization points keeps string dumps faithful to the raw binary while still deobfuscating function, class, field, and method outputs.

## `r_str_newf ()` In This Tree Is Treated As Infallible

Local radare2 coding rules for this repo treat `r_str_newf ()` like `R_NEW`/`R_NEW0`: do not add `NULL` checks after the call. Cleanup in `flutter_analysis.c` can remove follow-up `if (!msg)` and `if (!flag_name)` branches when the only possible failure path was the `r_str_newf ()` allocation itself.

## Snapshot Hash Matching Should Use Exact String Equality

`dart_version_from_hash ()` matches canonical 32-character MD5 strings from `known_hashes[]`. Using `strncmp (..., 32)` there reads like a prefix test and would also accept a longer input whose first 32 bytes happen to match. `strcmp ()` is the clearer exact-match form for this table lookup.

## Minimal Offline Dart Runtime For Names

For Dart `3.8.1` ARM64 AOT with compressed pointers, the current raw `Function` scan offsets in `src/lib/dart_pool_parse.c` are not aligned with the SDK layout. The important corrected offsets are:

- `Function.entry_point = 0x08`
- `Function.code = 0x2c`
- `Function.kind_tag = 0x30`
- `Code.owner = 0x38`
- `Class.name = 0x08`
- `ClosureData.parent_function = 0x0c`

This is enough to justify a small read-only “REDART” layer inside `r2flutter`: parse tagged/compressed pointers, expose `Function`/`Code`/`Class`/`Library` accessors, port `String::ScrubName ()`, and then format names blutter-style. That gets us much closer to blutter’s semantics without embedding the Dart runtime or depending on the Dart toolchain.

## `offsets.json` Arm64 AOT Invariants

Re-checking the tagged SDK releases in `poc/dart-sdk/runtime/vm/compiler/runtime_offsets_extracted.h` shows that the arm64 AOT `Code` layout used by `offsets.json` is stable from Dart `2.10.0` through `3.10.7`:

- `Code.entry_point` candidates stay `[0x08, 0x18, 0x10, 0x20]`
- `Code.owner` stays `0x38`

The owner-name side also stays simple across those tags when cross-checking `runtime/vm/raw_object.h`:

- `Function.name = 0x18`
- `Class.name = 0x08`

That lets `offsets.json` grow by hash without inventing per-hash guesses: the missing hashes can all reuse the same source-backed arm64 AOT offsets, while `compressed_word_size` still follows the version/profile or the sample already recorded in-tree.

## Dart `3.8.1` Cluster Parser Fixes For Full Function Naming

Cross-checking `poc/unflutter-source/internal/cluster/*.go` against the current C parser exposed the real regressions behind the `-f` mismatch on `poc/app/libapp.so` and the Android `mafia` sample:

- object-header cluster tags use `CanonicalBit = 1`, not bit `0`
- clustered unsigned integers use the Dart VLE terminator rules (`byte > 127`, final contribution `byte - 128`)
- `Mint` alloc is not `count`-only: it is `count + count * ReadTagged64()`
- many predefined CIDs above `Instance` are **not** instance clusters; `Double`, `LibraryPrefix`, `Closure`, `Map`, `ConstMap`, `Set`, `ConstSet`, `GrowableObjectArray`, ports, and related runtime helper objects stay on simple/ref-based formats
- typed-data detection must only cover the real typed-data families (`TypedData`, `ExternalTypedData`, `TypedDataView`, and the internal `TypedDataInt8Array..ByteDataView` stride range), otherwise unrelated CIDs like `ConstMap` get misparsed as byte blobs
- `Type`, `FunctionType`, `RecordType`, and `TypeParameter` fill layouts for modern object-header snapshots were shifted/mismatched and must follow the version-specific CID table rather than older hard-coded assumptions

The naming side also needed one structural change borrowed from unflutter:

- prefer `Code.owner` -> `Function` resolution over `Function.code_index` as the primary binding from instruction-table slot to method name

That change fixes the main off-by-owner/name mismatches in practice. On the `mafia` sample it restores names like:

- `method.DateTime.compareTo`
- `method.DateTime.dyn:compareTo`
- `method._anon_closure`

Closure naming still needs the extra relation carried by `ClosureData`:

- `ClosureData.parent_function` is the snapshot-side link that lets a closure code object be rendered as `_anon_closure` instead of inheriting the parent function name verbatim

## Blutter Is Strictly Snapshot-Version Specific

**Finding**: The bundled Blutter executable in this checkout only matches Dart `3.8.1`, Android arm64, snapshot `830f4f59e7969c70b595182826435c19`.

The compatible `poc/app` sample runs successfully and produces object-pool dumps, IDA scripts, a Frida template, and 927 generated asm-backed Dart files. The generated files are useful as reconstructed navigation/disassembly, not as original Dart source.

The local Android fixtures under `test/bins` are real Flutter AOT samples but need different Blutter builds:

- `test/bins/android/first`: Dart `2.18.2`, snapshot `f91b8b03bf7f30a5e983fd19b23d978d`, no compressed pointers, expected executable name `blutter_dartvm2.18.2_android_arm64_no-compressed-ptrs`.
- `test/bins/android/mafia`: Dart `3.9.0`, snapshot `97ff04a728735e6b6b098bdf983faaba`, expected executable name `blutter_dartvm3.9.0_android_arm64`.

Directly running the Dart `3.8.1` executable on either fixture fails cleanly with `Wrong full snapshot version`. The iOS fixtures are Mach-O and are outside the current Blutter executable's ELF/Android support.

Follow-up testing showed that `mafia` works after building `blutter_dartvm3.9.0_android_arm64`, producing about `173M` of output and 1980 generated asm files. The older `first` fixture is stricter: even after building Dart `2.18.2` no-analysis/no-compressed-pointers Blutter binaries for both Android and a patched Linux VM target, Dart rejects the snapshot because the snapshot feature string requires `no-tsan arm64 linux no-compressed-pointers` while the local Dart VM reports `no-asserts arm64-sysv no-compressed-pointers no-null-safety`.

Rerunning the compatible `poc/app` target into a fresh directory produced the same file count and size. Byte diffs are mostly ASLR-dependent native/heap pointer values embedded in `pp.txt`, `objs.txt`, IDA structs, and asm comments; after normalizing those runtime addresses, representative app asm matched.

## R2R Extras Must Load The Local Core Plugin

The `test/db/extras` cases exercise the `r2flutter` command inside radare2, not only the standalone `bin/r2flutter` CLI. Running `r2r test/db/extras` from a checkout with no user-installed plugin leaves those commands unhandled, which looks like empty stdout instead of a parser failure. Keep the extras fixtures self-contained by loading `../src/r2/core_flutter.so` in their `CMDS` blocks, and make `make test-r2r` build `src/r2/core_flutter.so` before invoking r2r.

`r2flutter -AAA` can internally ask radare2 to create functions for recovered Dart entrypoints. Some entrypoints are already present in radare2's exact-address function table before they have blocks, so checking only `r_anal_get_fcn_in ()` can miss them and trigger noisy duplicate-function warnings from `af`. Check `r_anal_get_function_at ()` first and suppress warning-level logs around the internal `af` loop; the user-facing analysis summary should remain the only plugin log line.

## Radare2 Script Export Audit

Current r2 command export is split across the standalone `-R` script mode, the per-action `-r` renderers, and the in-r2 plugin's direct core mutations:

- [x] `bin/r2flutter -R` emits a loadable script header, `e emu.str=true`, `f app.base`, `f app.heap_base`, one `f method.* = addr` per recovered Dart function, and a `CC` comment at each method address with the recovered name.
- [x] `bin/r2flutter -R` also sets Dart's pool pointer view with `dr x27=\`e anal.gp\`` and `'f PP=x27`. The expensive per-function `pdj 96` PP-offset scan is skipped by default because large apps can have tens of thousands of recovered functions; use xref/analysis paths when pool-slot refs are needed.
- [x] `bin/r2flutter -r -f` emits only method flags and method-name comments. It does not create functions with `af`, assign calling conventions, or attach classes.
- [x] `bin/r2flutter -r -z` emits `# Dart Strings`, `iz+ addr len`, `f str.*`, and `Cs*` entries for reliable ObjectPool strings; use `-r -zz` to register fuzzy/carved strings.
- [x] `bin/r2flutter -r -H` emits snapshot flags (`f dart.vm_data`, `f dart.vm_instr`, `f dart.iso_data`, `f dart.iso_instr`, container flags when present) and `CC` comments for snapshot hash/version/tag-style/alignment metadata.
- [x] `bin/r2flutter -r -i` emits `f it.code_N = addr` / `f it.stub_N = addr` InstructionTable flags and `# it[N] name` comments.
- [x] `bin/r2flutter -r -x` emits human-readable xref comments and `f xref.* = dst_addr` flags for xrefs with concrete destination addresses. It does not currently emit `ax` commands.
- [x] `bin/r2flutter -r -c` and `-r -T` emit quoted C-like `td struct Name { ... };` commands, then append a class metadata script section.
- [x] The class metadata section emits `ic+Class @ 0` for each recovered class, `ic+Class.method @ addr` for every recovered method (`@ 0` when the entrypoint is unknown), `ic+Class..field type @ offset` for fields, and `ic+Class:Base` for superclass/interface edges, using dot-free sanitized names so `ic+` parsing is stable.
- [x] The class metadata section mirrors the same classes into r2 analysis classes with `ac Class`, adds concrete-address methods with `acm Class method addr`, and records extends/interfaces as hierarchy edges with `acb Class Base 0`.
- [x] Interfaces are exported as `ic+Class:Interface` class-table hierarchy edges, plus `acb` analysis-class edges and `# interface ... implements ...` comments.
- [x] Fields are represented by C-safe `td` struct members, `ic+Class..field type @ offset` entries, and `# field Class.field +offset type=... static/final/const/late` comments. Original Dart field types are preserved in comments and, for the plugin path, in `RBinField.type`.
- [x] Methods are exported to the script class section with `ic+Class.method @ addr`; concrete-address methods additionally get `acm Class method addr` and method comments. The class script does not emit `af`/`afc`, because that depends on functions already existing in the current r2 analysis state.
- [x] The generic Dart AOT dyncc string remains available in method comments: `dyncc:x0+8,^:x0` for static-like methods and `dyncc:x0+8,^:x0!T0` for methods that carry a Dart receiver. The `!T0` role follows `doc/dyncc.md`: instance-ness is represented by a T role, not by a separate static/instance mode.
- [ ] The generic Dart AOT dyncc string models the ARM64 value-register ABI (`x0..x7`, stack tail, `x0` return) but is not yet narrowed per recovered signature arity or optional/named argument shape.
- [x] Current r2 `td` parsing accepts quoted C-like struct definitions but not `struct.dart.Name`, member offsets (`@ 0x...`), generic types (`List<int>`), or function types (`(int) => String`) as field declarations. The renderer maps Dart fields to C-safe storage declarations and keeps Dart-specific type text out of the parser path.
- [x] The in-r2 plugin `r2flutter -C` path mutates the core directly: it adds Dart classes, methods, and fields to `RBinClass` for `ic`; mirrors classes/methods/bases into `RAnal` classes; registers struct types with `r_anal_save_base_type`; and replays the new `ic+` class-table commands so `ic` also records inheritance and field/method additions through the same command surface as standalone scripts.

## Parser Split Boundaries

The modern object-header cluster naming code now lives in `src/lib/dart_pool_modern.c`. Snapshot header parsing, Dart unsigned decoding, UTF-16 decoding, bounded memory reads, and the shared cluster stream reader live in `src/lib/dart_pool_snapshot.c`. Snapshot discovery lives in `src/lib/dart_pool_discovery.c`. Code-name and name-pool discovery lives in `src/lib/dart_pool_names.c`. String extraction and string dump formatting live in `src/lib/dart_pool_strings.c`. Raw data-image `Field` / `Function` object scanning lives in `src/lib/dart_pool_data_image.c`. InstructionTable fixed/varint/linear decoding lives in `src/lib/dart_pool_it.c`. Cross-reference collection and dump formatting lives in `src/lib/dart_pool_xrefs.c`. Legacy clustered snapshot decoding lives in `src/lib/dart_pool_clusters.c`. Class extraction, enum recovery, and class dump formatting live in `src/lib/dart_pool_classes.c`. These are intentionally separated from the public parser API through `src/lib/dart_pool_parse_priv.h`.

Keep future splits on the same boundary: move whole parser subsystems behind private headers first, then reduce the remaining orchestration in `dart_pool_parse.c`. The remaining parser file should mostly be public API orchestration and header rendering.

## Recovery Model Boundary

Fast extractors should stay pure: `dart_pool_extract_strings ()` extracts
strings, `dart_pool_extract_classes ()` extracts class metadata, and neither
should call the other just to enrich an output view. Cross-feature joins now go
through the private `DartRecoveryModel`, which owns the loaded strings, classes,
instruction-table entries, and shared indexes by string value/address,
class name, and method entrypoint.

That boundary keeps output features from becoming recursive parsers. String
reverse references, xrefs, and plugin analysis can consume the same model while
slow code analysis remains an explicit layer on top.

## Modern AOT Function Names And VM Base Symbols

Dart AOT `Function.code_index` values are serialized one-based: `0` is reserved for the lazy-compile stub, and non-zero values must be converted to the zero-based `InstructionsTable` slot with `code_index - 1`. Using the raw value as a slot lets a later function fallback name bleed into the next instruction-table entry; on the Android `mafia` fixture this made both `0xe12220` and `0xe122a8` render as `_Double._greaterThan`.

Modern isolate snapshots also refer to VM-snapshot base objects for predefined symbols. Operator method names such as `+` and `>` may therefore live in the VM data snapshot, not in the isolate string clusters. Populate base `strings_by_ref` entries from the VM snapshot's string cluster before resolving isolate `Function.name` refs, then normalize operator symbols to stable names like `op_add` and `op_gt`.

VM base strings can also expose `::` for top-level function owners. Treat that placeholder as an empty owner when rendering names; otherwise top-level functions and closures become noisy names like `method.::._anon_closure`.

## Cleanup Invariants

The project assumes radare2 list constructors (`r_list_new` / `r_list_newf`) do not return `NULL`, and `r_list_free` accepts `NULL`. Keep parser cleanup code aligned with that contract: do not add constructor null checks or wrap list frees unless a caller needs to skip other dereferences.

The fallback class-name scanner reads fixed-size chunks that are not guaranteed to be null-terminated. Only inspect `buf[slen]` when `slen < to_read`; printable runs that reach the end of a chunk should be skipped until a delimiter is observed instead of reading past the buffer.

Validate the CLI obfuscation map only after `dart_app_new_from_core ()` copies the initial `DartCtx`; loading it before that copy would share one hash table across two independently finalized contexts. After validation, keep the map loaded in the context that will use it instead of immediately forcing a second lazy parse.

Modern object-header cluster helpers run only after `dart_modern_is_supported_snapshot ()` succeeds. Past that public gate, `ctx`, `ctx->layout`, and compressed 32-bit pointer mode are invariants for `src/lib/dart_pool_modern.c`, so private CID accessors should read layout fields directly and stay `static inline`. Keep null/layout fallback checks on the public gate, not inside every CID comparison or fill-skip path.

## 2026-06-01: Class and Field Cluster Recovery

Modern Dart AOT Class and Field metadata is not available in the alloc phase.
`ClassSerializationCluster::WriteAlloc` only assigns refs and writes class IDs;
`FieldSerializationCluster::WriteAlloc` only assigns refs. Names, owners,
instance sizes, method refs, field kind bits, and field offset refs are emitted
later in `WriteFill`. A parser that tries to decode fields during alloc will
desynchronize and eventually fall back to string-only class names.

For compressed ObjectHeader snapshots (`cws=4`, e.g. Android mafia / Dart
3.9.2), `dart_modern_extract_classes_from_clusters ()` now walks the alloc
section to collect cluster ref ranges and Smi/Mint values, then walks fill to
recover Class, Field, Function, and String metadata. This populates `ic` with
real class members and avoids the old `0fields` class-only result.

Non-compressed ObjectHeader snapshots (`cws=8`, e.g. Android first and the iOS
sample) still need a separate ROData string/ref path. Until that exists, the
class extractor skips the legacy alloc-phase decoder and reports string-based
fallback classes explicitly instead of logging bogus huge CIDs.

## Extended Header Cluster Walk

`-HH` is the structural form of `-H`: it prints the normal AOT header and then walks
the VM and isolate cluster allocation streams. Each cluster row records the CID,
allocation kind, fill kind, object count, ref range, allocation/fill byte ranges,
canonical/immutable flags, and small length aggregates for variable-sized
clusters. JSON mode mirrors this as `snapshots[].clusters[]`.

`-HHH` enables selected payload diagnostics on top of that same walk. The first
target is `ObjectPool`: when the fill range is parsed, it decodes entry bits,
entry type, patchability, snapshot behavior, raw immediates or target refs, and
both `pool_off`/`pp_off` annotations. Tagged-object entries are now resolved
back through the cluster table when possible, so text/JSON/r2 output can include
`resolved_kind`, `resolved_cid`, `resolved_name`, and function `code_index`
fields for strings, functions, classes/libraries, and other known cluster
kinds. If an `ObjectPool` allocation is visible but a prior incomplete fill rule
prevents reaching its payload, the row reports `object_pool_decode:
fill_not_parsed` instead of pretending entries are known. This keeps the
PP/ObjectPool work inspectable and feeds the focused `-p` path.

`-p` now builds a synthetic static ObjectPool image from the decoded fill stream
when the parser can reach a concrete ObjectPool payload. Plain quiet output is
the address pair (`vaddr=0x100000000 paddr=...` in current builds). JSON output
marks the result as `kind=synthetic` and reports top-level `vaddr`/`paddr`, plus
the source cluster/ref/length. `-r -p` emits a radare2 setup script that maps the
synthetic image with `o malloc://`, writes it with `wx`, and sets both
`e anal.gp` and `dr x27` to the synthetic `vaddr`.

The runtime PP value itself is not serialized in the snapshot. Dart's VM creates
the live object pool during deserialization, so tagged entries that point to heap
objects cannot be assigned real heap addresses statically. The synthetic image
preserves pool length, entry bits, and immediate values, while unresolved tagged
object/native entries remain zero placeholders until deeper object materialization
exists. The reported `paddr` is the serialized ObjectPool fill payload backing
the reconstruction, not a live runtime pool mapping. This is why `-p` is useful
for setting up PP-relative analysis shape but should not be described as a
recovered live `x27` value.

ObjectHeader cluster tags are still Dart signed-VLE `ReadTagged32 ()` values;
`no-compressed-pointers` changes object payload layout, not the cluster tag
encoding. For full-width AOT snapshots, string clusters are ROData-backed:
allocation contains offset deltas into the data image and fill consumes no
inline string bytes. Treating those deltas as inline string lengths shifts the
fill cursor immediately.

The extended header view is diagnostic, so it should keep the allocation walk
visible even when a later fill rule is incomplete for an unknown hash. Mark the
first failed cluster with `fill_status=failed` and leave later clusters as
`fill_status=not_parsed` instead of collapsing the whole section to
`unsupported`.

## RVec Conversion Boundaries

Use `RVec` for hot arrays of plain records or records with simple per-element finalizers. `DartApp.functions`, instruction-table entries, and local address/offset collector arrays fit this model because iteration is linear and callers do not require stable heap object addresses.

Do not convert clustered `ctx->strings`, `ctx->classes`, and `ctx->functions` blindly: `ctx->refs` stores object pointers into those decoded records. Moving those records into a growing vector would invalidate pointers on reallocation unless the parser first reserves a stable capacity or changes `ctx->refs` to store indexes.

## Dart VM CID Tables

Dart VM predefined CIDs are deterministic for one SDK build, but they are not a stable cross-version ABI. The numeric values come from the ordered `CLASS_LIST` macros in `runtime/vm/class_id.h`, so inserting or removing a VM class shifts later IDs. For example, `Library` is `12` in Dart 2.14 but `13` in Dart 2.15+, while `Namespace` is `13` in Dart 2.14. Avoid global constants such as `kLibraryCid` when parsing versioned snapshots.

Use the shared `dart_cid_get ()` / `DartCidKind` API as the source of truth for named CIDs. In hot cluster walks, resolve the version table once before entering the loop and compare cached `const int` values instead of calling the generic lookup for every object or cluster.

| Dart VM | PatchClass | Library | Namespace | Code | ObjectPool | Array | String | OneByteString | NumPredefined |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| 2.10.0 | 5 | 13 | 14 | 16 | 20 | 78 | 80 | 81 | 156 |
| 2.13.0 | 5 | 11 | 12 | 15 | 18 | 75 | 77 | 78 | 148 |
| 2.14.0 | 5 | 12 | 13 | 16 | 20 | 79 | 81 | 82 | 152 |
| 2.15.0 | 6 | 13 | 14 | 17 | 21 | 79 | 82 | 83 | 153 |
| 2.19.0 | 6 | 13 | 14 | 17 | 21 | 89 | 92 | 93 | 176 |
| 3.0.5 | 6 | 13 | 14 | 18 | 22 | 90 | 93 | 94 | 177 |
| 3.4.3 | 6 | 13 | 14 | 18 | 22 | 89 | 92 | 93 | 174 |
| 3.10.7 | 6 | 13 | 14 | 18 | 23 | 90 | 93 | 94 | 175 |

## String Xrefs In R2 Scripts

`-z -r -x` and `-zzrx` emit `ax` commands for string references after registering the recovered strings. ObjectPool string references use the reconstructed synthetic PP address space (`0x100000000 + pp_off`), matching the `-r -p` PP mapping. Metadata-only references that have an object ref but no concrete file address use a synthetic object-ref namespace (`0x200000000 + object_ref`) so r2 can still carry the relation as an xref.
