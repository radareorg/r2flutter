# Discoveries and Technical Findings

This document summarizes key technical findings discovered during the implementation of class extraction features in r2flutter.

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

**Implication**: `--dump-strings` can recover some of these today with non-NUL-delimited text scanning, but complete support should come from snapshot-aware string-cluster decoding rather than classic C-string assumptions.

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

## `--use-name-pool` Must Stay Opt-In

**Finding**: The name-pool fallback is useful for exploratory reversing, but it is too weak to enable by default because it can silently mislabel functions.

Current behavior:

- `collect_data_names ()` scans the data image for `package:` and `dart:` strings and stores them in discovery order
- `resolve_it_entry_name ()` only consults that pool after exact symbol, entrypoint, and stack-map-based naming fails
- when enabled, unresolved code entries consume names sequentially via `name_pool_idx++`

Why this is risky:

- there is no proof that pool index `N` belongs to instruction-table entry `N`
- one early mismatch shifts all later fallback names
- the resulting names look plausible enough to be mistaken for confirmed metadata

Use `--use-name-pool` for manual triage only. The default synthetic `method.fn_*` names are intentionally less informative, but more honest.

## Enum Recovery In `--dump-types` Is Heuristic But Useful

**Finding**: Production AOT samples still do not expose enough `Class` metadata to recover enum declarations directly, but enum names and variants often survive as qualified strings such as `AppLifecycleState.resumed` plus a matching `AppLifecycleState.` marker.

`--dump-types` now supplements the existing type-name scanner with a conservative enum inference pass over extracted strings:

- require a trailing `EnumName.` marker
- require at least two lowercase `EnumName.value` strings
- score candidates so enum-shaped type names like `...State`, `...Action`, `...Mode`, `...Direction`, `...Alignment`, and `...Affinity` are preferred
- reject obvious factory-style false positives such as `Future.value`, `List.from`, and similar constructor-heavy APIs

This recovers real enums in the shipped fixtures on both platforms, for example `AppLifecycleState` on iOS and Android, and `TextInputAction` on the Android `mafia` sample.

## Dump Header JSON Superset

**Finding**: `-j --dump-header` emits the same snapshot/cluster fields as the old dump-snapshot JSON, plus layout metadata (version, tag style, CID table).

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

**Finding**: `--dump-it` should be treated like the other dump commands, not as a stderr-only debug side effect.

The command now:

- writes to stdout
- honors `-j` for JSON
- honors `-r` for radare2 flags
- honors `--limit` for manageable output on large apps

The parser also needs a wider scan than the raw `it_off` hint on some iOS samples, because the offset can land inside the table payload rather than exactly on the `InstructionsTable::Data` header.

## Plugin String Dump Flag Uses Lowercase `-s`

**Finding**: The radare2 plugin now uses `r2flutter -s` for JSON string dumping instead of `r2flutter -S`.

This keeps the short command set lowercase for string-oriented output (`-s` JSON, `-t` r2 comments) and avoids carrying an unnecessary uppercase-only alias in the plugin help and parser.

## r2r Coverage Needs Short Cross-Platform Windows

**Finding**: The `test/db/cmd` suite is more maintainable when every dump mode is exercised on both Android and iOS using short deterministic windows instead of full dumps.

The current matrix covers `--dump-header`, `--dump-funcs`, `--dump-it`, `--dump-strings`, `--dump-classes`, and `--dump-types` against `test/bins/android/first` and `test/bins/ios/Runner.app`, using `--limit` or `sed -n` to keep expectations stable and fast.

This avoids brittle megabyte-scale expectations while still checking platform-specific snapshot addresses, instruction table metadata, and representative function/class/type/string prefixes.

## Stub Symbols Should Stay With RBin

**Finding**: Loader-provided ELF/Mach-O stub symbols do not add useful Flutter-specific signal, because radare2 already exposes them through `RBin`.

`r2flutter` now skips those stubs by default in `--dump-funcs` and analysis output, which keeps the plugin focused on Dart-derived names and makes function-dump tests line up with the augmented data we actually recover.

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

This produces clean `--dump-strings` output even when the clustered snapshot contains compressed or stripped string objects, while also giving analysts a quick way to filter out VM noise and focus on app-facing literals like `"Hello, Dart!"`.

## `--dump-strings` Must Stay Inside Dart Snapshot Windows

**Finding**: Letting the string dumper scan every readable section regresses badly on iOS once Mach-O `__text`, code stubs, cert blobs, and loader metadata are included in the candidate set.

The practical fix is:

- prefer snapshot-bounded windows (`vm_data` up to the next snapshot, and similarly for `iso_data` when applicable)
- keep the broad fallback limited to read-only constant sections such as Mach-O `__const` / `__cstring` and ELF `.rodata` / `.data.rel.ro`
- keep short-string heuristics strict enough to drop opcode-shaped junk like `_X;,` while preserving real Dart identifiers like `_Set`

This removes the worst false positives from `--dump-strings` without sacrificing the real Dart names stored in the const area of the shipped iOS and Android fixtures.

## Cross References Split Into Metadata, Data-Image, And Code Layers

**Finding**: Not all useful Dart snapshot xrefs come from the same place.

There are three distinct layers:

- **snapshot metadata xrefs**: serialized ref-id links such as `Class.name_ref`, `Class.library_ref`, `Class.super_class_ref`, `Field.owner_ref`, `Field.name_ref`, and `Field.type_ref`
- **data-image object xrefs**: raw `Function` and `Field` objects that can still be scanned in release builds even when full class metadata is missing
- **code xrefs**: object-pool loads, field-offset accesses, and call edges that only appear in disassembly

Practical implication:

- `object -> name/owner/super` style links are often dumpable from the binary without disassembly
- `function uses string/class/field/method` style links generally require code analysis

Current gaps:

- `DartStringInfo.references` exists but is not populated yet, so reverse `string -> metadata users` xrefs are still missing
- object-pool offsets can be collected from code, but pool entries are not decoded yet, so `code -> string/class/field/method` xrefs are not end-to-end
- library URI resolution and `Field.type_ref` name resolution are still incomplete

The repo now exposes the currently recoverable subset through:

- CLI: `--dump-xrefs`
- radare2 plugin: `r2flutter -x`

The new dumper intentionally stops at metadata/data-image edges. Disassembly-derived object-pool xrefs and call/use edges are still future work.

## `r2flutter -a` Uses Live `RCore` Metadata But Keeps PP Resolution Conservative

**Finding**: The new plugin-side analysis pass now runs inside the already loaded `RCore` session, reuses the current function/flag state, normalizes tagged Dart entrypoints to executable addresses, and scans analyzed ARM64 ops to recover:

- direct call xrefs
- string/class/field/type refs when the target can be tied back to known metadata or live flags
- PP (`x27`) slot-use comments such as `dart: PP slot +0x530`

This closes part of the old "metadata only" gap for code xrefs without pretending we can fully decode every object-pool entry yet.

Important current limitation:

- the shipped samples do not populate `anal.gp`, and the repo still does not decode object-pool entries end-to-end
- so `-a` can reliably annotate PP-relative slot usage and indirect-call breadcrumbs, but not yet resolve every `PP+imm` load into a final string/class/method object

## Recovering Methods Without Class Clusters

Production snapshots omit the `Class` cluster, but `Function` objects are still serialized in the ROData image. r2flutter now scans the data image for objects whose CID equals `cid_function` and extracts:

- Entry point (validated against the isolate instructions region)
- Symbolic name strings
- Owning class pointers to recover class names
- `kind_tag` values to classify constructors/getters/stubs

Functions whose owner names resolve to discovered classes are attached to the matching class in both JSON and r2 outputs. We deduplicate functions by entry point and cap the scan at 30k methods to keep processing bounded.

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

Class names, method names, and field names are **never completely removed** - they are required for VM runtime type checking, dynamic dispatch, and GC.

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

Strings in compressed-pointer snapshots are serialized inline in the cluster stream via `StringSerializationCluster`, NOT stored in ROData. The `--dump-strings` feature currently does NOT extract strings from compressed-pointer binaries' cluster streams.

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

Flutter obfuscation maps use the VM `--save-obfuscation-map` format: one JSON array with alternating `original, obfuscated` strings. r2flutter has to reverse that relation during analysis because the snapshot only carries the obfuscated side. Applying the rename map at identifier materialization points keeps `--dump-strings` faithful to the raw binary while still deobfuscating function, class, field, and method outputs.
