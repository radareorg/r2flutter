# Discoveries and Technical Findings

This document summarizes key technical findings discovered during the implementation of class extraction features in r2flutter.

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
