# Dart AOT Object Pool Internals

This document explains the internal structure of Dart AOT (Ahead-of-Time) compiled binaries, focusing on the Object Pool and clustered snapshot format used in Flutter applications.

## Overview

When Flutter compiles a Dart application for release, it uses AOT compilation to generate native machine code. The resulting binary contains two main components:

1. **Snapshot Data** - Serialized Dart objects (strings, classes, functions, constants)
2. **Snapshot Instructions** - Native machine code for all compiled functions

The Object Pool is the runtime data structure that holds references to all Dart objects needed during execution. Understanding its serialization format is key to reverse engineering Flutter apps.

## Binary Layout

### Android (libapp.so)

```
ELF Header
├── .rodata section
│   ├── _kDartVmSnapshotData        (VM isolate data)
│   ├── _kDartIsolateSnapshotData   (App isolate data) ← Object Pool lives here
│   └── _kDartIsolateSnapshotInstructions (App code)
└── .text section
    └── _kDartVmSnapshotInstructions (VM code)
```

### iOS (App.framework/App)

```
Mach-O Header
├── __DATA segment
│   ├── _kDartVmSnapshotData
│   └── _kDartIsolateSnapshotData   ← Object Pool lives here
└── __TEXT segment
    ├── _kDartVmSnapshotInstructions
    └── _kDartIsolateSnapshotInstructions
```

## Snapshot Header Format

Every Dart snapshot begins with a fixed header:

```
Offset  Size    Field
──────────────────────────────────────────────────────
0x00    4       Magic number (0xf5f5dcdc, little-endian)
0x04    8       Length (total size minus magic, int64)
0x0C    8       Kind (snapshot type, int64)
0x14    32      Version hash (ASCII hex string, NOT null-terminated)
0x34    N       Features string (null-terminated)
```

### Snapshot Kinds

| Value | Name       | Description |
|-------|------------|-------------|
| 0     | kFull      | Full snapshot with all objects |
| 1     | kFullCore  | Core libraries only |
| 2     | kFullJIT   | JIT compilation snapshot |
| 3     | kFullAOT   | AOT compilation snapshot (Flutter release) |
| 4     | kModule    | Deferred module snapshot |

### Features String

The features string describes build configuration:
```
product no-code_comments no-dwarf_stack_traces_mode no-lazy_dispatchers 
dedup_instructions no-tsan arm64 ios no-compressed-pointers null-safety
```

Key flags:
- `product` - Release build (no debug info)
- `no-compressed-pointers` - Uses full 64-bit pointers (pre-2.18 or iOS)
- `compressed-pointers` - Uses 32-bit compressed pointers (Dart 2.18+)
- `null-safety` - Null safety enabled

## Clustered Data Format

After the header comes the clustered serialization data. This is the heart of the Object Pool.

### Clustered Header

Immediately after the features string's null terminator:

```
Field                          Encoding
───────────────────────────────────────────
num_base_objects               ULEB128
num_objects                    ULEB128
num_clusters                   ULEB128
instructions_table_len         ULEB128
instruction_table_data_offset  ULEB128
```

**ULEB128** (Unsigned Little-Endian Base 128) is a variable-length integer encoding:
- Each byte's lower 7 bits contain data
- High bit (0x80) indicates more bytes follow
- Example: `0x89 0x43` decodes to `0x09 | (0x43 << 7) = 8585`

### Cluster Structure

The snapshot contains `num_clusters` cluster entries, each representing a group of related objects:

```
┌─────────────────────────────────────┐
│ Cluster Tag (uint32)                │
├─────────────────────────────────────┤
│ Object Count (ULEB128)              │
├─────────────────────────────────────┤
│ Alloc Data (cluster-specific)       │
├─────────────────────────────────────┤
│ Fill Data (cluster-specific)        │
└─────────────────────────────────────┘
```

### Cluster Tag Encoding

The 32-bit cluster tag encodes multiple fields:

```
Bits     Field
─────────────────────────────────
0        CanonicalBit (object is canonical/interned)
1        DeeplyImmutableBit
2-7      Reserved flags
8-11     SizeTag (4 bits, encoded object size)
12-31    ClassId (20 bits, identifies object type)
```

To extract the Class ID:
```c
uint32_t cid = (tag >> 12) & 0xFFFFF;
```

## Two-Phase Deserialization

Dart uses a two-phase approach for snapshot deserialization:

### Phase 1: Alloc (Allocation)

During the Alloc phase:
1. Read the cluster tag to identify the object type
2. Read the object count
3. Allocate memory for each object
4. Assign sequential **reference IDs** starting from `num_base_objects + 1`

Reference IDs are indices into a global array that allows objects to reference each other before they're fully initialized.

```
Reference Array Layout:
┌───────────────────────────────────────────────────┐
│ Index 0: Reserved (unreachable sentinel)          │
├───────────────────────────────────────────────────┤
│ Index 1 to num_base_objects: VM base objects      │
├───────────────────────────────────────────────────┤
│ Index num_base_objects+1 onwards: App objects     │
└───────────────────────────────────────────────────┘
```

### Phase 2: Fill

During the Fill phase:
1. Read actual field values for each object
2. Resolve reference IDs to actual object pointers
3. Initialize object contents

This two-phase approach handles circular references - objects can reference each other because all objects are allocated (with known reference IDs) before any fields are filled.

## Class IDs (CIDs)

Dart has predefined Class IDs for built-in types:

| CID | Class |
|-----|-------|
| 0   | kIllegalCid (invalid) |
| 5   | kClassCid |
| 7   | kFunctionCid |
| 10  | kFieldCid |
| 12  | kLibraryCid |
| 40  | kCodeCid |
| 45  | kObjectPoolCid |
| 72  | kStringCid |
| 73  | kOneByteStringCid |
| 74  | kTwoByteStringCid |
| 75  | kArrayCid |

CIDs above ~128 are dynamically assigned to user-defined classes.

## String Serialization

Strings are among the most important objects for reverse engineering.

### Encoding

String length and type are combined in a single ULEB128:
```
encoded = (length << 1) | is_two_byte
```

- Bit 0: 0 = OneByteString (Latin-1), 1 = TwoByteString (UTF-16)
- Bits 1+: String length

### OneByteString Layout

```
┌────────────────────────────────────┐
│ Object Header (tags, etc.)         │
├────────────────────────────────────┤
│ Length (Smi - tagged integer)      │
├────────────────────────────────────┤
│ Hash (cached, computed on demand)  │
├────────────────────────────────────┤
│ Character data (1 byte per char)   │
└────────────────────────────────────┘
```

### TwoByteString Layout

Same as OneByteString but character data uses 2 bytes per character (UTF-16 encoding).

## Function and Code Objects

### Function Object

Represents a Dart function with metadata:
- `name_` → Reference to String (function name)
- `owner_` → Reference to Class or Library
- `signature_` → Reference to FunctionType
- `code_` → Reference to Code object (in JIT) or code index (in AOT)

### Code Object

Represents compiled machine code:
- `entry_point_` → Address of function's first instruction
- `owner_` → Back-reference to Function
- `object_pool_` → Reference to ObjectPool for this code
- `instructions_` → Pointer to actual machine code bytes

In AOT snapshots, Code objects reference entries in the InstructionsTable rather than storing instructions inline.

## InstructionsTable

The InstructionsTable maps function indices to code entry points. It's stored in the Data Image (rodata section).

### Fixed-Size Format

```
Header:
  length:           uint32 (total entries)
  first_with_code:  uint32 (first entry with actual code)

Entries[length]:
  pc_offset:        uint32 (offset from instructions base)
  source_map_off:   uint32 (offset to source map data)
```

### Variable-Length Format (Delta-Encoded)

Some snapshots use LEB128 delta encoding for smaller size:

```
header_len:        ULEB128
first_with_code:   ULEB128

Entries[header_len]:
  pc_delta:        ULEB128 (delta from previous pc_offset)
  sm_delta:        ULEB128 (delta from previous source_map_off)
```

To decode: accumulate deltas starting from 0.

## Compressed Pointers

Since Dart 2.18, object references use 32-bit compressed pointers instead of full 64-bit addresses.

### How It Works

```
Compressed:   32-bit offset from heap base
Absolute:     heap_base + (compressed_ref << alignment_shift)
```

The heap base is stored in a dedicated register (x27/PP on ARM64).

### Benefits

- ~30% smaller binary size
- Faster object access (single register + offset)
- Better cache locality

### Detection

Check the features string for `compressed-pointers` or `no-compressed-pointers`.

## Data Image Layout

After the snapshot stream comes the Data Image, containing read-only data:

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

## Practical Extraction

### Finding Snapshots

1. **By symbol name**: Look for `_kDartIsolateSnapshotData`
2. **By magic scan**: Search for `0xf5f5dcdc` in rodata sections

### Extracting Strings

1. Parse snapshot header
2. Skip to clustered data
3. Find String clusters (CID 72, 73, or 74)
4. Decode string objects

### Extracting Functions

1. Parse InstructionsTable from Data Image
2. Each entry's `pc_offset` + `iso_instr` = function entry point
3. Match with Function objects to get names

### Building Call Graphs

1. Disassemble each function
2. Find `bl` (branch-link) instructions
3. Resolve targets via InstructionsTable indices
4. Map indices to Function names

## Version Differences

Different Dart/Flutter versions may have:

- Different cluster tag encoding
- Different object layouts
- Different CID assignments
- Compressed vs uncompressed pointers

The 32-byte version hash in the header identifies the exact Dart SDK version. Tools should maintain a database of known layouts per version hash.

## References

- Dart SDK source: `runtime/vm/clustered_snapshot.cc`
- Snapshot header: `runtime/vm/snapshot.h`
- Class IDs: `runtime/vm/class_id.h`
- Object layouts: `runtime/vm/raw_object.h`
- Vyacheslav Egorov's Dart VM internals: https://mrale.ph/dartvm/

## Tools

- **r2flutter**: radare2-based Flutter/Dart analyzer (this project)
- **blutter**: Uses actual Dart VM for deserialization
- **unflutter**: Pure static analysis without VM dependencies
- **reFlutter**: Runtime patching and traffic interception
