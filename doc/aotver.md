## Version Identification in Dart/Flutter AOT Snapshots

### The Snapshot Hash (Checksum)

**What it is**: A **32-byte ASCII MD5 hash** (Snapshot_hash) generated at compile time using the `make_version.py` script in the Flutter Engine source . This hash is **not of the binary itself**, but rather a hash representing the **Dart VM version and snapshot format**.

**Where it's stored**:
- **Android**: In `libapp.so` (the AOT snapshot) and `libflutter.so` (the Flutter engine)
- **iOS**: In `App.framework/App` and `Flutter.framework/Flutter`
- **Purpose**: Runtime compatibility checking between the engine and the snapshot

### How Tools Associate Hash with Version

#### 1. **reFlutter's Approach: Static CSV Table**
reFlutter uses a manually maintained **`enginehash.csv`** file that maps:
- `Snapshot_hash` → `Engine_commit` → Flutter version → Dart version 

Example from their table:
```csv
Flutter_Version, Engine_commit, Snapshot_hash
2.10.0, 5f105a6ca7a5ac7b8bc9b241f4c2d86f4188cf5c, d56742caf7b3b3f4bd2df93a9bbb5503
```

**Update mechanism**: The table is **periodically updated manually** when new Flutter versions are released. If a hash isn't found, the tool reports "Engine not supported" .

#### 2. **unflutter's Approach: Constraint-Based Version Detection**
unflutter uses a **different philosophy** - it doesn't rely on a downloadable table. Instead:

- The **version hash in the snapshot header** selects a **constraint set** (CID table, tag encoding, pointer compression rules) 
- Version-specific data is **statically defined in code** as version profiles:
  - Dart 2.10.0: CID-Int32, Uncompressed pointers, 4 header fields
  - Dart 2.18.0: CID-Shift1, Compressed pointers, Signed refs
  - Dart 3.4.3+: ObjectHeader, Compressed, Record types 

**Key insight**: unflutter proves you can **statically define all version constraints** without runtime downloads because the snapshot format changes are deterministic and versioned.

#### 3. **Blutter's Approach: SDK Compilation**
Blutter **compiles the matching Dart SDK** for each version:
- Detects version hash from snapshot
- Downloads/checkout the exact Dart SDK source for that version
- Builds the VM library to parse the snapshot 

This is the most accurate but slowest approach.

---

## What Data is Version-Associated?

### Version-Specific Data Structures

| Component | Version-Dependent? | Description |
|-----------|-------------------|-------------|
| **Snapshot Header** | Yes | Magic (0xf5f5dcdc), version hash (32 bytes), feature flags |
| **CID Table** | Yes | Maps Class IDs to cluster handlers; changes per version |
| **Tag Encoding** | Yes | How object tags are packed (CID-Int32, CID-Shift1, ObjectHeader) |
| **Pointer Compression** | Yes | 32-bit vs 64-bit references (introduced in 2.18.0) |
| **Cluster Grammar** | Yes | How alloc/fill phases encode object fields |
| **THR (Thread) Fields** | Yes | Offset maps for thread-local storage access |
| **Instruction Layout** | Partial | Stubs vs code regions, entry point formats |

### Static vs Dynamic Definition

**You can statically define everything.** Here's why:

1. **The version hash is in the snapshot itself** - you read it directly from the binary at a known offset
2. **Format changes are versioned** - Dart uses semantic versioning, and snapshot format changes happen at specific version boundaries
3. **Constraint sets are finite** - unflutter demonstrates this by having version profiles for every major Dart version from 2.10.0 to 3.10.7 

### Version Hash Location in Binary

```
Snapshot Header Structure:
[0x00-0x03] Magic: 0xf5f5dcdc
[0x04-0x23] Version Hash: 32-byte ASCII (e.g., "d56742caf7b3b3f4bd2df93a9bbb5503")
[0x24-...] Feature flags, pointer size, etc.
```

---

## Recommendation for Your Implementation

### Option 1: Static Constraint Tables (Recommended)
Like unflutter, define version constraints statically:

```go
// Example version profile structure
var VersionProfiles = map[string]VersionProfile{
    "d56742caf7b3b3f4bd2df93a9bbb5503": {
        DartVersion:      "2.16.0",
        TagStyle:         "CID-Shift1",
        PointerSize:      8,  // Uncompressed
        HeaderFields:     5,
        CIDTable:         Pre210CIDTable,
        ClusterHandlers:  Pre210ClusterHandlers,
    },
    "1441d6b13b8623fa7fbf61433abebd31": {
        DartVersion:      "2.17.0",
        TagStyle:         "CID-Shift1", 
        PointerSize:      4,  // Compressed pointers
        HeaderFields:     5,
        CIDTable:         Post218CIDTable,
        ClusterHandlers:  Post218ClusterHandlers,
    },
}
```

### Option 2: Hybrid Approach
- **Static**: Core constraint tables for known versions
- **Dynamic**: Download new version profiles when encountering unknown hashes (rare, only for bleeding-edge Flutter versions)

### Where to Get Version Data

1. **hadysata/flutter-versions** repo: Comprehensive table of Flutter version ↔ Dart version ↔ Snapshot hash ↔ Engine commit 
2. **mildsunrise/darter/info/versions.md**: Historical snapshot hash reference 
3. **Google Storage**: `storage.googleapis.com/flutter_infra_release/flutter/<engine_commit>/` for engine artifacts 

### Critical Files in Dart SDK Source

If you need to extract version-specific logic from the Dart SDK source :
- `runtime/vm/clustered_snapshot.cc`: Serialization/deserialization logic
- `runtime/vm/raw_object.h`: Object tag definitions per version
- `runtime/vm/object.cc`: Class ID assignments

---

## Summary

**You do NOT need to download anything at runtime.** The version hash in the snapshot header (32-byte ASCII at offset 0x04) maps to a finite set of constraint profiles that can be statically defined. unflutter proves this works for all Dart versions from 2.10.0 to 3.10.7 without any runtime SDK compilation or network downloads .

The only time you'd need dynamic updates is when Flutter releases a new version with breaking snapshot format changes - which happens infrequently and follows a predictable release cycle (stable, beta, dev channels) .

---

## r2flutter Implementation

r2flutter implements Option 1 (Static Constraint Tables) from this document. The implementation in `src/lib/dart_pool_parse.c` includes:

### Hash-to-Version Mapping
- 40+ known snapshot hashes from Flutter 1.22.x (Dart 2.10.0) to Flutter 3.38.x (Dart 3.10.7)
- Sources: unflutter version.go, reFlutter enginehash.csv, blutter precompiled SDKs

### Version Profiles
Each supported Dart version has a profile with:
- Tag encoding style (CID-Int32, CID-Shift1, ObjectHeader)
- Header field count (4-6 depending on version)
- CID table mapping (Class, Function, Code, String, Array, etc.)
- Compressed pointer configuration
- Number of predefined CIDs

### Supported Versions
| Dart Version | Tag Style | Notes |
|--------------|-----------|-------|
| 2.10.0 | Int32 CID | Pre-FunctionType, single cluster loop |
| 2.13.0 | Int32 CID | Split canonical/non-canonical clusters |
| 2.14.0-2.17.6 | CID Shift1 | `(cid << 1) \| canonical` |
| 2.18.0-3.3.0 | CID Shift1 | Various CID changes |
| 3.4.3-3.10.7 | ObjectHeader | CID at bits 12-31 |

Unknown hashes fall back to v3.9.2 profile with ObjectHeader encoding.

