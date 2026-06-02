# Compressed Pointer Strings

This note documents what people usually mean by "compressed pointer strings" in Dart AOT snapshots, how they are built, how to find them, and how to recognize common string operations in generated code.

The short version:

- Dart does not have a special "compressed string" class.
- String character data is not entropy-compressed.
- What changes is:
  - object/reference width (`cws=4` vs `cws=8`)
  - string object header/padding
  - how canonical strings are emitted into the AOT snapshot

In this repo, the practical problem is not "decode compressed text". It is "recover string payloads from snapshots built with compressed pointers, where strings are often serialized as packed cluster data instead of NUL-terminated ROData objects".

## Investigation Plan

Use this order when studying or implementing support:

1. Detect whether the snapshot uses compressed pointers.
2. Decide whether strings are direct-mapped ROData objects or serialized cluster payloads.
3. Resolve the target version profile so CID values and header style are correct.
4. Recover strings from the correct storage mode.
5. Only then reason about higher-level string operations in code.

## Reality Check: What "Compressed Pointers" Actually Means

In the current Dart VM sources shipped in `third_party/sdk`, compressed pointers are not stored as `heap_base + (offset << alignment_shift)`.

The actual model is:

```c
// tagged heap object pointer, low bit already set
tagged = untagged_address + kHeapObjectTag;

// stored inside compressed fields
stored32 = (uint32_t)tagged;

// reconstruction
tagged = heap_base + stored32;
```

Key details:

- heap objects are tagged with `kHeapObjectTag = 1`
- Smis keep bit 0 clear
- `kCompressedWordSize = 4` when `DART_COMPRESSED_POINTERS` is enabled
- `kCompressedWordSize = 8` otherwise
- `kHeapBaseMask = ~(4GB - 1)` on compressed builds

So the low 32 bits of the already-tagged pointer are stored, then the shared upper bits are reattached at runtime.

Relevant source files:

- `third_party/sdk/runtime/vm/tagged_pointer.h`
- `third_party/sdk/runtime/vm/pointer_tagging.h`
- `third_party/sdk/runtime/vm/globals.h`

## Supported Architectures

In this checkout, compressed pointers are only allowed for:

- `arm64`
- `x64`

The build rules explicitly reject compressed pointers for:

- `arm`
- `ia32`
- `riscv32`
- `riscv64`

Source:

- `third_party/sdk/runtime/BUILD.gn`

That matters for reversing:

- on `arm64` and `x64`, `cws=4` is a real case you must handle
- on `arm`, `ia32`, and current `riscv*` builds in this tree, string references stay full-width

## Operating System Notes

The pointer encoding itself is OS-independent. The surrounding container and heap reservation strategy are not.

Common cases:

- Android/Linux: AOT snapshot is usually packaged in ELF (`libapp.so`)
- iOS/macOS: AOT snapshot is usually packaged in Mach-O (`App.framework/App`)
- Windows: same pointer model, different virtual memory helper
- Fuchsia: compressed heap support is special-cased; do not assume the normal compressed-heap helper is present

Important distinction:

- `PP` is the object-pool register, not the heap-base register
- on ARM64, `PP = x27`
- on ARM64 compressed loads use `HEAP_BITS = x28`
- on x64 compressed loads add `Thread::heap_base_offset()`

Relevant source files:

- `third_party/sdk/runtime/vm/constants_arm64.h`
- `third_party/sdk/runtime/vm/thread.h`
- `third_party/sdk/runtime/vm/compiler/assembler/assembler_arm64.cc`
- `third_party/sdk/runtime/vm/compiler/assembler/assembler_x64.cc`

## String Object Layout

At the object level, modern Dart strings are:

- `String`
- `OneByteString`
- `TwoByteString`

The important part is:

- `length_` is stored as a compressed Smi field
- character data is inline, immediately after the fixed header
- `OneByteString` stores 1 byte per code unit
- `TwoByteString` stores UTF-16LE code units inline
- string objects themselves do not contain trailing object-pointer arrays

Simplified modern layout:

### OneByteString

```text
[object header / tags]
[length_ : compressed Smi]
[padding on compressed builds if needed]
[data bytes...]
[rounded tail padding zeroed]
```

### TwoByteString

```text
[object header / tags]
[length_ : compressed Smi]
[padding on compressed builds if needed]
[utf16 data...]
[rounded tail padding zeroed]
```

Two details matter for recovery:

1. On compressed builds the length field is only 4 bytes, but string data stays word-aligned, so there is an alignment gap before `data_`.
2. Tail padding is zeroed so equality and copy fast paths do not need special-case remainder handling.

Relevant source files:

- `third_party/sdk/runtime/vm/raw_object.h`
- `third_party/sdk/runtime/vm/object.h`
- `third_party/sdk/runtime/vm/object.cc`

## Version-Sensitive Details

Do not hardcode one string CID table for all snapshots.

Examples from the repo:

| Style | `kStringCid` | `kOneByteStringCid` | `kTwoByteStringCid` |
| --- | ---: | ---: | ---: |
| Dart 3.4.x family | 92 | 93 | 94 |
| Dart 3.5+ family in samples | 93 | 94 | 95 |

Also, object-header encoding changes across versions:

- older snapshots use raw/int-shifted cluster tags
- newer snapshots use `TAG_STYLE_OBJECT_HEADER`

For recovery, prefer the version profile already maintained by `r2flutter` instead of open-coded constants.

## Two Different AOT String Storage Modes

This is the part that matters most for reversing.

### 1. Full-Width Pointer AOT With Direct ROData Strings

When compressed pointers are not used, canonical strings may be emitted as direct ROData heap objects.

The serializer does this through `RODataSerializationCluster`, but only when:

- the snapshot includes code
- compressed pointers are disabled

That produces the familiar NUL-padded patterns visible in the local samples.

Example from `test/bins/android/first/libapp.so` and `test/bins/ios/Runner.app/Frameworks/App.framework/App`:

```text
_Uint16List 00 00 00 00 00
_ExternalInt64Array 00 00 ...
```

Observed bytes:

```text
32 d2 05 00 ... 5f 55 69 6e 74 31 36 4c 69 73 74 00 00 00 00 00
```

This is why simple ASCII scanning works well on these binaries.

### 2. Compressed-Pointer AOT With Packed String Clusters

When compressed pointers are enabled, the VM does not direct-map those read-only string objects into the final image in this path. Instead, strings are serialized through `StringSerializationCluster`.

The reason is stated directly in the serializer:

- direct-mapped ROData objects are skipped under compressed pointers because the load address may not stay inside the 4 GB region needed by compressed references

In this mode, strings are packed into the clustered snapshot stream:

- alloc phase writes `count`
- alloc phase writes `encoded = (length << 1) | is_two_byte`
- fill phase writes the same `encoded` again
- fill phase writes raw bytes:
  - `length` bytes for one-byte strings
  - `length * 2` bytes for two-byte strings

That produces byte patterns like this from `test/bins/android/mafia/libapp.so`:

```text
... 8c 48 61 6e 64 6c 65 82 1a 82 34 ac 4d 6f 6e 6f 6d 6f 72 70 68 69 63 53 ...
```

Which reads as:

```text
... "Handle" <binary> "MonomorphicSmiableCall" <binary> ...
```

Those binary bytes are not compression. They are cluster metadata, ULEB values, or the next serialized object fields.

This is the main reason a naive `strings(1)` or NUL-terminated scan under-recovers compressed-pointer snapshots.

Relevant source files:

- `third_party/sdk/runtime/vm/app_snapshot.cc`
- `third_party/sdk/runtime/vm/object.h`
- `third_party/sdk/runtime/vm/object.cc`

## How To Detect Which Mode You Are In

Use the most reliable signals first.

### Signal 1: Snapshot Header / Version Layout

If you already have a parsed header, `compressed_word_size` tells you the answer directly:

- `cws = 4` -> compressed pointers
- `cws = 8` -> full-width slots

Observed in local fixtures:

- `test/bins/android/first` -> `cws=8`
- `test/bins/android/mafia` -> `cws=4`
- `test/bins/ios/Runner.app` -> `cws=8`
- `test/bins/ios/AuthPass.app` -> `cws=8`

Important:

- the local iOS samples are full-width
- the VM sources still allow compressed pointers on `arm64` in general
- so treat this as a product/toolchain choice, not an ARM64 impossibility

### Signal 2: Features String

The snapshot features string contains:

- `compressed-pointers`
- or `no-compressed-pointers`

### Signal 3: Raw Byte Shape

If you only have raw bytes:

- direct ROData strings: ASCII names are often followed by `00` padding
- compressed-pointer clustered strings: printable runs are immediately followed by non-printable metadata bytes such as `0x82`, `0x8c`, `0x96`, `0xac`, etc.

### Signal 4: Serializer Path

Once the version is known:

- `RODataSerializationCluster` path only exists for non-compressed code snapshots
- `StringSerializationCluster` path is the one to expect for compressed-pointer AOT

## How To Recover Them Reliably

### Best Method: Parse The Snapshot String Clusters

For correctness and stable output, parse the clustered snapshot instead of only scanning for printable runs.

Recommended flow:

1. Locate snapshot base.
2. Parse the standard header and features string.
3. Resolve the version profile and CID table.
4. Walk the cluster stream.
5. When the cluster CID is a string CID, decode:
   - one-byte vs two-byte from bit 0
   - length from bits 1+
   - payload bytes from the fill phase
6. Emit recovered strings even if they are not NUL-terminated in the file.

This is the right place to make `-z` more complete for compressed-pointer snapshots.

### Fast Heuristic Method: Non-NUL Text Scanning

If you want a cheap fallback:

- scan printable ASCII runs bounded by any non-printable byte, not just `0x00`
- also scan UTF-16LE runs
- accept that this is heuristic and object-unaware

This repo already gets useful results from that approach. On the compressed Android `mafia` sample, the current `-z` already recovers strings such as:

- `Handle`
- `MonomorphicSmiableCall`
- `_Uint16List`

That works because the parser treats any non-text byte as a separator, not just NUL.

The downside is that this recovers text fragments, not verified string objects.

## Common Operation Signatures

The VM only intrinsifies some string operations. Others stay as higher-level Dart loops.

### `length`

Stable signature:

- load compressed/full-width Smi from `String::length_offset()`

Reverse-engineering clue:

- repeated field load from the fixed string-length slot
- often followed by Smi compare or untag

### `isEmpty`

Stable signature:

- load `length`
- compare against Smi zero

Intrinsic backends:

- ARM
- ARM64
- IA32
- X64
- RISCV

### `codeUnitAt` / `charAt`

Stable signature:

- verify index is Smi/integer
- bounds check against `length`
- dispatch on one-byte vs two-byte class
- load 1-byte or 2-byte element from `data_offset()`

Common low-level shape:

- one-byte: `data_offset + index`
- two-byte: `data_offset + index * 2`

On compressed builds you still load the character bytes directly from inline data. Pointer compression affects the surrounding object fields, not the string payload bytes.

### Equality / `_substringMatches`

Typical clues:

- compare lengths first
- compare characters in a tight byte/word loop
- one-byte equality is commonly intrinsified

This is a good anchor when looking for fast-path string checks in stripped binaries.

### `substring` / `_substringUnchecked`

Most useful recovery pattern:

1. compute `end - start`
2. allocate new `OneByteString` or `TwoByteString`
3. compute source start = `base + data_offset + start`
4. copy `length` bytes or UTF-16 code units into result

For one-byte strings the fast path is especially recognizable:

- destination allocation
- source pointer arithmetic
- short byte-copy loop or memmove-like sequence

### Append / Concatenation

There is no special "append string object". The VM creates a new result string and copies both inputs.

Native/runtime paths:

- `String_concat`
- `String_concatRange`

Typical clues:

1. load `len1`
2. load `len2`
3. add lengths
4. choose one-byte vs two-byte result
5. allocate destination
6. copy left string
7. copy right string

For all-one-byte paths, Dart code may also go through `_OneByteString._concatAll`.

### Interpolation

User-visible interpolation normally lowers to:

- `_StringBase._interpolateSingle`
- `_StringBase._interpolate`
- then either `_OneByteString._concatAll` or `String_concatRange`

Common clue:

- values are converted with `toString()`
- result length is accumulated
- concatenation happens at the end

### `trim`, `trimLeft`, `trimRight`

These are not dedicated VM intrinsics in this checkout.

They are implemented in Dart patch code as:

- a forward and/or backward scan
- repeated `codeUnitAt`
- whitespace classification
- fast return of `this` or `""`
- final `_substringUnchecked(...)` call

So the most stable reverse-engineering signature is not a unique helper symbol. It is:

1. loop from front and/or back
2. compare code units against whitespace ranges
3. if unchanged, return original string
4. otherwise call substring

Whitespace sets used by the VM patch libraries:

- one-byte fast set:
  - `0x09..0x0d`
  - `0x20`
  - `0x85`
  - `0xA0`
- two-byte adds:
  - `0x1680`
  - `0x2000..0x200A`
  - `0x2028`
  - `0x2029`
  - `0x202F`
  - `0x205F`
  - `0x3000`
  - `0xFEFF`

That makes trim detection possible, but much less stable than `length`, `isEmpty`, `charAt`, or one-byte substring.

## Backend-Specific Notes

### ARM64

Compressed loads use:

- 32-bit load from the slot
- add upper heap bits from `HEAP_BITS`

Important registers:

- `PP = x27`
- `HEAP_BITS = x28`
- `THR = x26`

`HEAP_BITS` contains:

- `write_barrier_mask << 32`
- `heap_base >> 32`

### X64

Compressed loads use:

- `movl` from the slot
- `addq` with `Thread::heap_base_offset()`

So a common compressed-field pattern on x64 is:

```text
movl reg, [base+disp]
addq reg, [thr+heap_base]
```

### ARM / IA32 / RISCV

These backends still have string intrinsics, but in this tree compressed pointers are not the supported deployment mode for them. For recovery purposes, treat them as full-width string-object targets unless the VM/toolchain changes.

## What This Means For `r2flutter`

If the goal is "show them in `-z`", there are two valid levels of support:

### Level 1: Heuristic text recovery

Keep the current approach:

- scan printable ASCII runs
- scan UTF-16LE runs
- do not require NUL terminators

This already works surprisingly well on compressed Android samples.

### Level 2: Structured snapshot recovery

Add a string-cluster decoder for compressed-pointer AOT:

1. reuse the version profile and CID table
2. walk alloc/fill string clusters
3. decode `encoded = (length << 1) | is_two_byte`
4. emit exact strings from fill payloads
5. optionally track cluster/file offsets separately from runtime object addresses

That is the correct long-term implementation if you want deterministic, object-aware `-z` output.

## Repo Validation Summary

The conclusions above were cross-checked against:

- local repo docs in `doc/*.md`
- Dart VM sources in `third_party/sdk/runtime/vm`
- Dart patch libraries in `third_party/sdk/sdk/lib/_internal/vm/lib/string_patch.dart`
- shipped binaries in:
  - `test/bins/android/first`
  - `test/bins/android/mafia`
  - `test/bins/ios/Runner.app`
  - `test/bins/ios/AuthPass.app`

Observed local facts:

- `first` and the iOS fixtures use `cws=8`
- `mafia` uses `cws=4`
- non-compressed samples show NUL-padded ROData strings
- the compressed Android sample shows packed serialized string payloads separated by binary metadata bytes

## Bottom Line

If you remember only one thing, remember this:

`compressed pointer strings` are not compressed text. They are normal Dart string payloads embedded in snapshots that were built with 32-bit compressed object slots, and in that mode the strings are often packed into serialized clusters instead of direct NUL-padded ROData objects.

That is why they are easy to miss with classic string scanning, and why the correct recovery path is snapshot-aware string-cluster decoding.
