# Dart Strings in AOT Snapshots

This note documents how Dart strings are represented, how `r2flutter` currently
recovers them, and what information is exact versus heuristic.

## Core Facts

Dart `String` values are not C strings. They are not semantically
NUL-terminated, and their real length comes from Dart object or snapshot
metadata.

The Dart VM uses specialized string classes:

- `OneByteString`: one-byte code units. These are ASCII-compatible for ASCII
  text, but the general encoding is one-byte character data, not "UTF-8 string"
  as a VM invariant.
- `TwoByteString`: two-byte UTF-16 code units.

`r2flutter` usually stores recovered display values as normal UTF-8 C strings
because that is convenient for JSON, text output, and radare2 comments. That
display encoding is not necessarily the original storage encoding.

## Exact Lengths

There are only two reliable ways to determine a string length without carving.

### Snapshot String Records

When parsing a serialized string record from the clustered snapshot, the length
is encoded in the stream:

```c
encoded = read_unsigned ();
is_two_byte = encoded & 1;
length = encoded >> 1;
payload_bytes = is_two_byte? length * 2: length;
```

For `OneByteString`, `length` is the number of one-byte code units. For
`TwoByteString`, `length` is the number of UTF-16 code units. The payload that
follows has exactly `payload_bytes` bytes. No terminator is required.

Current code paths using this model include:

- `src/lib/dart_pool_clusters.c`: `decode_string_cluster`
- `src/lib/dart_pool_modern.c`: `modern_read_cluster_string`
- `src/lib/dart_pool_modern.c`: `modern_skip_fill_string`
- `src/lib/dart_pool_strings.c`: packed string record scanning

### Runtime/Data-Image Dart Objects

When starting from a tagged pointer to a Dart string object, the object itself
must be decoded:

1. Resolve the tagged pointer.
2. If compressed pointers are enabled, rebuild the full tagged pointer from the
   compressed value and heap base.
3. Untag the heap-object pointer.
4. Read the object header and verify the CID is `String`, `OneByteString`, or
   `TwoByteString` for the active version profile.
5. Read the version-specific `String.length_` field.
6. Decode the Smi value.
7. Compute payload size as `length` or `length * 2`.

The object-pool slot does not itself contain the length. It contains a tagged
value, which may be a string object pointer, a Smi, a class, a type, a code
object, or something else. The length comes only after resolving and decoding
the target object.

## Tagged Pointers

Dart heap object pointers are tagged. Smis and heap objects are distinguished
by low tag bits. For the purposes of string recovery:

- Smi values are immediate integers, not object pointers.
- Heap object pointers must be untagged before reading object fields.
- Compressed-pointer builds store a 32-bit compressed tagged value in object
  fields and pools.

In the Dart VM sources used by this repo, compressed pointers are reconstructed
by reattaching the heap base to the stored low bits of an already-tagged
pointer. In practice, `r2flutter` must know:

- whether the snapshot is compressed (`compressed_word_size == 4`)
- the heap base / PP base where relevant
- the active pointer tag and object-header layout
- the active CID table for the snapshot hash

The CID table is version-dependent. Do not hardcode string CIDs globally. Use
the resolved `DartVerLayout` values for `cid_string`, `cid_one_byte_string`, and
`cid_two_byte_string`.

## NUL Termination

NUL bytes are not the Dart string delimiter.

You may see NUL padding in some uncompressed data-image regions because objects
or payloads are aligned. Standard C-string scanning works there by accident, not
because Dart strings are C strings.

Compressed snapshots often store strings as tightly packed records. The byte
after one string may be the next snapshot encoding byte, not `0x00`. In that
case NUL-terminated scanning misses valid strings or truncates the region
incorrectly.

## Carving

Carving means recovering text from bytes without object metadata.

The current `-z` scanner does this as a fallback and as a broad triage layer:

- scan printable one-byte runs
- scan UTF-16LE-looking runs and convert them to UTF-8 for display
- scan snapshot/data windows
- scan readable sections such as `.__const`, `.__cstring`, `.rodata`, and
  `.data.rel.ro`

Carving can recover useful user-facing text, package paths, class names, and
runtime strings, but it cannot prove real Dart object length. The stopping
condition is a heuristic: non-printable byte, invalid UTF-16 profile, size
bound, or text-shape filter.

Important consequences:

- It can miss valid non-Latin text.
- It can split strings incorrectly.
- It can merge adjacent printable data.
- It can report strings that are not Dart `String` objects.
- Its `address` is usually a payload/run address, not necessarily an object
  address.

Use carving output for triage. Use decoded string records or resolved string
objects for exact lengths.

## Object Pools and Indexes

Object pools are arrays of tagged values. A string can be reachable through a
pool slot, but the slot index is not the same thing as a string ID.

Useful identifiers have different meanings:

- snapshot ref ID: the object's reference number in the serialized snapshot
- object-pool index: slot number in a Dart object pool
- code index: slot in the InstructionsTable / Code mapping
- `DartStringInfo.ref_id`: local `r2flutter` extraction counter for `-z`

Do not treat `DartStringInfo.ref_id` as a VM object ref or pool index unless the
producer explicitly populated it from structured snapshot decoding.

## `DartString` vs `DartStringInfo`

There are two local string structs in this codebase.

`DartString` is a smaller internal record used when decoding string clusters:

```c
typedef struct {
	ut64 ref_id;
	char *value;
	int length;
	bool is_two_byte;
} DartString;
```

This is closer to the serialized snapshot model. `ref_id` is the snapshot ref
counter used by the cluster parser, `length` is the decoded Dart length, and
`is_two_byte` records the string storage kind.

`DartStringInfo` is the richer recovery/output record used by `-z`, xrefs, and
the recovery model:

```c
typedef struct DartStringInfo {
	ut64 ref_id;
	char *value;
	ut32 length;
	ut32 flags;
	ut64 address;
	RList *references;
	DartStringCategory category;
} DartStringInfo;
```

`DartStringInfo` records are not stored in the target binary. They are allocated
by `r2flutter`, appended to an `RList`, indexed by value/address in
`DartRecoveryModel`, emitted as text/JSON/r2 commands, and then freed.

Field meanings:

- `ref_id`: local extraction ID. It is not inherently a VM ref or pool slot.
- `value`: recovered display value, stored as a C string. UTF-16 inputs are
  converted to UTF-8 for output.
- `length`: output length recorded by the current extractor. For carved text it
  is the recovered run length. For converted UTF-16 paths it may be UTF-8 byte
  length rather than original UTF-16 code-unit length.
- `flags`: bitmask such as `DART_STRING_TWO_BYTE`, `DART_STRING_CANONICAL`, and
  `DART_STRING_EXTERNAL`.
- `address`: recovered payload/run address. It is not guaranteed to be the Dart
  object address.
- `references`: metadata users attached later, such as class names, field
  names, method names, and signatures.
- `category`: triage class derived from string contents.

## Classification

Current `-z` classification is value-based:

- `rnt`: values starting with `dart:`, or containing `dartvm` / `dart/`
- `lib`: values starting with `package:`, containing `.dart`, or slash paths
- `app`: values with spaces or common human-text punctuation
- `unknown`: empty or otherwise unclassified values

This is useful for filtering, but it is not provenance. A string classified as
`app` may still be referenced by runtime code; a string classified as `lib` may
be a user literal containing a path.

The recovery model can attach stronger reference information when metadata
survives. It matches recovered class, library, field, and method metadata back
to recovered strings and appends `DartStringRef` records with kinds such as:

- `class.name`
- `library.name`
- `class.super`
- `class.interface`
- `field.name`
- `field.type`
- `method.name`
- `method.signature`

Those references are more useful than the value-only category when deciding
where a string participates in the Dart object graph.

## Better Provenance Model

For deterministic string provenance, prefer this priority order:

1. Structured object decode: exact object address, CID, length, payload, and
   snapshot ref ID.
2. Object-pool resolution: pool slot to tagged object, then decode object.
3. Metadata references: class/library/field/method ownership.
4. Snapshot source: VM snapshot vs isolate snapshot.
5. Section and address range: `.__const`, `.rodata`, data image, or fallback
   scan region.
6. Value heuristic: `app`, `lib`, `rnt`.

A future `DartStringInfo` extension could keep separate fields for:

- object address
- payload address
- source snapshot kind (`vm` / `isolate`)
- section name
- snapshot ref ID
- pool slot
- original code-unit length
- display byte length
- storage encoding (`one-byte` / `two-byte`)

That would make `-z` distinguish exact object-aware strings from carved text
without losing the practical triage value of broad scans.

## Implementation Rule of Thumb

When implementing a new string recovery path, decide first which mode it is:

- exact structured decode: must use snapshot record length or object `length_`
- pool decode: must resolve tagged pointer and then decode object
- carved text: must be labeled as heuristic and should not claim VM ref IDs or
  exact Dart lengths

Mixing these modes is where most string bugs come from.
