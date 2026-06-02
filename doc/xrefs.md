# Cross References In Dart AOT Snapshots

This note describes the kinds of cross references we can recover from Flutter/Dart AOT snapshots in this repo, where those links live, and whether they come from:

- direct snapshot metadata
- scanning serialized objects in the binary data image
- disassembling machine code and interpreting object-pool use

The important distinction is:

- some links are true serialized object references and can be dumped without disassembly
- some links only exist implicitly in code and need instruction analysis
- some links are only heuristics because production AOT builds strip or omit useful metadata

## What Counts As An Xref Here

For this project, an "xref" is any stable relationship such as:

- class -> name string
- class -> library
- class -> superclass
- class -> interface type
- field -> owner class
- field -> name string
- field -> type object
- method/function -> owner class
- method/function -> name string
- method/function -> code entrypoint
- instruction-table entry -> code address
- string -> metadata object that references it
- code -> object-pool slot
- code -> string, class, method, or field used at runtime
- function -> callee

These do not all come from the same source.

## Quick Matrix

| Xref | Where it lives | Can be dumped from metadata/data image alone? | Needs code analysis? | Status in this repo |
| --- | --- | --- | --- | --- |
| Snapshot symbol -> snapshot region | loader symbols / magic scan | Yes | No | Implemented |
| IT entry -> code address | `InstructionsTable::Data` | Yes | No | Implemented |
| Function -> name string | `Function` metadata or heuristics | Usually yes | No | Implemented, mixed confidence |
| Function -> owner class/library | `Function.owner_` | Often yes | No | Partly implemented via data-image scan |
| Class -> name string | `Class.name_` or strings | Sometimes | No | Implemented, often heuristic in release builds |
| Class -> library | `Class.library_` | Yes if cluster survives | No | Metadata exists, URI resolution incomplete |
| Class -> superclass | `Class.super_type_` / class ref | Yes if cluster survives | No | Implemented for surviving class metadata |
| Class -> interface | `Class.interfaces_` array of type refs | Yes if class/array/type metadata survives | No | Implemented for surviving metadata |
| Field -> owner class | `Field.owner_` | Yes | No | Implemented |
| Field -> name string | `Field.name_` | Yes | No | Implemented |
| Field -> type | `Field.type_` | Yes | No | Implemented for direct, generic, type-parameter, and simple function types |
| String -> address/value | string cluster or raw/packed bytes | Yes | No | Implemented |
| String -> metadata users | reverse of `name_ref`/`owner_ref`/etc. | Yes | No | Implemented for decoded class/library/field/method metadata |
| Code -> object-pool slot | `ldr ..., [x27, #imm]` and peers | No | Yes | Offset collection implemented |
| Code -> string/class/method/field | object-pool slot contents or inline targets | No | Yes | Partly implemented when `anal.gp` and target strings/flags are available |
| Function -> callee | branch targets / dispatch sites | No | Yes | Not implemented |
| Code -> field access | field offsets in loads/stores | No | Yes | Requires receiver/type inference |

## Three Xref Layers

### 1. Snapshot Metadata Xrefs

These are the strongest links. They come from serialized reference IDs inside the clustered snapshot stream.

The general pattern is:

1. Parse the snapshot header.
2. Walk clusters in alloc/fill order.
3. Assign `ref_id` values.
4. Store each decoded object in `ctx->refs[ref_id]`.
5. Resolve `name_ref`, `owner_ref`, `library_ref`, `super_class_ref`, `type_ref`, and similar links by looking them up in that reference table.

This is how `dart_pool_extract_classes ()` resolves names and ownership today.

### Class Xrefs

When a `Class` cluster is present, the useful links are:

- `Class.name_ref` -> string object
- `Class.library_ref` -> library object
- `Class.super_class_ref` -> parent class
- `Class.interfaces_ref` -> array of interface `Type` refs
- class flags -> abstract / enum / mixin
- layout metadata -> instance size, type parameter count, type-argument offset

This is enough to recover:

- class name
- library ownership
- inheritance edge
- `implements` edges when the interface array and type refs survive
- a partial type/layout view

Important limitation:

- production AOT builds often do not serialize useful `Class` objects for app classes
- when that happens, the repo falls back to string scanning and only gets names, not full class-object edges

So:

- `class -> name` is often still recoverable
- `class -> library`, `class -> superclass`, and `class -> interface` are only reliable when the class metadata itself survives

### Field Xrefs

When a `Field` cluster is present, the useful links are:

- `Field.name_ref` -> string object
- `Field.owner_ref` -> owning class
- `Field.type_ref` -> type object
- initializer ref
- kind bits -> static / final / const / late
- field offset

This is enough to recover:

- field name
- field owner
- field flags
- field offset inside an instance layout
- readable field type names for direct `Type`, `TypeArguments`,
  `TypeParameter`, and simple `FunctionType` refs

Current limitation:

- data-image method scans still recover names and entrypoints only, without
  signature refs
- complex optional named-parameter flags and production layouts still need more
  coverage

So `field -> type` exists in metadata and can often be rendered now, while
cluster-backed `method -> signature` edges are emitted when Function metadata
survives. Class interface arrays are also emitted as `class -> interface type`
edges when the class, array, and type metadata survive.

### Method / Function Xrefs

There are two related sources:

- `Function` metadata objects
- instruction-table entries

From `Function` metadata, the useful links are:

- `Function.name_ref` -> string object
- `Function.owner_ref` -> class or library
- `kind_tag` -> constructor/getter/setter/closure/etc.

From the instruction table, the useful links are:

- entry index -> code index
- entry index -> `pc_offset`
- `pc_offset + iso_instr` -> code address

This gives two different xref shapes:

- `function metadata -> name/owner`
- `instruction-table entry -> code address`

To turn that into `method -> entrypoint`, you need to join both worlds. In this repo that is mostly done by scanning data-image `Function` objects directly and reading their entry/name/owner fields.

### Library Xrefs

The metadata edge exists:

- `Class.library_ref` -> library object
- library object -> name/URI string

But the current implementation only decodes a minimal `LibraryInfo` record and does not fully resolve the URI into `LibraryInfo.uri`.

So the xref is real in the snapshot format, but the repo does not yet materialize the full library name reliably in outputs.

### String Name Xrefs

Many higher-level names are just string references:

- class names
- field names
- method names
- library URIs
- enum-like value names when present

This means a large fraction of "naming xrefs" are really:

- object -> string

That is metadata-only and does not require disassembly.

### 2. Data-Image Object Scans

Some useful xrefs survive in the post-snapshot data image even when the clean cluster path is incomplete or stripped.

This is still binary-only analysis. It does not require disassembling instructions. It does require:

- knowing the object header/tag style for the Dart version
- handling compressed pointers vs full-width pointers
- scanning aligned objects and interpreting likely field offsets

### Method Recovery From `Function` Objects

`scan_methods_from_data_image ()` looks for `Function` objects in the data image by:

- checking object CID against `cid_function`
- reading an entry field that points into `iso_instr`
- reading the name pointer
- reading the owner pointer
- reading `kind_tag`

That recovers:

- method name
- owner class name
- entrypoint
- method kind

This is one of the most useful xref sources for release builds because it does not depend on a surviving `Class` cluster.

### Field Recovery From `Field` Objects

`scan_fields_from_data_image ()` looks for `Field` objects by CID and reads:

- field name pointer
- owner pointer
- kind bits
- instance offset

That recovers:

- `field -> owner`
- `field -> name`
- `field -> offset`

again without disassembly.

### Why This Is Different From Cluster Parsing

Cluster parsing gives clean reference IDs.

Data-image scanning gives raw object pointers and inferred layouts.

Both are metadata-like, but:

- cluster parsing is cleaner and more structural
- data-image scanning is more useful when release snapshots omit or flatten the original class metadata

### 3. Code Xrefs

These links are not serialized as explicit object references. They only appear when code loads a pool entry, accesses a field offset, or branches to another function.

These require disassembly.

### Code -> Object Pool Slot

On ARM64, AOT code commonly uses the object-pool register:

- `PP = x27`

Typical pattern:

```asm
ldr xN, [x27, #imm]
```

That means:

- current function -> object-pool slot at offset `imm`

The repo extracts these offsets in `dart_pool_xrefs.c` by
parsing bounded `pdj` output and looking for `[x27, ...]`. Both hexadecimal
`#0x...` and decimal displacements are accepted.

What this gives today:

- function -> pool offset
- when `anal.gp` is non-zero, pool offset -> raw pool entry
- pool entry -> string/class/type/field/method when the target is a readable
  Dart string or an already-created Dart flag

What is still missing:

- full ObjectPool entry kind decoding
- general Dart object decoding for arbitrary pool entries
- dispatch target and call-graph reconstruction

Without `anal.gp`, PP offsets are still breadcrumbs rather than full semantic
xrefs. With `anal.gp`, the xref dumper emits only relationships it can resolve
directly.

### Code -> String

There are two main cases:

1. the code loads a pool slot that contains a string object
2. the string is referenced indirectly through another object

Metadata-only string dumping tells you that the string exists and where its bytes live.

It does not tell you which function uses it.

To recover `function -> string` you need:

- object-pool slot extraction from disassembly
- object-pool entry decoding
- string-object resolution

So this is a code-analysis xref, not a pure metadata xref. Current `-x` support
handles the direct string-object case when the object pool base is known through
`anal.gp`.

### Code -> Class / Type

Similar logic applies to class and type references:

- a function may load a class object from the pool
- a function may perform type checks using class IDs or header bits
- a function may reference type arguments or allocation stubs indirectly

Some of these patterns are visible in code, but they are not directly serialized as an easy "caller -> class" edge.

Recovering them needs:

- disassembly
- object-pool decoding
- Dart-version-specific interpretation of the loaded object

Current `-x` support only claims a class/type xref when the pool entry resolves
to a readable class-name string or to a live `dart.class.*` / `dart.type.*`
flag. It does not yet decode arbitrary Class, Type, TypeArguments, or allocation
stub objects directly from the pool entry.

### Code -> Field

There are two broad cases:

1. static field access via the object pool
2. instance field access via load/store offsets from an object pointer

Instance-field access is usually something like:

- load receiver
- `ldur` / `stur` at an immediate offset

To turn that into `function -> field`, you need more than the offset:

- the field metadata must tell you that class `C` has a field at offset `X`
- you must know the receiver type at that instruction

The offset alone is not enough because different classes can reuse the same offset.

So field-use xrefs are possible, but they are not metadata-only.

### Function -> Callee

Direct call xrefs come from:

- `bl target`
- occasionally indirect calls through pool-loaded stubs or dispatch helpers

These are classic code xrefs and require disassembly.

The instruction table helps because it gives a stable list of Dart code entrypoints, but it does not by itself give caller -> callee edges.

So:

- IT gives the target universe
- disassembly gives the actual call edges

## How To Find Each Kind Of Reference

### Class References

### Best case: direct metadata

Use when a real `Class` cluster survives.

Procedure:

1. Parse the isolate snapshot header.
2. Build the `ref_id` table while walking clusters.
3. Decode `Class` objects.
4. Resolve:
   - `name_ref`
   - `library_ref`
   - `super_class_ref`

This gives:

- class name
- superclass
- library link

### Common production case: string fallback

If the `Class` cluster is absent, scan strings between `vm_data` and `iso_data` and treat strong type-name candidates as class names.

This gives:

- probable class/type names

It does not give:

- reliable superclass edges
- reliable library ownership
- reliable class object addresses

### Code-analysis case

To know where a class is used by code, you need:

- object-pool analysis
- or type-check / allocation pattern analysis in disassembly

That cannot be dumped directly from the binary as a clean metadata edge today.

### String References

### Finding strings themselves

There are three useful storage modes in this repo:

1. direct string clusters
2. packed string runs inside compressed-pointer snapshots
3. raw ASCII / UTF-16 text scanning across readable sections

This is enough to recover:

- string value
- approximate address of payload bytes
- rough category (`app`, `lib`, `rnt`)

### Finding who references a string

There are two different questions:

1. which metadata object names point to this string?
2. which code paths use this string at runtime?

For metadata users, you can reverse-index:

- `Class.name_ref`
- `Field.name_ref`
- `Function.name_ref`
- library name refs
- any future `Type` name refs

That is a metadata-only xref and is implemented by filling `DartStringInfo.references`.

For code users, you need:

- disassembly
- object-pool slot resolution

So `string -> metadata users` is dumpable from the binary structure itself.
`string -> code users` requires code analysis.

Current repo state:

- `DartStringInfo.references` exists
- it is filled from decoded class/library/field/method metadata
- text and JSON string dumps include the metadata user kind and object name
- production string-only fallback classes are intentionally skipped because they
  do not carry a real metadata reference

### Method References

There are three useful levels.

### 1. Method -> entrypoint

This is usually recoverable without disassembly by joining:

- instruction table
- `Function` objects from the data image

This is the strongest current method xref.

### 2. Method -> owner class

This is recoverable from `Function.owner_` when:

- the owner object is still readable
- the owner's name string can be resolved

In practice, the repo does this through data-image scanning more often than through pure cluster parsing.

### 3. Method -> caller / callee graph

This is not metadata-only.

You need:

- disassembly
- branch target resolution
- optional pool decoding for indirect calls

So the existence of the method can be dumped from the binary, but the call graph requires code analysis.

### Field References

### Field -> owner / name / offset

This is recoverable from field metadata or direct `Field` object scans.

That is binary-data analysis, not disassembly.

### Field -> type

The raw `type_ref` is available in metadata.

Readable type names still need:

- `Type` decoding
- or a heuristic string/type pass

So the edge exists, but the repo does not yet present it cleanly.

### Code -> field use

This requires disassembly because field uses are encoded as memory accesses, not as explicit symbolic xrefs.

You need to match:

- load/store immediate offset in code
- field offset from metadata
- receiver class inference

Without receiver typing, the result is ambiguous.

## Confidence Levels

Not all xrefs are equally trustworthy.

### High confidence

- snapshot symbol -> region
- IT entry -> code address
- metadata `ref_id` links actually decoded from clusters
- data-image `Function` / `Field` objects whose pointers and names resolve cleanly

### Medium confidence

- names recovered by scanning data-image objects with version/layout hints
- string values recovered from packed cluster runs

### Low confidence

- IT names guessed from nearby stack-map strings
- name-pool fallback
- enum recovery from strings alone

These low-confidence links are still useful for triage, but they should not be presented as hard ground truth.

## What We Can Dump Today

With current repo code, the main directly dumpable pieces are:

- `-H`
  - snapshot layout
  - CID table basics
  - pointer-compression mode
- `-i`
  - instruction-table entries
  - code entrypoint addresses
- `-f`
  - recovered function entrypoints and best-effort names
- `-c`
  - class/type names
  - surviving superclass/library metadata when present
  - field/method attachment when data-image scans succeed
- `-z`
  - string values and byte addresses
  - reverse metadata users for decoded class/library/field/method name refs
- `-x`
  - flattened metadata/object-graph xrefs
  - class -> string/library/super links
  - field -> owner/name/type links when metadata survives
  - method -> owner/name/entry links when data-image scans succeed
  - code -> string/class/type/field/method links when `anal.gp` and readable
    pool targets are available
  - instruction-table entry -> code/stub address links
- `-R`
  - recovered function flags
  - PP-relative object-pool offsets seen in code

From radare2, the equivalent entrypoint is:

- `r2flutter -x`

The xref dumper remains intentionally limited to:

- metadata xrefs
- data-image object scan xrefs
- conservative object-pool xrefs tied to a live `anal.gp` value

It does not yet include:

- full ObjectPool entry kind decoding
- call graph edges
- field-use xrefs from load/store analysis

## What Still Needs More Work

To get richer xrefs, the next missing pieces are:

- resolve library URI/name strings fully
- broaden ObjectPool decoding beyond readable strings and live Dart flags
- decode Class/Type/TypeArguments/static-field entries directly from pool
  objects instead of relying on flags or string-name inference
- build a real call graph from disassembly
- recover complete field-use xrefs through receiver-type inference

## Practical Bottom Line

If the question is "can this xref be dumped from the binary itself, or does it require code analysis?", the answer is:

- class/string/field/method naming and ownership links are often recoverable from metadata or data-image objects alone
- code-use links are usually not
- anything of the form `function uses X` generally needs disassembly
- anything of the form `object is named/owned by X` is usually metadata

In short:

- object graph xrefs: dumpable
- naming xrefs: usually dumpable
- inheritance xrefs: dumpable only if class metadata survives
- field layout xrefs: often dumpable
- code -> pool/string/class/field/method xrefs: require code analysis
