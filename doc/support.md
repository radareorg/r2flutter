# Support Matrix

This document summarizes what the current first-party source supports. It is a
parser/layout support note, not a promise that every Flutter engine patch in a
range has regression coverage.

r2flutter targets Dart AOT snapshots embedded in Flutter applications. It uses
radare2 for binary loading and then reads Dart snapshot metadata, data images,
instruction tables, and strings directly.

## Main Targets

| Area | Supported in source |
|------|---------------------|
| App containers | Android directories containing `libapp.so`; iOS `.app` directories containing `Frameworks/App.framework/App`; direct binary paths. |
| Binary loaders | Whatever radare2 `RBin` opens, with explicit code paths for ELF-style symbols/sections and Mach-O app binaries. |
| Mach-O details | Thin Mach-O64 and fat Mach-O/fat64; arm64 slice is preferred. LC_NOTE owner `__dart_app_snap` is detected and the embedded Dart Mach-O payload is extracted to a temporary file. |
| Architecture | ARM64/AArch64 is the real target. Instruction-table entrypoints are based on ARM64 code offsets, PP tracking uses `x27`, and the radare2 analysis pass understands AArch64 registers/op metadata. |
| Snapshot kind | Clustered Dart AOT snapshots with magic `0xdcdcf5f5`, 32-byte snapshot hashes, feature strings, and unsigned varint header fields. |
| Dart layouts | In-tree profiles cover Dart `2.10.0` through `3.10.7`, roughly Flutter `1.22.x` through `3.38.x`. |
| Unknown hashes | First tries `r2flutter/offsets.json` or `offsets.json`; otherwise uses v3.9.2-shaped ObjectHeader defaults while reporting the Dart version as `unknown`. |
| Obfuscation maps | Flutter/Dart `--save-obfuscation-map` JSON arrays are supported with `-m <file>` or `e r2flutter.mapfile=<file>` in the plugin. |

## Layout Profiles

`CWS` is the profile default compressed word size. The actual value can be
overridden by snapshot feature flags: `compressed-pointer` sets CWS to 4 unless
`no-compressed-pointer` or `no-compressed` is present; otherwise CWS is 8.
Compressed ObjectHeader snapshots, and compressed Shift1 snapshots from Dart
2.19 onward, can raise object alignment to 64 bytes.

The CID column is compacted as:

`class/function/code/string/one_byte_string/two_byte_string/array/mint/object_pool`

| Dart | Flutter range | Tag style | CWS | Header fields | Predefined CIDs | CID set | Source note |
|------|---------------|-----------|-----|---------------|-----------------|---------|-------------|
| 2.10.0 | 1.22.x | `CID_INT32` | 8 | 4 | 156 | `4/6/16/80/81/82/78/53/20` | Pre-FunctionType split. |
| 2.13.0 | 2.2.x - 2.3.x | `CID_INT32` | 8 | 5 | 148 | `4/6/15/77/78/79/75/51/18` | Split canonical clusters. |
| 2.14.0 | 2.4.x - 2.5.x | `CID_SHIFT1` | 8 | 5 | 152 | `4/6/16/81/82/83/79/54/20` | TypeParameters era. |
| 2.15.0 | 2.6.x - 2.7.x | `CID_SHIFT1` | 8 | 5 | 153 | `5/7/17/82/83/84/79/55/21` | NativePointer inserted. |
| 2.16.0 | 2.8.x - 2.16.x | `CID_SHIFT1` | 8 | 6 | 154 | `5/7/17/84/85/86/81/55/21` | ConstMap/ConstSet added. |
| 2.17.6 | 2.17.x | `CID_SHIFT1` | 4 | 6 | 158 | `5/7/17/89/90/91/86/59/21` | WeakReference added. |
| 2.18.0 | 3.3.x | `CID_SHIFT1` | 4 | 5 | 159 | `5/7/17/90/91/92/87/59/21` | SuspendState added. |
| 2.19.0 | 3.7.x | `CID_SHIFT1` | 4 | 5 | 176 | `5/7/17/92/93/94/89/60/21` | RecordType/Record added. |
| 3.0.5 | 3.10.x - 3.12.x | `CID_SHIFT1` | 4 | 5 | 177 | `5/7/18/93/94/95/90/61/22` | WeakArray added. |
| 3.1.0 | 3.13.x | `CID_SHIFT1` | 4 | 5 | 176 | `5/7/18/92/93/94/89/60/22` | TypeRef removed. |
| 3.2.5 | 3.16.x | `CID_SHIFT1` | 4 | 5 | 176 | `5/7/18/92/93/94/89/60/22` | PoolType swapped. |
| 3.3.0 | 3.19.x | `CID_SHIFT1` | 4 | 5 | 176 | `5/7/18/92/93/94/89/60/22` | Last Shift1 profile in-tree. |
| 3.4.3 | 3.22.x | `OBJECT_HEADER` | 4 | 5 | 174 | `5/7/18/92/93/94/89/60/22` | ObjectHeader tag encoding begins. |
| 3.5.0 | 3.24.x | `OBJECT_HEADER` | 4 | 5 | 174 | `5/7/18/92/93/94/89/60/22` | ObjectHeader family. |
| 3.6.2 | 3.27.x | `OBJECT_HEADER` | 4 | 5 | 175 | `5/7/18/93/94/95/90/61/23` | CID table update. |
| 3.7.0 | 3.29.x | `OBJECT_HEADER` | 4 | 5 | 175 | `5/7/18/93/94/95/90/61/23` | Same modern profile family. |
| 3.8.1 | 3.32.x | `OBJECT_HEADER` | 4 | 5 | 175 | `5/7/18/93/94/95/90/61/23` | Same modern profile family. |
| 3.9.2 | 3.35.x | `OBJECT_HEADER` | 4 | 5 | 175 | `5/7/18/93/94/95/90/61/23` | Unknown-hash fallback baseline. |
| 3.10.7 | 3.38.x | `OBJECT_HEADER` | 4 | 5 | 175 | `5/7/18/93/94/95/90/61/23` | Newest in-tree profile. |

All profiles use heap object tag `1`, default alignment `16`, and instruction
table capacity `20000` before feature-flag or `offsets.json` adjustments.

## Known Snapshot Hashes

These hashes are mapped directly by `src/lib/dart_version.c`.

| Dart version | Hashes |
|--------------|--------|
| 2.10.0 | `8ee4ef7a67df9845fba331734198a953` |
| 2.13.0 | `e4a09dbf2bb120fe4674e0576617a0dc`, `34f6eec64e9371856eaaa278ccf56538`, `7a5b240780941844bae88eca5dbaa7b8` |
| 2.14.0 | `9cf77f4405212c45daf608e1cd646852`, `659a72e41e3276e882709901c27de33d` |
| 2.15.0 | `f10776149bf76be288def3c2ca73bdc1`, `24d9d411c2f90c8fbe8907f99e89d4b0` |
| 2.16.0 | `d56742caf7b3b3f4bd2df93a9bbb5503`, `3318fe66091c0ffbb64faec39976cb7d`, `adf563436d12ba0d50ea5beb7f3be1bb` |
| 2.17.6 | `1441d6b13b8623fa7fbf61433abebd31`, `a0cb0c928b23bc17a26e062b351dc44d`, `ded6ef11c73fdc638d6ff6d3ad22a67b` |
| 2.18.0 | `b0e899ec5a90e4661501f0b69e9dd70f`, `b6d0a1f034d158b0d37b51d559379697`, `8e50e448b241be23b9e990094f4dca39`, `6a9b5a03a7e784a4558b10c769f188d9` |
| 2.19.0 | `adb4292f3ec25074ca70abcd2d5c7251`, `501ef5cbd64ca70b6b42672346af6a8a` |
| 3.0.5 | `90b56a561f70cd55e972cb49b79b3d8b`, `aa64af18e7d086041ac127cc4bc50c5e`, `36b0375d284ee2af0d0fffc6e6e48fde`, `16ad76edd19b537bf6ea64fdd31977a7` |
| 3.1.0 | `7dbbeeb8ef7b91338640dca3927636de` |
| 3.2.5 | `f71c76320d35b65f1164dbaa6d95fe09` |
| 3.3.0 | `ee1eb666c76a5cb7746faf39d0b97547` |
| 3.4.3 | `d20a1be77c3d3c41b2a5accaee1ce549` |
| 3.5.0 | `80a49c7111088100a233b2ae788e1f48`, `cda356e9bae476c70de33809fd92e009` |
| 3.6.2 | `2858c2c0920495f00b9bce9edf6a8cd9`, `f956f595844a2f845a55707faaaa51e4` |
| 3.7.0 | `d91c0e6f35f0eb2e44124e8f42aa44a7` |
| 3.8.1 | `830f4f59e7969c70b595182826435c19` |
| 3.9.2 | `97ff04a728735e6b6b098bdf983faaba` |
| 3.10.7 | `1ce86630892e2dca9a8543fdb8ed8e22` |

`offsets.json` can enrich or override a hash with `compressed_word_size`,
`heap_object_tag`, `max_alignment`, `it_cap`, `code_entry_point_offsets`,
`code_owner_offsets`, and `function_name_offsets`. The code looks for it first
under `r2flutter/offsets.json`, then in the current directory as `offsets.json`.

## Snapshot Discovery

Discovery first looks for these exact symbol spellings:

- `_kDartVmSnapshotData`
- `DartVmSnapshotData`
- `_kDartVmSnapshotInstructions`
- `DartVmSnapshotInstructions`
- `_kDartIsolateSnapshotData`
- `DartIsolateSnapshotData`
- `_kDartIsolateSnapshotInstructions`
- `DartIsolateSnapshotInstructions`

If symbols are missing, readable sections are scanned in 4 KB windows for
snapshot magic. Candidates that parse as data snapshots are split from
instruction snapshots; the smaller data snapshot is treated as VM data and the
larger as isolate data. The same size heuristic is used for instruction
snapshots.

Header parsing reads:

- magic, total length, and snapshot kind
- 32-byte hash
- null-terminated feature string, capped at 2048 scanned bytes
- base object count, object count, cluster count, instruction-table length,
  instruction-table data offset
- cluster stream start

Cluster values are rejected or downgraded when they are obviously too large:
cluster count must stay below 1,000,000 and object count below 10,000,000 for
full deserialization.

## Extraction Support

### Functions and Names

Function discovery merges several sources:

- instruction-table entries
- class method metadata recovered from clusters or data image scans
- legacy clustered Function objects
- loader symbols only when stubs are explicitly included internally

The default CLI and plugin set `no_stubs=true`, so loader-provided ELF/Mach-O
stub symbols are skipped. That keeps output focused on Dart-derived names.

Recovered method names are normalized into radare2-safe names. Class-method
names use the `method.<library>.<owner>.<leaf>` shape. Library names strip
`package:` and trailing `.dart`; non-name characters collapse to underscores.
Constructors, getters, setters, anonymous closures, and Dart operators are
renamed into stable leaf names such as `ctor`, `get_name`, `set_name`,
`_anon_closure`, `op_eq`, `op_add`, and `op_ushr`.

The optional `-n` / `r2flutter.namepool` fallback consumes `package:` and
`dart:` strings from the data image as sequential names. It is intentionally
opt-in because one wrong stub/function distinction shifts every later name.

### Instruction Table

`-i` exposes the instruction table. JSON output includes:

- table `length`
- `first_entry_with_code`
- `canonical_stack_map_entries_offset`
- per-entry `index`, `code_index`, `address`, `pc_offset`,
  `stack_map_offset`, `kind`, and optional `name`

The decoder supports:

- linear fallback when `itdata == 0`: `iso_instr + index * 4`
- fixed table data with 8-byte entries (`pc_offset`, `stack_map_offset`)
- header probing near `data_image_base + itdata`
- scanning OneByteString-like payloads for embedded table data
- bounded fallback scans in the first data-image region
- varint-encoded table fallback around the expected table address

Entry names are resolved in this order: modern cluster code-index map, loader
symbol at the entrypoint, data-image code-name scan, nearby stack-map string,
opt-in name pool, owner-kind stub names, then `method.fn_<index>`.

Modern compressed ObjectHeader snapshots also classify code owners so allocation
stubs, type-test stubs, VM stubs, and regular functions do not consume the same
name-pool stream.

### Modern ObjectHeader Naming

The modern cluster scanner is enabled only for snapshots with:

- `OBJECT_HEADER` tag style
- CWS 4 compressed pointers

It walks allocation/fill records for strings, classes, libraries, patch
classes, closure data, functions, code objects, arrays, typed data,
object pools, contexts, records, and common runtime objects. Its primary goal
is name recovery, not full object reconstruction.

It maps:

- Function owners to `method.<owner>.<name>`
- closure data to `_anon_closure`
- class-owned Code objects to `stub.Allocate<ClassName>Stub`
- type-owned Code objects to `stub.TypeTest_<TypeName>`
- ownerless Code objects to VM stubs

Full-width ObjectHeader snapshots still use the layout profile, data-image
scans, instruction-table decoding, and string scans, but they do not take this
compressed modern cluster naming path.

### Classes, Types, Fields, and Methods

`-c` dumps class metadata. `-T` prints a type-oriented view and runs enum
recovery. `-C` in the radare2 plugin emits type definitions.

Class output can include:

- reference id and class name
- library ref/name
- superclass ref/name
- instance size, type-parameter count, type-argument offset
- flags: abstract, enum, mixin, top-level
- enum values
- fields with name, type, offset, and static/final/const/late flags
- methods with entrypoint, owner, kind tag, and decoded method kind

Cluster extraction reads String, Class, Field, and Library records where the
cluster layout is understood. If that does not produce classes, a string-based
type-name fallback scans the VM-to-isolate data window.

Data-image scans add fields and methods back onto recovered classes. Field
scans recognize Field objects and read owner/name strings and offsets. Method
scans recognize Function objects, entrypoints, kind tags, owner class names,
and method names.

Recognized method kind names are:

- `RegularFunction`
- `ClosureFunction`
- `ImplicitClosureFunction`
- `GetterFunction`
- `SetterFunction`
- `Constructor`
- `ImplicitGetter`
- `ImplicitSetter`
- `ImplicitStaticGetter`
- `FieldInitializer`
- `MethodExtractor`
- `NoSuchMethodDispatcher`
- `InvokeFieldDispatcher`
- `IrregexpFunction`
- `DynamicInvocationForwarder`
- `FfiTrampoline`
- `RecordFieldGetter`

Enum recovery is heuristic. It looks for type-name strings, trailing
`TypeName.`, and `TypeName.value` pairs. Candidate names must look like Dart
types, values must look like enum values, and suffixes such as `Action`,
`Behavior`, `Direction`, `Kind`, `Mode`, `State`, `Status`, and `Style` boost
confidence.

### Strings

`-z` dumps reliable strings reached from decoded ObjectPool entries. Text output
is a string list by default; `-q -z` prints only string values, one per line.
Use `-xz` when ObjectPool/reference metadata should be included.

`-zz` dumps broad fuzzy/carved strings. The fuzzy scanner supports:

- ASCII strings
- UTF-16LE strings converted to UTF-8
- packed strings inside compressed snapshots
- snapshot cluster/data windows
- readable sections ending in `.__const`, `.__cstring`, `.rodata`, or
  `.data.rel.ro`

Strings are classified as:

- `rnt` for Dart runtime-looking strings (`dart:`, `dartvm`, `dart/`)
- `lib` for package/library-looking strings (`package:`, `.dart`, slash paths)
- `app` for human text with spaces or punctuation
- `unknown` otherwise

Fuzzy string scans are bounded: 64 MB per snapshot region, 8 MB per data-image
window, 32 MB per section, and 50,000 total strings.

### Xrefs

`-x` combines metadata, data-image scans, strings, classes, and instruction
table entries into cross-reference records.

Supported xref kinds include:

- `class.name`
- `class.library`
- `class.super`
- `field.owner`
- `field.name`
- `field.type`
- `method.owner`
- `method.name`
- `method.entry`
- `it.code`
- `it.stub`

Origins are reported as `metadata`, `data-image`, or `scan`.

### Obfuscation Maps

The obfuscation map loader expects a JSON array of alternating original and
obfuscated strings. It builds an inverse map from obfuscated name to original
name, then applies it to:

- function names
- instruction-table names
- class names
- field names
- method owner/name strings
- dotted names component by component

## CLI Support

`bin/r2flutter` supports one action per invocation.

| Flag | Support |
|------|---------|
| `-h` | Help. |
| `-V` | Version string. |
| `-j` | JSON output where the selected action supports it. |
| `-q` | Compact dump output and suppress non-essential stdout/log noise. |
| `-r` | radare2 command/script output where the selected action supports it. |
| `-n` | Enable heuristic name-pool fallback for otherwise unnamed functions. |
| `-v`, `-vv` | Increase stderr diagnostics; `-vv` also prints extra snapshot/header bytes. |
| `-A` | Analyze the snapshot and apply recovered flags/comments without dumping. |
| `-AA` | Analyze with field extraction enabled. |
| `-AAA` | Run Dart-aware code analysis and recover refs/comments. |
| `-c` | Dump classes. |
| `-f` | Dump recovered functions as `addr name`; with `-j`, emits objects with `addr`, `name`, and optional `size`. |
| `-H` | Dump snapshot header/layout/container information. |
| `-HH` | Dump the snapshot header plus VM/isolate cluster allocation/fill layout. |
| `-HHH` | Add selected cluster payload diagnostics, currently ObjectPool entry decoding/status plus conservative ref resolution. |
| `-i` | Dump instruction-table entries. |
| `-p` | Print the reconstructed static ObjectPool PP address pair; with `-r`, map the synthetic pool image and set `anal.gp`/`x27` from the synthetic vaddr. |
| `-R` | Dump a radare2 script for applying method flags/comments and PP helpers. |
| `-T` | Dump type-oriented class output and run enum recovery. |
| `-x` | Dump metadata/data-image xrefs; combine with `-z` to include string refs. |
| `-z` | Dump reliable ObjectPool-referenced strings; `-q -z` prints values only. |
| `-zz` | Dump all fuzzy/carved strings; `-xzz` includes refs. |
| `-l <N>` | Limit function or instruction-table/xref output depending on the action. |
| `-m <file>` | Load a Flutter obfuscation map JSON file. |

Directory inputs are resolved as Android first (`libapp.so`), then iOS
(`Frameworks/App.framework/App`).

## radare2 Plugin Support

The core plugin command is `r2flutter`. Running it with no flags shows help.
Both the standalone CLI and core plugin use repeated `A` actions for analysis
depth: `-A`, `-AA`, and `-AAA`.

Config keys:

- `r2flutter.mapfile`: Flutter obfuscation map JSON path
- `r2flutter.namepool`: enable heuristic name-pool fallback

Plugin modifiers:

| Modifier | Support |
|----------|---------|
| `-j` | JSON output for dump actions. |
| `-q` | Compact dump output and quiet analysis logs. |
| `-r` | radare2 command output for dump actions. |
| `-n` | Enable heuristic name-pool fallback for otherwise unnamed functions. |
| `-v`, `-vv` | Increase parser diagnostics. |
| `-l N` | Limit function, instruction-table, or xref output depending on the action. |
| `-m file` | Load a Flutter obfuscation map JSON file. |

Plugin actions:

| Command | Support |
|---------|---------|
| `r2flutter` | Show help. |
| `r2flutter -A` | Analyze Dart snapshot, apply method flags/comments, and set `e emu.str=true`. |
| `r2flutter -AA` | Analyze with field extraction enabled. |
| `r2flutter -AAA` | Run Dart-aware code analysis and recover refs/comments. |
| `r2flutter -H` | Print snapshot header info. |
| `r2flutter -HH` | Print snapshot header info plus VM/isolate cluster allocation/fill layout. |
| `r2flutter -HHH` | Print cluster layout plus selected payload diagnostics, currently ObjectPool entries/status and ref resolution. |
| `r2flutter -i` | Print instruction-table entries. |
| `r2flutter -p` | Print the reconstructed static ObjectPool PP address pair. |
| `r2flutter -R` | Print full radare2 script output. |
| `r2flutter -f` | Dump recovered functions. |
| `r2flutter -c` | Dump classes. |
| `r2flutter -C` | Apply Dart classes, fields, methods, and types to r2. |
| `r2flutter -x` | Dump xrefs as text. |
| `r2flutter -z` | Dump reliable ObjectPool-referenced strings; `-q -z` prints values only. |
| `r2flutter -zz` | Dump all fuzzy/carved strings; `-xzz` includes refs. |

Examples:

```bash
r2flutter -c       # classes as text
r2flutter -jc      # classes as JSON
r2flutter -rz      # reliable ObjectPool string registration commands
r2flutter -rzz     # fuzzy/carved string registration commands
r2flutter -jH      # snapshot header as JSON
r2flutter -HH -l 8 # snapshot header plus first 8 clusters per snapshot
r2flutter -HHH -l 36 # cluster walk plus ObjectPool entry diagnostics/status/ref resolution
r2flutter -r -p    # map a synthetic ObjectPool and set anal.gp/x27
```

The Dart-aware analysis pass creates or reuses functions at recovered Dart
entrypoints, tracks AArch64 register values, follows PP-relative loads through
`x27`, propagates simple stack values, annotates direct string/class/type/field
refs, adds call xrefs, and comments indirect calls through PP slots.

## radare2 Script Output

The `-R` path emits:

- `e emu.str=true`
- `app.base` and `app.heap_base` flags
- `method.*` flags for recovered functions
- comments at method entrypoints
- `PP=x27`; per-function PP offset helper scanning is intentionally skipped by
  default in script output because it is too slow on large apps
- `-r -p` is the focused PP setup path: it opens a malloc map at the synthetic
  PP base, writes the reconstructed ObjectPool image, and sets `e anal.gp` plus
  `dr x27`

## Practical Limits

- The implementation is ARM64-oriented. Header and string extraction may work
  on other containers if radare2 maps the snapshots, but instruction-table
  naming, PP analysis, and code comments assume AArch64 conventions.
- Modern cluster name reconstruction currently requires compressed
  ObjectHeader snapshots. Full-width ObjectHeader snapshots rely more heavily
  on data-image and string heuristics.
- `-HHH` can resolve many tagged ObjectPool entries to their owning cluster
  kind, CID, and static names such as strings/functions. `-p` still materializes
  only the ObjectPool shape and immediate entries; tagged Dart object entries
  remain placeholders because their runtime heap addresses are assigned by VM
  deserialization and are not stored as static file addresses.
- Legacy cluster parsing uses conservative decoders and skips unknown clusters;
  when class/function records cannot be trusted, the code falls back to bounded
  scans.
- `-n` can produce plausible but wrong names. It is a last-resort fallback for
  samples where metadata cannot associate names with instruction-table slots.
- This is not a Dart decompiler and does not parse Dart bytecode, kernel
  `.dill`, Flutter web JavaScript, or the Flutter engine itself.
- Snapshot discovery prefers symbol names, then section scanning. Stripped or
  unusual packers can still require manual triage with `-v`, `-vv`, `-H`, and
  `-i`.
