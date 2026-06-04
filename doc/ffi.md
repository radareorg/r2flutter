# Dart FFI and Native Function Notes

This document records the current understanding of Dart FFI, VM native
functions, ObjectPool `native_function` entries, and how r2flutter should expose
that information. It is written for static analysis of Flutter AOT snapshots,
not for running an isolate or linking symbols at runtime.

## Vocabulary

`PP` is the Dart object-pool register. On ARM64 AOT it is `x27`. A PP-relative
load such as `ldr x0, [x27, #0x1234]` reads a slot from the current Dart
ObjectPool.

`NativeFunction` is overloaded terminology:

- In `dart:ffi`, `Pointer<NativeFunction<T>>` is a typed native C function
  pointer that can be converted to a Dart callable with `asFunction()`.
- In a Dart VM ObjectPool, `native_function` means
  `ObjectPoolBuilderEntry::kNativeFunction`. That is an ObjectPool entry kind,
  not a Dart object and not a loader import entry.
- In the Dart embedding API, `Dart_NativeFunction` is a C callback with the
  `Dart_NativeArguments` calling convention. This is the older VM native-entry
  mechanism, distinct from normal C ABI FFI calls.

Do not assume these three meanings identify the same thing in the file.

## FFI Lookup Model

The public Dart FFI API is in `dart:ffi`.

`DynamicLibrary.open(path)` loads a native library file and stores a runtime
library handle. On Unix-like systems this is backed by `dlopen`; on Windows by
the platform loader. The path string may be a literal string in the snapshot,
or it may be constructed dynamically.

`DynamicLibrary.process()` creates a library handle for global symbols already
visible in the current process. On Linux, macOS, Android, and Fuchsia this uses
the equivalent of `RTLD_DEFAULT`. There is no library path string for this case.

`DynamicLibrary.executable()` creates a library handle for the running
executable. This is useful when native code is statically linked into the app or
host executable. Again, there may be no library path string.

`DynamicLibrary.lookup<T>(symbolName)` resolves a symbol and returns a
`Pointer<T>`. For FFI functions this is commonly used as
`lookup<NativeFunction<CSignature>>("symbol")`.

`DynamicLibrary.lookupFunction<T, F>(symbolName, isLeaf: ...)` resolves a symbol
and directly returns a Dart callable. `T` is the native C signature and `F` is
the Dart signature.

`DynamicLibrary.providesSymbol(symbolName)` checks whether a handle can resolve
the symbol.

The important static point is that `symbolName` and `path` are Dart `String`
values. If they are constants, they are usually recoverable from string
clusters, object pools, or direct snapshot string scans. If they are built at
runtime, static recovery becomes partial.

## `@Native` and Native Assets

Modern Dart also supports `@Native<T>()` annotations on external functions and
variables. This path is related to FFI but does not always look like an
explicit `DynamicLibrary.lookup("name")` call in optimized AOT code.

For an `@Native` declaration, the symbol name is either:

- the annotation's `symbol:` value, or
- the annotated Dart declaration name when `symbol:` is omitted.

The asset is either:

- the annotation's `assetId:`,
- the library-level `@DefaultAsset`, or
- the library URI string when no explicit asset is given.

The VM resolution order for `@Native` is:

1. resolve the symbol in the provided/default asset,
2. use the library's resolver installed with `Dart_SetFfiNativeResolver`,
3. fall back to the current process.

The native-assets path can map an asset ID to an absolute path, relative path,
system library, executable, or process handle. The embedder may provide this map
at runtime, so a static tool may see only the asset ID, not the final library
path.

`Dart_SetFfiNativeResolver` is especially important for reverse engineering:
the library may deserialize with its resolver fields set to null, and the
embedder or runtime can install a resolver later. If a resolver synthesizes or
maps symbols dynamically, the final address and sometimes the final name are not
present as a normal import table entry.

## ObjectPool `native_function`

In the VM's ObjectPool builder, each entry has an entry type, patchability bit,
and snapshot behavior:

- entry type:
  - `0`: `immediate`
  - `1`: `tagged_object`
  - `2`: `native_function`
- patchability:
  - `0`: `patchable`
  - `1`: `not_patchable`
- snapshot behavior:
  - `0`: `snapshotable`
  - `1`: `not_snapshotable`
  - `2`: `reset_to_bootstrap_native`
  - `3`: `reset_to_switchable_call_miss_entrypoint`
  - `4`: `set_to_zero`

The low four bits encode the entry type. The next bit encodes patchability. The
next three bits encode snapshot behavior.

Example from `-HHH`:

```text
[931] pool_off=0x1d27 pp_off=0x1d28 bits=0x02 type=native_function patch=patchable behavior=snapshotable stream=0x385d35
```

This decodes as:

- `bits=0x02`: entry type `2`, so `native_function`
- patch bit `0`: `patchable`
- snapshot behavior `0`: `snapshotable`
- `pool_off=0x1d27`: the VM's ObjectPool offset form for this slot
- `pp_off=0x1d28`: the offset normally observed in PP-relative code loads

r2flutter prints both offsets because the serialized ObjectPool layout and the
machine-code PP addressing convention use adjacent offset forms. The `pp_off`
value is the one to compare with `ldr ..., [x27, #imm]` instructions.

For `kNativeFunction`, snapshot serialization writes the entry bits but writes
no payload value. During deserialization the VM initializes the slot with
`NativeEntry::LinkNativeCallEntry()`, a lazy native-call linker. The first call
can resolve the real native target and patch the call site or pool slot.

That means a static `native_function` ObjectPool entry is not itself a pointer
to the final native target. It tells us "this slot participates in VM native
call resolution", not "this slot imports symbol X from library Y".

## Patchable Meaning

`patchable` means the VM is allowed to rewrite the entry or the call site after
loading or after first execution. This is common for lazy native calls because
the VM starts with a linker entry and later installs the resolved target and the
right trampoline.

`not_patchable` means the compiler/VM expects the value to stay stable after
setup. It does not mean "more static" in the sense of being easier to name; it
only describes the runtime mutation policy for that ObjectPool entry.

For static analysis, a patchable `native_function` should be reported as a
candidate with no concrete target address unless we can correlate it with other
metadata or runtime information.

## Is It Like an Import Table?

Only partially.

A normal ELF/Mach-O/PE import table is owned by the platform loader. It maps
external symbol names to relocation slots and can usually tell us the imported
library and symbol name.

Dart FFI and VM native calls add extra layers:

- `DynamicLibrary.open("libfoo.so")` plus `lookup("bar")` is import-like, but
  the string lookup happens in Dart code at runtime.
- `DynamicLibrary.process()` and `DynamicLibrary.executable()` have no library
  path string and resolve against process/executable visibility.
- `@Native` may resolve through a native asset ID, an embedder-provided native
  assets table, a `Dart_SetFfiNativeResolver` callback, or process lookup.
- ObjectPool `native_function` entries store no symbol payload in the snapshot.
- VM bootstrap natives and runtime helpers may be resolved through VM resolver
  tables, not the binary's loader imports.

So `native_function` is an import-like signal, but it is not equivalent to an
ELF/Mach-O import entry. A good r2flutter report should keep loader imports,
FFI lookups, `@Native` declarations, and ObjectPool native-function slots as
separate evidence sources.

## What Names Can Be Found Statically

The following sources can expose library or symbol names:

- loader imports from radare2/RBin (`ii`, `iij`): useful for actual platform
  imports, Dart API exports, plugin registrants, and dynamic-loader calls
- Dart strings in the AOT snapshot: `libfoo.so`, `foo.framework/foo`,
  `libfoo.dylib`, `kernel32.dll`, `bar_symbol`, asset IDs, package URIs
- calls or object-pool references to `DynamicLibrary.open`, `process`,
  `executable`, `lookup`, `lookupFunction`, and `providesSymbol`
- `@Native` annotation data: `symbol`, `assetId`, `DefaultAsset`, and function
  names when the symbol defaults to the declaration name
- native-assets metadata: asset IDs and possibly resolved paths, depending on
  what is serialized and what the embedder supplies
- ObjectPool entry details: `native_function` slots, `tagged_object` strings,
  `immediate` code/stub values, and PP offsets used by machine code
- FFI callback metadata: `FfiTrampolineData` stores callback IDs and function
  kind values for native-to-Dart callbacks

The strongest static case is:

1. a constant library path string reaches `DynamicLibrary.open`,
2. a constant symbol string reaches `lookup` or `lookupFunction`,
3. a call site uses the returned pointer/function,
4. the same symbol is present in a loaded binary's export table or imports.

The weakest static case is:

1. a `native_function` ObjectPool slot appears,
2. no nearby strings or function metadata identify it,
3. no runtime resolver table is available.

In that weak case we can report a native-call candidate and PP offset, but not a
symbol or library name.

## Static Recovery Workflow

A practical static pipeline for r2flutter should be:

1. Decode the AOT header and cluster layout.
2. Decode ObjectPool fill payloads when the snapshot version/layout is
   supported.
3. Build an ObjectPool slot map keyed by pool index, `pool_off`, and `pp_off`.
4. Decode or reference tagged string objects reachable from ObjectPool entries.
5. Scan code for PP-relative loads and indirect calls using the existing
   AArch64 analysis path.
6. Correlate call sites with ObjectPool slots and nearby string loads.
7. Search for strings that look like dynamic libraries, asset IDs, and C symbol
   names.
8. Correlate those strings with Dart FFI API names and recovered function names.
9. Merge in loader import/export information from RBin.
10. Emit candidates with confidence, not as unconditional facts.

Confidence should be explicit. For example:

- `high`: constant `DynamicLibrary.open` path and constant `lookupFunction`
  symbol are both recovered and tied to a call site
- `medium`: symbol string is adjacent to a `lookup` use, but library handle is
  `process` or unknown
- `low`: ObjectPool slot is `native_function`, but no symbol string is attached
- `runtime_only`: resolver/native-assets path requires runtime embedder data

## Current r2flutter State

`-HHH` now gives the low-level structure needed for this work. For ObjectPool
clusters whose fill range has been parsed, it can emit entries like:

```text
type=native_function patch=patchable behavior=snapshotable pool_off=... pp_off=...
```

If an ObjectPool allocation exists but the fill payload was not parsed, it emits
`object_pool_decode: fill_not_parsed`.

This is structural data. It does not yet name native symbols, identify dynamic
libraries, or build an FFI call graph.

`-x` already works on the code-analysis side: it can collect PP-relative slot
uses, call xrefs, and comments around indirect calls when enough radare2 context
is available. The missing link is a richer ObjectPool and FFI metadata layer to
attach semantic names to those PP offsets.

## CLI Exposure Options

Keep `-HHH` as the structural cluster/object-pool decoder. It should answer
"what is serialized here?" and stay useful even when no semantic inference is
possible.

Add a separate native/FFI report flag. The best short flag is probably `-N`
because it is mnemonic for native and does not overload `-H` or `-x`.

Proposed commands:

```sh
bin/r2flutter -N app.so
bin/r2flutter -j -N app.so
bin/r2flutter -r -N app.so
```

Text output should group by evidence source:

```text
ffi lookup candidates
  symbol=foo library=libbar.so source=dynamic_library_lookup confidence=high
  symbol=baz library=process source=dynamic_library_process confidence=medium

object pool native functions
  pool_ref=123 entry=931 pp_off=0x1d28 source=object_pool confidence=low

native callbacks
  callback_id=7 kind=... source=ffi_trampoline_data confidence=medium
```

JSON output should be stable and machine-readable:

```json
{
  "ffi": [
    {
      "kind": "lookup",
      "symbol": "foo",
      "library": "libbar.so",
      "library_kind": "open",
      "source": "dynamic_library_lookup",
      "confidence": "high",
      "pool_ref": 123,
      "pool_index": 931,
      "pp_offset": 7464,
      "callsites": [4198400]
    }
  ],
  "native_functions": [
    {
      "kind": "object_pool_native_function",
      "pool_ref": 123,
      "pool_index": 931,
      "pool_offset": 7463,
      "pp_offset": 7464,
      "patch": "patchable",
      "behavior": "snapshotable",
      "confidence": "low"
    }
  ]
}
```

Radare2 output should create flags and comments rather than pretending these are
real loader imports:

```text
f dart.ffi.lookup.foo @ 0x...
CCu base64:<symbol/library note> @ 0x...
f dart.pool.native.123.931 @ 0x...
CC Dart ObjectPool native_function pp_off=0x1d28 patchable snapshotable @ 0x...
```

For the core plugin, mirror the CLI spelling:

```text
r2flutter -N
r2flutter -j -N
r2flutter -r -N
```

The plugin can also use live `RCore` data to improve the report:

- RBin imports/exports for the current binary
- flags already created for Dart functions/classes/strings
- `anal.gp` when the user has provided the ObjectPool base
- disassembly and xref information from the current radare2 analysis session

## Why Not Put This Only in `-x`

`-x` is about xrefs: code-to-code, code-to-pool, and code-to-object
relationships. FFI/native reporting is a higher-level correlation problem that
mixes ObjectPool entries, Dart strings, API calls, loader imports, and native
asset metadata.

`-x` should consume FFI information once it exists. For example, an indirect
call through a known FFI symbol can get a better comment. But the discovery and
reporting of FFI candidates should live behind a dedicated native/FFI command.

## Why Not Put This Only in `-HHH`

`-HHH` should remain a bounded structural decoder for the AOT file. It is the
right place to show:

- cluster order and ranges
- ObjectPool allocation/fill status
- ObjectPool entry bits
- `pool_off` and `pp_off`
- raw references or immediates present in the serialized stream

It is not the right place to decide that a string is definitely a C symbol or
that an ObjectPool slot is definitely `libfoo.so!bar`. Those claims require
cross-correlation with code and loader data.

## Recommended Implementation Plan

1. Extend the ObjectPool decoder into a reusable internal table, not only
   `-HHH` rendering.
2. Add a string classifier for likely library paths, asset IDs, and C symbols.
3. Add a native candidate model with fields for source, confidence, pool slot,
   symbol, library, callsites, and notes.
4. Teach the code-analysis pass to attach PP-relative callsites to ObjectPool
   slots.
5. Add `dart_pool_dump_native (ctx, fmt)` for CLI text/JSON/r2 output.
6. Add `-N` to `bin/r2flutter` and `r2flutter -N` to the core plugin.
7. Keep `-HHH` output unchanged except for future low-level entry fields.
8. Add small r2r fixtures for JSON shape and one text smoke test.

This sequence lets `-HHH` keep serving as the manual reasoning tool while `-N`
becomes the higher-level report.

## Limitations

Obfuscation can hide Dart function and class names, but literal FFI symbol
strings often remain because the native loader needs exact names.

Tree shaking can remove unused FFI bindings and strings.

Dynamic string construction can hide library and symbol names from simple
constant scanning.

`DynamicLibrary.process()` and `DynamicLibrary.executable()` intentionally avoid
a concrete library path.

Native-assets and `Dart_SetFfiNativeResolver` may depend on embedder data that
is not serialized in the AOT snapshot.

The platform binary may be stripped, so even a resolved native address may not
map back to a symbol name.

Some Flutter plugin calls are not Dart FFI at all. They can go through platform
channels, JNI, Objective-C/Swift, or generated registrant code. Those should be
reported separately from `dart:ffi`.

## Useful Local Sources

- `third_party/sdk/sdk/lib/ffi/dynamic_library.dart`
- `third_party/sdk/sdk/lib/ffi/ffi.dart`
- `third_party/sdk/runtime/lib/ffi_dynamic_library.cc`
- `third_party/sdk/runtime/vm/compiler/assembler/object_pool_builder.h`
- `third_party/sdk/runtime/vm/app_snapshot.cc`
- `third_party/sdk/runtime/vm/native_entry.cc`
- `doc/xrefs.md`
- `doc/objpool.md`
- `doc/learn.md`
