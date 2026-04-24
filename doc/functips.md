# FUNCTIPS — Function Listing In r2flutter

Practical notes for anyone touching `--dump-funcs`, the InstructionsTable path, or the cluster-based name recovery in r2flutter. Captures what I learned while fixing the `fix-funcs` branch on the Dart 3.8.1 / Android arm64 testcase (`poc/app/libapp.so`, snapshot `830f4f59e7969c70b595182826435c19`), plus the follow-ups that are deliberately left for future sessions.

## 1. Ground truth and how to diff

**Use blutter's `ida_script/addNames.py` as the golden list, not the `asm/` tree.**

- `asm/` only emits files whose library URL starts with `package:`. It silently drops `dart:core`, `dart:async`, `dart:typed_data`, `dart:_internal`, and every VM / shared stub. Diffing against `asm/` produced ≈7,500 phantom "blutter-only" addresses that vanish once you switch to `addNames.py`.
- `addNames.py` has one `ida_funcs.add_func(<start>,<end>)` line per Code object blutter recognizes (user functions + allocate stubs + type test stubs + VM stubs + closures). Each is followed by `idaapi.set_name(<addr>, "...")`.

Canonical extraction:

```
grep '^ida_funcs.add_func'   ida_script/addNames.py | awk -F'[(,)]' '{print $2}' | sort -u > /tmp/bl_addrs.txt
grep '^idaapi.set_name'      ida_script/addNames.py | sed 's/idaapi.set_name(\(0x[0-9a-f]*\), "\(.*\)")/\1 \2/' > /tmp/bl_named.txt
```

Compare:

```
./bin/r2flutter --dump-funcs poc/app/libapp.so 2>/dev/null | awk '{print $1}' | sort -u > /tmp/rf_addrs.txt
comm -12 /tmp/bl_addrs.txt /tmp/rf_addrs.txt | wc -l   # common
comm -23 /tmp/bl_addrs.txt /tmp/rf_addrs.txt | wc -l   # r2flutter misses
comm -13 /tmp/bl_addrs.txt /tmp/rf_addrs.txt | wc -l   # r2flutter invents
```

Expected ballpark on `poc/app`: ≈26,100 common, 473 blutter-only (VM stubs before `iso_instr`), 295 r2flutter-only (`dyn:` trampolines).

## 2. Why blutter is version-locked

Blutter is not a static parser. `DartLoader::Load` calls `Dart_SetVMFlags` → `Dart_Initialize` → `Dart_CreateIsolateGroup`, handing the linked `libdartvm<ver>_<os>_<arch>.a` the snapshot buffers. The VM refuses to deserialize unless:

1. the `DART_SDK_HASH` compiled into the VM matches the 32-char hash in the snapshot header, **and**
2. the feature-string embedded at `vm_snapshot_data + 0x30` matches the VM's own feature string byte-for-byte (`product no-code_comments ... arm64 android compressed-pointers`).

So the `linux` vs `android` token alone is enough to fail the compatibility check even when the code paths are identical. After deserialization blutter reads objects through inline accessors in the VM's headers — those accessors hard-code struct offsets, hence the per-version `.a` build.

r2flutter never boots Dart, so it has to re-implement the cluster readers it needs. That is what `scan_modern_names_from_clusters` is — a partial deserializer.

## 3. The InstructionsTable is the real function table

On Dart 2.14+ the snapshot embeds an `InstructionsTable` whose `Data` byte-array decodes into `(pc_offset, stack_map_offset)` pairs. Each pair maps to one Code object, which is the unit r2flutter lists as a "function".

Two non-obvious points that bit us:

- `cluster.it_len` in the serialized cluster header is **not** the real length. On `poc/app` it reports 2,953 but the actual IT has 26,413 entries. Trust the `length` field of the `OneByteString` that wraps the `Data` payload in the RO image instead. This is already handled in `locate_it_data_header` / `scan_it_data_header_in_strings`.
- Pre-3.4 snapshots use different tag encodings (`CID_INT32`, `CID_SHIFT1`) and do not have an `InstructionsTable::Data` object — fallback paths are `emit_it_linear` and `emit_it_varint`. The modern fast path is `emit_it_fixed` gated on `modern_is_supported_snapshot`.

## 4. The bug this branch fixed

### Symptom

Running `diff <(r2flutter --dump-funcs) <(blutter addNames.py)` showed ~54% of common addresses with the wrong name. Sampling revealed a pattern:

```
0x6572f0  blutter=AllocateSelectionContainerStub      r2flutter=method.TooltipState._buildTooltipOverlay
0x4ce46c  blutter=AllocateSelectableIconButtonStub    r2flutter=method.VisualDensity.effectiveConstraints
```

Allocate stubs wearing method names, and everything downstream shifted.

### Root cause

The Code cluster decoder recorded `code_owner_ref_by_index[slot] = owner_ref` but never recorded **which cluster that ref came from**. Naming then filtered with:

```c
if (!function_name_ref[owner_ref]) continue;    // SKIP non-Function owners
```

Code objects whose `owner` is a `Class` (allocate stubs) or `AbstractType` (type test stubs) or null (VM stubs) left the corresponding `name_by_code_index[slot]` empty. `resolve_it_entry_name` then happily consumed the next string from `collect_data_names` to fill the slot, so the name pool walked out of phase by one per stub seen. Since there are thousands of allocate stubs, downstream names shifted by thousands.

### Fix

Three changes, all in `src/lib/dart_pool_parse.c` and `include/r2flutter/dart_r2.h`:

- **A. Capture owner cid.** In the Code cluster decode loop, after reading `owner_ref`, resolve it back to a cluster cid by scanning `meta[]` (`meta[m].start_ref <= owner_ref < meta[m].start_ref + meta[m].count`). Store in a local `code_owner_cid_by_index[]`.
- **B. Synthesize names per owner kind.** Rewrite the naming pass so every slot picks a branch:

  | Owner cid                | r2flutter kind          | Synthesized name                               |
  |--------------------------|-------------------------|------------------------------------------------|
  | `modern_cid_function()`  | `DART_OWNER_FUNCTION`   | existing `method.<Class>.<method>`             |
  | `modern_cid_class()`     | `DART_OWNER_CLASS`      | `stub.Allocate<ClassName>Stub`                 |
  | other non-zero           | `DART_OWNER_TYPE`       | `stub.TypeTest_<resolved-name>`                |
  | zero (no owner)          | `DART_OWNER_VM_STUB`    | (left empty here, IT resolver emits `stub.vm_N`) |

  The chosen kind is persisted on `ctx->owner_kind_by_code_index[slot]`.

- **C. Gate the name-pool fallback.** `resolve_it_entry_name` now checks `owner_kind_by_code_index`. The pool is consumed only when the slot is `DART_OWNER_FUNCTION` or `DART_OWNER_UNKNOWN`. Stubs never advance `name_pool_idx`.

### Measurable impact on `poc/app`

```
name_match_ok:   12,448 -> 18,559   (+6,111)
method.fn_ fallbacks:  ~7,500 -> 528
stub.Allocate*:  0 -> 2,475
stub.typetest_*: 0 -> 262
```

All 26 JSON custom tests + 7 r2r tests for the mafia fixture pass. Regression guards added in `test/db/cmd/funcs-mafia` and `test/custom/dump-funcs-stub-naming.json` pin:

- `0x5b6bf4 stub.AllocateDurationStub` (mafia Dart 3.9.0)
- Absence of `0x5b6bf4 method.fn_` at the same address
- Exactly 4,080 `stub.Allocate*` and 395 `stub.typetest_*` entries in the full dump

## 5. Things to keep in mind when touching this code

- `DartCtx.name_by_code_index` and `DartCtx.owner_kind_by_code_index` have identical lifecycles — they are (re)allocated by `scan_modern_names_from_clusters` and freed in the `beach:` label of `decode_pool_and_emit`. If you add a third parallel array, free it in both places.
- `modern_is_supported_snapshot()` gates the OBJECT_HEADER-era path. Anything you add that depends on cluster decoding must either be behind this gate or extend the other two tag-style paths explicitly. Changes here do not affect the `first` fixture (Dart 2.18, CID_SHIFT1).
- The Code cluster owner ref is the first of six ref-ids (`k == 0` in the `for (k=0; k<6; k++)` loop). Don't assume anything about the remaining five — they are intentionally read and discarded in the skip path.
- `meta[].main_count` is the count of "real" Code objects in the cluster. Objects past that are deferred discards; their payload is a single ref_id, not the six-ref group. Get this wrong and the stream desynchronizes on the very next cluster.
- `modern_name_quality` is the reason later passes don't clobber earlier names — it prefers longer / more-dotted names. Synthesized stub names should score lower than real method names so a late Function-cluster pass can overwrite a placeholder if it finds the real owner.
- The `-n` / `no_stubs` CLI flag is about **ELF/Mach-O loader-provided stub symbols** (handled by `RBin`). It has nothing to do with the Dart-level stubs introduced here. Don't conflate them when naming flags.

## 6. Follow-up work (not done on this branch)

### D. Fold `dyn:` trampolines

Symptom: on `poc/app`, r2flutter lists 295 addresses that blutter does not. ≈280 of them are dynamic-entry trampolines — a Dart `Code` object has two entry points (`EntryPoint()` and `UncheckedEntryPoint()`), and the InstructionsTable emits an entry for each, so r2flutter prints the same function twice (once as `method.X.foo`, once as `method.X.dyn:foo`).

Blutter collapses them because it keeps a single `DartFnBase` per `Code` object and folds the second entry into the function's range.

What to change:

- During `modern_skip_fill_code`, preserve the `unchecked_entry_offset` for every main-count slot (currently the loop reads the six ref-ids and drops them on the floor). Store it on a new `ut32 *code_unchecked_entry_off_by_index[]`.
- After IT decode, post-process: if entry `i+1` points at exactly `entry[i].address + unchecked_entry_off`, suppress it (or rename it to the canonical `dyn:` form and mark as an alias of `entry[i]`).
- Add a regression test on `test/bins/android/mafia` that pins the before/after count at `0x5b6b64` / `0x5b6c34` (currently both listed separately as `method.Duration.dyn:*`).

Expected impact: -280 entries on `poc/app`, closer count-parity with blutter.

### E. Name the 473 pre-`iso_instr` VM stubs

`OBJECT_STORE_STUB_CODE_LIST` + `VM_STUB_CODE_LIST` + `SHARED_STUB_CODE_LIST` expand to an ordered list of named stubs that the Dart VM instantiates at startup. Blutter pulls them from `StubCode::` and `ObjectStore` accessors; r2flutter has no equivalent.

Strategy:

- Per Dart major (2.18, 2.19, 3.0, 3.1, 3.2, 3.4, 3.6, 3.8, 3.9, 3.10), run blutter once against a known sample, extract the pairs `(ep_offset_from_iso_instr_start, stub_name)` from `addNames.py`, drop them into a static C table keyed by snapshot hash → version profile.
- On load, walk from `iso_instr` start forward: each stub is a contiguous Code region. The first stub begins at `iso_instr`; subsequent stubs start at `prev_ep + prev_size`. The sizes are known from blutter's output. Emit one function per entry.
- This only matters when `iso_instr` - `vm_instr` is non-empty (Android AOT) — iOS ships a separate `.dylib` for `App.framework/App`.

Expected impact: +473 VM stubs on `poc/app`, closing the count gap to blutter's 26,591.

### F. Resolve closure parents

The `method.*._anon_closure` entries (the "method-name mismatches" that remain after B) should expand to the parent function's name suffix. Blutter does this via `DartFunction::parent` (a second Function pointer stored on the `ClosureData`). r2flutter already reads `closure_parent_ref[data_ref]` but only to tag the closure; it never follows the parent chain.

The fix is small once D is in — during the Function cluster naming pass, when `data_ref` points at a `ClosureData`, build the name as `<parent-full-name>._anon_closure_<index>` instead of the bare `method.<Class>._anon_closure`.

### G. Pre-3.4 snapshots

`modern_is_supported_snapshot` currently returns true only for OBJECT_HEADER + compressed-pointers. The `first` fixture (Dart 2.18, no compressed pointers) falls through to `emit_it_linear`, so it never gets the stub / owner-kind treatment. If we want cross-version parity, `scan_modern_names_from_clusters` needs an equivalent for the `CID_SHIFT1` cluster tag style, with a corresponding `legacy_skip_fill_*` family.

Lower priority because almost no Flutter apps in the wild ship on 2.18 now, but it keeps the `first` test fixture as a meaningful acceptance case rather than a black box.

### H. Cross-tool parity metric

Right now the diff is a handful of ad-hoc `comm` and `awk` invocations. It would be worth committing a `scripts/diff_vs_blutter.py` that takes `--blutter-out <dir>` and `--r2flutter-bin <path>`, runs both, and prints:

```
common:         <n>
blutter-only:   <n>   (top-10 by name prefix)
r2flutter-only: <n>   (top-10 by name prefix)
same-name:      <n>
diff-name:      <n>   (sample 20)
stub classes:   AllocateStub=<n>  TypeStub=<n>  VMStub=<n>
```

…and fails CI if any category regresses past a threshold. That's the only way D/E/F don't silently regress again.

## 7. What does NOT belong in r2flutter

Resist the temptation to reimplement these blutter behaviors — they are either orthogonal to function listing or require the live Dart VM:

- Full type-signature recovery (parameter types, default values). Blutter reads these from `FunctionType` + `TypeParameters` via VM accessors; reconstructing them from the snapshot is possible but large, and buys very little for function *listing*.
- Frida script generation, IDA struct dump, asm-annotated Dart files. These are blutter's output products, not r2flutter's responsibility; r2flutter emits r2-native outputs (flags, comments, symbols) only.
- Object pool walking for field discovery beyond names. Fields belong to `--dump-classes`; keep function listing focused on the Code cluster + InstructionsTable.

Keep `--dump-funcs` tight: one name per Code object, named by owner kind, diffable against blutter. Everything else is a different subcommand.
