# InstructionTable Entries

`-i` dumps entries from Dart's `InstructionsTable::Data`.

## What An "Instruction Table Entry Address" Is

Each entry stores:

- `pc_offset`: an offset relative to the isolate instructions image base (`iso_instr`)
- `stack_map_offset`: an offset into the compressed stack-map payload area

The address printed by `r2flutter` is:

```c
entry_address = iso_instr + pc_offset;
```

That address is the start address the Dart VM uses when it needs to map machine code back to a code range or stack map. In practice, these entries are the VM's indexable view of AOT code entrypoints.

## Why It Matters

The table lets the VM:

- map a program counter back to the owning code range
- recover the matching compressed stack map
- distinguish Dart code entrypoints from the raw instruction blob

For reversing work, this is useful because it gives a stable index -> address list directly from snapshot metadata instead of relying only on disassembly heuristics.

## Output Modes

Plain text:

```bash
bin/r2flutter -i test/bins/ios/Runner.app
```

JSON:

```bash
bin/r2flutter -j -l 16 -i test/bins/ios/Runner.app
```

radare2 flags:

```bash
bin/r2flutter -r -l 16 -i test/bins/ios/Runner.app
```

`-l` is useful because real apps can have thousands of entries.

## Fields Exposed By r2flutter

Plain output shows:

- entry index
- resolved entry address
- entry kind
- best-effort name

JSON also includes:

- `length`
- `first_entry_with_code`
- `canonical_stack_map_entries_offset`
- per-entry `pc_offset`
- per-entry `stack_map_offset`

## Notes

- Output is written to `stdout`, not `stderr`.
- `-j` and `-r` now affect `-i` the same way they affect the other dump commands.
- The current parser finds the table by scanning the mapped data image for a valid `InstructionsTable::Data` header when the snapshot's `it_off` field does not point exactly at the payload start.
