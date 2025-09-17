# Blutter R2C - Dart AOT via Constant Pool

This utility integrates with radare2 but does NOT rely on r2 analysis (afl/aflj).
It is self-contained C code (no Dart VM headers or libs) and will read the Dart
snapshots/constant pool directly to derive names and addresses.

## Features

- Derives names/addresses from Dart constant pool (no afl parsing)
- Uses radare2 to locate AOT snapshot symbols within ELF64
- Emits `addNames.r2` and `r2_dart_struct.h`

## Building

```bash
make
```

## Usage

```bash
./blutter_r2 [options] <libapp_path_or_dir>
```

Options

- `-h`, `--help`: Show help
- `-V`, `--version`: Show version
- `-v` / `-vv`: Increase verbosity on stderr (prints snapshot hash, header info)
- `--no-stubs`: Do not emit ELF/r2 stub functions into the output
- `--dump-snapshot-json`: Print a single-line JSON with snapshot header and clustered header fields
- `--dump-it`: Print InstructionTable indices and resolved addresses to stderr

## Dependencies

- radare2 (with development headers)
- pkg-config

## Architecture

- `main.c` - CLI entry, opens file with radare2
- `dart_app.c` - App model and integration
 - `dart_pool_parse.c` - Standalone parser entry (finds snapshot blobs via r2; WIP: decodes clustered snapshot/ObjectPool and emits function entrypoints)
- `dart_dumper.c` - Emits radare2 scripts and pool offset flags (via PP/x27)

## Current Status

This component sources names from the Dart ObjectPool (work-in-progress), mirroring
`./blutter`, without using afl or depending on Dart VM.
