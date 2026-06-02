# r2flutter - Dart/Flutter support for Radare2

<p>
<img border="0" align="left" width="125px" height="125px" src="doc/images/r2flutter500.png" />

[![ci](https://github.com/trufae/r2flutter/actions/workflows/ci.yml/badge.svg)](https://github.com/trufae/r2flutter/actions/workflows/ci.yml)

<br />
This utility integrates with radare2 but does NOT rely on r2 analysis (afl/aflj).
It is self-contained C code (no Dart VM headers or libs) and will read the Dart
snapshots/constant pool directly to derive names and addresses.
</p>

## Features

- Support iOS and Android Flutter apps
- Derives names/addresses from Dart constant pool (no afl parsing)
- Uses radare2 to locate AOT snapshot symbols within ELF64 and Mach-O binaries
- Emits `addNames.r2` and `r2_dart_struct.h`

## Supported Dart/Flutter Versions

r2flutter supports Dart AOT snapshots from **Dart 2.10.0 to 3.10.7** (Flutter 1.22.x to 3.38.x).

The detailed support matrix, including tag-style changes and Android/iOS-specific notes, lives in [doc/support.md](doc/support.md).

Unknown snapshot hashes default to the v3.9.2 profile with ObjectHeader tag encoding.

## Building

This project can be used from the system shell or directly integrated inside radare2:

```bash
make
```

To get the plugin inside your r2 shell do that:

```bash
make user-install
```

## Usage

```bash
Usage: bin/r2flutter [options] <libapp_path_or_dir>
Modifiers:
  -h                    Show help
  -j                    Output in JSON format
  -r                    Format output for r2 commands
  -V                    Show version
  -q                    Suppress non-essential output
  -v                    Verbose (stderr debug info)
  -vv                   More verbose (dump headers)
Actions:
  -c                    Print extracted class information
  -f                    Print all extracted functions (addr name)
  -H                    Print Dart AOT snapshot header info
  -i                    Print instruction table entries to stdout
  -R                    Print radare2 script for snapshot analysis
  -T                    Print string-based type names
  -x                    Print metadata/data-image xrefs
  -z                    Print all extracted strings
Options:
  -l <N>                Limit output to N items
  -n                    Heuristic fallback for unknown functions; may assign wrong names
  -o <file>             Load Flutter obfuscation map JSON
```

`-f` and the default analysis flow skip loader-provided ELF/Mach-O stub symbols; radare2 already gets those from `RBin`, so `r2flutter` stays focused on Dart-derived metadata.

`-o` consumes the JSON array emitted by Flutter/Dart `--save-obfuscation-map`. r2flutter inverts that mapping and applies it to recovered functions, instruction-table names, classes, fields, and method owners.

`-n` is intentionally opt-in. It consumes `package:` and `dart:` strings from the data image as a sequential fallback for otherwise unnamed functions, so it can produce plausible but incorrect names when the string order does not match the instruction table.

`-i` honors the global format modifiers:

```bash
bin/r2flutter -i test/bins/ios/Runner.app
bin/r2flutter -j -l 16 -i test/bins/ios/Runner.app
bin/r2flutter -r -l 16 -i test/bins/ios/Runner.app
```

## Dependencies

- radare2 (with development headers)
- pkg-config

## Other Projects

- https://github.com/dart-lang/sdk
- https://github.com/worawit/blutter
- https://github.com/zboralski/unflutter
- https://github.com/Impact-I/reFlutter
