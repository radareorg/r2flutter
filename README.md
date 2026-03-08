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
  -h, --help            Show help
  -j                    Output in JSON format
  -r                    Output in radare2 format
  -V, --version         Show version
  -v                    Verbose (stderr debug info)
  -vv                   More verbose (dump headers)
Actions:
  --dump-classes        Print extracted class information
  --dump-funcs          Print all extracted functions (addr name)
  --dump-header         Print Dart AOT snapshot header info
  --dump-it             Print instruction table entries to stdout
  --dump-r2script       Print radare2 script for snapshot analysis
  --dump-strings        Print all extracted strings
  --dump-types          Print string-based type names
Options:
  --no-stubs            Do not emit ELF/r2 stub functions
  --limit <N>           Limit output to N items (applies to dump-funcs, dump-it, etc.)
  --use-name-pool       Assign names from data image strings when unknown
```

`--dump-it` honors the global format modifiers:

```bash
bin/r2flutter --dump-it test/bins/ios/Runner.app
bin/r2flutter -j --limit 16 --dump-it test/bins/ios/Runner.app
bin/r2flutter -r --limit 16 --dump-it test/bins/ios/Runner.app
```

## Dependencies

- radare2 (with development headers)
- pkg-config

## Other Projects

- https://github.com/dart-lang/sdk
- https://github.com/worawit/blutter
- https://github.com/zboralski/unflutter
- https://github.com/Impact-I/reFlutter
