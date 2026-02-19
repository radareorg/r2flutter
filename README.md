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
- Uses radare2 to locate AOT snapshot symbols within ELF64
- Emits `addNames.r2` and `r2_dart_struct.h`

## Supported Dart/Flutter Versions

r2flutter supports Dart AOT snapshots from **Dart 2.10.0 to 3.10.7** (Flutter 1.22.x to 3.38.x):

| Dart Version | Flutter Version | Tag Style | Notes |
|--------------|-----------------|-----------|-------|
| 2.10.0 | 1.22.x | Int32 CID | Pre-FunctionType split |
| 2.13.0 | 2.2.x - 2.3.x | Int32 CID | Split canonical clusters |
| 2.14.0 | 2.4.x - 2.5.x | CID Shift1 | TypeParameters added |
| 2.15.0 | 2.6.x - 2.7.x | CID Shift1 | NativePointer inserted |
| 2.16.0 | 2.8.x - 2.16.x | CID Shift1 | ConstMap/ConstSet added |
| 2.17.6 | 2.17.x | CID Shift1 | WeakReference added |
| 2.18.0 | 3.3.x | CID Shift1 | SuspendState added |
| 2.19.0 | 3.7.x | CID Shift1 | RecordType/Record added |
| 3.0.5 | 3.10.x - 3.12.x | CID Shift1 | WeakArray added |
| 3.1.0 | 3.13.x | CID Shift1 | TypeRef removed |
| 3.2.5 | 3.16.x | CID Shift1 | PoolType swapped |
| 3.3.0 | 3.19.x | CID Shift1 | Last Shift1 format |
| 3.4.3 | 3.22.x | ObjectHeader | New tag encoding |
| 3.5.0 | 3.24.x | ObjectHeader | |
| 3.6.2 | 3.27.x | ObjectHeader | |
| 3.7.0 | 3.29.x | ObjectHeader | |
| 3.8.1 | 3.32.x | ObjectHeader | |
| 3.9.2 | 3.35.x | ObjectHeader | |
| 3.10.7 | 3.38.x | ObjectHeader | Current latest |

Unknown snapshot hashes default to v3.9.2 profile with ObjectHeader tag encoding.

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
$ bin/r2flutter
Usage: bin/r2flutter [options] <libapp_path_or_dir>
Modifiers:
  -h, --help       Show help
  -V, --version    Show version
  -v               Verbose (stderr info)
  -vv              More verbose (dump headers)
  -j               Output in JSON format
  -r               Output in radare2 format
  -q               Quiet mode (suppress non-essential output)
  -n               Do not emit radare2 flags/script to stdout
Actions:
  --dump-strings   Print all extracted strings
  --dump-classes   Print extracted class information
  --dump-types     Print string-based type names
  --dump-header    Print Dart AOT snapshot header info
  --dump-fns N     Print first N functions (addr name)
  --dump-it        Print instruction table entry addresses to stderr
Options:
  --no-stubs       Do not emit ELF/r2 stub functions
  --use-name-pool  Assign names from data image strings when unknown
  --dump-fields    Include field details in class output
$
```

## Dependencies

- radare2 (with development headers)
- pkg-config

## Other Projects

- https://github.com/dart-lang/sdk
- https://github.com/worawit/blutter
- https://github.com/zboralski/unflutter
- https://github.com/Impact-I/reFlutter
