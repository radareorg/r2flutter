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
Options:
  -h, --help                 Show help
  -V, --version              Show version
  -v                         Verbose (stderr info)
  -vv                        More verbose (dump headers)
  --no-stubs                 Do not emit ELF/r2 stub functions
  --dump-snapshot-json       Print snapshot header as a single JSON line
  --dump-it                  Print instruction table entry addresses to stderr
  --quiet                    Suppress non-essential stdout (only JSON if requested)
  --no-dump                  Do not emit radare2 flags/script to stdout
  --dump-fns N               Print first N functions (addr name) to stdout
  --use-name-pool            Assign names from data image strings when unknown
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
