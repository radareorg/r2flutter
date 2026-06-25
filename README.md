# r2flutter - Dart/Flutter support for Radare2

<p>
<img border="0" align="left" width="125px" height="125px" src="doc/images/r2flutter500.png" />

[![ci](https://github.com/trufae/r2flutter/actions/workflows/ci.yml/badge.svg)](https://github.com/trufae/r2flutter/actions/workflows/ci.yml)

<br />
The default parser uses radare2 for binary loading but does not rely on existing
r2 analysis (`afl`/`aflj`); Dart-aware code analysis is opt-in with `-AAA`. The
Dart parser is self-contained C code (no Dart VM headers or libs) and reads AOT
snapshots, data images, clusters, ObjectPool records, and instruction tables
directly.
</p>

## Features

- Support iOS and Android Flutter apps
- Accepts direct binaries, Android directories with `libapp.so`, and iOS `.app`
  bundles with `Frameworks/App.framework/App`
- Derives names/addresses from Dart snapshots, data images, clusters,
  ObjectPool records, and instruction tables
- Recovers snapshot headers, functions, classes, fields, string refs, xrefs,
  reconstructed ObjectPool PP data, and best-effort SBOM/component reports
- Uses radare2 for binary loading while keeping the Dart parser self-contained
- Prints text, JSON, or radare2 command output for supported dump actions

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
  -n                    Heuristic fallback for unknown functions; may assign wrong names
  -q                    Compact output; suppress non-essential detail
  -r                    Output r2 commands for the selected action
  -v                    Verbose (stderr debug info)
  -vv                   More verbose (dump headers)
  -V                    Show version
Actions:
  -A                    Analyze Dart snapshot and apply flags/comments
  -AA                   Analyze with field extraction enabled
  -AAA                  Run Dart-aware code analysis and recover code refs
  -c                    Print extracted class information
  -f                    Print all extracted functions (addr name)
  -H                    Print Dart AOT snapshot header info
  -HH                   Print extended snapshot header and cluster layout
  -HHH                  Decode selected cluster payloads for diagnostics
  -i                    Print instruction table entries to stdout
  -O <addr|pp+off>      Decode Dart tagged/object pointer or ObjectPool PP slot
  -p                    Print reconstructed ObjectPool PP value
  -R                    Print radare2 script for snapshot analysis
  -S                    Print best-effort recovered SBOM/components
  -T                    Print string-based type names
  -x                    Print metadata/data-image xrefs; with -z, include string refs/ax in -r
  -z                    Print reliable ObjectPool-referenced strings (-q prints values only)
  -zz                   Print all fuzzy/carved extracted strings (-xzz includes refs/ax in -r)
Options:
  -D <hash|version>     Override Dart snapshot profile for analysis
  -l <N>                Limit output to N items
  -m <file>             Load Flutter obfuscation map JSON
```

`bin/r2flutter` runs one action per invocation. Directory inputs resolve Android
first (`libapp.so`), then iOS (`Frameworks/App.framework/App`).

`-f` and the `-A` analysis flow skip loader-provided ELF/Mach-O stub symbols; radare2 already gets those from `RBin`, so `r2flutter` stays focused on Dart-derived metadata.

`-m` consumes the JSON array emitted by Flutter/Dart `--save-obfuscation-map`. r2flutter inverts that mapping and applies it to recovered functions, instruction-table names, classes, fields, and method owners.

`-n` is intentionally opt-in. It consumes `package:` and `dart:` strings from the data image as a sequential fallback for otherwise unnamed functions, so it can produce plausible but incorrect names when the string order does not match the instruction table.

`-D` forces the Dart profile used for layout/CID decoding without patching the
input binary. Pass either a known 32-byte snapshot hash or a supported Dart
version such as `3.8.1`.

`-S` emits a best-effort recovered component report, not a complete dependency
inventory. JSON output uses `format: "r2flutter-recovered-sbom"` and
`complete: false`; package versions are usually `null` unless explicit packaged
metadata such as `pubspec.lock`, `.dart_tool/package_config.json`, or framework
`Info.plist` survived in the input bundle.

Dump actions honor the global format modifiers:

```bash
bin/r2flutter -i test/bins/ios/Runner.app
bin/r2flutter -j -l 16 -i test/bins/ios/Runner.app
bin/r2flutter -r -l 16 -i test/bins/ios/Runner.app
bin/r2flutter -jS test/bins/ios/Runner.app
bin/r2flutter -HHH -l 36 test/bins/android/mafia/libapp.so
bin/r2flutter -O pp+0x68 test/bins/android/mafia/libapp.so
bin/r2flutter -qrz test/bins/ios/Runner.app
bin/r2flutter -rz test/bins/ios/Runner.app
bin/r2flutter -rzz test/bins/ios/Runner.app
```

## radare2 Plugin

`make user-install` installs the core plugin command as `r2flutter`. Inside r2,
the same modifiers apply to dump actions:

```text
r2flutter -A       analyze and apply flags/comments
r2flutter -AA      analyze with field extraction enabled
r2flutter -AAA     run Dart-aware code analysis and recover refs/comments
r2flutter -C       apply Dart classes, fields, methods and types
r2flutter -D 3.8.1  override Dart snapshot profile for analysis
r2flutter -jS      print recovered components/SBOM as JSON
r2flutter -r -p    map a synthetic ObjectPool and set anal.gp/x27
```

Plugin config keys:

- `r2flutter.mapfile`: Flutter obfuscation map JSON path
- `r2flutter.namepool`: enable heuristic name-pool fallback
- `r2flutter.profile`: override Dart profile by snapshot hash or Dart version

## Dependencies

- radare2 (with development headers)
- pkg-config

## Other Projects

- https://github.com/dart-lang/sdk
- https://github.com/worawit/blutter
- https://github.com/zboralski/unflutter
- https://github.com/Impact-I/reFlutter
