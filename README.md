# r2flutter

<p align="center">
  <img width="160" src="doc/images/r2flutter500.png" alt="r2flutter logo" />
</p>

[![ci](https://github.com/trufae/r2flutter/actions/workflows/ci.yml/badge.svg)](https://github.com/trufae/r2flutter/actions/workflows/ci.yml)

**r2flutter brings Dart and Flutter AOT awareness to [radare2](https://rada.re/).**
It reads the snapshots embedded in release builds and turns their metadata into
useful names, addresses, strings, classes, and references for reverse
engineering. It is available both as the `bin/r2flutter` command-line tool and
as an `r2flutter` command inside radare2.

Give it an extracted Android `libapp.so`, an Android directory containing one,
an iOS `.app` bundle, or a direct AOT binary. AArch64 is the primary analysis
target. The parser has in-tree layouts for Dart 2.10 through 3.12; see the
[support matrix](doc/support.md) for platform and version details.

## What it can do

- Find Dart AOT snapshots in Flutter apps and supported standalone Dart
  containers.
- Recover snapshot headers, functions, classes, fields, type names, strings,
  ObjectPool values, instruction-table entries, and metadata references.
- Apply recovered names, flags, comments, classes, and code references to a
  radare2 session.
- Emit readable text, JSON for automation, or radare2 commands for importing
  into another session.
- Use Flutter's `--save-obfuscation-map` output to restore recovered names.

r2flutter is a metadata and analysis aid, not a Dart source-code decompiler.
Recovery depends on what survived in the AOT snapshot, so some names and
references are necessarily best effort.

## Build and install

You need a recent `radare2` installation, including its development headers,
and `r2` must be on `PATH`. The build obtains the required flags from `r2 -H`.

```sh
git clone https://github.com/trufae/r2flutter.git
cd r2flutter
make
```

The command-line tool is now ready at `bin/r2flutter`.

To install the radare2 plugin for your user account:

```sh
make user-install
```

For a system-wide command-line tool and plugin, build the plugin first and
then use the usual install prefix:

```sh
make r2
sudo make install
```

## First look at an app

Start with the snapshot header. It confirms that r2flutter found a Dart AOT
image and shows the detected Dart profile:

```sh
bin/r2flutter -H path/to/libapp.so
```

Then try a small, practical extraction:

```sh
# Recovered Dart function entrypoints and names
bin/r2flutter -f path/to/libapp.so

# A compact JSON header, useful for scripts
bin/r2flutter -jH path/to/libapp.so

# The first 20 instruction-table entries
bin/r2flutter -l 20 -i path/to/libapp.so
```

Directory and bundle inputs work too. For example, pass an Android directory
containing `libapp.so`, or an iOS `Runner.app` bundle directly.

After `make user-install`, open the same binary in radare2 and apply the Dart
metadata to the analysis session:

```sh
r2 -q path/to/libapp.so
> r2flutter -AAA
> afl~method
```

`-AAA` is the Dart-aware analysis pass. For a concise list of every action and
output modifier, run `bin/r2flutter -h` or `r2flutter -h` inside radare2.

## Learn more

- [Support matrix](doc/support.md) — accepted containers, platform scope, and
  Dart layout coverage.
- [AuthPass walkthrough](doc/tuto-authpass.md) — a complete iOS AOT analysis
  example using recovered method names in radare2.
- [ObjectPool internals](doc/objpool.md) and [instruction-table entries](doc/its.md)
  — the two central structures behind function and constant recovery.
- [Strings](doc/strings.md) and [cross references](doc/xrefs.md) — what can be
  recovered and how reliable each result is.
- [Flutter obfuscation maps](doc/obfuscate.md) — restore names from a map
  produced during a Flutter build.

## Related projects

- [Dart SDK](https://github.com/dart-lang/sdk)
- [blutter](https://github.com/worawit/blutter)
- [unflutter](https://github.com/zboralski/unflutter)
- [reFlutter](https://github.com/Impact-I/reFlutter)

Released under the [MIT license](LICENSE.txt).
