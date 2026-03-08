Agent Notes for r2flutter Work

Scope
- This document is for agents working in this repo to implement and iterate on the Dart AOT snapshot/ObjectPool parser and CLI.

Build
- Requires radare2 dev headers (`r_core`) and `pkg-config`.
- Build with `make` (uses pkg-config to resolve r2 includes/libs).
- Do not build with gcc oneliners, always use `make`
- Run `make fmt` to format/indent the source code

Usage
- Use bin/r2flutter cli program to test the changes and implementation of the dart aot snapshots
- Update doc/learn.md to record anotations and important findings and discoveries while solving more tasks
- When using radare2 to read the raw contents of a file you should use `r2 -n` to not load the sections and actually read physical address instead of the virtual mapped ones.

Coding Rules
- `R_NEW`/`R_NEW0` macros never return NULL
- Do not check for null before calling free methods
- The `r_json_parse` does not own the string passed, we must free it after freeing the parser
- Function calls require a space before the parenthesis. (p.ex: Use `foo ()` instead of `foo()`)
- Use tabs instead of spaces to indent the code
- Follow the `radare2` coding style

Reference Sources
- Third party code is found in the `./third_party` directory
- radare2 source code `./third_party/radare2` see the `libr/include` directory for the headers
- blutter is the original project in python+c++ that we used as inspiration for this project. the source code is in `./third_party/blutter`
- dart and its VM are also available in there

Tests
- Uses r2r to run tests in `test/db`.
- The `test/bins` directory contains android and ios binaries for testing the implementation
- Run with `make test` which wraps `r2r test/db` in a Python timeout (180s) to avoid hanging on heavy samples.
- Add each new test as a single file under `test/db/cmd/`.
  - Example: `test/db/cmd/json-android` runs the CLI and expects a single JSON line.
- It's important to ensure the behaviour is correct on both iOS and Android binaries before accepting a fix

CLI Flags (debugging)
- `-v` / `-vv`: increase stderr verbosity for snapshot discovery.
- `--no-stubs`: skip emitting ELF/r2 stub functions.
- `-j --dump-header`: emit one JSON line with snapshot + cluster info.
- `--dump-it`: print InstructionTable entries to stdout. Supports plain text, `-j`, and `-r`.
- `--quiet`: suppress non-essential stdout (handy for JSON-only tests).
- `--no-dump`: suppress printing radare2 flags/script.

Iteration Loop
1) Implement a focused change (parser or flags), build with `make`.
2) Add a minimal r2r test exercising the new behavior under `test/db/cmd/`.
3) Run `make test` to validate. If it times out, reduce test output (use `--quiet`, `--no-dump`).
4) When failures occur, use the debug flags (`-v`, `-vv`, `--dump-it`) and small inputs to triage. Adjust parser heuristics accordingly.
5) Keep tests deterministic: prefer single-line stable outputs and avoid large dumps.

Parser Notes
- Snapshot discovery prefers symbol names, then falls back to section scan+magic.
- InstructionTable decoding reconstructs entrypoints for AOT bare-instructions.
- Offsets/layout can be enriched via `offsets.json` keyed by snapshot hash.
- Keep memory reads bounded and walk headers conservatively to avoid large reads.

Links Of Interest:
- https://mrale.ph/dartvm/
