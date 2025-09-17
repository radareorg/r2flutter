Agent Notes for r2flutter Work

Scope
- This document is for agents working in this repo to implement and iterate on the Dart AOT snapshot/ObjectPool parser and CLI.

Build
- Requires radare2 dev headers (`r_core`) and `pkg-config`.
- Build with `make` (uses pkg-config to resolve r2 includes/libs).

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

CLI Flags (debugging)
- `-v` / `-vv`: increase stderr verbosity for snapshot discovery.
- `--no-stubs`: skip emitting ELF/r2 stub functions.
- `--dump-snapshot-json`: emit one JSON line with snapshot + cluster info.
- `--dump-it`: print InstructionTable index→address pairs to stderr.
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
