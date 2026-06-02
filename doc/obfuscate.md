# Flutter Obfuscation Maps

Flutter AOT builds produced with `--obfuscate` can also emit a rename map with `--save-obfuscation-map=<file>`. The file format is a JSON array of alternating original and obfuscated names:

```json
["OriginalName", "a", "OtherSymbol", "b"]
```

## r2flutter

Use either flag:

```sh
bin/r2flutter -o path/to/map.json -f test/bins/ios/Runner.app
bin/r2flutter -o path/to/map.json -i test/bins/android/first
```

When a map is provided, r2flutter deobfuscates recovered function names, instruction-table names, class names, field names, and method owner/name pairs. Raw string extraction is left untouched so `-z` continues to report what is physically stored in the binary.
