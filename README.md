# Blutter R2C - Pure C Implementation

This is a pure C reimplementation of the Blutter Dart analysis tool that integrates with radare2.

## Features

- Pure C implementation (no C++ dependencies)
- Integrates with radare2 APIs
- Performs Dump4Radare2 functionality
- Creates radare2 flags for Dart libraries, classes, and methods

## Building

```bash
make
```

## Usage

```bash
./blutter_r2 <libapp_path> <output_directory>
```

## Dependencies

- radare2 (with development headers)
- pkg-config

## Architecture

- `main.c` - Main entry point
- `dart_app.c` - DartApp functionality
- `dart_dumper.c` - Dumping functionality for radare2

## Current Status

This is a basic skeleton implementation that:
- Initializes radare2 core
- Loads binary files
- Creates basic flags for demonstration
- Provides framework for full Dart analysis

The full implementation would require:
- Parsing Dart VM structures
- Analyzing Dart classes and functions
- Implementing complete Dump4Radare2 functionality