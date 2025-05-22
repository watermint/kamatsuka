# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Kamatsuka is a Rust-based tool for working with Dropbox's Stone DSL (API definition language). It provides:
- Conversion between Stone DSL and OpenAPI specifications
- Verification that Stone and OpenAPI definitions match
- Modeling of Dropbox API in Alloy to analyze whether arbitrary use cases are feasible

## Commands

### Development
```bash
# Build the project
cargo build

# Run tests
cargo test

# Run linter
cargo clippy

# Format code
cargo fmt

# Run the main CLI
cargo run -- <command>

# The main binary handles all functionality
# No separate binaries needed
```

### CLI Usage
```bash
# Compare Stone and OpenAPI specifications
cargo run -- compare --stone <stone-file> --openapi <openapi-file>

# Convert Stone to OpenAPI
cargo run -- convert --stone <stone-file> --output <output-file>

# Verify Stone files in a directory
cargo run -- verify-stone --path <directory>
```

## Architecture

### Core Components

1. **Stone Parser** (`stone.pest`): PEG grammar that parses Stone DSL into an AST
   - Supports: namespaces, imports, structs, unions, routes, aliases, documentation
   - Key types: `StoneSpecification`, `Definition`, `DataType`

2. **Converter** (`src/converter/`): Transforms Stone AST to OpenAPI
   - Maps Stone structs → OpenAPI schemas
   - Maps Stone routes → OpenAPI paths
   - Handles type references and imports

3. **Verifier** (`src/verifier/`): Compares Stone and OpenAPI for consistency
   - Validates that converted specs match original definitions
   - Provides colored diff output for mismatches

### Project Structure

```
kamatsuka/
├── src/
│   ├── main.rs          # Main CLI with compare, convert, verify-stone commands
│   ├── converter/       # Stone to OpenAPI converter module
│   │   └── mod.rs       # Converter implementation
│   └── verifier/        # Stone-OpenAPI verifier module
│       └── mod.rs       # Verifier implementation
├── stone.pest           # PEG grammar for parsing Stone DSL
├── stone/               # Dropbox API specifications in Stone DSL
│   └── dropbox-api-spec/
├── openapi/             # OpenAPI specifications
│   └── users.yaml       # Example OpenAPI spec
└── examples/            # Alloy use cases
    └── use_cases.als    # Example API use cases in Alloy
```

- `stone/dropbox-api-spec/`: Dropbox's official Stone API specifications (git submodule)
- `openapi/`: OpenAPI specification outputs
- `examples/`: Alloy models for API use case analysis
- All functionality integrated into a single binary with subcommands

### Key Design Patterns

1. **AST-based processing**: Stone DSL is parsed into a strongly-typed AST before any transformations
2. **Type mapping**: Stone types (String, UInt64, List, etc.) map to OpenAPI types with proper formats
3. **Reference resolution**: Handles cross-file imports and namespace references
4. **Error handling**: Uses Result types throughout with descriptive error messages

## Stone DSL Specifics

- **Namespace**: Groups related definitions (e.g., `namespace users`)
- **Import**: References definitions from other files
- **Struct**: Maps to OpenAPI object schema
- **Union**: Tagged union type with variants
- **Route**: API endpoint definition with request/response types
- **Alias**: Type alias for reusability

Proceed assuming that all stone definitions in `stone/dropbox-api-spec` are correct.

## Working with the Codebase

When modifying the parser:
1. Update `stone.pest` grammar
2. Regenerate parser with `cargo build`
3. Update AST types in `src/main.rs` to match grammar changes
4. Test with files in `stone/dropbox-api-spec/`

When adding OpenAPI features:
1. Extend the `to_openapi_*` methods in `src/main.rs`
2. Ensure proper type mapping in `stone_type_to_openapi`
3. Test round-trip conversion with the verifier

Do not make any change files under `stone/`
