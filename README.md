# Kamatsuka - Stone DSL to OpenAPI Converter

Kamatsuka is a Rust-based tool for working with Dropbox's Stone DSL (API definition language).
It provides conversion between Stone DSL and OpenAPI specifications, verification capabilities, and modeling of Dropbox API in Alloy to analyze API use case feasibility.

## Features

🔄 **Stone to OpenAPI Conversion**
- Convert individual Stone files or entire directories to OpenAPI 3.0.3 specifications
- Support for all Stone DSL syntax including complex types, unions, and constraints
- Handles cross-namespace references and type aliases
- Generates complete REST API documentation

📋 **OpenAPI Validation**
- Built-in OpenAPI 3.0.3 compliance validation
- Schema reference integrity checking
- YAML syntax validation
- Comprehensive validation reports

🔍 **Stone DSL Verification**
- Parse and validate Stone DSL syntax
- Compare Stone definitions with OpenAPI specifications
- Identify discrepancies and missing elements

📊 **API Analysis**
- Model Dropbox API in Alloy for feasibility analysis
- Determine if arbitrary use cases are possible
- Example: Check if adding users to team folders is feasible

## Installation

### Prerequisites
- Rust 1.70+ (https://rustup.rs/)
- Git

### Build from Source
```bash
git clone <repository-url>
cd kamatsuka
cargo build --release
```

The binary will be available at `target/release/kamatsuka`.

## Usage

### Convert Stone DSL to OpenAPI

**Single File Conversion:**
```bash
cargo run -- convert --stone path/to/file.stone --output api.yaml
```

**Directory Conversion (recommended for complete APIs):**
```bash
cargo run -- convert --stone stone/dropbox-api-spec --output dropbox-api-complete.yaml
```

**With Custom Base URL:**
```bash
cargo run -- convert --stone stone/dropbox-api-spec --output api.yaml --base-url https://api.example.com/v2
```

### Validate OpenAPI Specification

**Basic Validation:**
```bash
cargo run -- validate-openapi --openapi openapi/dropbox-api-complete.yaml
```

**Verbose Validation with Details:**
```bash
cargo run -- validate-openapi --openapi openapi/dropbox-api-complete.yaml --verbose
```

### Compare Stone and OpenAPI

```bash
cargo run -- compare --stone path/to/file.stone --openapi path/to/api.yaml --verbose
```

### Verify Stone DSL Syntax

```bash
cargo run -- verify-stone --path stone/dropbox-api-spec --verbose
```

## Generated OpenAPI Specification

The tool generates a complete OpenAPI 3.0.3 specification from Dropbox's Stone DSL definitions:

### Statistics (Dropbox API Complete)
- **API Endpoints:** 243 routes
- **Data Schemas:** 2,064 definitions  
- **Security Schemes:** OAuth2 with all scopes
- **Schema References:** 3,200+ cross-references
- **File Size:** ~30,000 lines

### Key Features
- ✅ Full OpenAPI 3.0.3 compliance
- ✅ OAuth2 security configuration
- ✅ Complete request/response schemas
- ✅ Type constraints (patterns, lengths, value ranges)
- ✅ Union types with discriminators
- ✅ List types with item constraints
- ✅ Comprehensive error handling

## Project Structure

```
kamatsuka/
├── src/
│   ├── main.rs              # CLI interface and command handlers
│   ├── converter/           # Stone to OpenAPI conversion
│   │   └── mod.rs          # Core conversion logic
│   ├── verifier/           # Stone-OpenAPI verification
│   │   └── mod.rs          # Comparison and validation
│   └── stone.pest          # PEG grammar for Stone DSL parsing
├── stone/
│   └── dropbox-api-spec/   # Dropbox Stone API definitions (40+ files)
├── openapi/                # Generated OpenAPI specifications
│   └── dropbox-api-complete.yaml  # Complete Dropbox API
├── examples/               # Alloy models for API analysis
│   └── use_cases.als      # Example API use cases
├── test/                   # Test Stone files
├── logs/                   # Application logs (timestamped)
├── target/                 # Rust build artifacts
├── LICENSE                 # Apache License 2.0
├── README.md               # This documentation
└── Cargo.toml              # Rust project configuration
```

## Stone DSL Support

The parser supports the complete Stone DSL syntax used by Dropbox:

### Core Features
- **Namespaces:** `namespace users "User management API"`
- **Imports:** `import common`
- **Data Types:** All primitives (String, Int32/64, UInt32/64, Float32/64, Boolean, Bytes, Timestamp, Void)
- **Type Constraints:** Pattern validation, length limits, value ranges
- **Complex Types:** Lists, Maps, Optional types (`Type?`)
- **Structures:** Object definitions with inheritance (`extends`)
- **Unions:** Tagged union types (open/closed)
- **Routes:** API endpoint definitions with parameters
- **Examples:** Named examples with field values
- **Attributes:** Route-level metadata (scopes, app folder access)

### Advanced Features
- **Cross-namespace references:** `common.AccountId`
- **Type aliases:** `alias EmailAddress = String(pattern="...", max_length=255)`
- **Inline unions:** Union definitions within structs
- **Parameterized types:** `List(String, min_items=1, max_items=100)`
- **Documentation:** Multi-line descriptions and field docs

## Logging

All operations are logged to timestamped files in the `logs/` directory:
- Detailed parsing information
- Conversion progress and statistics
- Error diagnosis and debugging info
- File processing status

## Examples

### Basic Conversion
```bash
# Convert all Dropbox Stone files to a single OpenAPI spec
cargo run -- convert --stone stone/dropbox-api-spec --output openapi/dropbox-complete.yaml

# Validate the generated specification
cargo run -- validate-openapi --openapi openapi/dropbox-complete.yaml --verbose
```

### Development Workflow
```bash
# 1. Verify Stone syntax
cargo run -- verify-stone --path stone/dropbox-api-spec

# 2. Convert to OpenAPI
cargo run -- convert --stone stone/dropbox-api-spec --output api.yaml --verbose

# 3. Validate output
cargo run -- validate-openapi --openapi api.yaml --verbose

# 4. Compare for consistency  
cargo run -- compare --stone stone/sample.stone --openapi api.yaml
```

## API Modeling with Alloy

The `examples/` directory contains Alloy models for analyzing API feasibility:

```alloy
// Example: Check if adding users to team folders is possible
run AddUserToTeamFolder for 3
```

Use the Alloy Analyzer to explore API constraints and determine feasibility of complex use cases.

## Contributing

### Development Commands
```bash
# Build the project
cargo build

# Run tests
cargo test

# Run linter
cargo clippy

# Format code
cargo fmt
```

### Adding New Features
1. Update the Stone grammar in `src/stone.pest` if needed
2. Implement parsing logic in converter/verifier modules  
3. Add CLI commands in `src/main.rs`
4. Update tests and documentation

## License

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

Copyright 2025 Takayuki Okazaki

## Acknowledgments

- Dropbox for the Stone DSL specification
- Pest parsing library for grammar parsing
- OpenAPI Initiative for the specification standard