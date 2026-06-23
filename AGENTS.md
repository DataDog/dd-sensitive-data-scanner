# Agent Guidance for running commands in this repository

This is a multi-language library providing core Sensitive Data Scanner (SDS) functionality for detecting and redacting sensitive information. The Rust implementation lives in a single crate under `sds/`, with Go FFI bindings gated behind Cargo features.

**Documentation:** https://datadoghq.dev/dd-sensitive-data-scanner/dd_sds/

## Build & Test Commands

Use `make` to see available commands for building, testing, and formatting.

## Code Quality Requirements

- **Warnings are errors:** CI runs with `RUSTFLAGS="-D warnings"`
- **Clippy:** All clippy warnings must be fixed
- **Formatting:** Code must be formatted before committing

## Project Structure

```
sds/                    # Single Rust crate
├── src/
│   ├── scanner/        # Core scanning engine
│   ├── parser/         # Pattern parsing
│   ├── match_validation/       # Async validation (HTTP, AWS)
│   ├── secondary_validation/   # Checksum validators (Luhn, etc.)
│   ├── proximity_keywords/     # Keyword proximity detection
│   └── ...
├── benches/            # Performance benchmarks
└── tools/fuzz/         # AFL fuzzing target declared by sds/Cargo.toml

sds-go/                 # Go FFI wrapper
└── go/                 # Go bindings
```

Key files: 
- `sds/src/lib.rs` - Main library entry point
- `sds/src/scanner/mod.rs` - Core scanner implementation
- `sds/src/event.rs` - Event trait for scanning interface
- `sds/src/match_action.rs` - Redaction/masking actions
- `sds/src/native/` - Rust side of the Go FFI, enabled with the `dd_sds_go` feature
- `sds/src/bindings_utils.rs` - Shared binding utilities, enabled with the `sds-bindings-utils` feature
- `sds-go/go/scanner.go` - Main Go API


## Code Quality Standards

**Naming and Clarity:**
- Use explicit, self-documenting names for variables, functions, and classes
- Code should be readable without comments explaining what it does
- If you need to explain 'what', your names aren't clear enough

**Comments:**
- Add comments ONLY to explain WHY code exists or WHY a particular approach was chosen
- Explain business logic, non-obvious decisions, or workarounds
- Document edge cases and assumptions
- NEVER write comments that simply describe what the code does

**Testing:**
- Add extensive tests to increase overall test coverage
- Minimize duplicated test logic - use test helpers and shared fixtures
- Test edge cases, error conditions, and happy paths
- Ensure tests are maintainable and clearly named
- Each test should validate one specific behavior
- **Always use simple, fake regex patterns in tests** (e.g. `"secret"`, `"foo"`, `"[0-9]+"`) — never real production regexes. A reader should understand what a test asserts without decoding a complex pattern. It is always possible to construct a simple regex that exercises any edge case.

## Maintenance

Keep this file up to date when making changes that affect build commands, project structure, or development workflows.
