# Sensitive Data Scanner

[Rust Docs](https://datadoghq.dev/dd-sensitive-data-scanner/dd_sds/)

This is the open-source library of the core SDS (Sensitive Data Scanner) functionality.

This contains:
- Core SDS engine, which takes events and runs rules to find sensitive data
- Built-in regex rule support, with optional keywords and secondary validator support
- Generic rule trait, which allows implementing arbitrary rules outside of this repo
- An extensive library of secondary validators / checksums
- Go bindings

## Updating the Go bindings

The Go bindings use the generated C header at `sds-go/go/dd_sds.h`. When an
exported Rust function in `sds/src/native/` is added, removed, or its signature
changes, install `cbindgen` 0.29.2 and regenerate the header:

```shell
cargo install cbindgen --version 0.29.2 --locked
make update-sds-go-header
```

Commit the regenerated header with the Rust and Go changes. CI runs
`make check-sds-go-bindings` to verify that the header is current and that the
Go bindings build and pass their tests against the Rust library.

