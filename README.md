# Sensitive Data Scanner

[Rust Docs](https://datadoghq.dev/dd-sensitive-data-scanner/dd_sds/)

This is the open-source library of the core SDS (Sensitive Data Scanner) functionality.

This contains:
- Core SDS engine, which takes events and runs rules to find sensitive data
- Built-in regex rule support, with optional keywords and secondary validator support
- Generic rule trait, which allows implementing arbitrary rules outside of this repo
- An extensive library of secondary validators / checksums
- Go bindings


