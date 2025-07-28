cargo fmt --check --manifest-path="sds/Cargo.toml" --all
cargo check --manifest-path="sds/Cargo.toml" --benches --workspace
cargo clippy --manifest-path="sds/Cargo.toml" --workspace -- -D warnings
echo "Run 'dd-rust-license-tool write' to update a 3rd party license file"
(cd sds; dd-rust-license-tool check)