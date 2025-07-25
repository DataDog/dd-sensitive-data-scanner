cargo fmt --check --manifest-path="sds/Cargo.toml" --all
cargo check --manifest-path="sds/Cargo.toml" --benches --workspace
cargo clippy --manifest-path="sds/Cargo.toml" --workspace -- -D warnings
if ./scripts/generate_license_3rdparty.sh check; then
    echo "License check passed"
else
    echo "Run 'make update-licenses' to update the 3rd party license file"
    exit 1
fi