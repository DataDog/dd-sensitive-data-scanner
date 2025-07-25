for manifest_path in sds/Cargo.toml sds-go/rust/Cargo.toml; do
    cargo fmt --check --manifest-path="$manifest_path" --all
    cargo check --manifest-path="$manifest_path" --benches --workspace
    cargo clippy --manifest-path="$manifest_path" --workspace -- -D warnings
done
