set -e

for manifest_path in sds/Cargo.toml sds-go/rust/Cargo.toml; do
    cargo check --manifest-path="$manifest_path" --benches --workspace
    cargo clippy --manifest-path="$manifest_path" --workspace -- -D warnings
done

DID_STASH=0

## Formatting related checks
cleanup() {
    if [ "$DID_STASH" -eq 1 ]; then
        git stash pop -q || true
    fi
}
trap cleanup EXIT

# Stash only if there are changes (staged or unstaged)
if ! git diff --quiet || ! git diff --cached --quiet; then
    git stash push -u -m "rust_checks.sh temp stash" >/dev/null 2>&1 || true
    DID_STASH=1
fi

for manifest_path in sds/Cargo.toml sds-go/rust/Cargo.toml; do
    cargo fmt --check --manifest-path="$manifest_path" --all
    git diff --exit-code
done