set -e

cargo check --manifest-path="sds/Cargo.toml" --benches --features dd_sds_go
cargo check --manifest-path="sds/Cargo.toml" --bin fuzz --features sds-fuzz
cargo clippy --manifest-path="sds/Cargo.toml" --features dd_sds_go -- -D warnings
cargo clippy --manifest-path="sds/Cargo.toml" --bin fuzz --features sds-fuzz -- -D warnings

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

cargo fmt --check --manifest-path="sds/Cargo.toml" --all
git diff --exit-code