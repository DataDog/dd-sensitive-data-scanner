#!/usr/bin/env bash

set -euo pipefail

cd "$(dirname "$0")/../sds"

cargo hack check --each-feature --no-dev-deps
cargo hack clippy --each-feature --no-dev-deps -- -D warnings
cargo check --all-targets --all-features
cargo fmt --all --check
