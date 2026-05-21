#!/bin/bash
set -e

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
license_config="${root}/license-tool.toml"
license_manifest_dir=$(mktemp -d)
license_manifest_path="${license_manifest_dir}/Cargo.toml"
expected_file=$(mktemp)

cleanup() {
  rm -rf "${license_manifest_dir}"
  rm -f "${expected_file}"
}
trap cleanup EXIT

# Build license data from an all-feature view of the single crate. Different
# dd-rust-license-tool versions disagree on optional dependencies, so make the
# feature set explicit without changing the real crate defaults.
mkdir -p "${license_manifest_dir}/src" "${license_manifest_dir}/tools/fuzz/src" "${license_manifest_dir}/benches"
cp "${root}/sds/Cargo.toml" "${license_manifest_path}"
cp "${root}/sds/Cargo.lock" "${license_manifest_dir}/Cargo.lock"
touch \
  "${license_manifest_dir}/src/lib.rs" \
  "${license_manifest_dir}/tools/fuzz/src/main.rs" \
  "${license_manifest_dir}/benches/bench.rs" \
  "${license_manifest_dir}/benches/multithreaded_scanning.rs"
python3 - "${license_manifest_path}" <<'PY'
import pathlib
import sys

path = pathlib.Path(sys.argv[1])
contents = path.read_text()
default_features = 'default = ["dd-sds"]'
license_features = 'default = ["dd-sds", "sds-bindings-utils", "dd_sds_go", "sds-fuzz", "hyperscan", "manual_test"]'

if default_features not in contents:
    raise SystemExit(f"Unable to find expected default feature line in {path}")

path.write_text(contents.replace(default_features, license_features, 1))
PY

dd-rust-license-tool -c "${license_config}" --manifest-path "${license_manifest_path}" dump | LC_COLLATE=C sort -u > "${expected_file}"

if [ "$1" == "check" ]; then
  if [ -f "${root}/LICENSE-3rdparty.csv" ]; then
    diff "${expected_file}" "${root}/LICENSE-3rdparty.csv"
  else
    echo "LICENSE-3rdparty.csv does not exist"
    exit 1
  fi
  echo "LICENSE-3rdparty.csv is up to date"
else
  cp "${expected_file}" "${root}/LICENSE-3rdparty.csv"
  echo "Wrote LICENSE-3rdparty.csv"
fi

