#!/bin/bash
set -e

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
license_config="${root}/license-tool.toml"
manifest_path="${root}/sds/Cargo.toml"
expected_file=$(mktemp)

cleanup() {
  rm -f "${expected_file}"
}
trap cleanup EXIT

dd-rust-license-tool -c "${license_config}" --manifest-path "${manifest_path}" dump | LC_COLLATE=C sort -u > "${expected_file}"

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

