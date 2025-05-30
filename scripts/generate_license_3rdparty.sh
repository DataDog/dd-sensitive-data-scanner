#!/bin/bash
set -e

root=$(pwd)
license_config=$root/license-tool.toml
paths=("/sds" "/sds-go/rust" "/sds-bindings-utils")

for path in "${paths[@]}"; do
  cd "${root}${path}"
  dd-rust-license-tool -c $license_config write
done

expected=$(cat "${root}"/*/**/LICENSE-3rdparty.csv | LC_COLLATE=C sort -u)

for path in "${paths[@]}"; do
  cd "${root}${path}"
  rm -f "${root}${path}/LICENSE-3rdparty.csv"
done

if [ "$1" == "check" ]; then
  if [ -f "${root}/LICENSE-3rdparty.csv" ]; then
    diff <(echo "$expected") "${root}/LICENSE-3rdparty.csv"
  else
    echo "LICENSE-3rdparty.csv does not exist"
    exit 1
  fi
  echo "LICENSE-3rdparty.csv is up to date"
else
  rm -f "${root}/LICENSE-3rdparty.csv"
  echo "$expected" > "${root}/LICENSE-3rdparty.csv"
  echo "Wrote LICENSE-3rdparty.csv"
fi

