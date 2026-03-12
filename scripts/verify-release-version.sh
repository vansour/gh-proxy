#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 1 ]]; then
  echo "usage: $0 <expected-version>" >&2
  exit 1
fi

expected_version="$1"

extract_version() {
  sed -n 's/^version = "\(.*\)"/\1/p' "$1" | head -n 1
}

workspace_version="$(extract_version Cargo.toml)"
backend_version="$(extract_version backend/Cargo.toml)"
frontend_version="$(extract_version frontend/dioxus-app/Cargo.toml)"

if [[ -z "${workspace_version}" || -z "${backend_version}" || -z "${frontend_version}" ]]; then
  echo "failed to extract one or more package versions" >&2
  exit 1
fi

if [[ "${workspace_version}" != "${expected_version}" ]]; then
  echo "workspace version mismatch: expected ${expected_version}, got ${workspace_version}" >&2
  exit 1
fi

if [[ "${backend_version}" != "${expected_version}" ]]; then
  echo "backend version mismatch: expected ${expected_version}, got ${backend_version}" >&2
  exit 1
fi

if [[ "${frontend_version}" != "${expected_version}" ]]; then
  echo "frontend version mismatch: expected ${expected_version}, got ${frontend_version}" >&2
  exit 1
fi

echo "verified release version ${expected_version}"
