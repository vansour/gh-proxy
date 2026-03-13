#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 1 ]]; then
  echo "usage: $0 <expected-version>" >&2
  exit 1
fi

expected_version="$1"

run_step() {
  echo "+ $*"
  "$@"
}

run_step bash scripts/verify-release-version.sh "${expected_version}"
run_step cargo fmt --all -- --check
run_step cargo check --workspace --all-targets --locked --quiet
run_step cargo test --locked -q -p gh-proxy
run_step cargo test --locked -q -p gh-proxy-frontend

if [[ "${RELEASE_PREFLIGHT_SKIP_DOCKER_SMOKE:-0}" == "1" ]]; then
  echo "+ skipping docker smoke test because RELEASE_PREFLIGHT_SKIP_DOCKER_SMOKE=1"
else
  run_step bash docker/smoke-test.sh
fi

echo "release preflight passed for ${expected_version}"
