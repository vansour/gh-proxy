#!/usr/bin/env bash
set -euo pipefail

IMAGE_TAG="${IMAGE_TAG:-gh-proxy:smoke}"
CONTAINER_NAME="${CONTAINER_NAME:-gh-proxy-smoke-$RANDOM}"
HOST_PORT="${HOST_PORT:-18080}"
TIMEOUT_SECS="${TIMEOUT_SECS:-180}"
DOCKERFILE_PATH="${DOCKERFILE_PATH:-Dockerfile}"
BUILD_CONTEXT="${BUILD_CONTEXT:-.}"

base_url="http://127.0.0.1:${HOST_PORT}"

cleanup() {
  docker rm -f "${CONTAINER_NAME}" >/dev/null 2>&1 || true
}

wait_for_http_ok() {
  local url="$1"
  local deadline=$((SECONDS + TIMEOUT_SECS))

  while (( SECONDS < deadline )); do
    if curl -fsS "${url}" >/dev/null; then
      return 0
    fi

    if ! docker inspect "${CONTAINER_NAME}" >/dev/null 2>&1; then
      echo "Container disappeared before smoke test completed" >&2
      return 1
    fi

    local status
    status="$(docker inspect --format '{{.State.Status}}' "${CONTAINER_NAME}")"
    if [[ "${status}" == "exited" || "${status}" == "dead" ]]; then
      echo "Container is not running (status=${status})" >&2
      docker logs "${CONTAINER_NAME}" >&2 || true
      return 1
    fi

    sleep 2
  done

  echo "Timed out waiting for ${url}" >&2
  docker logs "${CONTAINER_NAME}" >&2 || true
  return 1
}

assert_response_contains() {
  local url="$1"
  local needle="$2"
  local body

  body="$(curl -fsS "${url}")"
  if [[ "${body}" != *"${needle}"* ]]; then
    echo "Response from ${url} did not contain expected text: ${needle}" >&2
    echo "${body}" >&2
    return 1
  fi
}

trap cleanup EXIT

echo "Building Docker image ${IMAGE_TAG}"
docker build --pull -t "${IMAGE_TAG}" -f "${DOCKERFILE_PATH}" "${BUILD_CONTEXT}"

echo "Starting container ${CONTAINER_NAME}"
docker run -d \
  --name "${CONTAINER_NAME}" \
  -p "127.0.0.1:${HOST_PORT}:8080" \
  "${IMAGE_TAG}" >/dev/null

echo "Waiting for container HTTP surface"
wait_for_http_ok "${base_url}/healthz"

echo "Checking health and config endpoints"
assert_response_contains "${base_url}/healthz" "\"accepting_requests\":true"
assert_response_contains "${base_url}/healthz" "\"version\""
assert_response_contains "${base_url}/readyz" "\"checks\""
assert_response_contains "${base_url}/api/config" "\"registry\""
assert_response_contains "${base_url}/api/config" "\"allowedHosts\""

echo "Checking static UI entrypoint"
curl -fsSI "${base_url}/" >/dev/null

echo "Docker smoke test passed"
