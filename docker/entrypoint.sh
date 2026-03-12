#!/bin/sh
set -eu

DEFAULT_CONFIG_PATH="/app/.defaults/config/config.toml"
CONFIG_PATH="${GH_PROXY_CONFIG:-/app/config/config.toml}"

if [ ! -f "${DEFAULT_CONFIG_PATH}" ]; then
    echo "Default config not found: ${DEFAULT_CONFIG_PATH}" >&2
    exit 1
fi

if [ -d "${CONFIG_PATH}" ]; then
    echo "Warning: ${CONFIG_PATH} is a directory (likely a Docker volume mount)." >&2
    CONFIG_PATH="${CONFIG_PATH}/config.toml"
    echo "Falling back to: ${CONFIG_PATH}"
fi

mkdir -p "$(dirname "${CONFIG_PATH}")"

if [ ! -f "${CONFIG_PATH}" ]; then
    if [ -d "${CONFIG_PATH}" ]; then
        echo "Error: ${CONFIG_PATH} is a directory, cannot initialize config file." >&2
        exit 1
    fi
    cp "${DEFAULT_CONFIG_PATH}" "${CONFIG_PATH}"
    echo "Initialized config at ${CONFIG_PATH}"
fi

exec /app/gh-proxy "$@"
