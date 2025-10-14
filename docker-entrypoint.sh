#!/bin/bash
set -e

# Copy default config files if they don't exist in the mounted volume
if [ ! -f "/app/config/config.toml" ]; then
    echo "Config file not found, copying default config..."
    cp /app/config-default/config.toml /app/config/config.toml
fi

if [ ! -f "/app/config/blacklist.json" ]; then
    echo "Blacklist file not found, copying default blacklist..."
    cp /app/config-default/blacklist.json /app/config/blacklist.json
fi

# Start the application
exec /app/gh-proxy
