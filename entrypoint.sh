#!/usr/bin/env sh
set -e

CONFIG_DIR="/app/config"
DEFAULTS_DIR="/app/.defaults/config"
CONFIG_FILE="$CONFIG_DIR/config.toml"
DEFAULT_FILE="$DEFAULTS_DIR/config.toml"

# 确保目录存在
mkdir -p "$CONFIG_DIR"

# 如果没有配置文件，用默认的填充一次（不覆盖已有修改）
if [ ! -f "$CONFIG_FILE" ]; then
  if [ -f "$DEFAULT_FILE" ]; then
    cp "$DEFAULT_FILE" "$CONFIG_FILE"
    echo "[entrypoint] Populated $CONFIG_FILE from defaults."
  else
    echo "[entrypoint] ERROR: No config file found at $CONFIG_FILE and no default at $DEFAULT_FILE"
    exit 1
  fi
fi

# 运行应用
exec /app/gh-proxy
