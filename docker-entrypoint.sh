#!/bin/bash
set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Logging functions
log_info() {
    echo -e "${GREEN}[INFO]${NC} $*"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $*"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $*"
}

# Configuration
APP_DIR="/app"
CONFIG_DIR="${APP_DIR}/config"
CONFIG_DEFAULT_DIR="${APP_DIR}/config-default"
LOGS_DIR="${APP_DIR}/logs"
BINARY="${APP_DIR}/gh-proxy"

# Ensure logs directory exists
if [ ! -d "${LOGS_DIR}" ]; then
    log_info "Creating logs directory: ${LOGS_DIR}"
    mkdir -p "${LOGS_DIR}"
fi

# Initialize config directory if empty
if [ ! -f "${CONFIG_DIR}/config.toml" ]; then
    log_info "Initializing config directory..."
    
    if [ -d "${CONFIG_DEFAULT_DIR}" ]; then
        log_info "Copying default configuration files..."
        cp -r "${CONFIG_DEFAULT_DIR}"/* "${CONFIG_DIR}/" || log_warn "Failed to copy default config"
    else
        log_warn "Default config directory not found at ${CONFIG_DEFAULT_DIR}"
    fi
fi

# Verify config.toml exists
if [ ! -f "${CONFIG_DIR}/config.toml" ]; then
    log_error "Configuration file not found: ${CONFIG_DIR}/config.toml"
    log_error "Please mount your config directory or ensure default config exists"
    exit 1
fi

log_info "Configuration file verified: ${CONFIG_DIR}/config.toml"

# Verify blacklist.json exists (if referenced in config)
if grep -q "blacklistFile" "${CONFIG_DIR}/config.toml"; then
    BLACKLIST_FILE=$(grep "blacklistFile" "${CONFIG_DIR}/config.toml" | cut -d'"' -f2)
    if [ ! -f "${BLACKLIST_FILE}" ]; then
        log_warn "Blacklist file not found: ${BLACKLIST_FILE}"
        log_info "Creating empty blacklist file..."
        mkdir -p "$(dirname "${BLACKLIST_FILE}")"
        echo "[]" > "${BLACKLIST_FILE}"
    fi
fi

# Verify binary exists
if [ ! -f "${BINARY}" ]; then
    log_error "Application binary not found: ${BINARY}"
    exit 1
fi

log_info "Application binary verified: ${BINARY}"
log_info "Starting gh-proxy..."

# Execute the application, replacing the shell process
exec "${BINARY}" "$@"
