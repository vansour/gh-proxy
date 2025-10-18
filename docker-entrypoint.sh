#!/bin/bash
set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
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

log_debug() {
    echo -e "${BLUE}[DEBUG]${NC} $*"
}

# Configuration
APP_DIR="/app"
CONFIG_DIR="${APP_DIR}/config"
CONFIG_DEFAULT_DIR="${APP_DIR}/config-default"
LOGS_DIR="${APP_DIR}/logs"
BINARY="${APP_DIR}/gh-proxy"

log_info "================================"
log_info "GH-Proxy Docker Startup Script"
log_info "================================"

# Ensure logs directory exists
if [ ! -d "${LOGS_DIR}" ]; then
    log_info "Creating logs directory: ${LOGS_DIR}"
    mkdir -p "${LOGS_DIR}"
    log_debug "Logs directory created successfully"
fi

# Initialize config directory if empty
if [ ! -f "${CONFIG_DIR}/config.toml" ]; then
    log_info "Initializing config directory..."
    
    if [ -d "${CONFIG_DEFAULT_DIR}" ]; then
        log_info "Copying default configuration files from: ${CONFIG_DEFAULT_DIR}"
        cp -r "${CONFIG_DEFAULT_DIR}"/* "${CONFIG_DIR}/" || log_warn "Failed to copy default config"
        log_debug "Configuration files copied successfully"
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

log_info "✓ Configuration file verified: ${CONFIG_DIR}/config.toml"

# Display configuration summary
log_info "Configuration Summary:"
if grep -q "^host = " "${CONFIG_DIR}/config.toml"; then
    HOST=$(grep "^host = " "${CONFIG_DIR}/config.toml" | cut -d'"' -f2)
    log_info "  - Host: ${HOST}"
fi
if grep -q "^port = " "${CONFIG_DIR}/config.toml"; then
    PORT=$(grep "^port = " "${CONFIG_DIR}/config.toml" | cut -d' ' -f3)
    log_info "  - Port: ${PORT}"
fi
if grep -q "^level = " "${CONFIG_DIR}/config.toml"; then
    LOG_LEVEL=$(grep "^level = " "${CONFIG_DIR}/config.toml" | cut -d'"' -f2)
    log_info "  - Log Level: ${LOG_LEVEL}"
fi

# Verify blacklist.json exists (if enabled in config)
if grep -q "^enabled = true" "${CONFIG_DIR}/config.toml" | grep -B 1 "blacklist" > /dev/null 2>&1; then
    BLACKLIST_FILE=$(grep "blacklistFile" "${CONFIG_DIR}/config.toml" | cut -d'"' -f2)
    if [ -n "${BLACKLIST_FILE}" ]; then
        if [ ! -f "${BLACKLIST_FILE}" ]; then
            log_warn "Blacklist file not found: ${BLACKLIST_FILE}"
            log_info "Creating empty blacklist file..."
            mkdir -p "$(dirname "${BLACKLIST_FILE}")"
            echo "[]" > "${BLACKLIST_FILE}"
            log_debug "Empty blacklist file created successfully"
        else
            log_info "✓ Blacklist file verified: ${BLACKLIST_FILE}"
        fi
    fi
fi

# Verify binary exists
if [ ! -f "${BINARY}" ]; then
    log_error "Application binary not found: ${BINARY}"
    exit 1
fi

log_info "✓ Application binary verified: ${BINARY}"

# Display environment info
log_info "Environment Information:"
log_info "  - OS: $(uname -s)"
log_info "  - Architecture: $(uname -m)"
if command -v git &> /dev/null; then
    log_debug "  - Git available: $(git --version)"
fi

log_info "================================"
log_info "Starting gh-proxy..."
log_info "================================"

# Trap signals for graceful shutdown
trap 'log_info "Received SIGTERM, initiating graceful shutdown..."; exit 0' SIGTERM
trap 'log_info "Received SIGINT, initiating graceful shutdown..."; exit 0' SIGINT

# Execute the application, replacing the shell process
exec "${BINARY}" "$@"
