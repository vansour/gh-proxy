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

# Ensure logs directory exists and is writable
if [ ! -d "${LOGS_DIR}" ]; then
    log_info "Creating logs directory: ${LOGS_DIR}"
    mkdir -p "${LOGS_DIR}"
    log_debug "Logs directory created successfully"
else
    # Ensure the directory is writable by current user
    if [ ! -w "${LOGS_DIR}" ]; then
        log_warn "Logs directory exists but is not writable. Attempting to fix permissions..."
        chmod 755 "${LOGS_DIR}" 2>/dev/null || log_warn "Could not modify logs directory permissions"
    fi
fi

# Initialize config directory if empty
if [ ! -f "${CONFIG_DIR}/config.toml" ]; then
    log_info "Initializing config directory..."
    
    if [ -d "${CONFIG_DEFAULT_DIR}" ]; then
        log_info "Copying default configuration files from: ${CONFIG_DEFAULT_DIR}"
        if cp -r "${CONFIG_DEFAULT_DIR}"/* "${CONFIG_DIR}/" 2>/dev/null; then
            log_debug "Configuration files copied successfully"
        else
            log_warn "Failed to copy default config files"
            # Try creating a minimal config if copy fails
            mkdir -p "${CONFIG_DIR}" 2>/dev/null
            if [ ! -f "${CONFIG_DIR}/config.toml" ] && [ -f "${CONFIG_DEFAULT_DIR}/config.toml" ]; then
                cp "${CONFIG_DEFAULT_DIR}/config.toml" "${CONFIG_DIR}/config.toml" 2>/dev/null
                log_debug "Minimal config.toml copied"
            fi
        fi
    else
        log_warn "Default config directory not found at ${CONFIG_DEFAULT_DIR}"
    fi
fi

# Ensure config directory exists and is writable
if [ ! -d "${CONFIG_DIR}" ]; then
    log_info "Creating config directory: ${CONFIG_DIR}"
    mkdir -p "${CONFIG_DIR}" || {
        log_error "Failed to create config directory"
        exit 1
    }
    log_debug "Config directory created successfully"
else
    # Ensure the directory is writable by current user
    if [ ! -w "${CONFIG_DIR}" ]; then
        log_warn "Config directory is not writable. Attempting to fix permissions..."
        chmod 755 "${CONFIG_DIR}" 2>/dev/null || log_warn "Could not modify config directory permissions"
    fi
fi

# Verify config directory is readable
if [ ! -r "${CONFIG_DIR}" ]; then
    log_error "Configuration directory is not readable: ${CONFIG_DIR}"
    log_error "Please ensure the directory has proper read permissions"
    exit 1
fi

# Verify config.toml exists
if [ ! -f "${CONFIG_DIR}/config.toml" ]; then
    log_error "Configuration file not found: ${CONFIG_DIR}/config.toml"
    log_error ""
    log_error "Solutions:"
    log_error "1. Create config directory and copy default config:"
    log_error "   mkdir -p ./config && cp ./config/* ./config/"
    log_error ""
    log_error "2. Or use compose with pre-initialized config directory"
    log_error ""
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
