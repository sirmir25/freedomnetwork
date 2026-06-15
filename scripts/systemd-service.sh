#!/usr/bin/env bash
# Generate and install a systemd user service for FreedomNet.
# Supports both user-level (no root) and system-level (root) installation.

set -euo pipefail

BIN="${1:-$(command -v fn 2>/dev/null || echo "$HOME/.local/bin/fn")}"
ARGS="${FN_ARGS:---listen 127.0.0.1:1080}"
MODE="${FN_SERVICE_MODE:-user}"   # user | system

GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
RESET='\033[0m'
BOLD='\033[1m'

ok()   { echo -e "${GREEN}✓${RESET} $*"; }
warn() { echo -e "${YELLOW}⚠${RESET}  $*"; }
log()  { echo -e "${BLUE}${BOLD}[systemd]${RESET} $*"; }

if [ ! -x "$BIN" ]; then
    echo "Error: binary not found at $BIN"
    echo "Build first: cargo build --release && cp target/release/fn ~/.local/bin/"
    exit 1
fi

UNIT_NAME="freedomnet.service"

if [ "$MODE" = "system" ]; then
    UNIT_DIR="/etc/systemd/system"
    CTL_FLAGS=""
    if [ "$(id -u)" != "0" ]; then
        echo "Error: system mode requires root. Run with sudo or set FN_SERVICE_MODE=user"
        exit 1
    fi
else
    UNIT_DIR="$HOME/.config/systemd/user"
    CTL_FLAGS="--user"
fi

mkdir -p "$UNIT_DIR"
UNIT_FILE="$UNIT_DIR/$UNIT_NAME"

log "Writing service file: $UNIT_FILE"

if [ "$MODE" = "system" ]; then
    cat > "$UNIT_FILE" << SYSUNIT
[Unit]
Description=FreedomNet DPI Bypass Proxy
Documentation=https://github.com/sirmir25/freedomnetwork
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=nobody
Group=nogroup
ExecStart=${BIN} ${ARGS}
Restart=on-failure
RestartSec=5
TimeoutStopSec=10

# Hardening
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=read-only
PrivateTmp=yes
PrivateDevices=yes
CapabilityBoundingSet=
AmbientCapabilities=
SecureBits=noroot

[Install]
WantedBy=multi-user.target
SYSUNIT
else
    cat > "$UNIT_FILE" << USERUNIT
[Unit]
Description=FreedomNet DPI Bypass Proxy
Documentation=https://github.com/sirmir25/freedomnetwork
After=network.target

[Service]
Type=simple
ExecStart=${BIN} ${ARGS}
Restart=on-failure
RestartSec=5
TimeoutStopSec=10
Environment=RUST_LOG=info

[Install]
WantedBy=default.target
USERUNIT
fi

ok "Service file written"

log "Reloading systemd..."
systemctl $CTL_FLAGS daemon-reload

log "Enabling service..."
systemctl $CTL_FLAGS enable "$UNIT_NAME"

log "Starting service..."
systemctl $CTL_FLAGS start "$UNIT_NAME"

sleep 1
STATUS=$(systemctl $CTL_FLAGS is-active "$UNIT_NAME" 2>/dev/null || echo "unknown")
if [ "$STATUS" = "active" ]; then
    ok "Service is running"
else
    warn "Service status: $STATUS"
    systemctl $CTL_FLAGS status "$UNIT_NAME" --no-pager || true
fi

echo
echo -e "${BOLD}Management commands:${RESET}"
echo "  systemctl $CTL_FLAGS status  $UNIT_NAME"
echo "  systemctl $CTL_FLAGS stop    $UNIT_NAME"
echo "  systemctl $CTL_FLAGS start   $UNIT_NAME"
echo "  systemctl $CTL_FLAGS restart $UNIT_NAME"
echo "  journalctl $CTL_FLAGS -u $UNIT_NAME -f"
echo
ok "FreedomNet service installed ($MODE mode)"
