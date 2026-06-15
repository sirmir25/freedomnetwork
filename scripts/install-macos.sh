#!/usr/bin/env bash
# FreedomNet installer for macOS (Intel and Apple Silicon)
# Requires: Homebrew (will install if missing)
# Usage:
#   bash scripts/install-macos.sh

set -euo pipefail

REPO_URL="https://github.com/sirmir25/freedomnetwork.git"
INSTALL_DIR="$HOME/.local/share/freedomnet"
BIN_DIR="$HOME/.local/bin"
LAUNCH_AGENTS="$HOME/Library/LaunchAgents"
PLIST_ID="com.sirmir25.freedomnet"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
BOLD='\033[1m'
RESET='\033[0m'

log()  { echo -e "${BLUE}${BOLD}[fninstall]${RESET} $*"; }
ok()   { echo -e "${GREEN}✓${RESET} $*"; }
warn() { echo -e "${YELLOW}⚠${RESET}  $*"; }
fail() { echo -e "${RED}✗${RESET} $*"; exit 1; }

ARCH=$(uname -m)
echo
echo -e "${BOLD}FreedomNet macOS Installer${RESET}"
echo -e "${BLUE}──────────────────────────────────────────────${RESET}"
echo -e "Architecture: ${ARCH}"
echo

# ── Homebrew ──────────────────────────────────────────────────────────────────
install_homebrew() {
    if command -v brew &>/dev/null; then
        ok "Homebrew $(brew --version | head -1) already installed"
        return 0
    fi
    log "Installing Homebrew..."
    /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"

    # Add brew to PATH for Apple Silicon
    if [ "$ARCH" = "arm64" ]; then
        eval "$(/opt/homebrew/bin/brew shellenv)"
        echo 'eval "$(/opt/homebrew/bin/brew shellenv)"' >> "$HOME/.zprofile"
    fi
    ok "Homebrew installed"
}

# ── Xcode CLT ────────────────────────────────────────────────────────────────
install_xcode_clt() {
    if xcode-select -p &>/dev/null; then
        ok "Xcode Command Line Tools already installed"
        return 0
    fi
    log "Installing Xcode Command Line Tools..."
    xcode-select --install
    warn "A dialog will appear. Click 'Install' and wait for it to complete."
    warn "Then re-run this installer."
    exit 0
}

# ── Rust ──────────────────────────────────────────────────────────────────────
install_rust() {
    if command -v rustc &>/dev/null; then
        ok "Rust $(rustc --version | awk '{print $2}') already installed"
        return 0
    fi
    log "Installing Rust..."
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs \
        | sh -s -- -y --profile minimal
    # shellcheck disable=SC1090
    source "$HOME/.cargo/env"
    ok "Rust $(rustc --version | awk '{print $2}') installed"
}

# ── ldc2 (D compiler) ─────────────────────────────────────────────────────────
install_ldc() {
    if command -v ldc2 &>/dev/null; then
        ok "ldc2 already installed"
        return 0
    fi
    log "Installing ldc2 D compiler via Homebrew..."
    brew install ldc
    ok "ldc2 $(ldc2 --version 2>&1 | head -1) installed"
}

# ── clone / update ────────────────────────────────────────────────────────────
fetch_repo() {
    if [ -d "$INSTALL_DIR/.git" ]; then
        log "Updating $INSTALL_DIR..."
        git -C "$INSTALL_DIR" pull --ff-only
    else
        log "Cloning to $INSTALL_DIR..."
        git clone "$REPO_URL" "$INSTALL_DIR"
    fi
    ok "Source at $INSTALL_DIR"
}

# ── build ─────────────────────────────────────────────────────────────────────
build_all() {
    log "Building Rust proxy + C++ bypass core..."
    cargo build --release --manifest-path "$INSTALL_DIR/Cargo.toml"
    ok "Proxy built"

    if command -v ldc2 &>/dev/null; then
        log "Building D VPN generator..."
        ldc2 -O2 -of="$INSTALL_DIR/vpngen/fn-vpn" "$INSTALL_DIR"/vpngen/source/*.d
        ok "VPN generator built"
    else
        warn "ldc2 not found; VPN generator not built"
    fi
}

# ── install ───────────────────────────────────────────────────────────────────
install_bins() {
    mkdir -p "$BIN_DIR"

    install -m 755 "$INSTALL_DIR/target/release/fn" "$BIN_DIR/fn"
    ok "Installed $BIN_DIR/fn"

    if [ -f "$INSTALL_DIR/vpngen/fn-vpn" ]; then
        install -m 755 "$INSTALL_DIR/vpngen/fn-vpn" "$BIN_DIR/fn-vpn"
        ok "Installed $BIN_DIR/fn-vpn"
    fi

    if [[ ":$PATH:" != *":$BIN_DIR:"* ]]; then
        SHELL_RC="$HOME/.zshrc"
        [ -n "${BASH_VERSION:-}" ] && SHELL_RC="$HOME/.bash_profile"
        echo "export PATH=\"$BIN_DIR:\$PATH\"" >> "$SHELL_RC"
        warn "Added $BIN_DIR to PATH in $SHELL_RC"
    fi
}

# ── LaunchAgent (auto-start) ──────────────────────────────────────────────────
install_launchagent() {
    echo
    read -r -p "Install LaunchAgent (auto-start at login)? [y/N] " ans
    [[ "$ans" != "y" && "$ans" != "Y" ]] && return 0

    mkdir -p "$LAUNCH_AGENTS"
    PLIST="$LAUNCH_AGENTS/$PLIST_ID.plist"
    cat > "$PLIST" << PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
  "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>${PLIST_ID}</string>

  <key>ProgramArguments</key>
  <array>
    <string>${BIN_DIR}/fn</string>
  </array>

  <key>RunAtLoad</key>
  <true/>

  <key>KeepAlive</key>
  <true/>

  <key>StandardOutPath</key>
  <string>${HOME}/Library/Logs/freedomnet.log</string>

  <key>StandardErrorPath</key>
  <string>${HOME}/Library/Logs/freedomnet.log</string>
</dict>
</plist>
PLIST

    launchctl load "$PLIST"
    ok "LaunchAgent installed and loaded"
    ok "Manage with:"
    echo "    launchctl unload $PLIST   # stop"
    echo "    launchctl load   $PLIST   # start"
    echo "    tail -f ~/Library/Logs/freedomnet.log"
}

# ── configure system proxy ────────────────────────────────────────────────────
configure_system_proxy() {
    echo
    log "System SOCKS5 proxy configuration (optional):"
    echo
    echo -e "  ${BOLD}To set for ALL apps (System Settings):${RESET}"
    echo -e "  System Preferences → Network → your connection → Proxies"
    echo -e "  Check 'SOCKS Proxy': ${GREEN}127.0.0.1${RESET}  Port: ${GREEN}1080${RESET}"
    echo
    echo -e "  ${BOLD}Or via terminal (replace 'Wi-Fi' with your interface):${RESET}"
    echo -e "  sudo networksetup -setsocksfirewallproxy Wi-Fi 127.0.0.1 1080"
    echo -e "  sudo networksetup -setsocksfirewallproxystate Wi-Fi on"
    echo
    echo -e "  ${BOLD}Undo:${RESET}"
    echo -e "  sudo networksetup -setsocksfirewallproxystate Wi-Fi off"
    echo
    echo -e "  ${BOLD}Firefox:${RESET}  Settings → General → Network Settings → Manual proxy"
    echo -e "            SOCKS v5: ${GREEN}127.0.0.1${RESET}  Port: ${GREEN}1080${RESET}"
    echo -e "            ✓ Proxy DNS when using SOCKS v5"
    echo
    echo -e "  ${BOLD}PAC auto-config:${RESET}"
    echo -e "  System Preferences → Network → Proxies → Automatic Proxy Configuration"
    echo -e "  URL: ${GREEN}http://127.0.0.1:8085/proxy.pac${RESET}"
    echo
}

main() {
    install_xcode_clt
    install_homebrew
    install_rust
    install_ldc
    fetch_repo
    build_all
    install_bins
    install_launchagent
    configure_system_proxy

    echo
    echo -e "${GREEN}${BOLD}Installation complete!${RESET}"
    echo
    echo -e "Start the proxy:     ${BOLD}fn${RESET}"
    echo -e "Check blocked sites: ${BOLD}fn-vpn check google.com youtube.com${RESET}"
    echo -e "Generate VPN config: ${BOLD}fn vpn wireguard --server HOST:PORT --pubkey KEY${RESET}"
    echo
}

main "$@"
