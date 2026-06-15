#!/usr/bin/env bash
# FreedomNet installer for Linux (Debian/Ubuntu, Fedora/RHEL, Arch)
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/sirmir25/freedomnetwork/main/scripts/install-linux.sh | bash
#   # or locally:
#   bash scripts/install-linux.sh

set -euo pipefail

REPO_URL="https://github.com/sirmir25/freedomnetwork.git"
INSTALL_DIR="$HOME/.local/share/freedomnet"
BIN_DIR="$HOME/.local/bin"
SYSTEMD_DIR="$HOME/.config/systemd/user"

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

# ── banner ────────────────────────────────────────────────────────────────────
echo
echo -e "${BOLD}FreedomNet Linux Installer${RESET}"
echo -e "${BLUE}──────────────────────────────────────────────${RESET}"
echo

# ── detect distro ─────────────────────────────────────────────────────────────
detect_distro() {
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        echo "${ID:-unknown}"
    elif command -v lsb_release &>/dev/null; then
        lsb_release -si | tr '[:upper:]' '[:lower:]'
    else
        echo "unknown"
    fi
}

DISTRO=$(detect_distro)
log "Detected distro: $DISTRO"

# ── install system dependencies ───────────────────────────────────────────────
install_deps() {
    case "$DISTRO" in
        ubuntu|debian|linuxmint|pop|elementary)
            log "Installing build dependencies (apt)..."
            sudo apt-get update -q
            sudo apt-get install -y -q \
                build-essential curl git pkg-config \
                libssl-dev ca-certificates
            ;;
        fedora|rhel|centos|rocky|alma)
            log "Installing build dependencies (dnf/yum)..."
            if command -v dnf &>/dev/null; then
                sudo dnf install -y gcc make curl git openssl-devel pkgconfig
            else
                sudo yum install -y gcc make curl git openssl-devel pkgconfig
            fi
            ;;
        arch|manjaro|endeavouros)
            log "Installing build dependencies (pacman)..."
            sudo pacman -Sy --noconfirm --needed base-devel curl git openssl
            ;;
        opensuse*|suse*)
            log "Installing build dependencies (zypper)..."
            sudo zypper install -y gcc make curl git openssl-devel
            ;;
        *)
            warn "Unknown distro '$DISTRO'. Assuming dependencies are installed."
            ;;
    esac
    ok "System dependencies installed"
}

# ── install Rust ──────────────────────────────────────────────────────────────
install_rust() {
    if command -v rustc &>/dev/null && command -v cargo &>/dev/null; then
        RUST_VER=$(rustc --version | awk '{print $2}')
        ok "Rust $RUST_VER already installed"
        return 0
    fi

    log "Installing Rust via rustup..."
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs \
        | sh -s -- -y --profile minimal --default-toolchain stable
    # shellcheck disable=SC1090
    source "$HOME/.cargo/env"
    ok "Rust $(rustc --version | awk '{print $2}') installed"
}

# ── install D compiler (ldc2) ─────────────────────────────────────────────────
install_ldc() {
    if command -v ldc2 &>/dev/null; then
        ok "ldc2 $(ldc2 --version 2>&1 | head -1) already installed"
        return 0
    fi
    if command -v dmd &>/dev/null; then
        ok "dmd $(dmd --version 2>&1 | head -1) already installed"
        return 0
    fi

    log "Installing ldc2 D compiler..."
    case "$DISTRO" in
        ubuntu|debian|linuxmint|pop)
            sudo apt-get install -y -q ldc 2>/dev/null || true
            ;;
        fedora|rhel|centos|rocky|alma)
            sudo dnf install -y ldc 2>/dev/null || true
            ;;
        arch|manjaro|endeavouros)
            sudo pacman -Sy --noconfirm --needed ldc 2>/dev/null || true
            ;;
        *)
            warn "Could not auto-install ldc2. VPN generator will not be available."
            warn "Install manually: https://dlang.org/download.html"
            return 0
            ;;
    esac

    if command -v ldc2 &>/dev/null; then
        ok "ldc2 installed"
    else
        warn "ldc2 not found after install attempt. VPN features unavailable."
    fi
}

# ── clone / update repo ───────────────────────────────────────────────────────
fetch_repo() {
    if [ -d "$INSTALL_DIR/.git" ]; then
        log "Updating existing clone at $INSTALL_DIR..."
        git -C "$INSTALL_DIR" pull --ff-only
    else
        log "Cloning FreedomNet to $INSTALL_DIR..."
        git clone "$REPO_URL" "$INSTALL_DIR"
    fi
    ok "Source at $INSTALL_DIR"
}

# ── build ─────────────────────────────────────────────────────────────────────
build_proxy() {
    log "Building FreedomNet proxy (Rust + C++)..."
    cargo build --release --manifest-path "$INSTALL_DIR/Cargo.toml"
    ok "Proxy built: $INSTALL_DIR/target/release/fn"
}

build_vpngen() {
    if ! command -v ldc2 &>/dev/null && ! command -v dmd &>/dev/null; then
        warn "No D compiler found; skipping VPN generator build"
        return 0
    fi

    log "Building VPN generator (D)..."
    DC="ldc2"
    command -v ldc2 &>/dev/null || DC="dmd"
    $DC -O2 -of="$INSTALL_DIR/vpngen/fn-vpn" "$INSTALL_DIR"/vpngen/source/*.d
    ok "VPN generator built: $INSTALL_DIR/vpngen/fn-vpn"
}

# ── install binaries ──────────────────────────────────────────────────────────
install_bins() {
    mkdir -p "$BIN_DIR"
    cp "$INSTALL_DIR/target/release/fn" "$BIN_DIR/fn"
    chmod +x "$BIN_DIR/fn"
    ok "Installed: $BIN_DIR/fn"

    if [ -f "$INSTALL_DIR/vpngen/fn-vpn" ]; then
        cp "$INSTALL_DIR/vpngen/fn-vpn" "$BIN_DIR/fn-vpn"
        chmod +x "$BIN_DIR/fn-vpn"
        ok "Installed: $BIN_DIR/fn-vpn"
    fi

    # Ensure ~/.local/bin is in PATH
    if [[ ":$PATH:" != *":$BIN_DIR:"* ]]; then
        warn "$BIN_DIR is not in PATH"
        SHELL_RC="$HOME/.bashrc"
        [ -f "$HOME/.zshrc" ] && SHELL_RC="$HOME/.zshrc"
        echo "export PATH=\"$BIN_DIR:\$PATH\"" >> "$SHELL_RC"
        warn "Added $BIN_DIR to PATH in $SHELL_RC (restart terminal or: source $SHELL_RC)"
    fi
}

# ── optional systemd service ──────────────────────────────────────────────────
install_service() {
    if ! command -v systemctl &>/dev/null; then
        warn "systemd not available; skipping service install"
        return 0
    fi

    echo
    read -r -p "Install systemd user service (auto-start at login)? [y/N] " ans
    if [[ "$ans" != "y" && "$ans" != "Y" ]]; then
        return 0
    fi

    mkdir -p "$SYSTEMD_DIR"
    cat > "$SYSTEMD_DIR/freedomnet.service" << SERVICE
[Unit]
Description=FreedomNet DPI Bypass Proxy
After=network.target

[Service]
Type=simple
ExecStart=${BIN_DIR}/fn
Restart=on-failure
RestartSec=5
Environment=RUST_LOG=info

[Install]
WantedBy=default.target
SERVICE

    systemctl --user daemon-reload
    systemctl --user enable freedomnet.service
    systemctl --user start freedomnet.service
    ok "systemd service installed and started"
    ok "Manage with: systemctl --user {start|stop|restart|status} freedomnet"
}

# ── configure browsers ────────────────────────────────────────────────────────
configure_browsers() {
    echo
    log "Browser configuration:"
    echo
    echo -e "  ${BOLD}Firefox:${RESET}  Settings → General → Network Settings → Manual proxy"
    echo -e "            SOCKS v5: ${GREEN}127.0.0.1${RESET}  Port: ${GREEN}1080${RESET}"
    echo -e "            ✓ Proxy DNS when using SOCKS v5"
    echo
    echo -e "  ${BOLD}Chrome/Chromium:${RESET}"
    echo -e "    chromium --proxy-server='socks5://127.0.0.1:1080'"
    echo
    echo -e "  ${BOLD}PAC auto-config (system-wide):${RESET}"
    echo -e "    Settings → Network → Proxy → Automatic"
    echo -e "    URL: ${GREEN}http://127.0.0.1:8085/proxy.pac${RESET}"
    echo
    echo -e "  ${BOLD}curl:${RESET}   curl --socks5-hostname 127.0.0.1:1080 https://bbc.com"
    echo -e "  ${BOLD}wget:${RESET}   https_proxy=socks5h://127.0.0.1:1080 wget https://bbc.com"
    echo
}

# ── main ──────────────────────────────────────────────────────────────────────
main() {
    install_deps
    install_rust
    install_ldc
    fetch_repo
    build_proxy
    build_vpngen
    install_bins
    install_service
    configure_browsers

    echo
    echo -e "${GREEN}${BOLD}Installation complete!${RESET}"
    echo
    echo -e "Start the proxy:"
    echo -e "  ${BOLD}fn${RESET}"
    echo
    echo -e "Generate VPN configs:"
    echo -e "  ${BOLD}fn vpn openvpn --server vpn.example.com --port 1194${RESET}"
    echo -e "  ${BOLD}fn vpn wireguard --server 1.2.3.4:51820 --pubkey KEY${RESET}"
    echo -e "  ${BOLD}fn vpn shadowsocks --server 1.2.3.4 --password PASSWORD${RESET}"
    echo
    echo -e "Test blocked sites:"
    echo -e "  ${BOLD}fn-vpn check google.com youtube.com bbc.com${RESET}"
    echo
}

main "$@"
