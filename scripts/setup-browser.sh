#!/usr/bin/env bash
# FreedomNet browser proxy configurator
# Automatically configures Firefox, Chromium, and system proxy settings.

set -euo pipefail

PROXY_HOST="127.0.0.1"
PROXY_PORT="1080"
PAC_URL="http://127.0.0.1:8085/proxy.pac"

GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
BOLD='\033[1m'
RESET='\033[0m'

log()  { echo -e "${BLUE}${BOLD}[browser-setup]${RESET} $*"; }
ok()   { echo -e "${GREEN}✓${RESET} $*"; }
warn() { echo -e "${YELLOW}⚠${RESET}  $*"; }

OS=$(uname -s)

# ── Firefox ───────────────────────────────────────────────────────────────────
configure_firefox() {
    log "Configuring Firefox..."

    # Find Firefox profile directory
    local profile_dir=""
    case "$OS" in
        Darwin)
            profile_dir=$(find "$HOME/Library/Application Support/Firefox/Profiles" \
                -name "prefs.js" 2>/dev/null | head -1 | xargs -I{} dirname {})
            ;;
        Linux)
            profile_dir=$(find "$HOME/.mozilla/firefox" \
                -name "prefs.js" 2>/dev/null | head -1 | xargs -I{} dirname {})
            ;;
    esac

    if [ -z "$profile_dir" ]; then
        warn "Firefox profile not found. Configure manually:"
        warn "  Settings → General → Network Settings → Manual proxy"
        warn "  SOCKS v5: $PROXY_HOST  Port: $PROXY_PORT"
        warn "  ✓ Proxy DNS when using SOCKS v5"
        return 1
    fi

    local prefs="$profile_dir/prefs.js"

    # Backup existing prefs
    cp "$prefs" "$prefs.bak.$(date +%s)"

    # Remove existing proxy settings
    grep -v 'network.proxy\|socks\|proxyType' "$prefs" > "$prefs.tmp" || true
    mv "$prefs.tmp" "$prefs"

    # Write new proxy settings
    cat >> "$prefs" << EOF

// FreedomNet SOCKS5 proxy — added by setup-browser.sh
user_pref("network.proxy.type", 1);
user_pref("network.proxy.socks", "$PROXY_HOST");
user_pref("network.proxy.socks_port", $PROXY_PORT);
user_pref("network.proxy.socks_version", 5);
user_pref("network.proxy.socks_remote_dns", true);
user_pref("network.proxy.no_proxies_on", "localhost, 127.0.0.1, ::1, 10.0.0.0/8, 192.168.0.0/16");
EOF

    ok "Firefox configured (SOCKS5 $PROXY_HOST:$PROXY_PORT)"
    warn "Restart Firefox for changes to take effect"
}

# ── Chromium / Chrome ─────────────────────────────────────────────────────────
configure_chromium() {
    log "Generating Chromium launch script..."

    local script="$HOME/.local/bin/freedom-chrome"
    mkdir -p "$(dirname "$script")"

    cat > "$script" << CHROMESCRIPT
#!/usr/bin/env bash
# Launch Chrome/Chromium with FreedomNet SOCKS5 proxy

SOCKS="socks5://${PROXY_HOST}:${PROXY_PORT}"

for browser in google-chrome chromium-browser chromium brave-browser; do
    if command -v "\$browser" &>/dev/null; then
        exec "\$browser" --proxy-server="\$SOCKS" "\$@"
    fi
done

# macOS
for app in "Google Chrome" "Chromium" "Brave Browser"; do
    if [ -d "/Applications/\${app}.app" ]; then
        exec open -a "\${app}" --args --proxy-server="\$SOCKS" "\$@"
    fi
done

echo "Chrome/Chromium not found. Install from https://www.google.com/chrome/"
exit 1
CHROMESCRIPT

    chmod +x "$script"
    ok "Created: $script"
    ok "Use: freedom-chrome [url...]"
}

# ── System proxy (macOS) ──────────────────────────────────────────────────────
configure_system_macos() {
    if [ "$OS" != "Darwin" ]; then return 0; fi
    log "Configuring macOS system SOCKS5 proxy..."

    # Get all network services
    local services
    services=$(networksetup -listallnetworkservices 2>/dev/null | tail -n +2)

    while IFS= read -r svc; do
        [ -z "$svc" ] && continue
        networksetup -setsocksfirewallproxy "$svc" "$PROXY_HOST" "$PROXY_PORT" 2>/dev/null || true
        networksetup -setsocksfirewallproxystate "$svc" on 2>/dev/null || true
        ok "System SOCKS5 set for: $svc"
    done <<< "$services"
}

# ── System proxy (Linux/GNOME) ────────────────────────────────────────────────
configure_system_linux() {
    if [ "$OS" != "Linux" ]; then return 0; fi

    if command -v gsettings &>/dev/null; then
        log "Configuring GNOME system proxy..."
        gsettings set org.gnome.system.proxy mode 'manual'
        gsettings set org.gnome.system.proxy.socks host "$PROXY_HOST"
        gsettings set org.gnome.system.proxy.socks port "$PROXY_PORT"
        ok "GNOME system proxy configured"
        return 0
    fi

    warn "Auto system-proxy not supported for your desktop environment."
    warn "Set manually: SOCKS5 $PROXY_HOST:$PROXY_PORT"
}

# ── curl / wget env ───────────────────────────────────────────────────────────
configure_cli_tools() {
    log "Configuring CLI proxy environment..."

    SHELL_RC="$HOME/.bashrc"
    [ -f "$HOME/.zshrc" ] && SHELL_RC="$HOME/.zshrc"

    # Avoid duplicate
    if grep -q 'FREEDOMNET_PROXY' "$SHELL_RC" 2>/dev/null; then
        ok "CLI proxy already configured in $SHELL_RC"
        return 0
    fi

    cat >> "$SHELL_RC" << SHELLEOF

# FreedomNet DPI bypass proxy
export FREEDOMNET_PROXY="socks5h://${PROXY_HOST}:${PROXY_PORT}"
# Uncomment to route all CLI tools through FreedomNet:
# export ALL_PROXY="\$FREEDOMNET_PROXY"
# export HTTP_PROXY="http://${PROXY_HOST}:${PROXY_PORT}"
# export HTTPS_PROXY="http://${PROXY_HOST}:${PROXY_PORT}"

# Convenience aliases
alias fn-curl="curl --socks5-hostname ${PROXY_HOST}:${PROXY_PORT}"
alias fn-wget="https_proxy=socks5h://${PROXY_HOST}:${PROXY_PORT} wget"
SHELLEOF

    ok "Added proxy aliases to $SHELL_RC"
    ok "  fn-curl https://bbc.com"
    ok "  fn-wget https://bbc.com"
}

# ── main ──────────────────────────────────────────────────────────────────────
echo
echo -e "${BOLD}FreedomNet Browser Configurator${RESET}"
echo

configure_firefox
configure_chromium
configure_system_macos
configure_system_linux
configure_cli_tools

echo
ok "Done! Proxy: SOCKS5 $PROXY_HOST:$PROXY_PORT"
ok "PAC URL:  $PAC_URL"
echo
