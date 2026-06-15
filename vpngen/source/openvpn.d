/**
 * openvpn.d — OpenVPN client config generator.
 *
 * Generates a production-ready .ovpn file that works with any standard
 * OpenVPN 2.x / 3.x server.  Certificate slots are clearly marked so the
 * user can paste CA cert, client cert, and private key from their server.
 */
module openvpn;

import std.stdio  : File, stdout, stderr, writeln, writefln;
import std.format : format;
import std.string : empty;

struct OpenVpnConfig
{
    string server;
    ushort port;
    string proto;    // "udp" or "tcp"
    string outPath;
}

void generate(in OpenVpnConfig cfg)
{
    if (cfg.server.empty) {
        stderr.writeln("[fn-vpn] error: --server is required");
        return;
    }

    immutable content = format(q"CONF
# ============================================================
# FreedomNet — OpenVPN client config
# Generated for server: %s:%d (%s)
#
# HOW TO USE:
#   1. Paste your CA certificate between <ca>...</ca>
#   2. Paste your client certificate between <cert>...</cert>
#   3. Paste your client private key between <key>...</key>
#   4. Import this file into OpenVPN Connect / Tunnelblick / NetworkManager
# ============================================================

client
dev         tun
proto       %s
remote      %s %d

resolv-retry infinite
nobind
persist-key
persist-tun

# TLS hardening
remote-cert-tls server
tls-client
tls-version-min 1.2
tls-cipher      TLS-ECDHE-RSA-WITH-AES-256-GCM-SHA384:TLS-ECDHE-RSA-WITH-AES-128-GCM-SHA256

# Data-channel cipher
cipher  AES-256-GCM
auth    SHA256

# Redirect all traffic through the VPN
redirect-gateway def1 bypass-dhcp

# Use VPN server's DNS (change to your preference)
dhcp-option DNS 1.1.1.1
dhcp-option DNS 8.8.8.8

# Keep-alive (10s ping, 120s timeout)
keepalive 10 120

# Compression disabled for security (VORACLE)
compress

verb 3
mute 10

# ── Certificates (paste below) ──────────────────────────────
<ca>
# Paste your CA certificate here (-----BEGIN CERTIFICATE-----)
</ca>

<cert>
# Paste your client certificate here
</cert>

<key>
# Paste your client private key here (-----BEGIN PRIVATE KEY-----)
</key>
CONF",
        cfg.server, cfg.port, cfg.proto,
        cfg.proto, cfg.server, cfg.port
    );

    auto f = File(cfg.outPath, "w");
    f.write(content);
    f.close();

    writefln("[fn-vpn] OpenVPN config written → %s", cfg.outPath);
    writeln();
    writeln("Next steps:");
    writefln("  1. Open %s and paste CA cert, client cert, private key.", cfg.outPath);
    writeln("  2. Install OpenVPN: https://openvpn.net/client/");
    writefln("  3. Import %s and connect.", cfg.outPath);
}
