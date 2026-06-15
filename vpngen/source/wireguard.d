/**
 * wireguard.d — WireGuard client config generator.
 *
 * Generates a wg0.conf suitable for `wg-quick up`.
 * The user must supply their server's public key and endpoint.
 * Client keypair generation instructions are included in the output.
 */
module wireguard;

import std.stdio  : File, stdout, stderr, writeln, writefln;
import std.format : format;
import std.string : empty;

struct WireGuardConfig
{
    string serverEndpoint;  // "host:port"
    string serverPubkey;    // base64 WireGuard public key
    string clientAddress;   // e.g. "10.0.0.2/32"
    string dns;
    string outPath;
}

void generate(in WireGuardConfig cfg)
{
    if (cfg.serverEndpoint.empty || cfg.serverPubkey.empty) {
        stderr.writeln("[fn-vpn] error: --server and --pubkey are required");
        return;
    }

    immutable content = format(q"CONF
# ============================================================
# FreedomNet — WireGuard client config
# Endpoint: %s
# ============================================================
#
# HOW TO USE:
#   1. Generate your keypair:
#        wg genkey | tee /tmp/wg_private | wg pubkey > /tmp/wg_public
#   2. Give the PUBLIC key (/tmp/wg_public) to your server admin.
#      They must add a [Peer] entry on the server side.
#   3. Paste your PRIVATE key into PrivateKey below.
#   4. Connect:
#        sudo wg-quick up %s      (Linux/macOS)
#        Import in WireGuard app  (Windows/Android/iOS)
# ============================================================

[Interface]
# Replace <PASTE_PRIVATE_KEY_HERE> with output of: cat /tmp/wg_private
PrivateKey      = <PASTE_PRIVATE_KEY_HERE>
Address         = %s
DNS             = %s
MTU             = 1420

[Peer]
# Server identity
PublicKey       = %s
Endpoint        = %s
AllowedIPs      = 0.0.0.0/0, ::/0
PersistentKeepalive = 25
CONF",
        cfg.serverEndpoint,
        cfg.outPath,
        cfg.clientAddress,
        cfg.dns,
        cfg.serverPubkey,
        cfg.serverEndpoint
    );

    auto f = File(cfg.outPath, "w");
    f.write(content);
    f.close();

    writefln("[fn-vpn] WireGuard config written → %s", cfg.outPath);
}
