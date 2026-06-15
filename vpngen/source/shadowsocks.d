/**
 * shadowsocks.d — Shadowsocks client config generator.
 *
 * Generates a JSON config file compatible with shadowsocks-libev, shadowsocks-rust,
 * and most Shadowsocks clients (ss-local / Shadowrocket / Clash).
 */
module shadowsocks;

import std.stdio  : File, stderr, writeln, writefln;
import std.format : format;
import std.string : empty;

struct ShadowsocksConfig
{
    string server;
    ushort port;
    string password;
    string method;   // e.g. "aes-256-gcm", "chacha20-ietf-poly1305"
    string outPath;
}

void generate(in ShadowsocksConfig cfg)
{
    if (cfg.server.empty || cfg.password.empty) {
        stderr.writeln("[fn-vpn] error: --server and --password are required");
        return;
    }

    // Escape the password for JSON (handle backslash and double-quote)
    string escapedPw;
    foreach (char c; cfg.password) {
        if      (c == '"')  escapedPw ~= `\"`;
        else if (c == '\\') escapedPw ~= `\\`;
        else                escapedPw ~= c;
    }

    immutable content = format(q"JSON
{
    "server":        "%s",
    "server_port":   %d,
    "password":      "%s",
    "method":        "%s",
    "local_address": "127.0.0.1",
    "local_port":    1080,
    "timeout":       300,
    "fast_open":     false,
    "mode":          "tcp_and_udp"
}
JSON",
        cfg.server,
        cfg.port,
        escapedPw,
        cfg.method
    );

    auto f = File(cfg.outPath, "w");
    f.write(content);
    f.close();

    writefln("[fn-vpn] Shadowsocks config written → %s", cfg.outPath);
    writeln();
    writeln("Run with shadowsocks-rust:  sslocal -c " ~ cfg.outPath);
    writeln("Run with shadowsocks-libev: ss-local -c " ~ cfg.outPath);
}
