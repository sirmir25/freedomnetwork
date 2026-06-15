/**
 * app.d — fn-vpn: VPN client config generator.
 *
 * Part of FreedomNet. Generates ready-to-use configs for:
 *   OpenVPN, WireGuard, Shadowsocks
 *
 * Usage:
 *   fn-vpn openvpn    --server <host> [--port 1194] [--tcp] [--out client.ovpn]
 *   fn-vpn wireguard  --server <host:port> --pubkey <b64> [--address 10.0.0.2/32] [--out wg0.conf]
 *   fn-vpn shadowsocks --server <host> --password <pw> [--port 8388] [--method aes-256-gcm] [--out ss.json]
 */
module app;

import std.stdio   : stderr, writeln, writefln;
import std.getopt  : getopt, config, GetOptException;
import std.string  : empty, toLower;
import openvpn     : OpenVpnConfig,    generate;
import wireguard   : WireGuardConfig,  generate;
import shadowsocks : ShadowsocksConfig, generate;
import checker     : runChecker;
import config      : runConfigCmd;

void printHelp()
{
    writeln("fn-vpn — FreedomNet VPN config generator & domain checker");
    writeln();
    writeln("Commands:");
    writeln("  openvpn     --server <host> [--port 1194] [--tcp] [--out client.ovpn]");
    writeln("  wireguard   --server <host:port> --pubkey <key> [--address 10.0.0.2/32] [--out wg0.conf]");
    writeln("  shadowsocks --server <host> --password <pw> [--port 8388] [--method aes-256-gcm] [--out ss.json]");
    writeln("  check       <domain1> [domain2] ...   Test direct TCP reachability");
    writeln();
    writeln("Examples:");
    writeln("  fn-vpn check google.com youtube.com bbc.com rutracker.org");
    writeln("  fn-vpn openvpn --server vpn.example.com --port 1194");
    writeln("  fn-vpn wireguard --server 1.2.3.4:51820 --pubkey abc123==");
    writeln("  fn-vpn shadowsocks --server 1.2.3.4 --password s3cr3t --method chacha20-ietf-poly1305");
}

int main(string[] args)
{
    if (args.length < 2) {
        printHelp();
        return 0;
    }

    immutable cmd = args[1].toLower();

    switch (cmd) {
        case "openvpn":
            return cmdOpenVpn(args[2..$]);
        case "wireguard":
            return cmdWireGuard(args[2..$]);
        case "shadowsocks":
            return cmdShadowsocks(args[2..$]);
        case "check":
            return runChecker(args[2..$]);
        case "config":
            return runConfigCmd(args[2..$]);
        case "-h", "--help", "help":
            printHelp();
            return 0;
        default:
            stderr.writefln("[fn-vpn] Unknown command: %s", cmd);
            printHelp();
            return 1;
    }
}

int cmdOpenVpn(string[] args)
{
    string server, outFile = "client.ovpn";
    ushort port = 1194;
    bool   tcp  = false;

    try {
        string[] a = ["fn-vpn"] ~ args; // getopt requires args[0] = program name
        auto info = getopt(a,
            config.passThrough,
            "server|s", "Server hostname or IP",  &server,
            "port|p",   "Server port (def 1194)", &port,
            "tcp",      "Use TCP instead of UDP", &tcp,
            "out|o",    "Output .ovpn file",      &outFile
        );
        if (info.helpWanted) { printHelp(); return 0; }
    } catch (GetOptException e) {
        stderr.writefln("[fn-vpn] %s", e.msg);
        return 1;
    }

    generate(OpenVpnConfig(server, port, tcp ? "tcp" : "udp", outFile));
    return 0;
}

int cmdWireGuard(string[] args)
{
    string server, pubkey, address = "10.0.0.2/32", dns = "1.1.1.1", outFile = "wg0.conf";

    try {
        string[] a = ["fn-vpn"] ~ args;
        auto info = getopt(a,
            config.passThrough,
            "server|s",  "Server endpoint (host:port)", &server,
            "pubkey|k",  "Server WireGuard public key", &pubkey,
            "address|a", "Client tunnel IP (CIDR)",     &address,
            "dns|d",     "DNS inside tunnel",           &dns,
            "out|o",     "Output .conf file",           &outFile
        );
        if (info.helpWanted) { printHelp(); return 0; }
    } catch (GetOptException e) {
        stderr.writefln("[fn-vpn] %s", e.msg);
        return 1;
    }

    generate(WireGuardConfig(server, pubkey, address, dns, outFile));
    return 0;
}

int cmdShadowsocks(string[] args)
{
    string server, password, method = "aes-256-gcm", outFile = "ss-config.json";
    ushort port = 8388;

    try {
        string[] a = ["fn-vpn"] ~ args;
        auto info = getopt(a,
            config.passThrough,
            "server|s",   "Server hostname or IP",          &server,
            "port|p",     "Server port (def 8388)",         &port,
            "password|w", "Shadowsocks password",           &password,
            "method|m",   "Cipher method (def aes-256-gcm)", &method,
            "out|o",      "Output JSON file",               &outFile
        );
        if (info.helpWanted) { printHelp(); return 0; }
    } catch (GetOptException e) {
        stderr.writefln("[fn-vpn] %s", e.msg);
        return 1;
    }

    generate(ShadowsocksConfig(server, port, password, method, outFile));
    return 0;
}
