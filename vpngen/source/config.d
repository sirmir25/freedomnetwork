/**
 * config.d — FreedomNet configuration file parser and manager.
 *
 * Reads and writes a simple INI-style config file at ~/.config/freedomnet/config.ini
 *
 * Format:
 *   [section]
 *   key = value
 *   # comment
 *
 * Example config.ini:
 *   [proxy]
 *   listen = 127.0.0.1:1080
 *   pac_listen = 127.0.0.1:8085
 *   debug = false
 *
 *   [bypass]
 *   rules_file = ~/.config/freedomnet/rules.txt
 *   tls_split_mode = 3
 *   http_mangle = true
 *
 *   [doh]
 *   primary = https://cloudflare-dns.com/dns-query
 *   fallback = https://dns.google/dns-query
 *   cache_ttl = 300
 *
 *   [dashboard]
 *   enabled = true
 *   listen = 127.0.0.1:8086
 */
module config;

import std.stdio    : writeln, writefln, stderr, File;
import std.string   : strip, startsWith, indexOf, toLower;
import std.conv     : to, ConvException;
import std.file     : exists, mkdirRecurse, readText, write;
import std.path     : expandTilde, buildPath, dirName;
import std.array    : split, join;
import std.algorithm : strip;

// ── Data types ────────────────────────────────────────────────────────────────

struct ProxyConfig {
    string listen     = "127.0.0.1:1080";
    string pacListen  = "127.0.0.1:8085";
    bool   noPac      = false;
    bool   debug_     = false;
}

struct BypassConfig {
    string rulesFile     = "";
    int    tlsSplitMode  = 2;   // 2 or 3 records
    bool   httpMangle    = true;
    bool   anonLayer     = true;
}

struct DohConfig {
    string primary   = "https://cloudflare-dns.com/dns-query";
    string fallback  = "https://dns.google/dns-query";
    string tertiary  = "https://dns.quad9.net/dns-query";
    int    cacheTtl  = 300;  // seconds
}

struct DashboardConfig {
    bool   enabled  = true;
    string listen   = "127.0.0.1:8086";
}

struct FreedomNetConfig {
    ProxyConfig     proxy;
    BypassConfig    bypass;
    DohConfig       doh;
    DashboardConfig dashboard;
    string          configPath;
}

// ── Default config path ────────────────────────────────────────────────────────
string defaultConfigPath()
{
    version (Windows)
        return buildPath("%APPDATA%", "FreedomNet", "config.ini");
    else
        return expandTilde("~/.config/freedomnet/config.ini");
}

// ── Parser ────────────────────────────────────────────────────────────────────
FreedomNetConfig loadConfig(string path = "")
{
    FreedomNetConfig cfg;
    if (path.length == 0) path = defaultConfigPath();
    cfg.configPath = path;

    if (!exists(path)) {
        return cfg;
    }

    string text = readText(path);
    string section = "";

    foreach (rawLine; text.split('\n')) {
        string line = rawLine.strip();
        if (line.length == 0 || line.startsWith('#') || line.startsWith(';'))
            continue;

        if (line.startsWith('[') && line.indexOf(']') > 0) {
            section = line[1 .. line.indexOf(']')].strip().toLower();
            continue;
        }

        auto eqPos = line.indexOf('=');
        if (eqPos < 0) continue;

        string key = line[0 .. eqPos].strip().toLower();
        string val = line[eqPos + 1 .. $].strip();
        // strip inline comments
        auto hashPos = val.indexOf('#');
        if (hashPos >= 0) val = val[0 .. hashPos].strip();

        applyValue(cfg, section, key, val);
    }

    return cfg;
}

private void applyValue(ref FreedomNetConfig c,
                        string section, string key, string val)
{
    switch (section) {
    case "proxy":
        switch (key) {
        case "listen":      c.proxy.listen    = val; break;
        case "pac_listen":  c.proxy.pacListen = val; break;
        case "no_pac":      c.proxy.noPac     = parseBool(val); break;
        case "debug":       c.proxy.debug_    = parseBool(val); break;
        default: break;
        }
        break;

    case "bypass":
        switch (key) {
        case "rules_file":     c.bypass.rulesFile    = expandTilde(val); break;
        case "tls_split_mode": c.bypass.tlsSplitMode = safeToInt(val, 2); break;
        case "http_mangle":    c.bypass.httpMangle   = parseBool(val); break;
        case "anon_layer":     c.bypass.anonLayer    = parseBool(val); break;
        default: break;
        }
        break;

    case "doh":
        switch (key) {
        case "primary":    c.doh.primary   = val; break;
        case "fallback":   c.doh.fallback  = val; break;
        case "tertiary":   c.doh.tertiary  = val; break;
        case "cache_ttl":  c.doh.cacheTtl  = safeToInt(val, 300); break;
        default: break;
        }
        break;

    case "dashboard":
        switch (key) {
        case "enabled": c.dashboard.enabled = parseBool(val); break;
        case "listen":  c.dashboard.listen  = val; break;
        default: break;
        }
        break;

    default: break;
    }
}

// ── Writer ────────────────────────────────────────────────────────────────────
void saveConfig(const ref FreedomNetConfig c)
{
    mkdirRecurse(dirName(c.configPath));

    auto f = File(c.configPath, "w");
    f.writeln("# FreedomNet configuration");
    f.writeln("# Generated by fn-vpn config --save");
    f.writeln();
    f.writeln("[proxy]");
    f.writefln("listen     = %s", c.proxy.listen);
    f.writefln("pac_listen = %s", c.proxy.pacListen);
    f.writefln("no_pac     = %s", c.proxy.noPac);
    f.writefln("debug      = %s", c.proxy.debug_);
    f.writeln();
    f.writeln("[bypass]");
    f.writefln("rules_file     = %s", c.bypass.rulesFile.length > 0
                                      ? c.bypass.rulesFile
                                      : "bypass-rules.txt");
    f.writefln("tls_split_mode = %d", c.bypass.tlsSplitMode);
    f.writefln("http_mangle    = %s", c.bypass.httpMangle);
    f.writefln("anon_layer     = %s", c.bypass.anonLayer);
    f.writeln();
    f.writeln("[doh]");
    f.writefln("primary   = %s", c.doh.primary);
    f.writefln("fallback  = %s", c.doh.fallback);
    f.writefln("tertiary  = %s", c.doh.tertiary);
    f.writefln("cache_ttl = %d", c.doh.cacheTtl);
    f.writeln();
    f.writeln("[dashboard]");
    f.writefln("enabled = %s", c.dashboard.enabled);
    f.writefln("listen  = %s", c.dashboard.listen);
    f.close();
}

// ── Printer (for 'fn-vpn config --show') ─────────────────────────────────────
void printConfig(const ref FreedomNetConfig c)
{
    writefln("Config file: %s", c.configPath);
    writefln("  [proxy]");
    writefln("    listen     = %s", c.proxy.listen);
    writefln("    pac_listen = %s", c.proxy.pacListen);
    writefln("    no_pac     = %s", c.proxy.noPac);
    writefln("    debug      = %s", c.proxy.debug_);
    writefln("  [bypass]");
    writefln("    rules_file     = %s",
             c.bypass.rulesFile.length > 0 ? c.bypass.rulesFile : "(default bypass-rules.txt)");
    writefln("    tls_split_mode = %d (records per ClientHello)", c.bypass.tlsSplitMode);
    writefln("    http_mangle    = %s", c.bypass.httpMangle);
    writefln("    anon_layer     = %s", c.bypass.anonLayer);
    writefln("  [doh]");
    writefln("    primary   = %s", c.doh.primary);
    writefln("    fallback  = %s", c.doh.fallback);
    writefln("    tertiary  = %s", c.doh.tertiary);
    writefln("    cache_ttl = %ds", c.doh.cacheTtl);
    writefln("  [dashboard]");
    writefln("    enabled = %s", c.dashboard.enabled);
    writefln("    listen  = %s", c.dashboard.listen);
}

// ── CLI integration ────────────────────────────────────────────────────────────
int runConfigCmd(string[] args)
{
    bool doShow = false, doSave = false, doReset = false;
    string cfgPath = defaultConfigPath();

    import std.getopt : getopt, config, GetOptException;
    try {
        string[] a = ["fn-vpn"] ~ args;
        auto info = getopt(a,
            config.passThrough,
            "show",   "Print current config",            &doShow,
            "save",   "Save defaults to config file",    &doSave,
            "reset",  "Reset config to defaults",        &doReset,
            "file|f", "Config file path",                &cfgPath,
        );
        if (info.helpWanted) {
            writeln("fn-vpn config [--show] [--save] [--reset] [--file PATH]");
            return 0;
        }
    } catch (GetOptException e) {
        stderr.writefln("[config] %s", e.msg);
        return 1;
    }

    FreedomNetConfig cfg = loadConfig(cfgPath);

    if (doReset) cfg = FreedomNetConfig(); // reset to defaults

    if (doSave || doReset) {
        cfg.configPath = cfgPath;
        saveConfig(cfg);
        writefln("Saved to %s", cfgPath);
    }

    if (doShow || (!doSave && !doReset)) {
        printConfig(cfg);
    }

    return 0;
}

// ── Utilities ─────────────────────────────────────────────────────────────────
private bool parseBool(string s)
{
    switch (s.toLower()) {
    case "true", "yes", "1", "on":  return true;
    case "false", "no", "0", "off": return false;
    default: return false;
    }
}

private int safeToInt(string s, int def)
{
    try { return s.to!int; }
    catch (ConvException) { return def; }
}
