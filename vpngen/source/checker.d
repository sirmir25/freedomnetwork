/**
 * checker.d — FreedomNet domain reachability checker.
 *
 * Tests whether a list of domains are accessible via direct TCP connection.
 * Useful for quickly seeing which sites are blocked by your ISP before
 * running FreedomNet, and verifying that the proxy fixes the issue.
 *
 * Usage (via fn-vpn):
 *   fn-vpn check google.com youtube.com bbc.com rutracker.org
 *
 * Output example:
 *   Checking 4 domains on port 443 (timeout 3s)...
 *   ✓  google.com          142ms   reachable
 *   ✓  youtube.com         156ms   reachable
 *   ✗  bbc.com             3001ms  BLOCKED (timeout)
 *   ✗  rutracker.org        timeout  BLOCKED (DNS/TCP)
 *
 *   Summary: 2 reachable, 2 blocked
 */
module checker;

import std.socket    : TcpSocket, InternetAddress, SocketOption, SocketOptionLevel;
import std.stdio     : writeln, writefln, stderr;
import std.datetime  : Duration, dur;
import core.time     : MonoTime;
import std.algorithm : max;
import std.string    : format;
import std.conv      : to;

private struct Result {
    string domain;
    bool   ok;
    long   msec;
    string note;
}

private Result probe(string domain, ushort port, int timeoutMs)
{
    auto start = MonoTime.currTime;
    try {
        auto addr = new InternetAddress(domain, port);
        auto sock = new TcpSocket();
        scope(exit) sock.close();

        // SO_RCVTIMEO / SO_SNDTIMEO as a Duration
        auto tv = dur!"msecs"(timeoutMs);
        sock.setOption(SocketOptionLevel.SOCKET, SocketOption.RCVTIMEO, tv);
        sock.setOption(SocketOptionLevel.SOCKET, SocketOption.SNDTIMEO, tv);

        sock.connect(addr);
        long ms = (MonoTime.currTime - start).total!"msecs";
        return Result(domain, true, ms, "reachable");
    } catch (Exception e) {
        long ms = (MonoTime.currTime - start).total!"msecs";
        string note = ms >= timeoutMs - 50 ? "BLOCKED (timeout)" : "BLOCKED (" ~ e.msg ~ ")";
        return Result(domain, false, ms, note);
    }
}

private void colorLine(Result r)
{
    // ANSI colours: green = 32, red = 31, reset = 0
    string tick = r.ok ? "\033[32m✓\033[0m" : "\033[31m✗\033[0m";
    writefln("  %s  %-30s  %4dms  %s", tick, r.domain, r.msec, r.note);
}

int runChecker(string[] domains)
{
    if (domains.length == 0) {
        stderr.writeln("[checker] No domains specified.");
        stderr.writeln("Usage: fn-vpn check <domain1> [domain2] ...");
        return 1;
    }

    immutable ushort port       = 443;
    immutable int    timeoutMs  = 3000;

    writefln("\nChecking %d domain(s) on port %d (timeout %ds)...\n",
             domains.length, port, timeoutMs / 1000);

    int blocked = 0, ok = 0;
    foreach (d; domains) {
        auto r = probe(d, port, timeoutMs);
        colorLine(r);
        if (r.ok) ++ok; else ++blocked;
    }

    writeln();
    writefln("Summary: \033[32m%d reachable\033[0m, \033[31m%d blocked\033[0m",
             ok, blocked);

    if (blocked > 0) {
        writeln("\nRun FreedomNet proxy and set your browser to SOCKS5 127.0.0.1:1080");
        writeln("to bypass the blocked sites listed above.");
    }
    writeln();
    return blocked > 0 ? 2 : 0;  // exit 2 = some blocked, 0 = all clear
}
