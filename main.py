#!/usr/bin/env python3
"""
DPI Bypass Proxy
================
Local SOCKS5 + HTTP-CONNECT proxy that evades Deep Packet Inspection without
routing traffic through any remote server.

Techniques applied per-connection:
  1. DNS over HTTPS  — resolves hostnames via Cloudflare/Google DoH instead of
                       the ISP's poisoned/blocked DNS servers.
  2. TLS fragmentation — splits the TLS ClientHello across two TCP segments at
                         the midpoint of the SNI hostname field.  Most DPI
                         hardware that does first-packet SNI inspection misses
                         the hostname completely.
  3. HTTP mangling   — randomises HTTP header-name casing for plaintext HTTP
                       requests to defeat keyword-match blocking.

Usage:
  python main.py [--port 1080] [--host 127.0.0.1] [--debug]

  Then point your browser's proxy to SOCKS5 127.0.0.1:1080
  (or HTTP proxy 127.0.0.1:1080 for HTTPS-only via CONNECT).
"""
from __future__ import annotations

import argparse
import asyncio
import logging
import os
import socket
import struct
import sys

from config import CHUNK_SIZE, CONNECT_TIMEOUT, DEFAULT_PORT, READ_TIMEOUT
from doh import resolve
from http_bypass import is_http, mangle_request
from tls_fragment import is_client_hello, split_into_records, split_tcp_only

log = logging.getLogger("bypass")
DEBUG = False


# ── Bidirectional relay ──────────────────────────────────────────────────────

async def _relay(src: asyncio.StreamReader, dst: asyncio.StreamWriter) -> None:
    try:
        while True:
            chunk = await src.read(CHUNK_SIZE)
            if not chunk:
                break
            dst.write(chunk)
            await dst.drain()
    except (ConnectionResetError, BrokenPipeError, asyncio.CancelledError, OSError):
        pass
    finally:
        try:
            dst.close()
        except Exception:
            pass


# ── Core tunnel with DPI bypass ──────────────────────────────────────────────

async def _tunnel(
    client_r: asyncio.StreamReader,
    client_w: asyncio.StreamWriter,
    host: str,
    port: int,
) -> None:
    loop = asyncio.get_event_loop()

    # — DNS via DoH —
    ip = await resolve(host)
    if not ip:
        log.warning("DNS failed: %s", host)
        client_w.close()
        return

    if DEBUG:
        log.debug("DNS %s → %s", host, ip)

    # — TCP connect with TCP_NODELAY so fragment sends reach the wire separately —
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    sock.setblocking(False)

    try:
        await asyncio.wait_for(loop.sock_connect(sock, (ip, port)), timeout=CONNECT_TIMEOUT)
    except Exception as exc:
        log.warning("Connect %s:%d → %s", host, port, exc)
        sock.close()
        client_w.close()
        return

    # — Read first payload from browser (TLS ClientHello or HTTP request) —
    try:
        first = await asyncio.wait_for(client_r.read(CHUNK_SIZE), timeout=READ_TIMEOUT)
    except asyncio.TimeoutError:
        sock.close()
        client_w.close()
        return

    if not first:
        sock.close()
        client_w.close()
        return

    # — Apply DPI bypass and send to server via raw socket (guarantees segmentation) —
    try:
        if is_client_hello(first):
            # TLS record fragmentation: repackage into 2 TLS records, each in
            # its own TCP segment.  Breaks DPI parsers even when they reassemble TCP.
            r1, r2 = split_into_records(first)
            if DEBUG:
                log.debug("TLS record-split %s → record1=%dB record2=%dB", host, len(r1), len(r2))
            await loop.sock_sendall(sock, r1)
            await loop.sock_sendall(sock, r2)
        elif is_http(first):
            await loop.sock_sendall(sock, mangle_request(first))
        else:
            await loop.sock_sendall(sock, first)
    except OSError as exc:
        log.warning("Send to %s:%d failed: %s", host, port, exc)
        sock.close()
        client_w.close()
        return

    # — Hand socket to asyncio streams and pipe the rest bidirectionally —
    srv_r, srv_w = await asyncio.open_connection(sock=sock)

    await asyncio.gather(
        _relay(client_r, srv_w),
        _relay(srv_r, client_w),
        return_exceptions=True,
    )


# ── SOCKS5 handler (RFC 1928, no-auth only) ──────────────────────────────────

async def _handle_socks5(r: asyncio.StreamReader, w: asyncio.StreamWriter) -> None:
    try:
        nmethods = (await r.readexactly(1))[0]
        await r.readexactly(nmethods)           # discard offered auth methods
        w.write(b"\x05\x00")                    # reply: no authentication
        await w.drain()

        _ver, cmd, _rsv, atyp = await r.readexactly(4)
        if cmd != 0x01:                         # only CONNECT supported
            w.write(b"\x05\x07\x00\x01\x00\x00\x00\x00\x00\x00")
            return

        if atyp == 0x01:                        # IPv4
            host = socket.inet_ntoa(await r.readexactly(4))
        elif atyp == 0x03:                      # domain name
            n = (await r.readexactly(1))[0]
            host = (await r.readexactly(n)).decode("ascii")
        elif atyp == 0x04:                      # IPv6
            host = socket.inet_ntop(socket.AF_INET6, await r.readexactly(16))
        else:
            w.write(b"\x05\x08\x00\x01\x00\x00\x00\x00\x00\x00")
            return

        port = struct.unpack("!H", await r.readexactly(2))[0]

        w.write(b"\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00")  # success
        await w.drain()

        log.info("SOCKS5  %s:%d", host, port)
        await _tunnel(r, w, host, port)

    except (asyncio.IncompleteReadError, ConnectionResetError, OSError):
        pass
    finally:
        try:
            w.close()
        except Exception:
            pass


# ── HTTP CONNECT handler ──────────────────────────────────────────────────────

async def _handle_http_connect(
    r: asyncio.StreamReader, w: asyncio.StreamWriter, first_byte: bytes
) -> None:
    try:
        rest = await asyncio.wait_for(r.readuntil(b"\r\n\r\n"), timeout=10)
        request_line = (first_byte + rest).split(b"\r\n")[0].decode("ascii", errors="replace")
        parts = request_line.split()

        if len(parts) < 2 or parts[0].upper() != "CONNECT":
            return

        hostport = parts[1]
        if ":" in hostport:
            host, port_s = hostport.rsplit(":", 1)
            port = int(port_s)
        else:
            host, port = hostport, 443

        w.write(b"HTTP/1.1 200 Connection established\r\n\r\n")
        await w.drain()

        log.info("CONNECT %s:%d", host, port)
        await _tunnel(r, w, host, port)

    except (asyncio.IncompleteReadError, asyncio.TimeoutError, ConnectionResetError, OSError, ValueError):
        pass
    finally:
        try:
            w.close()
        except Exception:
            pass


# ── Protocol dispatcher ───────────────────────────────────────────────────────

async def _dispatch(r: asyncio.StreamReader, w: asyncio.StreamWriter) -> None:
    try:
        first = await asyncio.wait_for(r.read(1), timeout=10)
    except (asyncio.TimeoutError, ConnectionResetError, OSError):
        try:
            w.close()
        except Exception:
            pass
        return

    if not first:
        w.close()
        return

    if first == b"\x05":
        await _handle_socks5(r, w)
    else:
        await _handle_http_connect(r, w, first)


# ── Entry point ───────────────────────────────────────────────────────────────

async def _serve(host: str, port: int) -> None:
    server = await asyncio.start_server(_dispatch, host, port)
    addr = server.sockets[0].getsockname()
    print(f"\n  DPI Bypass Proxy ready on {addr[0]}:{addr[1]}")
    print("  ─────────────────────────────────────────────")
    print(f"  Browser proxy settings (pick one):")
    print(f"    SOCKS5   {addr[0]}  port {addr[1]}")
    print(f"    HTTP     {addr[0]}  port {addr[1]}")
    print()
    print("  Active techniques: DoH DNS · TLS record fragmentation · HTTP mangling")
    print("  Press Ctrl+C to stop.\n")

    async with server:
        await server.serve_forever()


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Local DPI bypass proxy — no VPN, no remote server.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--port", type=int, default=DEFAULT_PORT, help=f"Listen port (default {DEFAULT_PORT})")
    parser.add_argument("--host", default="127.0.0.1", help="Listen address (default 127.0.0.1)")
    parser.add_argument("--debug", action="store_true", help="Verbose per-connection logging")
    args = parser.parse_args()

    global DEBUG
    DEBUG = args.debug
    if DEBUG:
        os.environ["BYPASS_DEBUG"] = "1"

    logging.basicConfig(
        format="%(asctime)s %(levelname)s %(message)s",
        level=logging.DEBUG if args.debug else logging.INFO,
    )

    try:
        asyncio.run(_serve(args.host, args.port))
    except KeyboardInterrupt:
        print("Stopped.")
    except OSError as exc:
        sys.exit(f"Error: {exc}")


if __name__ == "__main__":
    main()
