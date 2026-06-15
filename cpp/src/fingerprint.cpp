/*
 * fingerprint.cpp — TLS fingerprint analysis for DPI detection research.
 *
 * Parses a ClientHello and extracts a JA3-style fingerprint string:
 *   SSLVersion,Ciphers,Extensions,EllipticCurves,EllipticCurvePointFormats
 *
 * This is used internally to classify TLS sessions and decide the optimal
 * bypass strategy (2-split, 3-split, or HTTP-mangle for plain traffic).
 *
 * Reference: https://github.com/salesforce/ja3
 */
#include "bypass_core.h"

#include <cstring>
#include <cstdint>
#include <cstdio>
#include <cstdlib>

/* ── safe big-endian reads ────────────────────────────────────────────────── */

static inline uint16_t u16be(const uint8_t *p)
{
    return static_cast<uint16_t>((p[0] << 8) | p[1]);
}

static inline uint32_t u32be(const uint8_t *p)
{
    return (static_cast<uint32_t>(p[0]) << 24)
         | (static_cast<uint32_t>(p[1]) << 16)
         | (static_cast<uint32_t>(p[2]) <<  8)
         | (static_cast<uint32_t>(p[3]));
}

/* ── output helpers ───────────────────────────────────────────────────────── */

/* Append decimal representation of v to buf[pos], return new pos. */
static size_t append_u16(char *buf, size_t cap, size_t pos, uint16_t v)
{
    char tmp[8];
    int n = std::snprintf(tmp, sizeof(tmp), "%u", static_cast<unsigned>(v));
    if (pos + n >= cap) return pos;
    std::memcpy(buf + pos, tmp, n);
    return pos + n;
}

static size_t append_char(char *buf, size_t cap, size_t pos, char c)
{
    if (pos + 1 >= cap) return pos;
    buf[pos] = c;
    return pos + 1;
}

/* ── JA3 GREASE filter ────────────────────────────────────────────────────── */
/* GREASE values (RFC 8701) must be excluded from JA3 fingerprint. */
static bool is_grease(uint16_t v)
{
    switch (v) {
    case 0x0a0a: case 0x1a1a: case 0x2a2a: case 0x3a3a:
    case 0x4a4a: case 0x5a5a: case 0x6a6a: case 0x7a7a:
    case 0x8a8a: case 0x9a9a: case 0xaaaa: case 0xbaba:
    case 0xcaca: case 0xdada: case 0xeaea: case 0xfafa:
        return true;
    default:
        return false;
    }
}

/*
 * fn_ja3_fingerprint — compute JA3 fingerprint of a TLS ClientHello.
 *
 * @param data      ClientHello bytes (TLS record layer included)
 * @param data_len  Length
 * @param out       Output buffer for null-terminated fingerprint string
 * @param out_cap   Capacity of out (recommend >= 256)
 * @return  Length of fingerprint string, or 0 on error
 */
size_t fn_ja3_fingerprint(const uint8_t *data, size_t data_len,
                           char *out, size_t out_cap)
{
    if (!out || out_cap < 2) return 0;
    out[0] = '\0';

    /* Outer TLS record: type(1) ver_hi(1) ver_lo(1) len(2) */
    if (data_len < 6 || data[0] != 0x16) return 0;

    uint16_t rec_ver = u16be(data + 1);
    /* Handshake starts at offset 5 */
    const uint8_t *hs     = data + 5;
    size_t         hs_max = data_len - 5;

    /* Handshake type(1) + length(3) + ClientHello version(2) */
    if (hs_max < 6 || hs[0] != 0x01) return 0;

    uint16_t ch_ver = u16be(hs + 4);

    /* Skip: type(1) length(3) version(2) random(32) */
    size_t pos = 1 + 3 + 2 + 32;
    if (pos + 1 > hs_max) return 0;

    /* Session ID */
    pos += 1 + hs[pos];
    if (pos + 2 > hs_max) return 0;

    /* Cipher suites */
    uint16_t cs_len = u16be(hs + pos);
    pos += 2;
    if (pos + cs_len > hs_max) return 0;

    /* Build output: version */
    size_t op = 0;
    op = append_u16(out, out_cap, op, ch_ver);
    op = append_char(out, out_cap, op, ',');

    /* Cipher suites (comma-separated, GREASE filtered) */
    bool first = true;
    for (size_t i = 0; i + 1 < cs_len; i += 2) {
        uint16_t cs = u16be(hs + pos + i);
        if (is_grease(cs)) continue;
        if (!first) op = append_char(out, out_cap, op, '-');
        op = append_u16(out, out_cap, op, cs);
        first = false;
    }
    pos += cs_len;

    /* Skip compression methods */
    if (pos + 1 > hs_max) goto finish;
    pos += 1 + hs[pos];

    /* Extensions */
    if (pos + 2 > hs_max) goto finish;
    {
        uint16_t ext_total = u16be(hs + pos);
        pos += 2;
        size_t ext_end = pos + ext_total;
        if (ext_end > hs_max) ext_end = hs_max;

        op = append_char(out, out_cap, op, ',');

        /* Three separate passes: ext_types, curves, point_formats */
        bool ext_first = true;

        /* -- pass 1: extension types -- */
        size_t p = pos;
        while (p + 4 <= ext_end) {
            uint16_t etype = u16be(hs + p);
            uint16_t elen  = u16be(hs + p + 2);
            p += 4;
            if (!is_grease(etype)) {
                if (!ext_first) op = append_char(out, out_cap, op, '-');
                op = append_u16(out, out_cap, op, etype);
                ext_first = false;
            }
            if (p + elen > ext_end) break;
            p += elen;
        }

        op = append_char(out, out_cap, op, ',');

        /* -- pass 2: supported_groups (0x000a) -- */
        p = pos;
        bool curves_first = true;
        while (p + 4 <= ext_end) {
            uint16_t etype = u16be(hs + p);
            uint16_t elen  = u16be(hs + p + 2);
            p += 4;
            if (etype == 0x000a && elen >= 2) {
                uint16_t list_len = u16be(hs + p);
                size_t   g        = p + 2;
                while (g + 1 < p + 2 + list_len && g + 1 < ext_end) {
                    uint16_t curve = u16be(hs + g);
                    if (!is_grease(curve)) {
                        if (!curves_first) op = append_char(out, out_cap, op, '-');
                        op = append_u16(out, out_cap, op, curve);
                        curves_first = false;
                    }
                    g += 2;
                }
            }
            if (p + elen > ext_end) break;
            p += elen;
        }

        op = append_char(out, out_cap, op, ',');

        /* -- pass 3: ec_point_formats (0x000b) -- */
        p = pos;
        bool pf_first = true;
        while (p + 4 <= ext_end) {
            uint16_t etype = u16be(hs + p);
            uint16_t elen  = u16be(hs + p + 2);
            p += 4;
            if (etype == 0x000b && elen >= 1) {
                uint8_t pf_len = hs[p];
                for (uint8_t i = 0; i < pf_len && p + 1 + i < ext_end; ++i) {
                    if (!pf_first) op = append_char(out, out_cap, op, '-');
                    op = append_u16(out, out_cap, op, hs[p + 1 + i]);
                    pf_first = false;
                }
            }
            if (p + elen > ext_end) break;
            p += elen;
        }
    }

finish:
    if (op < out_cap) out[op] = '\0';
    return op;
}

/*
 * fn_is_tls13 — returns true if the ClientHello advertises TLS 1.3 support.
 *
 * TLS 1.3 is indicated by the supported_versions extension (0x002b) containing
 * 0x0304.  The outer legacy_version is always 0x0303 for TLS 1.3 hellos.
 */
bool fn_is_tls13(const uint8_t *data, size_t data_len)
{
    if (data_len < 6 || data[0] != 0x16) return false;

    const uint8_t *hs = data + 5;
    size_t hs_max = data_len - 5;

    if (hs_max < 6 || hs[0] != 0x01) return false;

    size_t pos = 1 + 3 + 2 + 32; /* skip type, length, version, random */
    if (pos + 1 > hs_max) return false;
    pos += 1 + hs[pos]; /* session id */
    if (pos + 2 > hs_max) return false;
    uint16_t cs_len = u16be(hs + pos);
    pos += 2 + cs_len;
    if (pos + 1 > hs_max) return false;
    pos += 1 + hs[pos]; /* compression methods */
    if (pos + 2 > hs_max) return false;

    uint16_t ext_total = u16be(hs + pos);
    pos += 2;
    size_t ext_end = pos + ext_total;
    if (ext_end > hs_max) ext_end = hs_max;

    while (pos + 4 <= ext_end) {
        uint16_t etype = u16be(hs + pos);
        uint16_t elen  = u16be(hs + pos + 2);
        pos += 4;

        if (etype == 0x002b) { /* supported_versions */
            size_t p = pos;
            if (p + 1 > ext_end) break;
            uint8_t sv_len = hs[p++];
            while (p + 1 < pos + sv_len && p + 1 < ext_end) {
                if (u16be(hs + p) == 0x0304) return true;
                p += 2;
            }
        }

        if (pos + elen > ext_end) break;
        pos += elen;
    }
    return false;
}
