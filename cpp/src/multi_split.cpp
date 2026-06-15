/*
 * multi_split.cpp — three-record TLS ClientHello fragmenter.
 *
 * fn_tls_split3() slices one ClientHello into three TLS records:
 *
 *   r1 → only the first byte of the Handshake body (HandshakeType = 0x01)
 *   r2 → bytes 2 … SNI_midpoint-1
 *   r3 → SNI_midpoint … end
 *
 * Splitting at the very first byte forces DPI to reassemble at least r1+r2
 * before it can even begin Handshake parsing, and the SNI is still never
 * complete in any single record.  Servers are fully RFC-compliant: they MUST
 * reassemble TLS records before parsing the Handshake layer (RFC 5246 §6.2.1).
 */
#include "bypass_core.h"

#include <cstring>
#include <cstdint>

/* ── helpers (replicated locally to keep this TU self-contained) ─────────── */

static bool is_ch(const uint8_t *d, size_t n)
{
    /* TLS record:  0x16  legacy-major  legacy-minor  len_hi  len_lo
       Handshake:   0x01  ...                                        */
    return n >= 6 && d[0] == 0x16 && d[1] == 0x03 && d[5] == 0x01;
}

/* Write one TLS record: type=0x16, version=0x0301, payload = data[off..off+plen] */
static size_t emit(uint8_t *dst, size_t cap,
                   const uint8_t *payload, size_t plen)
{
    if (cap < plen + 5) return 0;
    dst[0] = 0x16;
    dst[1] = 0x03;
    dst[2] = 0x01;
    dst[3] = static_cast<uint8_t>(plen >> 8);
    dst[4] = static_cast<uint8_t>(plen & 0xff);
    std::memcpy(dst + 5, payload, plen);
    return plen + 5;
}

/* Find SNI midpoint offset within the raw Handshake payload (after outer header).
 * Returns 0 if not found (use payload_len/2 as fallback). */
static size_t sni_midpoint(const uint8_t *hs, size_t hs_len)
{
    /* skip HandshakeType(1) + Length(3) + ClientHello fixed header(34) */
    size_t pos = 1 + 3 + 34;
    if (pos + 2 > hs_len) return 0;

    /* session id */
    pos += 1 + hs[pos];
    if (pos + 2 > hs_len) return 0;

    /* cipher suites */
    uint16_t cs = static_cast<uint16_t>((hs[pos] << 8) | hs[pos+1]);
    pos += 2 + cs;
    if (pos + 1 > hs_len) return 0;

    /* compression methods */
    pos += 1 + hs[pos];
    if (pos + 2 > hs_len) return 0;

    /* extensions total length */
    uint16_t ext_total = static_cast<uint16_t>((hs[pos] << 8) | hs[pos+1]);
    pos += 2;
    size_t ext_end = pos + ext_total;
    if (ext_end > hs_len) return 0;

    while (pos + 4 <= ext_end) {
        uint16_t etype = static_cast<uint16_t>((hs[pos] << 8) | hs[pos+1]);
        uint16_t elen  = static_cast<uint16_t>((hs[pos+2] << 8) | hs[pos+3]);
        pos += 4;
        if (pos + elen > ext_end) break;

        if (etype == 0x0000 && elen >= 5) {
            /* server_name list: list_len(2) type(1) name_len(2) name */
            size_t name_start = pos + 5;
            uint16_t name_len = static_cast<uint16_t>((hs[pos+3] << 8) | hs[pos+4]);
            if (name_start + name_len <= ext_end && name_len > 0) {
                /* +4 for the outer TLS record header that precedes hs[] */
                return (name_start + name_len / 2) + 5; /* +5 = outer rec header */
            }
        }
        pos += elen;
    }
    return 0;
}

/* ── public API ──────────────────────────────────────────────────────────── */

int fn_tls_split3(
    const uint8_t *data,   size_t data_len,
    uint8_t *r1, size_t r1_cap, size_t *r1_len,
    uint8_t *r2, size_t r2_cap, size_t *r2_len,
    uint8_t *r3, size_t r3_cap, size_t *r3_len)
{
    if (!is_ch(data, data_len)) return -1;

    /* outer TLS record header is 5 bytes; payload = data+5 */
    const uint8_t *hs     = data + 5;
    size_t         hs_len = data_len - 5;

    /* cut1: after the first byte of the Handshake body */
    size_t cut1 = 5 + 1;          /* offset in `data` */

    /* cut2: SNI midpoint (falls back to midpoint of full payload) */
    size_t cut2 = sni_midpoint(hs, hs_len);
    if (cut2 == 0 || cut2 <= cut1 || cut2 >= data_len)
        cut2 = 5 + hs_len / 2;    /* safe fallback */
    if (cut2 <= cut1) cut2 = cut1 + 1;
    if (cut2 >= data_len) cut2 = data_len - 1;

    size_t p1 = cut1 - 5;                  /* len of r1 payload */
    size_t p2 = cut2 - cut1;               /* len of r2 payload */
    size_t p3 = data_len - cut2;           /* len of r3 payload */

    size_t n1 = emit(r1, r1_cap, hs,              p1);
    size_t n2 = emit(r2, r2_cap, hs + p1,         p2);
    size_t n3 = emit(r3, r3_cap, hs + p1 + p2,    p3);

    if (!n1 || !n2 || !n3) return -2;

    *r1_len = n1;
    *r2_len = n2;
    *r3_len = n3;
    return 0;
}
