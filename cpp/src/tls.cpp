/*
 * tls.cpp — TLS ClientHello parser and DPI bypass fragmenter.
 *
 * Algorithm:
 *   1. Walk the ClientHello to locate the SNI extension.
 *   2. Split the Handshake payload into two separate TLS records at the
 *      midpoint of the SNI hostname.  Falls back to splitting at byte 3 if
 *      SNI cannot be found.
 *   3. Each output record is RFC-compliant; the server reassembles normally.
 *      Most DPI boxes do not merge TLS records and thus fail to read the SNI.
 */
#include "bypass_core.h"

#include <cstring>
#include <cstdint>

static uint16_t u16be(const uint8_t *p)
{
    return static_cast<uint16_t>((p[0] << 8) | p[1]);
}

struct SniLoc { size_t start, length; };

static bool locate_sni(const uint8_t *data, size_t len, SniLoc *out)
{
    if (len < 43) return false;

    size_t pos = 9; /* skip TLS record header(5) + Handshake header(4) */

    pos += 2 + 32; /* client_version + random */
    if (pos >= len) return false;

    size_t sid_len = data[pos++];
    if (pos + sid_len > len) return false;
    pos += sid_len;

    if (pos + 2 > len) return false;
    size_t cs_len = u16be(data + pos); pos += 2;
    if (pos + cs_len > len) return false;
    pos += cs_len;

    if (pos + 1 > len) return false;
    size_t cm_len = data[pos++];
    if (pos + cm_len > len) return false;
    pos += cm_len;

    if (pos + 2 > len) return false;
    size_t ext_total = u16be(data + pos); pos += 2;
    size_t ext_end   = pos + ext_total;
    if (ext_end > len) return false;

    while (pos + 4 <= ext_end) {
        uint16_t ext_type = u16be(data + pos);
        uint16_t ext_len  = u16be(data + pos + 2);
        size_t   ext_body = pos + 4;
        if (ext_body + ext_len > ext_end) break;

        if (ext_type == 0x0000 && ext_len >= 5) { /* server_name */
            size_t name_len   = u16be(data + ext_body + 3);
            size_t name_start = ext_body + 5;
            if (name_start + name_len <= len) {
                out->start  = name_start;
                out->length = name_len;
                return true;
            }
        }
        pos = ext_body + ext_len;
    }
    return false;
}

static void emit_record(uint8_t *buf, size_t *pos,
                        const uint8_t *payload, size_t payload_len)
{
    buf[(*pos)++] = 0x16;
    buf[(*pos)++] = 0x03;
    buf[(*pos)++] = 0x01; /* legacy version TLS 1.0 — RFC 8446 compat */
    buf[(*pos)++] = static_cast<uint8_t>(payload_len >> 8);
    buf[(*pos)++] = static_cast<uint8_t>(payload_len & 0xFF);
    std::memcpy(buf + *pos, payload, payload_len);
    *pos += payload_len;
}

bool fn_is_client_hello(const uint8_t *data, size_t len)
{
    return len > 9
        && data[0] == 0x16
        && data[1] == 0x03
        && data[5] == 0x01;
}

int fn_tls_split(
    const uint8_t *data,  size_t data_len,
    uint8_t       *r1,    size_t r1_cap,  size_t *r1_len,
    uint8_t       *r2,    size_t r2_cap,  size_t *r2_len)
{
    if (!fn_is_client_hello(data, data_len) || data_len <= 5) return -1;

    const uint8_t *payload     = data + 5;
    size_t         payload_len = data_len - 5;

    size_t cut;
    SniLoc sni;
    if (locate_sni(data, data_len, &sni) && sni.length >= 2) {
        size_t sni_rel = sni.start - 5;
        cut = sni_rel + sni.length / 2;
    } else {
        cut = 3;
    }
    if (cut < 1)               cut = 1;
    if (cut >= payload_len)    cut = payload_len - 1;

    size_t p1_len = cut;
    size_t p2_len = payload_len - cut;

    if (r1_cap < p1_len + 5 || r2_cap < p2_len + 5) return -2;

    size_t pos1 = 0, pos2 = 0;
    emit_record(r1, &pos1, payload,          p1_len);
    emit_record(r2, &pos2, payload + p1_len, p2_len);
    *r1_len = pos1;
    *r2_len = pos2;
    return 0;
}
