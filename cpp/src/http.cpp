/*
 * http.cpp — HTTP/1.x request mangler + version string.
 *
 * Randomises header-name casing so DPI keyword matchers fail.
 * Headers that must remain canonical for correct server parsing are kept as-is.
 */
#include "bypass_core.h"

#include <cctype>
#include <cstring>
#include <cstdint>

static bool str_ieq(const uint8_t *a, size_t a_len, const char *b, size_t b_len)
{
    if (a_len != b_len) return false;
    for (size_t i = 0; i < a_len; ++i)
        if (std::tolower(a[i]) != std::tolower(static_cast<unsigned char>(b[i])))
            return false;
    return true;
}

static const struct { const char *name; size_t len; } k_keep[] = {
    {"host",              4},
    {"content-length",   14},
    {"transfer-encoding",17},
    {"content-type",     12},
};

static bool keep_canonical(const uint8_t *name, size_t name_len)
{
    for (auto &kv : k_keep)
        if (str_ieq(name, name_len, kv.name, kv.len)) return true;
    return false;
}

static void mangle_name(const uint8_t *src, size_t len, uint8_t *dst)
{
    for (size_t i = 0; i < len; ++i) {
        uint8_t c = src[i];
        if (std::isalpha(c) && (i & 1) == 1) c ^= 0x20;
        dst[i] = c;
    }
}

bool fn_is_http(const uint8_t *data, size_t len)
{
    if (len < 3) return false;
    static const char *verbs[] = {"GET","POS","PUT","DEL","HEA","OPT","PAT",nullptr};
    for (const char **v = verbs; *v; ++v)
        if (std::memcmp(data, *v, 3) == 0) return true;
    return false;
}

size_t fn_mangle_http(const uint8_t *data, size_t data_len,
                      uint8_t *out, size_t out_cap)
{
    size_t hdr_end = 0;
    for (size_t i = 0; i + 3 < data_len; ++i) {
        if (data[i]=='\r' && data[i+1]=='\n' && data[i+2]=='\r' && data[i+3]=='\n') {
            hdr_end = i + 4; break;
        }
    }
    if (hdr_end == 0) {
        if (data_len > out_cap) return 0;
        std::memcpy(out, data, data_len);
        return data_len;
    }

    size_t out_pos = 0, pos = 0;
    bool first = true;

    while (pos < hdr_end) {
        size_t ls = pos;
        while (pos < hdr_end && !(data[pos]=='\r' && pos+1<hdr_end && data[pos+1]=='\n'))
            ++pos;
        size_t ll = pos - ls;
        pos += 2;

        if (out_pos + ll + 2 > out_cap) return 0;

        if (first) {
            std::memcpy(out + out_pos, data + ls, ll);
            out_pos += ll;
            first = false;
        } else {
            size_t colon = 0;
            for (size_t i = ls; i < ls + ll; ++i)
                if (data[i] == ':') { colon = i - ls; break; }

            if (colon > 0 && !keep_canonical(data + ls, colon)) {
                mangle_name(data + ls, colon, out + out_pos);
            } else {
                std::memcpy(out + out_pos, data + ls, colon ? colon : ll);
            }
            if (colon > 0) {
                out_pos += colon;
                size_t rest = ll - colon;
                std::memcpy(out + out_pos, data + ls + colon, rest);
                out_pos += rest;
            } else {
                out_pos += ll;
            }
        }
        out[out_pos++] = '\r';
        out[out_pos++] = '\n';
    }

    size_t body_len = data_len - hdr_end;
    if (out_pos + body_len > out_cap) return 0;
    std::memcpy(out + out_pos, data + hdr_end, body_len);
    return out_pos + body_len;
}

const char *fn_version(void)
{
    return "0.2.0";
}
