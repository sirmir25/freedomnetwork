/*
 * bypass_core.h — C API for DPI bypass operations.
 * Implemented in C++17, callable from Rust via extern "C" FFI.
 *
 * All functions are thread-safe (stateless pure computation on caller-provided buffers).
 */
#pragma once
#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ── TLS ──────────────────────────────────────────────────────────────────── */

/** True if data begins with a TLS 1.x ClientHello record. */
bool fn_is_client_hello(const uint8_t *data, size_t len);

/**
 * Repackage one TLS ClientHello into two separate TLS records.
 * The split point is placed at the midpoint of the SNI hostname field so
 * that DPI parsers inspecting a single record can never reconstruct the SNI.
 *
 * @param data      Input ClientHello (including outer TLS record header)
 * @param data_len  Input length
 * @param r1        Output buffer for first record  (must be >= data_len + 10)
 * @param r1_cap    Capacity of r1
 * @param r1_len    Bytes written to r1
 * @param r2        Output buffer for second record (must be >= data_len + 10)
 * @param r2_cap    Capacity of r2
 * @param r2_len    Bytes written to r2
 * @return  0 on success, -1 if not a ClientHello, -2 if buffers too small
 */
int fn_tls_split(
    const uint8_t *data,  size_t data_len,
    uint8_t       *r1,    size_t r1_cap,  size_t *r1_len,
    uint8_t       *r2,    size_t r2_cap,  size_t *r2_len
);

/* ── HTTP ─────────────────────────────────────────────────────────────────── */

/** True if data starts with a recognised HTTP method verb. */
bool fn_is_http(const uint8_t *data, size_t len);

/**
 * Mangle HTTP/1.x request headers to defeat keyword-match DPI.
 * - Randomises header-name casing (User-Agent → uSeR-AgEnT)
 * - Keeps Host, Content-Length, Transfer-Encoding, Content-Type canonical
 *
 * @param data     Input HTTP request bytes
 * @param data_len Input length
 * @param out      Output buffer (must be >= data_len * 2)
 * @param out_cap  Capacity of out
 * @return  Bytes written, or 0 on error
 */
size_t fn_mangle_http(
    const uint8_t *data,   size_t data_len,
    uint8_t       *out,    size_t out_cap
);

/* ── Info ─────────────────────────────────────────────────────────────────── */

/** Null-terminated version string, e.g. "0.2.0". */
const char *fn_version(void);

#ifdef __cplusplus
} /* extern "C" */
#endif
