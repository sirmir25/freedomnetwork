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

/** Null-terminated version string, e.g. "0.3.0". */
const char *fn_version(void);

/* ── Advanced split ───────────────────────────────────────────────────────── */

/**
 * Split ClientHello into THREE TLS records for maximum DPI disruption.
 * Record layout:
 *   r1 = first 1 byte of Handshake payload  (HandshakeType only)
 *   r2 = bytes from byte-2 up to SNI midpoint
 *   r3 = SNI midpoint to end
 *
 * @return 0 on success, -1 not a ClientHello, -2 buffer too small
 */
int fn_tls_split3(
    const uint8_t *data,   size_t data_len,
    uint8_t *r1, size_t r1_cap, size_t *r1_len,
    uint8_t *r2, size_t r2_cap, size_t *r2_len,
    uint8_t *r3, size_t r3_cap, size_t *r3_len
);

/* ── Fingerprinting (fingerprint.cpp) ─────────────────────────────────────── */

/**
 * Compute a JA3-style TLS fingerprint from a ClientHello record.
 * Format: SSLVersion,Ciphers,Extensions,EllipticCurves,PointFormats
 *
 * @param data      ClientHello bytes
 * @param data_len  Input length
 * @param out       Output buffer for null-terminated fingerprint (>= 256 bytes)
 * @param out_cap   Capacity of out
 * @return  Length of fingerprint string, 0 on error
 */
size_t fn_ja3_fingerprint(const uint8_t *data, size_t data_len,
                           char *out, size_t out_cap);

/** Returns true if the ClientHello advertises TLS 1.3 support. */
bool fn_is_tls13(const uint8_t *data, size_t data_len);

/* ── Socket window helpers (window.cpp) ───────────────────────────────────── */

/** Set SO_RCVBUF to `size` on socket `fd` to shrink the advertised TCP window. */
int fn_shrink_window(int fd, int size);

/** Restore SO_RCVBUF to the system default on socket `fd`. */
int fn_restore_window(int fd);

/** Enable or disable TCP_NODELAY on socket `fd`. */
int fn_set_nodelay(int fd, int enable);

/** Query the current SO_RCVBUF of socket `fd`. */
int fn_get_rcvbuf(int fd);

#ifdef __cplusplus
} /* extern "C" */
#endif
