//! Safe Rust wrappers around the C++ bypass_core library (libbypass_core.a).
//!
//! The raw `extern "C"` block matches `cpp/include/bypass_core.h` exactly.
//! All unsafe surface area is contained here; callers use only the safe
//! pub functions below.

use std::os::raw::{c_char, c_int};

// ── Raw C declarations ────────────────────────────────────────────────────────

extern "C" {
    fn fn_is_client_hello(data: *const u8, len: usize) -> bool;

    fn fn_tls_split(
        data: *const u8, data_len: usize,
        r1: *mut u8, r1_cap: usize, r1_len: *mut usize,
        r2: *mut u8, r2_cap: usize, r2_len: *mut usize,
    ) -> c_int;

    fn fn_is_http(data: *const u8, len: usize) -> bool;

    fn fn_mangle_http(
        data: *const u8, data_len: usize,
        out: *mut u8,    out_cap: usize,
    ) -> usize;

    fn fn_version() -> *const c_char;
}

// ── Safe wrappers ─────────────────────────────────────────────────────────────

/// Returns true if `data` starts with a TLS ClientHello record.
pub fn is_client_hello(data: &[u8]) -> bool {
    if data.is_empty() { return false; }
    // SAFETY: data is a valid slice; C function is read-only and bounds-checked.
    unsafe { fn_is_client_hello(data.as_ptr(), data.len()) }
}

/// Splits a TLS ClientHello into two TLS records for DPI evasion.
///
/// Returns `Some((record1, record2))` on success, or `None` if `data` is not a
/// valid ClientHello or an internal error occurs.
pub fn tls_split(data: &[u8]) -> Option<(Vec<u8>, Vec<u8>)> {
    // Allocate output buffers large enough for the worst case
    // (original data + 10 bytes per record for the new TLS header)
    let cap = data.len() + 16;
    let mut r1 = vec![0u8; cap];
    let mut r2 = vec![0u8; cap];
    let mut r1_len: usize = 0;
    let mut r2_len: usize = 0;

    // SAFETY: buffers are valid and correctly sized; C function is documented.
    let rc = unsafe {
        fn_tls_split(
            data.as_ptr(), data.len(),
            r1.as_mut_ptr(), cap, &mut r1_len,
            r2.as_mut_ptr(), cap, &mut r2_len,
        )
    };

    if rc != 0 {
        return None;
    }

    r1.truncate(r1_len);
    r2.truncate(r2_len);
    Some((r1, r2))
}

/// Returns true if `data` begins with a recognised HTTP method.
pub fn is_http(data: &[u8]) -> bool {
    if data.is_empty() { return false; }
    // SAFETY: as above.
    unsafe { fn_is_http(data.as_ptr(), data.len()) }
}

/// Mangles HTTP header names to defeat DPI keyword matching.
///
/// Returns the mangled request bytes, or a copy of the original if mangling
/// fails (e.g. no blank line found in the input).
pub fn mangle_http(data: &[u8]) -> Vec<u8> {
    let cap = data.len() * 2 + 64;
    let mut out = vec![0u8; cap];

    // SAFETY: out buffer is valid and has at least data.len()*2 bytes.
    let n = unsafe {
        fn_mangle_http(data.as_ptr(), data.len(), out.as_mut_ptr(), cap)
    };

    if n == 0 {
        // Fallback: return original unchanged
        return data.to_vec();
    }
    out.truncate(n);
    out
}

/// Version string of the compiled C++ bypass_core library.
#[allow(dead_code)]
pub fn native_version() -> &'static str {
    // SAFETY: fn_version returns a pointer to a string literal with static lifetime.
    let ptr = unsafe { fn_version() };
    if ptr.is_null() { return "unknown"; }
    unsafe { std::ffi::CStr::from_ptr(ptr) }
        .to_str()
        .unwrap_or("unknown")
}
