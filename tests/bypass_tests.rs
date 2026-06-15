// Integration tests for the FreedomNet C++ bypass_core library.
// These link directly against the compiled static library (bypass_core.a).
// Run with: cargo test

// ── Raw C declarations ────────────────────────────────────────────────────────
extern "C" {
    fn fn_is_client_hello(data: *const u8, len: usize) -> bool;
    fn fn_tls_split(
        data: *const u8, data_len: usize,
        r1: *mut u8, r1_cap: usize, r1_len: *mut usize,
        r2: *mut u8, r2_cap: usize, r2_len: *mut usize,
    ) -> i32;
    fn fn_tls_split3(
        data: *const u8, data_len: usize,
        r1: *mut u8, r1_cap: usize, r1_len: *mut usize,
        r2: *mut u8, r2_cap: usize, r2_len: *mut usize,
        r3: *mut u8, r3_cap: usize, r3_len: *mut usize,
    ) -> i32;
    fn fn_is_http(data: *const u8, len: usize) -> bool;
    fn fn_mangle_http(
        data: *const u8, data_len: usize,
        out: *mut u8, out_cap: usize,
    ) -> usize;
    fn fn_version() -> *const std::os::raw::c_char;
    fn fn_ja3_fingerprint(data: *const u8, data_len: usize,
                           out: *mut u8, out_cap: usize) -> usize;
    fn fn_is_tls13(data: *const u8, data_len: usize) -> bool;
}

// ── safe wrappers for test convenience ───────────────────────────────────────

fn is_client_hello(data: &[u8]) -> bool {
    if data.is_empty() { return false; }
    unsafe { fn_is_client_hello(data.as_ptr(), data.len()) }
}

fn tls_split(data: &[u8]) -> Option<(Vec<u8>, Vec<u8>)> {
    let cap = data.len() + 32;
    let mut r1 = vec![0u8; cap];
    let mut r2 = vec![0u8; cap];
    let (mut n1, mut n2) = (0usize, 0usize);
    let rc = unsafe {
        fn_tls_split(data.as_ptr(), data.len(),
                     r1.as_mut_ptr(), cap, &mut n1,
                     r2.as_mut_ptr(), cap, &mut n2)
    };
    if rc != 0 { return None; }
    r1.truncate(n1); r2.truncate(n2);
    Some((r1, r2))
}

fn tls_split3(data: &[u8]) -> Option<(Vec<u8>, Vec<u8>, Vec<u8>)> {
    let cap = data.len() + 32;
    let mut r1 = vec![0u8; cap];
    let mut r2 = vec![0u8; cap];
    let mut r3 = vec![0u8; cap];
    let (mut n1, mut n2, mut n3) = (0usize, 0usize, 0usize);
    let rc = unsafe {
        fn_tls_split3(data.as_ptr(), data.len(),
                      r1.as_mut_ptr(), cap, &mut n1,
                      r2.as_mut_ptr(), cap, &mut n2,
                      r3.as_mut_ptr(), cap, &mut n3)
    };
    if rc != 0 { return None; }
    r1.truncate(n1); r2.truncate(n2); r3.truncate(n3);
    Some((r1, r2, r3))
}

fn is_http(data: &[u8]) -> bool {
    if data.is_empty() { return false; }
    unsafe { fn_is_http(data.as_ptr(), data.len()) }
}

fn mangle(data: &[u8]) -> Vec<u8> {
    let cap = data.len() * 2 + 64;
    let mut out = vec![0u8; cap];
    let n = unsafe { fn_mangle_http(data.as_ptr(), data.len(), out.as_mut_ptr(), cap) };
    out.truncate(n);
    out
}

// Build a minimal TLS 1.2 ClientHello with SNI "example.com"
fn minimal_client_hello() -> Vec<u8> {
    let sni = b"example.com";
    let sni_len = sni.len() as u16;

    let mut sni_val = Vec::new();
    sni_val.extend_from_slice(&(sni_len + 3).to_be_bytes());
    sni_val.push(0x00); // host_name type
    sni_val.extend_from_slice(&sni_len.to_be_bytes());
    sni_val.extend_from_slice(sni);

    let mut exts = Vec::new();
    exts.extend_from_slice(&[0x00, 0x00]); // server_name extension
    exts.extend_from_slice(&(sni_val.len() as u16).to_be_bytes());
    exts.extend_from_slice(&sni_val);

    let mut hs_body = Vec::new();
    hs_body.extend_from_slice(&[0x03, 0x03]);  // ClientHello version
    hs_body.extend_from_slice(&[0u8; 32]);      // random
    hs_body.push(0x00);                          // session id len
    hs_body.extend_from_slice(&[0x00, 0x02]);   // cipher suites len
    hs_body.extend_from_slice(&[0xc0, 0x2b]);   // TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
    hs_body.push(0x01);                          // compression methods len
    hs_body.push(0x00);                          // null compression
    hs_body.extend_from_slice(&(exts.len() as u16).to_be_bytes());
    hs_body.extend_from_slice(&exts);

    let body_len = hs_body.len() as u32;
    let mut hs = vec![0x01]; // HandshakeType = ClientHello
    hs.push(((body_len >> 16) & 0xff) as u8);
    hs.push(((body_len >> 8)  & 0xff) as u8);
    hs.push(( body_len        & 0xff) as u8);
    hs.extend_from_slice(&hs_body);

    let total = hs.len() as u16;
    let mut record = vec![0x16, 0x03, 0x01]; // TLS Handshake, TLS 1.0 compat
    record.extend_from_slice(&total.to_be_bytes());
    record.extend_from_slice(&hs);
    record
}

// ── ClientHello detection ─────────────────────────────────────────────────────

#[test]
fn detect_client_hello() {
    assert!(is_client_hello(&minimal_client_hello()));
}

#[test]
fn reject_http_as_client_hello() {
    assert!(!is_client_hello(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n"));
}

#[test]
fn reject_empty_as_client_hello() {
    assert!(!is_client_hello(&[]));
}

#[test]
fn reject_too_short_as_client_hello() {
    assert!(!is_client_hello(&[0x16, 0x03]));
}

#[test]
fn reject_server_hello_as_client_hello() {
    // type=0x02 (ServerHello) instead of 0x01
    let mut ch = minimal_client_hello();
    ch[5] = 0x02;
    assert!(!is_client_hello(&ch));
}

// ── Two-record split ──────────────────────────────────────────────────────────

#[test]
fn split2_produces_two_records() {
    let ch = minimal_client_hello();
    let (r1, r2) = tls_split(&ch).expect("split2 failed on valid ClientHello");
    assert!(!r1.is_empty());
    assert!(!r2.is_empty());
}

#[test]
fn split2_records_are_tls_handshake_type() {
    let ch = minimal_client_hello();
    let (r1, r2) = tls_split(&ch).unwrap();
    assert_eq!(r1[0], 0x16, "r1 type");
    assert_eq!(r2[0], 0x16, "r2 type");
}

#[test]
fn split2_combined_payload_equals_original() {
    let ch = minimal_client_hello();
    let orig = &ch[5..];
    let (r1, r2) = tls_split(&ch).unwrap();
    let mut combined = r1[5..].to_vec();
    combined.extend_from_slice(&r2[5..]);
    assert_eq!(combined, orig, "combined payload should equal original handshake");
}

#[test]
fn split2_r1_smaller_than_original() {
    let ch = minimal_client_hello();
    let (r1, _) = tls_split(&ch).unwrap();
    assert!(r1.len() < ch.len(), "r1 should be smaller than original");
}

#[test]
fn split2_rejects_non_client_hello() {
    assert!(tls_split(b"\x16\x03\x01\x00\x04\x02blah").is_none());
}

#[test]
fn split2_rejects_empty() {
    assert!(tls_split(&[]).is_none());
}

// ── Three-record split ────────────────────────────────────────────────────────

#[test]
fn split3_produces_three_records() {
    let ch = minimal_client_hello();
    let (r1, r2, r3) = tls_split3(&ch).expect("split3 failed");
    assert!(!r1.is_empty());
    assert!(!r2.is_empty());
    assert!(!r3.is_empty());
}

#[test]
fn split3_records_have_tls_type() {
    let ch = minimal_client_hello();
    let (r1, r2, r3) = tls_split3(&ch).unwrap();
    assert_eq!(r1[0], 0x16);
    assert_eq!(r2[0], 0x16);
    assert_eq!(r3[0], 0x16);
}

#[test]
fn split3_combined_payload_equals_original() {
    let ch = minimal_client_hello();
    let orig = &ch[5..];
    let (r1, r2, r3) = tls_split3(&ch).unwrap();
    let mut combined = r1[5..].to_vec();
    combined.extend_from_slice(&r2[5..]);
    combined.extend_from_slice(&r3[5..]);
    assert_eq!(combined, orig);
}

#[test]
fn split3_r1_is_minimal() {
    // r1 should be only 6 bytes: 5-byte TLS header + 1 byte HandshakeType
    let ch = minimal_client_hello();
    let (r1, _, _) = tls_split3(&ch).unwrap();
    assert_eq!(r1.len(), 6, "r1 in 3-split should be exactly 1 payload byte + 5 header");
}

// ── HTTP detection and mangling ────────────────────────────────────────────────

#[test]
fn detect_get() { assert!(is_http(b"GET / HTTP/1.1\r\n")); }

#[test]
fn detect_post() { assert!(is_http(b"POST /x HTTP/1.1\r\n")); }

#[test]
fn detect_put() { assert!(is_http(b"PUT /x HTTP/1.1\r\n")); }

#[test]
fn detect_delete() { assert!(is_http(b"DELETE /x HTTP/1.1\r\n")); }

#[test]
fn detect_head() { assert!(is_http(b"HEAD / HTTP/1.1\r\n")); }

#[test]
fn reject_tls_as_http() { assert!(!is_http(&[0x16, 0x03, 0x01])); }

#[test]
fn reject_empty_as_http() { assert!(!is_http(&[])); }

#[test]
fn mangle_preserves_host() {
    let req = b"GET / HTTP/1.1\r\nHost: example.com\r\nUser-Agent: test\r\n\r\n";
    let out = mangle(req);
    let s = std::str::from_utf8(&out).unwrap();
    assert!(s.contains("Host: example.com"), "Host must remain canonical");
}

#[test]
fn mangle_preserves_content_length() {
    let req = b"POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 5\r\n\r\nhello";
    let out = mangle(req);
    let s = std::str::from_utf8(&out).unwrap();
    assert!(s.contains("Content-Length: 5"), "Content-Length must remain canonical");
}

#[test]
fn mangle_changes_user_agent_case() {
    let req = b"GET / HTTP/1.1\r\nHost: x\r\nUser-Agent: curl\r\n\r\n";
    let out = mangle(req);
    let s = std::str::from_utf8(&out).unwrap();
    assert!(!s.contains("\nUser-Agent:"), "User-Agent should be case-mangled");
}

#[test]
fn mangle_output_contains_crlfcrlf() {
    let req = b"GET / HTTP/1.1\r\nHost: a.com\r\n\r\n";
    let out = mangle(req);
    assert!(out.windows(4).any(|w| w == b"\r\n\r\n"), "must have CRLFCRLF terminator");
}

#[test]
fn mangle_preserves_body() {
    let req = b"POST /x HTTP/1.1\r\nHost: x\r\nContent-Length: 5\r\n\r\nhello";
    let out = mangle(req);
    assert!(out.ends_with(b"hello"), "body must be preserved");
}

#[test]
fn mangle_preserves_first_line() {
    let req = b"GET /path?q=1 HTTP/1.1\r\nHost: a.com\r\n\r\n";
    let out = mangle(req);
    let s = std::str::from_utf8(&out).unwrap();
    assert!(s.starts_with("GET /path?q=1 HTTP/1.1\r\n"), "request line must be unchanged");
}

// ── Version string ────────────────────────────────────────────────────────────

#[test]
fn version_string_non_empty() {
    let ptr = unsafe { fn_version() };
    assert!(!ptr.is_null());
    let s = unsafe { std::ffi::CStr::from_ptr(ptr) }.to_str().unwrap();
    assert!(!s.is_empty());
}

#[test]
fn version_string_has_dots() {
    let ptr = unsafe { fn_version() };
    let s = unsafe { std::ffi::CStr::from_ptr(ptr) }.to_str().unwrap();
    assert!(s.contains('.'), "version must be semver: {s}");
}

// ── JA3 fingerprint ────────────────────────────────────────────────────────────

#[test]
fn ja3_fingerprint_non_empty_for_ch() {
    let ch = minimal_client_hello();
    let mut buf = vec![0u8; 512];
    let n = unsafe { fn_ja3_fingerprint(ch.as_ptr(), ch.len(), buf.as_mut_ptr() as *mut u8, 512) };
    assert!(n > 0, "JA3 fingerprint should be non-empty for valid ClientHello");
    buf.truncate(n);
    let s = std::str::from_utf8(&buf).unwrap();
    // JA3 format: v,c,e,g,p — must have 4 commas
    assert_eq!(s.chars().filter(|&c| c == ',').count(), 4,
        "JA3 string must have exactly 4 commas: {s}");
}

#[test]
fn ja3_fingerprint_zero_for_non_ch() {
    let http = b"GET / HTTP/1.1\r\n\r\n";
    let mut buf = vec![0u8; 512];
    let n = unsafe { fn_ja3_fingerprint(http.as_ptr(), http.len(), buf.as_mut_ptr() as *mut u8, 512) };
    assert_eq!(n, 0, "JA3 must return 0 for non-ClientHello");
}

// ── TLS 1.3 detection ─────────────────────────────────────────────────────────

#[test]
fn tls12_not_detected_as_tls13() {
    // Our minimal_client_hello() has no supported_versions extension
    let ch = minimal_client_hello();
    let is13 = unsafe { fn_is_tls13(ch.as_ptr(), ch.len()) };
    assert!(!is13, "TLS 1.2 ClientHello should not be detected as TLS 1.3");
}

#[test]
fn non_tls_not_detected_as_tls13() {
    let http = b"GET / HTTP/1.1\r\n\r\n";
    let is13 = unsafe { fn_is_tls13(http.as_ptr(), http.len()) };
    assert!(!is13);
}
