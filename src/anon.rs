//! Anonymity and traffic normalisation layer.
//!
//! Applied on top of the DPI bypass tunnel to reduce fingerprinting:
//!   • Strip request headers that reveal real IP or proxy presence
//!   • Normalise User-Agent to a generic browser string
//!   • Remove Referer from cross-origin requests (privacy leak)
//!   • Accept-Language → generic "en-US,en;q=0.9"

/// Headers that reveal the client's real IP or proxy chain.
static STRIP_HEADERS: &[&str] = &[
    "x-real-ip",
    "x-forwarded-for",
    "x-forwarded-host",
    "x-forwarded-proto",
    "x-forwarded-port",
    "forwarded",
    "via",
    "proxy-connection",
    "proxy-authorization",
    "x-proxy-id",
    "x-tin",
    "client-ip",
    "x-client-ip",
    "true-client-ip",
    "cf-connecting-ip",
    "fastly-client-ip",
    "x-cluster-client-ip",
    "wl-proxy-client-ip",
];

/// Generic Chrome UA — high entropy, low uniqueness.
const GENERIC_UA: &str =
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) \
     AppleWebKit/537.36 (KHTML, like Gecko) \
     Chrome/124.0.0.0 Safari/537.36";

/// Apply anonymity transforms to a raw HTTP/1.x request.
///
/// - Strips privacy-leaking headers
/// - Replaces User-Agent with a generic browser UA
/// - Replaces Accept-Language with a generic value
/// - Removes Referer
///
/// Returns `Some(modified)` if any changes were made, `None` if `data` is
/// not an HTTP request or has no headers to strip.
pub fn sanitize_http(data: &[u8]) -> Vec<u8> {
    let sep = match data.windows(4).position(|w| w == b"\r\n\r\n") {
        Some(p) => p,
        None    => return data.to_vec(),
    };

    let header_block = &data[..sep];
    let body         = &data[sep..]; // includes the \r\n\r\n

    let mut out: Vec<u8> = Vec::with_capacity(data.len() + 64);
    let mut first = true;

    for raw_line in header_block.split(|&b| b == b'\n') {
        let line = raw_line.strip_suffix(b"\r").unwrap_or(raw_line);

        if first {
            // Request line — untouched
            out.extend_from_slice(line);
            out.extend_from_slice(b"\r\n");
            first = false;
            continue;
        }

        let Some(colon) = line.iter().position(|&b| b == b':') else {
            // Blank or malformed line
            out.extend_from_slice(line);
            out.extend_from_slice(b"\r\n");
            continue;
        };

        let name_bytes = &line[..colon];
        let name_lower: String = name_bytes
            .iter()
            .map(|&b| b.to_ascii_lowercase() as char)
            .collect();

        // Strip privacy-leaking headers
        if STRIP_HEADERS.contains(&name_lower.as_str()) {
            continue;
        }

        // Remove Referer (cross-origin privacy leak)
        if name_lower == "referer" {
            continue;
        }

        // Normalise User-Agent
        if name_lower == "user-agent" {
            out.extend_from_slice(b"User-Agent: ");
            out.extend_from_slice(GENERIC_UA.as_bytes());
            out.extend_from_slice(b"\r\n");
            continue;
        }

        // Normalise Accept-Language
        if name_lower == "accept-language" {
            out.extend_from_slice(b"Accept-Language: en-US,en;q=0.9\r\n");
            continue;
        }

        // Keep everything else verbatim
        out.extend_from_slice(line);
        out.extend_from_slice(b"\r\n");
    }

    out.extend_from_slice(body);
    out
}

/// Returns true if `data` starts with a recognised HTTP method.
pub fn is_http(data: &[u8]) -> bool {
    matches!(data.get(..3),
        Some(b"GET") | Some(b"POS") | Some(b"PUT") |
        Some(b"DEL") | Some(b"HEA") | Some(b"OPT") | Some(b"PAT"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strips_real_ip_header() {
        let req = b"GET / HTTP/1.1\r\nHost: example.com\r\nX-Real-IP: 1.2.3.4\r\n\r\n";
        let out = sanitize_http(req);
        assert!(!out.windows(10).any(|w| w == b"X-Real-IP"), "X-Real-IP must be stripped");
        assert!(out.windows(4).any(|w| w == b"Host"), "Host must be kept");
    }

    #[test]
    fn replaces_user_agent() {
        let req = b"GET / HTTP/1.1\r\nHost: example.com\r\nUser-Agent: curl/7.0\r\n\r\n";
        let out = sanitize_http(req);
        assert!(std::str::from_utf8(&out).unwrap().contains("Chrome/124"));
    }

    #[test]
    fn strips_referer() {
        let req = b"GET / HTTP/1.1\r\nHost: example.com\r\nReferer: https://other.com/\r\n\r\n";
        let out = sanitize_http(req);
        assert!(!std::str::from_utf8(&out).unwrap().to_lowercase().contains("referer"));
    }
}
