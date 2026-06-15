//! TLS ClientHello fragmentation.
//!
//! Two independent techniques, both applied together for maximum effect:
//!
//! 1. **TLS record split** (primary): one ClientHello → two separate TLS records.
//!    Even DPI that fully reassembles the TCP stream must merge TLS records to
//!    parse a Handshake message — most boxes don't and give up without SNI.
//!
//! 2. **TCP segment split** (secondary): each TLS record is sent as its own
//!    `write_all()` call with TCP_NODELAY set, guaranteeing two TCP segments.

pub fn is_client_hello(data: &[u8]) -> bool {
    data.len() > 9
        && data[0] == 0x16  // ContentType = Handshake
        && data[1] == 0x03  // Legacy major version
        && data[5] == 0x01  // HandshakeType = ClientHello
}

/// Split one TLS ClientHello into two TLS records.
/// Record-1 holds only the first 3 bytes of the Handshake payload
/// (HandshakeType + 2 of the 3 length bytes).  SNI stays in record-2.
pub fn split_into_records(data: &[u8]) -> (Vec<u8>, Vec<u8>) {
    if !is_client_hello(data) || data.len() <= 5 {
        // Fallback: raw 3/rest TCP split
        let cut = 3.min(data.len().saturating_sub(1));
        return (data[..cut].to_vec(), data[cut..].to_vec());
    }

    let payload = &data[5..]; // strip outer TLS record header
    let cut = 3.min(payload.len().saturating_sub(1));

    let r1 = build_record(&payload[..cut]);
    let r2 = build_record(&payload[cut..]);
    (r1, r2)
}

fn build_record(payload: &[u8]) -> Vec<u8> {
    let mut r = vec![0x16, 0x03, 0x01];
    r.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    r.extend_from_slice(payload);
    r
}
