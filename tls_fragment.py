"""
TLS ClientHello bypass — two complementary techniques:

1. TLS record fragmentation (primary, most effective):
   One ClientHello → two separate TLS records, each sent in its own TCP
   segment.  Even DPI that fully reassembles the TCP stream still has to
   combine TLS records to parse a Handshake message.  Most DPI boxes
   (TSPU/Echelon in Russia, IRIAMAN in Iran, etc.) simply don't do this
   and give up without seeing the SNI.

2. TCP-only split (fallback):
   Split the single TLS record across two TCP segments at the SNI midpoint.
   Effective against first-packet-only DPI.
"""
from __future__ import annotations


def is_client_hello(data: bytes) -> bool:
    return (
        len(data) > 9
        and data[0] == 0x16   # ContentType = Handshake
        and data[1] == 0x03   # Legacy major version
        and data[5] == 0x01   # HandshakeType = ClientHello
    )


def _sni_range(data: bytes) -> tuple[int, int]:
    """Return (start, end) byte offsets of SNI hostname inside data, or (-1,-1)."""
    try:
        pos = 9  # TLS record header (5) + Handshake type+len (4)
        pos += 2 + 32              # client_version + random
        pos += 1 + data[pos]       # session_id
        cs_len = int.from_bytes(data[pos:pos + 2], "big")
        pos += 2 + cs_len          # cipher_suites
        pos += 1 + data[pos]       # compression_methods

        if pos + 2 > len(data):
            return -1, -1

        ext_end = pos + 2 + int.from_bytes(data[pos:pos + 2], "big")
        pos += 2

        while pos + 4 <= ext_end and pos + 4 <= len(data):
            ext_type = int.from_bytes(data[pos:pos + 2], "big")
            ext_len  = int.from_bytes(data[pos + 2:pos + 4], "big")
            d = pos + 4
            if ext_type == 0:  # server_name
                name_len   = int.from_bytes(data[d + 3:d + 5], "big")
                name_start = d + 5
                return name_start, name_start + name_len
            pos = d + ext_len
    except (IndexError, ValueError):
        pass
    return -1, -1


def split_into_records(data: bytes) -> tuple[bytes, bytes]:
    """
    PRIMARY technique — TLS record fragmentation.

    Repackages one TLS ClientHello record into TWO separate TLS records:
      Record-1: just the first 3 bytes of the Handshake payload
                (HandshakeType + first 2 bytes of the 3-byte length field)
      Record-2: the rest (everything after those 3 bytes)

    The server's TLS stack reassembles them transparently.
    Most DPI parsers that expect a single complete record containing the SNI
    will fail to find it and let the connection through.
    """
    if not is_client_hello(data):
        return data, b""

    payload = data[5:]   # strip TLS record header; payload = Handshake message

    # Split very early: just 3 bytes in record-1 (type + 2 of 3 length bytes).
    # The SNI is deep inside record-2 where DPI won't look.
    cut = min(3, len(payload) - 1)

    r1_payload = payload[:cut]
    r2_payload = payload[cut:]

    record1 = b"\x16\x03\x01" + len(r1_payload).to_bytes(2, "big") + r1_payload
    record2 = b"\x16\x03\x01" + len(r2_payload).to_bytes(2, "big") + r2_payload

    return record1, record2


def split_tcp_only(data: bytes) -> tuple[bytes, bytes]:
    """
    FALLBACK — TCP segment split at SNI midpoint (original technique).
    Used when TLS record fragmentation alone isn't enough.
    """
    start, end = _sni_range(data)
    if start > 0 and end > start:
        cut = start + (end - start) // 2
    else:
        cut = 3
    return data[:cut], data[cut:]
