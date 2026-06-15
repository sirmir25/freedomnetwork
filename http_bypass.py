"""HTTP header mangling — randomises header-name casing to defeat DPI keyword matchers."""
from __future__ import annotations

import random


# These headers must stay lowercase/canonical or the server may reject the request
_KEEP_CANONICAL = {b"host", b"content-length", b"transfer-encoding", b"content-type"}


def _randomize_case(name: bytes) -> bytes:
    return bytes(
        c ^ (0x20 if 0x41 <= c <= 0x5A or 0x61 <= c <= 0x7A and random.random() > 0.5 else 0)
        for c in name
    )


def mangle_request(data: bytes) -> bytes:
    try:
        sep = data.index(b"\r\n\r\n")
    except ValueError:
        return data

    headers_block = data[:sep]
    body = data[sep:]

    lines = headers_block.split(b"\r\n")
    out = [lines[0]]  # request line — leave untouched

    for line in lines[1:]:
        if b":" in line:
            name, _, rest = line.partition(b":")
            if name.lower() not in _KEEP_CANONICAL:
                name = _randomize_case(name)
            out.append(name + b":" + rest)
        else:
            out.append(line)

    return b"\r\n".join(out) + body


def is_http(data: bytes) -> bool:
    return data[:3] in (b"GET", b"POS", b"PUT", b"DEL", b"HEA", b"OPT", b"PAT")
