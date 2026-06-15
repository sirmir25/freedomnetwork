//! HTTP/1.x request mangling.
//! Randomises header-name casing to defeat DPI keyword matching on plain HTTP.

pub fn is_http(data: &[u8]) -> bool {
    matches!(data.get(..3), Some(b"GET") | Some(b"POS") | Some(b"PUT") | Some(b"DEL") | Some(b"HEA") | Some(b"OPT") | Some(b"PAT"))
}

pub fn mangle(data: &[u8]) -> Vec<u8> {
    let sep = match data.windows(4).position(|w| w == b"\r\n\r\n") {
        Some(p) => p,
        None => return data.to_vec(),
    };

    let headers_block = &data[..sep];
    let body = &data[sep..];

    let mut out: Vec<u8> = Vec::with_capacity(data.len());
    let mut first = true;

    for line in headers_block.split(|&b| b == b'\n') {
        let line = line.strip_suffix(b"\r").unwrap_or(line);
        if first {
            out.extend_from_slice(line); // request line untouched
            out.extend_from_slice(b"\r\n");
            first = false;
            continue;
        }
        if let Some(colon) = line.iter().position(|&b| b == b':') {
            let name = &line[..colon];
            let rest = &line[colon..];
            if !should_keep_canonical(name) {
                out.extend(randomize_case(name));
            } else {
                out.extend_from_slice(name);
            }
            out.extend_from_slice(rest);
        } else {
            out.extend_from_slice(line);
        }
        out.extend_from_slice(b"\r\n");
    }
    out.extend_from_slice(body);
    out
}

fn should_keep_canonical(name: &[u8]) -> bool {
    let lower: Vec<u8> = name.iter().map(|b| b.to_ascii_lowercase()).collect();
    matches!(lower.as_slice(),
        b"host" | b"content-length" | b"transfer-encoding" | b"content-type")
}

fn randomize_case(name: &[u8]) -> Vec<u8> {
    name.iter().enumerate().map(|(i, &b)| {
        if b.is_ascii_alphabetic() && i % 2 == 1 {
            b ^ 0x20
        } else {
            b
        }
    }).collect()
}
