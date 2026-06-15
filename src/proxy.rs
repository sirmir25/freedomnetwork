//! SOCKS5 + HTTP CONNECT proxy server with DPI bypass via C++ native library.
//!
//! All heavy lifting (TLS parsing, HTTP mangling) is delegated to the
//! C++ `bypass_core` library through `crate::ffi`.

use std::{net::SocketAddr, sync::Arc, time::Duration};

use anyhow::Result;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    time::timeout,
};
use tracing::{debug, info, warn};

use crate::{anon, doh::Doh, ffi};

const CHUNK:           usize    = 65536;
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const FIRST_READ_TIMEOUT: Duration = Duration::from_secs(10);

pub struct ProxyConfig {
    pub listen: SocketAddr,
}

pub async fn serve(cfg: ProxyConfig) -> Result<()> {
    let listener = TcpListener::bind(cfg.listen).await?;
    let doh = Arc::new(Doh::new()?);

    println!("\n  FreedomNet DPI Bypass Proxy  [native core {}]",
             ffi::native_version());
    println!("  ──────────────────────────────────────────────────────");
    println!("  Listen   {}", cfg.listen);
    println!("  Protocol SOCKS5 + HTTP CONNECT");
    println!("  Bypass   DoH DNS  ·  C++ TLS record split  ·  C++ HTTP mangle");
    println!();
    println!("  Set browser proxy to  SOCKS5  {}  port {}",
             cfg.listen.ip(), cfg.listen.port());
    println!("                   or  HTTP     {}  port {}",
             cfg.listen.ip(), cfg.listen.port());
    println!("  Press Ctrl+C to stop.");
    println!("  ──────────────────────────────────────────────────────\n");

    loop {
        let (stream, peer) = listener.accept().await?;
        debug!("← {}", peer);
        let doh = Arc::clone(&doh);
        tokio::spawn(async move {
            if let Err(e) = dispatch(stream, doh).await {
                debug!("connection error: {}", e);
            }
        });
    }
}

// ── Protocol dispatcher ───────────────────────────────────────────────────────

async fn dispatch(mut s: TcpStream, doh: Arc<Doh>) -> Result<()> {
    let mut first = [0u8; 1];
    s.read_exact(&mut first).await?;

    match first[0] {
        0x05 => socks5(s, doh).await,
        _    => http_connect(s, first[0], doh).await,
    }
}

// ── SOCKS5 (RFC 1928) ─────────────────────────────────────────────────────────

async fn socks5(mut s: TcpStream, doh: Arc<Doh>) -> Result<()> {
    // Greeting — version byte already consumed
    let nmethods = s.read_u8().await? as usize;
    let mut _methods = vec![0u8; nmethods];
    s.read_exact(&mut _methods).await?;
    s.write_all(b"\x05\x00").await?; // no-auth

    // Request
    let mut hdr = [0u8; 4];
    s.read_exact(&mut hdr).await?;
    let cmd  = hdr[1];
    let atyp = hdr[3];

    if cmd != 0x01 {
        s.write_all(b"\x05\x07\x00\x01\x00\x00\x00\x00\x00\x00").await?;
        return Ok(());
    }

    let host = match atyp {
        0x01 => { // IPv4
            let mut ip = [0u8; 4];
            s.read_exact(&mut ip).await?;
            std::net::Ipv4Addr::from(ip).to_string()
        }
        0x03 => { // Domain
            let n = s.read_u8().await? as usize;
            let mut name = vec![0u8; n];
            s.read_exact(&mut name).await?;
            String::from_utf8(name)?
        }
        0x04 => { // IPv6
            let mut ip = [0u8; 16];
            s.read_exact(&mut ip).await?;
            std::net::Ipv6Addr::from(ip).to_string()
        }
        _ => {
            s.write_all(b"\x05\x08\x00\x01\x00\x00\x00\x00\x00\x00").await?;
            return Ok(());
        }
    };

    let mut port_buf = [0u8; 2];
    s.read_exact(&mut port_buf).await?;
    let port = u16::from_be_bytes(port_buf);

    s.write_all(b"\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00").await?;

    info!("SOCKS5  {}:{}", host, port);
    tunnel(s, &host, port, doh).await
}

// ── HTTP CONNECT ──────────────────────────────────────────────────────────────

async fn http_connect(mut s: TcpStream, first: u8, doh: Arc<Doh>) -> Result<()> {
    let mut buf = vec![first];

    // Read until \r\n\r\n
    loop {
        let b = s.read_u8().await?;
        buf.push(b);
        if buf.ends_with(b"\r\n\r\n") { break; }
        if buf.len() > 8192 { anyhow::bail!("HTTP CONNECT header too large"); }
    }

    let req_line = buf.split(|&b| b == b'\n').next().unwrap_or(&[]);
    let req_line = req_line.strip_suffix(b"\r").unwrap_or(req_line);
    let parts: Vec<&str> = std::str::from_utf8(req_line)?.split_whitespace().collect();

    if parts.len() < 2 || !parts[0].eq_ignore_ascii_case("CONNECT") {
        return Ok(());
    }

    let (host, port) = parse_hostport(parts[1])?;
    s.write_all(b"HTTP/1.1 200 Connection established\r\n\r\n").await?;

    info!("CONNECT {}:{}", host, port);
    tunnel(s, &host, port, doh).await
}

fn parse_hostport(hp: &str) -> Result<(String, u16)> {
    match hp.rsplit_once(':') {
        Some((h, p)) => Ok((h.to_string(), p.parse()?)),
        None         => Ok((hp.to_string(), 443)),
    }
}

// ── DPI bypass tunnel ─────────────────────────────────────────────────────────

async fn tunnel(mut client: TcpStream, host: &str, port: u16, doh: Arc<Doh>) -> Result<()> {
    // ① Resolve via DoH — bypasses ISP DNS
    let ip = match doh.resolve(host).await {
        Some(ip) => ip,
        None     => { warn!("DoH failed: {}", host); return Ok(()); }
    };

    // ② Connect — TCP_NODELAY ensures each write() lands in its own TCP segment
    let server = match timeout(CONNECT_TIMEOUT, TcpStream::connect(SocketAddr::new(ip, port))).await {
        Ok(Ok(s)) => s,
        Ok(Err(e)) => { warn!("connect {}:{} → {}", host, port, e); return Ok(()); }
        Err(_)    => { warn!("connect {}:{} timed out", host, port); return Ok(()); }
    };
    server.set_nodelay(true)?;

    // ③ Read first payload (TLS ClientHello or raw HTTP)
    let mut buf = vec![0u8; CHUNK];
    let n = match timeout(FIRST_READ_TIMEOUT, client.read(&mut buf)).await {
        Ok(Ok(n)) if n > 0 => n,
        _                  => return Ok(()),
    };
    let first = &buf[..n];

    // ④ Apply C++ bypass logic — two separate write_all() + TCP_NODELAY → two segments
    let (mut server_w, server_r) = {
        let (r, w) = tokio::io::split(server);
        (w, r)
    };

    if ffi::is_client_hello(first) {
        match ffi::tls_split(first) {
            Some((r1, r2)) => {
                debug!("TLS split {}:{} → {}B + {}B", host, port, r1.len(), r2.len());
                server_w.write_all(&r1).await?;
                server_w.write_all(&r2).await?;
            }
            None => {
                server_w.write_all(first).await?;
            }
        }
    } else if anon::is_http(first) {
        // C++ DPI mangle + Rust anonymity layer (strip IPs, normalise UA)
        let mangled = ffi::mangle_http(first);
        let sanitized = anon::sanitize_http(&mangled);
        debug!("HTTP {}:{} {}B → mangle {}B → sanitize {}B",
               host, port, first.len(), mangled.len(), sanitized.len());
        server_w.write_all(&sanitized).await?;
    } else {
        server_w.write_all(first).await?;
    }

    // ⑤ Bidirectional relay
    let (client_r, mut client_w) = tokio::io::split(client);

    let c2s = tokio::spawn(async move {
        let _ = tokio::io::copy(&mut tokio::io::BufReader::new(client_r), &mut server_w).await;
    });
    let s2c = tokio::spawn(async move {
        let _ = tokio::io::copy(
            &mut tokio::io::BufReader::new(server_r),
            &mut client_w,
        ).await;
    });

    let _ = tokio::join!(c2s, s2c);
    Ok(())
}
