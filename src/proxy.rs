//! SOCKS5 + HTTP CONNECT proxy server with built-in DPI bypass.
//!
//! Architecture:
//!   App/Browser → SOCKS5 (or HTTP CONNECT) on localhost:1080
//!     → DoH DNS resolution
//!     → TCP connect with TCP_NODELAY
//!     → TLS record fragmentation (ClientHello split into 2 TLS records)
//!     → bidirectional relay to real server

use std::{net::SocketAddr, sync::Arc};

use anyhow::Result;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};
use tracing::{debug, info, warn};

use crate::{doh::Doh, http, tls};

const CHUNK: usize = 65536;

pub struct ProxyConfig {
    pub listen: SocketAddr,
}

pub async fn serve(cfg: ProxyConfig) -> Result<()> {
    let listener = TcpListener::bind(cfg.listen).await?;
    let doh = Arc::new(Doh::new()?);

    println!("\n  FreedomNet DPI Bypass Proxy");
    println!("  ─────────────────────────────────────────────────");
    println!("  Listening on  {}", cfg.listen);
    println!("  Protocol      SOCKS5 + HTTP CONNECT");
    println!("  Techniques    DoH DNS · TLS record split · HTTP mangling");
    println!();
    println!("  Browser proxy setting (pick one):");
    println!("    SOCKS5    127.0.0.1   port {}", cfg.listen.port());
    println!("    HTTP      127.0.0.1   port {}", cfg.listen.port());
    println!();
    println!("  Press Ctrl+C to stop.");
    println!("  ─────────────────────────────────────────────────\n");

    loop {
        let (stream, peer) = listener.accept().await?;
        let doh = Arc::clone(&doh);
        debug!("New connection from {}", peer);
        tokio::spawn(async move {
            if let Err(e) = handle(stream, doh).await {
                debug!("Connection error: {}", e);
            }
        });
    }
}

async fn handle(mut stream: TcpStream, doh: Arc<Doh>) -> Result<()> {
    let mut first = [0u8; 1];
    stream.read_exact(&mut first).await?;

    match first[0] {
        0x05 => handle_socks5(stream, doh).await,
        _    => handle_http_connect(stream, first[0], doh).await,
    }
}

// ── SOCKS5 ────────────────────────────────────────────────────────────────────

async fn handle_socks5(mut s: TcpStream, doh: Arc<Doh>) -> Result<()> {
    // Greeting: consumed version byte, read nmethods + methods
    let mut buf = [0u8; 1];
    s.read_exact(&mut buf).await?;
    let nmethods = buf[0] as usize;
    let mut methods = vec![0u8; nmethods];
    s.read_exact(&mut methods).await?;

    s.write_all(b"\x05\x00").await?; // no auth

    // Request header
    let mut hdr = [0u8; 4];
    s.read_exact(&mut hdr).await?;
    let (_ver, cmd, _rsv, atyp) = (hdr[0], hdr[1], hdr[2], hdr[3]);

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
        0x03 => { // Domain name
            let mut len = [0u8; 1];
            s.read_exact(&mut len).await?;
            let mut name = vec![0u8; len[0] as usize];
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

async fn handle_http_connect(mut s: TcpStream, first: u8, doh: Arc<Doh>) -> Result<()> {
    let mut rest = Vec::with_capacity(512);
    rest.push(first);

    // Read until blank line
    let mut buf = [0u8; 1];
    loop {
        s.read_exact(&mut buf).await?;
        rest.push(buf[0]);
        if rest.ends_with(b"\r\n\r\n") {
            break;
        }
        if rest.len() > 8192 {
            anyhow::bail!("HTTP request too large");
        }
    }

    let request_line = std::str::from_utf8(rest.split(|&b| b == b'\n').next().unwrap_or(&[]))?
        .trim();
    let parts: Vec<&str> = request_line.split_whitespace().collect();

    if parts.len() < 2 || !parts[0].eq_ignore_ascii_case("CONNECT") {
        return Ok(());
    }

    let hostport = parts[1];
    let (host, port) = if let Some((h, p)) = hostport.rsplit_once(':') {
        (h.to_string(), p.parse::<u16>().unwrap_or(443))
    } else {
        (hostport.to_string(), 443)
    };

    s.write_all(b"HTTP/1.1 200 Connection established\r\n\r\n").await?;

    info!("CONNECT {}:{}", host, port);
    tunnel(s, &host, port, doh).await
}

// ── DPI-bypass tunnel ─────────────────────────────────────────────────────────

async fn tunnel(mut client: TcpStream, host: &str, port: u16, doh: Arc<Doh>) -> Result<()> {
    // DNS via DoH
    let ip = match doh.resolve(host).await {
        Some(ip) => ip,
        None => {
            warn!("DNS failed: {}", host);
            return Ok(());
        }
    };

    // Connect with TCP_NODELAY to ensure each write() = one TCP segment
    let mut server = TcpStream::connect(SocketAddr::new(ip, port)).await?;
    server.set_nodelay(true)?;

    // Read first payload from browser (TLS ClientHello or raw HTTP)
    let mut first = vec![0u8; CHUNK];
    let n = tokio::time::timeout(
        std::time::Duration::from_secs(10),
        client.read(&mut first),
    ).await??;

    if n == 0 {
        return Ok(());
    }
    let first = &first[..n];

    // Apply bypass technique
    if tls::is_client_hello(first) {
        let (r1, r2) = tls::split_into_records(first);
        debug!("TLS record-split {}:{} → {}B + {}B", host, port, r1.len(), r2.len());
        // Two separate write_all() calls + TCP_NODELAY → two TCP segments
        server.write_all(&r1).await?;
        server.write_all(&r2).await?;
    } else if http::is_http(first) {
        server.write_all(&http::mangle(first)).await?;
    } else {
        server.write_all(first).await?;
    }

    // Bidirectional relay (efficient tokio copy)
    let (mut cr, mut cw) = client.into_split();
    let (mut sr, mut sw) = server.into_split();

    let c2s = tokio::spawn(async move {
        let _ = tokio::io::copy(&mut cr, &mut sw).await;
    });
    let s2c = tokio::spawn(async move {
        let _ = tokio::io::copy(&mut sr, &mut cw).await;
    });

    let _ = tokio::join!(c2s, s2c);
    Ok(())
}
