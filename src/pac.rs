//! PAC (Proxy Auto-Config) file server.
//!
//! Serves a .pac file on http://localhost:<port>/proxy.pac so browsers and
//! OS network settings can auto-configure the proxy without manual setup.
//!
//! The generated PAC uses DIRECT for LAN / localhost and routes everything
//! else through the SOCKS5 proxy.

use std::net::SocketAddr;

use anyhow::Result;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
};
use tracing::debug;

/// Start a minimal HTTP server that serves the PAC file on `listen`.
/// Typically `listen` = 127.0.0.1:8085.
pub async fn serve_pac(listen: SocketAddr, proxy_addr: SocketAddr) -> Result<()> {
    let listener = TcpListener::bind(listen).await?;
    println!("  PAC file  http://{}:{}/proxy.pac", listen.ip(), listen.port());

    loop {
        let (mut stream, _) = listener.accept().await?;
        let proxy_addr = proxy_addr;

        tokio::spawn(async move {
            // Read the HTTP request (we don't actually need to parse it)
            let mut buf = [0u8; 1024];
            let _ = stream.read(&mut buf).await;

            let pac = build_pac(proxy_addr);
            let response = format!(
                "HTTP/1.1 200 OK\r\n\
                 Content-Type: application/x-ns-proxy-autoconfig\r\n\
                 Content-Length: {}\r\n\
                 Connection: close\r\n\
                 \r\n\
                 {}",
                pac.len(),
                pac
            );
            let _ = stream.write_all(response.as_bytes()).await;
            debug!("Served PAC file");
        });
    }
}

fn build_pac(proxy: SocketAddr) -> String {
    format!(
        r#"// FreedomNet Proxy Auto-Config
// Set this URL in: System Settings → Network → Proxies → Auto Proxy Config
// URL: http://127.0.0.1:8085/proxy.pac

function FindProxyForURL(url, host) {{
    // Direct for loopback and LAN
    if (isPlainHostName(host))         return "DIRECT";
    if (shExpMatch(host, "10.*"))      return "DIRECT";
    if (shExpMatch(host, "192.168.*")) return "DIRECT";
    if (shExpMatch(host, "172.16.*"))  return "DIRECT";
    if (host === "localhost")          return "DIRECT";
    if (host === "127.0.0.1")         return "DIRECT";

    // Route everything else through FreedomNet
    return "SOCKS5 {host} {port}; SOCKS {host} {port}; DIRECT";
}}
"#,
        host = proxy.ip(),
        port = proxy.port(),
    )
}
