//! Built-in web stats dashboard — served at http://127.0.0.1:8086
//!
//! Endpoints:
//!   GET /          — HTML dashboard page (self-contained, no CDN deps)
//!   GET /api/stats — JSON stats snapshot
//!   GET /api/rules — loaded bypass rules summary
//!   GET /health    — 200 OK

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use tokio::net::{TcpListener, TcpStream};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::stats::Stats;
use crate::rules::{Rules, Action};

const DASHBOARD_HTML: &str = include_str!("dashboard.html");

/// Start the dashboard HTTP server on `addr`.
pub async fn serve(addr: SocketAddr) -> Result<()> {
    let listener = TcpListener::bind(addr).await?;
    tracing::info!("Dashboard: http://{}", addr);

    loop {
        match listener.accept().await {
            Ok((stream, _)) => {
                tokio::spawn(handle_connection(stream));
            }
            Err(e) => {
                tracing::warn!("dashboard accept error: {}", e);
            }
        }
    }
}

async fn handle_connection(mut stream: TcpStream) {
    let mut buf = vec![0u8; 4096];
    let n = match stream.read(&mut buf).await {
        Ok(0) | Err(_) => return,
        Ok(n) => n,
    };

    let request = match std::str::from_utf8(&buf[..n]) {
        Ok(s) => s,
        Err(_) => return,
    };

    let path = extract_path(request).unwrap_or("/");

    let (status, content_type, body) = match path {
        "/api/stats"   => ("200 OK", "application/json", stats_json()),
        "/api/rules"   => ("200 OK", "application/json", rules_json()),
        "/health"      => ("200 OK", "text/plain",        "ok".to_string()),
        "/" | "/index.html" => ("200 OK", "text/html; charset=utf-8", DASHBOARD_HTML.to_string()),
        _              => ("404 Not Found", "text/plain", "Not Found".to_string()),
    };

    let response = format!(
        "HTTP/1.1 {}\r\nContent-Type: {}\r\nContent-Length: {}\r\nAccess-Control-Allow-Origin: *\r\nConnection: close\r\n\r\n{}",
        status, content_type, body.len(), body
    );

    let _ = stream.write_all(response.as_bytes()).await;
}

fn extract_path(request: &str) -> Option<&str> {
    let line = request.lines().next()?;
    let parts: Vec<&str> = line.split_whitespace().collect();
    if parts.len() >= 2 { Some(parts[1]) } else { None }
}

fn stats_json() -> String {
    let s = Stats::global();
    let up    = s.bytes_up.load(std::sync::atomic::Ordering::Relaxed);
    let down  = s.bytes_down.load(std::sync::atomic::Ordering::Relaxed);
    let total = s.total_connections.load(std::sync::atomic::Ordering::Relaxed);
    let active = s.active_connections.load(std::sync::atomic::Ordering::Relaxed).max(0) as u64;
    let splits2 = s.tls_splits.load(std::sync::atomic::Ordering::Relaxed);
    let splits3 = s.tls_splits3.load(std::sync::atomic::Ordering::Relaxed);
    let doh_h  = s.doh_hits.load(std::sync::atomic::Ordering::Relaxed);
    let doh_m  = s.doh_misses.load(std::sync::atomic::Ordering::Relaxed);
    let doh_rate = if doh_h + doh_m == 0 { 0.0_f64 }
                   else { doh_h as f64 / (doh_h + doh_m) as f64 };

    let uptime = s.start.elapsed();
    let h = uptime.as_secs() / 3600;
    let m = (uptime.as_secs() % 3600) / 60;
    let sec = uptime.as_secs() % 60;

    format!(
        r#"{{"total_connections":{total},"active_connections":{active},"bytes_up":{up},"bytes_down":{down},"bytes_up_human":"{up_h}","bytes_down_human":"{down_h}","tls_splits":{splits},"doh_hit_rate":{doh_rate:.3},"uptime":"{h:02}:{m:02}:{sec:02}","started_at":"{started}"}}"#,
        total   = total,
        active  = active,
        up      = up,
        down    = down,
        up_h    = fmt_bytes(up),
        down_h  = fmt_bytes(down),
        splits  = splits2 + splits3,
        doh_rate = doh_rate,
        h = h, m = m, sec = sec,
        started = "see uptime",
    )
}

fn rules_json() -> String {
    let r = Rules::global();
    // Sample a few well-known domains to report their action
    let samples = [
        "rutracker.org", "google.com", "youtube.com", "bbc.com",
        "facebook.com", "twitter.com", "localhost", "doubleclick.net",
    ];

    let mut entries = Vec::new();
    for domain in &samples {
        let action = match r.action_for(domain) {
            Action::Proxy  => "PROXY",
            Action::Direct => "DIRECT",
            Action::Block  => "BLOCK",
        };
        entries.push(format!(r#"{{"domain":"{}","action":"{}"}}"#, domain, action));
    }
    format!(r#"{{"samples":[{}]}}"#, entries.join(","))
}

fn fmt_bytes(b: u64) -> String {
    match b {
        b if b >= 1_073_741_824 => format!("{:.2} GB", b as f64 / 1_073_741_824.0),
        b if b >= 1_048_576     => format!("{:.1} MB", b as f64 / 1_048_576.0),
        b if b >= 1024          => format!("{:.1} KB", b as f64 / 1024.0),
        _                       => format!("{} B", b),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extract_root_path() {
        assert_eq!(extract_path("GET / HTTP/1.1\r\nHost: x\r\n"), Some("/"));
    }

    #[test]
    fn extract_api_path() {
        assert_eq!(extract_path("GET /api/stats HTTP/1.1\r\n"), Some("/api/stats"));
    }

    #[test]
    fn stats_json_is_valid() {
        let j = stats_json();
        assert!(j.starts_with('{'));
        assert!(j.ends_with('}'));
        assert!(j.contains("total_connections"));
        assert!(j.contains("bytes_up"));
    }

    #[test]
    fn fmt_bytes_gb() {
        assert!(fmt_bytes(2_000_000_000).contains("GB"));
    }

    #[test]
    fn fmt_bytes_mb() {
        assert!(fmt_bytes(5_000_000).contains("MB"));
    }

    #[test]
    fn fmt_bytes_kb() {
        assert!(fmt_bytes(5_000).contains("KB"));
    }

    #[test]
    fn fmt_bytes_b() {
        assert!(fmt_bytes(100).contains("B"));
        assert!(!fmt_bytes(100).contains("K"));
    }
}
