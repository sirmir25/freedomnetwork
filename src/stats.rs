//! Live connection statistics — atomic counters shared across all proxy tasks.
//!
//! Call `Stats::global()` to get a reference; `spawn_reporter()` starts a
//! background task that prints a one-liner to stderr every 30 seconds.

use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::time;

pub struct Stats {
    pub total_connections: AtomicU64,
    pub active_connections: AtomicI64,
    pub bytes_up: AtomicU64,
    pub bytes_down: AtomicU64,
    pub tls_splits: AtomicU64,
    pub tls_splits3: AtomicU64,
    pub http_mangles: AtomicU64,
    pub doh_hits: AtomicU64,
    pub doh_misses: AtomicU64,
    pub start: Instant,
}

impl Stats {
    fn new() -> Self {
        Self {
            total_connections: AtomicU64::new(0),
            active_connections: AtomicI64::new(0),
            bytes_up: AtomicU64::new(0),
            bytes_down: AtomicU64::new(0),
            tls_splits: AtomicU64::new(0),
            tls_splits3: AtomicU64::new(0),
            http_mangles: AtomicU64::new(0),
            doh_hits: AtomicU64::new(0),
            doh_misses: AtomicU64::new(0),
            start: Instant::now(),
        }
    }

    pub fn global() -> &'static Arc<Stats> {
        use std::sync::OnceLock;
        static G: OnceLock<Arc<Stats>> = OnceLock::new();
        G.get_or_init(|| Arc::new(Stats::new()))
    }

    pub fn conn_open(&self) {
        self.total_connections.fetch_add(1, Ordering::Relaxed);
        self.active_connections.fetch_add(1, Ordering::Relaxed);
    }

    pub fn conn_close(&self) {
        self.active_connections.fetch_sub(1, Ordering::Relaxed);
    }

    pub fn add_up(&self, n: u64) {
        self.bytes_up.fetch_add(n, Ordering::Relaxed);
    }

    pub fn add_down(&self, n: u64) {
        self.bytes_down.fetch_add(n, Ordering::Relaxed);
    }

    pub fn record_tls_split(&self) {
        self.tls_splits.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_tls_split3(&self) {
        self.tls_splits3.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_http_mangle(&self) {
        self.http_mangles.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_doh_hit(&self) {
        self.doh_hits.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_doh_miss(&self) {
        self.doh_misses.fetch_add(1, Ordering::Relaxed);
    }

    fn fmt_bytes(b: u64) -> String {
        if b < 1024 {
            format!("{b} B")
        } else if b < 1024 * 1024 {
            format!("{:.1} KB", b as f64 / 1024.0)
        } else if b < 1024 * 1024 * 1024 {
            format!("{:.1} MB", b as f64 / 1_048_576.0)
        } else {
            format!("{:.2} GB", b as f64 / 1_073_741_824.0)
        }
    }

    pub fn print_line(&self) {
        let up    = self.bytes_up.load(Ordering::Relaxed);
        let down  = self.bytes_down.load(Ordering::Relaxed);
        let total = self.total_connections.load(Ordering::Relaxed);
        let active = self.active_connections.load(Ordering::Relaxed).max(0) as u64;
        let splits = self.tls_splits.load(Ordering::Relaxed)
                   + self.tls_splits3.load(Ordering::Relaxed);
        let doh_h  = self.doh_hits.load(Ordering::Relaxed);
        let doh_m  = self.doh_misses.load(Ordering::Relaxed);
        let doh_pct = if doh_h + doh_m == 0 { 0 } else { doh_h * 100 / (doh_h + doh_m) };
        let uptime = self.start.elapsed().as_secs();
        let hh = uptime / 3600;
        let mm = (uptime % 3600) / 60;
        let ss = uptime % 60;

        eprintln!(
            "[{hh:02}:{mm:02}:{ss:02}]  \
             conns {total} total / {active} active  \
             ↑ {}  ↓ {}  \
             TLS bypass: {splits}  \
             DoH cache: {doh_pct}%",
            Self::fmt_bytes(up),
            Self::fmt_bytes(down),
        );
    }
}

/// Spawn a background tokio task that logs stats every `interval` seconds.
pub fn spawn_reporter(interval_secs: u64) {
    let stats = Arc::clone(Stats::global());
    tokio::spawn(async move {
        let mut ticker = time::interval(Duration::from_secs(interval_secs));
        ticker.tick().await; // skip the immediate first tick
        loop {
            ticker.tick().await;
            stats.print_line();
        }
    });
}
