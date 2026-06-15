//! DNS-over-HTTPS resolver.
//! Bypasses ISP DNS poisoning by querying Cloudflare / Google / Quad9 over HTTPS.
use std::{
    collections::HashMap,
    net::IpAddr,
    str::FromStr,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use anyhow::Result;
use reqwest::Client;
use serde_json::Value;
use tracing::debug;

const RESOLVERS: &[&str] = &[
    "https://cloudflare-dns.com/dns-query",
    "https://dns.google/dns-query",
    "https://dns.quad9.net/dns-query",
];

const TTL: Duration = Duration::from_secs(300);

#[derive(Clone)]
pub struct Doh {
    client: Client,
    cache:  Arc<Mutex<HashMap<String, (IpAddr, Instant)>>>,
}

impl Doh {
    pub fn new() -> Result<Self> {
        let client = Client::builder()
            .use_rustls_tls()
            .timeout(Duration::from_secs(5))
            .user_agent("curl/7.88.0")
            .build()?;
        Ok(Self { client, cache: Arc::new(Mutex::new(HashMap::new())) })
    }

    pub async fn resolve(&self, host: &str) -> Option<IpAddr> {
        // Cache hit?
        {
            let cache = self.cache.lock().unwrap();
            if let Some((ip, expires)) = cache.get(host) {
                if Instant::now() < *expires {
                    return Some(*ip);
                }
            }
        }

        // Try each resolver in order
        for url in RESOLVERS {
            if let Some(ip) = self.query(url, host).await {
                debug!("DoH {} → {}", host, ip);
                self.cache.lock().unwrap()
                    .insert(host.to_string(), (ip, Instant::now() + TTL));
                return Some(ip);
            }
        }

        // System DNS fallback
        if let Ok(addrs) = tokio::net::lookup_host(format!("{}:0", host)).await {
            for addr in addrs {
                let ip = addr.ip();
                self.cache.lock().unwrap()
                    .insert(host.to_string(), (ip, Instant::now() + TTL));
                return Some(ip);
            }
        }

        None
    }

    async fn query(&self, resolver: &str, host: &str) -> Option<IpAddr> {
        let url = format!("{}?name={}&type=A", resolver, host);
        let resp: Value = self.client.get(&url)
            .header("Accept", "application/dns-json")
            .send().await.ok()?
            .json().await.ok()?;

        for answer in resp["Answer"].as_array()? {
            if answer["type"].as_u64() == Some(1) {
                if let Some(ip_str) = answer["data"].as_str() {
                    if let Ok(ip) = IpAddr::from_str(ip_str) {
                        return Some(ip);
                    }
                }
            }
        }
        None
    }
}
