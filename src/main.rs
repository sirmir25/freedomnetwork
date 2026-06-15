mod anon;
mod doh;
mod ffi;
mod pac;
mod proxy;
mod rules;
mod stats;

use std::{net::SocketAddr, process::Command};

use anyhow::Result;
use clap::{Parser, Subcommand};
use tracing_subscriber::EnvFilter;

// ── CLI ───────────────────────────────────────────────────────────────────────

#[derive(Parser)]
#[command(
    name  = "fn",
    about = "FreedomNet — DPI bypass + anonymity proxy + VPN config generator",
    long_about = "\
FreedomNet bypasses internet censorship locally. No VPN server or remote relay
needed for proxy mode.

PROXY (default)  →  fn [--listen 127.0.0.1:1080]
  SOCKS5 + HTTP proxy with:
  • C++ TLS record fragmentation (bypasses Russia TSPU, Iran IRIAMAN, China GFW)
  • C++ HTTP header case-mangling
  • Rust anonymity layer: strips X-Real-IP / Forwarded / Via, normalises UA
  • DNS over HTTPS (Cloudflare → Google → Quad9 fallback)
  • Optional PAC file server for zero-click browser auto-config

VPN CONFIG  →  fn vpn <openvpn|wireguard|shadowsocks> [options]
  Generates client configs. Requires fn-vpn (D binary):
    cd vpngen && dub build -b release

SUPPORTED CENSORSHIP SYSTEMS:
  Russia TSPU/Echelon · Iran IRIAMAN · China GFW · Kazakhstan DPI · Belarus",
    version
)]
struct Cli {
    #[command(subcommand)]
    command: Option<Cmd>,

    /// SOCKS5 / HTTP proxy listen address
    #[arg(long, default_value = "127.0.0.1:1080", global = true)]
    listen: SocketAddr,

    /// Also serve a PAC file for zero-click browser auto-config
    #[arg(long, default_value = "127.0.0.1:8085")]
    pac_listen: SocketAddr,

    /// Disable PAC file server
    #[arg(long)]
    no_pac: bool,

    /// Verbose debug logging
    #[arg(long, short, global = true)]
    debug: bool,
}

#[derive(Subcommand)]
enum Cmd {
    /// Run DPI bypass proxy (default when no subcommand given)
    Proxy {
        #[arg(long, default_value = "127.0.0.1:1080")]
        listen: SocketAddr,
        #[arg(long, default_value = "127.0.0.1:8085")]
        pac_listen: SocketAddr,
        #[arg(long)]
        no_pac: bool,
    },

    /// Generate VPN client config (delegates to fn-vpn D binary)
    Vpn {
        /// VPN type: openvpn | wireguard | shadowsocks
        #[arg(value_name = "TYPE")]
        vpn_type: String,
        /// Remaining arguments forwarded to fn-vpn unchanged
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        args: Vec<String>,
    },
}

// ── Entry ─────────────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    let level = if cli.debug { "debug" } else { "info" };
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| EnvFilter::new(level))
        )
        .with_target(false)
        .init();

    match cli.command {
        None => {
            run_proxy(cli.listen, cli.pac_listen, cli.no_pac).await?;
        }
        Some(Cmd::Proxy { listen, pac_listen, no_pac }) => {
            run_proxy(listen, pac_listen, no_pac).await?;
        }
        Some(Cmd::Vpn { vpn_type, args }) => {
            run_fn_vpn(&vpn_type, &args)?;
        }
    }

    Ok(())
}

async fn run_proxy(listen: SocketAddr, pac_listen: SocketAddr, no_pac: bool) -> Result<()> {
    if !no_pac {
        let pac_l   = pac_listen;
        let proxy_l = listen;
        tokio::spawn(async move {
            if let Err(e) = pac::serve_pac(pac_l, proxy_l).await {
                tracing::warn!("PAC server error: {}", e);
            }
        });
    }
    // Pre-load bypass rules (logs count on first access)
    let _ = rules::Rules::global();
    // Start periodic stats reporter (every 30 seconds)
    stats::spawn_reporter(30);
    proxy::serve(proxy::ProxyConfig { listen }).await
}

/// Invoke the `fn-vpn` D binary (must be compiled first: cd vpngen && dub build).
fn run_fn_vpn(vpn_type: &str, extra_args: &[String]) -> Result<()> {
    let binary = if std::path::Path::new("vpngen/fn-vpn").exists() {
        "vpngen/fn-vpn"
    } else {
        "fn-vpn"
    };

    match Command::new(binary).arg(vpn_type).args(extra_args).status() {
        Ok(s) if s.success() => Ok(()),
        Ok(s) => anyhow::bail!("fn-vpn exited with {}", s),
        Err(e) => {
            eprintln!("Error: '{}': {}", binary, e);
            eprintln!("Build the D VPN generator:");
            eprintln!("  cd vpngen && dub build -b release");
            eprintln!("  https://dlang.org/download.html");
            anyhow::bail!("fn-vpn not found")
        }
    }
}
