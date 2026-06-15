mod doh;
mod http;
mod proxy;
mod tls;
mod vpn;

use std::{net::SocketAddr, path::PathBuf};

use anyhow::Result;
use clap::{Parser, Subcommand};
use tracing_subscriber::EnvFilter;

// ── CLI ───────────────────────────────────────────────────────────────────────

#[derive(Parser)]
#[command(
    name = "fn",
    about = "FreedomNet — DPI bypass proxy + VPN config generator",
    long_about = "
FreedomNet bypasses internet censorship without a VPN server or IP change.

PROXY MODE  (default):
  Runs a local SOCKS5 + HTTP proxy. Set your browser to SOCKS5 127.0.0.1:1080.
  Techniques: DoH DNS · TLS record fragmentation · HTTP header mangling
  Works against: Russia TSPU, Iran DPI, China GFW keyword blocking.

VPN MODE:
  Generates ready-to-use client config files for OpenVPN / WireGuard / Shadowsocks.
  You need your own server outside the censored country.
",
    version
)]
struct Cli {
    #[command(subcommand)]
    command: Option<Cmd>,

    /// Listen address for proxy mode
    #[arg(long, default_value = "127.0.0.1:1080")]
    listen: SocketAddr,

    /// Enable verbose debug logging
    #[arg(long, short)]
    debug: bool,
}

#[derive(Subcommand)]
enum Cmd {
    /// Run DPI bypass proxy (default mode)
    Proxy {
        #[arg(long, default_value = "127.0.0.1:1080")]
        listen: SocketAddr,
    },

    /// Generate VPN client configs
    Vpn {
        #[command(subcommand)]
        vpn: VpnCmd,
    },
}

#[derive(Subcommand)]
enum VpnCmd {
    /// Generate OpenVPN client config (.ovpn)
    Openvpn {
        /// VPN server hostname or IP
        #[arg(long)]
        server: String,

        /// VPN server port
        #[arg(long, default_value_t = 1194)]
        port: u16,

        /// Use TCP instead of UDP
        #[arg(long)]
        tcp: bool,

        /// Output file path
        #[arg(long, default_value = "client.ovpn")]
        out: PathBuf,
    },

    /// Generate WireGuard client config (.conf)
    Wireguard {
        /// Server endpoint as host:port
        #[arg(long)]
        server: String,

        /// Server WireGuard public key (base64)
        #[arg(long)]
        pubkey: String,

        /// Client tunnel IP (assigned by server admin)
        #[arg(long, default_value = "10.0.0.2/32")]
        address: String,

        /// DNS server to use inside the tunnel
        #[arg(long, default_value = "1.1.1.1")]
        dns: String,

        /// Output file path
        #[arg(long, default_value = "wg0.conf")]
        out: PathBuf,
    },

    /// Generate Shadowsocks client config (JSON)
    Shadowsocks {
        /// Server hostname or IP
        #[arg(long)]
        server: String,

        /// Server port
        #[arg(long, default_value_t = 8388)]
        port: u16,

        /// Password
        #[arg(long)]
        password: String,

        /// Cipher method
        #[arg(long, default_value = "aes-256-gcm")]
        method: String,

        /// Output file path
        #[arg(long, default_value = "ss-config.json")]
        out: PathBuf,
    },
}

// ── Entry ─────────────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    let log_level = if cli.debug { "debug" } else { "info" };
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| EnvFilter::new(format!("fn={},freedomnet={}", log_level, log_level)))
        )
        .with_target(false)
        .init();

    match cli.command {
        None | Some(Cmd::Proxy { .. }) => {
            let listen = match cli.command {
                Some(Cmd::Proxy { listen }) => listen,
                _ => cli.listen,
            };
            proxy::serve(proxy::ProxyConfig { listen }).await?;
        }

        Some(Cmd::Vpn { vpn }) => match vpn {
            VpnCmd::Openvpn { server, port, tcp, out } => {
                vpn::OpenVpnConfig {
                    server,
                    port,
                    proto: if tcp { "tcp" } else { "udp" },
                    out_path: out,
                }.write()?;
            }

            VpnCmd::Wireguard { server, pubkey, address, dns, out } => {
                vpn::WireGuardConfig {
                    server_endpoint: server,
                    server_pubkey: pubkey,
                    client_address: address,
                    dns,
                    out_path: out,
                }.write()?;
            }

            VpnCmd::Shadowsocks { server, port, password, method, out } => {
                vpn::ShadowsocksConfig {
                    server,
                    port,
                    password,
                    method,
                    out_path: out,
                }.write()?;
            }
        },
    }

    Ok(())
}
