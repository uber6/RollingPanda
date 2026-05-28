mod creds;
mod handler;
mod hostkey;
#[cfg(windows)]
mod pty_filter;
mod shell;

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use anyhow::Context;
use clap::Parser;
use handler::RollingPandaServer;
use russh::server::Server as _;
use tracing::info;
use tracing_subscriber::EnvFilter;

#[derive(Parser, Debug)]
#[command(
    name = "rollingpanda",
    about = "Lightweight SSH server with baked-in credentials (DropBear-style)"
)]
struct Cli {
    /// Address to bind (default: all interfaces)
    #[arg(long, default_value = "0.0.0.0")]
    bind: String,

    /// TCP port (default is compile-time `ROLLINGPANDA_PORT`, else 2222)
    #[arg(short, long, default_value_t = creds::PORT)]
    port: u16,

    /// Load host key from file instead of generating a new in-memory key each start
    #[arg(long, value_name = "PATH")]
    host_key: Option<PathBuf>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env().add_directive("rollingpanda=info".parse()?))
        .init();

    let cli = Cli::parse();
    let host_keys = match &cli.host_key {
        Some(path) => hostkey::load_from_file(path)?,
        None => hostkey::generate_in_memory()?,
    };
    let config = Arc::new(handler::server_config(host_keys));

    let bind: SocketAddr = format!("{}:{}", cli.bind, cli.port)
        .parse()
        .context("invalid bind address")?;

    info!(
        %bind,
        user = creds::USERNAME,
        "RollingPanda SSH server starting (password auth uses compile-time baked creds)"
    );
    info!(
        "Connect with: ssh -p {port} {user}@{host}",
        port = cli.port,
        user = creds::USERNAME,
        host = if cli.bind == "0.0.0.0" {
            "127.0.0.1"
        } else {
            cli.bind.as_str()
        }
    );
    info!(
        "Rebuild with custom settings: ROLLINGPANDA_USER=... ROLLINGPANDA_PASSWORD=... ROLLINGPANDA_PORT=... cargo build --release"
    );

    let mut server = RollingPandaServer;
    server
        .run_on_address(config, bind)
        .await
        .context("SSH server exited")?;
    Ok(())
}
