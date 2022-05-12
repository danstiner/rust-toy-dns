mod protocol;
mod resolver;
mod server;

use server::Server;
use std::{env, error::Error, sync::Arc};
use tokio::net::UdpSocket;
use tracing::info;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    // install global collector configured based on RUST_LOG env var.
    tracing_subscriber::fmt::init();

    let listen_addr = env::args()
        .nth(1)
        .unwrap_or_else(|| "127.0.0.1:8080".to_string());

    let remote_addr = env::args()
        .nth(2)
        .unwrap_or_else(|| "1.1.1.1:53".to_string());

    let socket = UdpSocket::bind(&listen_addr).await?;
    let resolver = resolver::Stub::new(&remote_addr)?;
    let resolver = resolver::ResponseCache::new(resolver, 1000);
    let resolver = resolver::Special::new(resolver);
    let resolver = resolver::InflightLimit::new(resolver, 200);
    let resolver = Arc::new(resolver);

    info!(?listen_addr, ?remote_addr, "Starting");

    Server::new(socket, resolver).run().await?;

    Ok(())
}
