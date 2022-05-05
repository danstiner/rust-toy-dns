mod protocol;
mod resolver;
mod server;

use resolver::{caching::CachingResolver, stub::StubResolver};
use server::Server;
use tracing::info;
use std::{env, error::Error, sync::Arc};
use tokio::net::UdpSocket;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    // install global collector configured based on RUST_LOG env var.
    tracing_subscriber::fmt::init();

    let listen_addr = env::args()
        .nth(1)
        .unwrap_or_else(|| "127.0.0.1:8080".to_string());

    info!(?listen_addr, "Starting");

    let socket = UdpSocket::bind(&listen_addr).await?;
    let resolver = StubResolver::new("1.1.1.1:53")?;
    let resolver = CachingResolver::new(resolver);
    let resolver = Arc::new(resolver);

    Server::new(socket, resolver).run().await?;

    Ok(())
}
