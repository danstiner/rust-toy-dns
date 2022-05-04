mod protocol;
mod resolver;
mod server;

use resolver::stub::StubResolver;
use server::Server;
use std::{env, error::Error, sync::Arc};
use tokio::net::UdpSocket;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    // install global collector configured based on RUST_LOG env var.
    tracing_subscriber::fmt::init();

    let listen_addr = env::args()
        .nth(1)
        .unwrap_or_else(|| "127.0.0.1:8080".to_string());

    let socket = UdpSocket::bind(&listen_addr).await?;
    let resolver = Arc::new(StubResolver::new("1.1.1.1:53")?);

    Server::new(socket, resolver).run().await?;

    Ok(())
}
