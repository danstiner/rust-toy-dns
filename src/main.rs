mod protocol;
mod resolver;
mod server;

use resolver::stub::ForwardingResolver;
use server::Server;
use std::{env, error::Error};
use tokio::net::UdpSocket;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    // install global collector configured based on RUST_LOG env var.
    tracing_subscriber::fmt::init();

    let listen_addr = env::args()
        .nth(1)
        .unwrap_or_else(|| "127.0.0.1:8080".to_string());

    let socket = UdpSocket::bind(&listen_addr).await?;
    let resolver_socket = UdpSocket::bind("0.0.0.0:0").await?;
    let resolver = ForwardingResolver::new(resolver_socket, "1.1.1.1:53")?;

    let server = Server::new(socket, resolver);

    // TODO hack, should await server/resolver directly
    let (s, r) = tokio::join!(server.run2(), server.resolver.run());
    s?;
    r?;

    Ok(())
}
