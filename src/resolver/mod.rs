pub mod caching;
pub mod stub;

use crate::protocol::{QuestionClass, QuestionType, Record};
use async_trait::async_trait;
use std::{io, net::SocketAddr};

/// A resolver takes queries and answers them. This can take many forms
/// from proxing requests to a remote recursive server to reading a fixed
/// set of record from a local file. From the caller's perspective what
/// the resolver does is not relevant, only the returned answer matters.
///
/// A common resolver pattern is to forward requests with a look-aside cache:
///
///               Local                        |  Remote
///                                            |
///  +--------+           +----------+         |  +--------+
///  |        |  queries  |          | queries |  |        |
///  | Caller |---------->|          |---------|->| Remote |
///  |        |           | Resolver |         |  |  Name  |
///  |        |<----------|          |<--------|--| Server |
///  |        | responses |          |responses|  |        |
///  +--------+           +----------+         |  +--------+
///                         |     A            |
///         cache additions |     | references |
///                         V     |            |
///                       +----------+         |
///                       |  cache   |         |
///                       +----------+         |
///
#[async_trait]
pub trait Resolver {
    async fn query(
        &self,
        domain: &str,
        qtype: QuestionType,
        qclass: QuestionClass,
    ) -> io::Result<Response>;
}

#[derive(Debug, Clone)]
pub struct Response {
    pub answers: Vec<Record>,
    pub origin: SocketAddr,
}
