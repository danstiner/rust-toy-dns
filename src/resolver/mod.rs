mod hide_ttl;
mod inflight_limit;
mod response_cache;
mod special;
mod stub;

use crate::protocol::*;
use async_trait::async_trait;
use std::{io, net::SocketAddr, sync::Arc};

pub use self::hide_ttl::HideTtl;
pub use self::inflight_limit::InflightLimitResolver as InflightLimit;
pub use self::response_cache::ResponseCache;
pub use self::special::SpecialResolver as Special;
pub use self::stub::StubResolver as Stub;

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
    async fn query(&self, question: Question) -> io::Result<Response>;

    async fn lookup_ip4(&self, domain: &str) -> io::Result<Response> {
        self.query(Question {
            domain: domain.to_owned(),
            qtype: QuestionType::A,
            qclass: QuestionClass::IN,
        })
        .await
    }
}

// Transparently support resolvers inside reference-counted pointers, very handy
// because spawned tasks using a resolver require a 'static bound. The server struct does this.
#[async_trait]
impl<R: Resolver + Send + Sync> Resolver for Arc<R> {
    #[inline]
    async fn query(&self, question: Question) -> io::Result<Response> {
        self.as_ref().query(question).await
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct Response {
    pub code: ResponseCode,
    pub answers: Vec<Record>,
    pub authority: Vec<Record>,
    pub additional: Vec<Record>,
    pub origin: Option<SocketAddr>,
}

impl Response {
    pub const EMPTY: Response = Response {
        code: ResponseCode::NoError,
        answers: vec![],
        authority: vec![],
        additional: vec![],
        origin: None,
    };
}
