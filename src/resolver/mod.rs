mod hide_ttl;
mod inflight_limit;
mod response_cache;
mod special;
mod stub;
mod timeout;

use crate::protocol::*;
use async_trait::async_trait;
use std::{io, net::SocketAddr, sync::Arc};
use thiserror::Error;

pub use self::hide_ttl::HideTtl;
pub use self::inflight_limit::InflightLimitResolver as InflightLimit;
pub use self::response_cache::ResponseCache;
pub use self::special::SpecialResolver as Special;
pub use self::stub::StubResolver as Stub;
pub use self::timeout::Timeout;

/// A resolver takes queries and answers them. This can take many forms
/// such as recursively resolving the query starting with the root nameservers
/// to forwarding the query to a remote recursive server to reading a fixed
/// set of records from a local file. From the caller's perspective how
/// the resolver works is not relevant, only the returned answer matters.
///
/// A common resolver pattern is to forward requests with a look-aside cache:
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
#[async_trait]
pub trait Resolver {
    async fn query(&self, question: Question) -> Result<Response, ResolveError>;

    async fn lookup_ip4(&self, domain: &str) -> Result<Response, ResolveError> {
        self.query(Question {
            domain: domain.to_owned(),
            qtype: QuestionType::A,
            qclass: QuestionClass::IN,
        })
        .await
    }

    async fn lookup_ip6(&self, domain: &str) -> Result<Response, ResolveError> {
        self.query(Question {
            domain: domain.to_owned(),
            qtype: QuestionType::AAAA,
            qclass: QuestionClass::IN,
        })
        .await
    }
}

// Transparently support resolvers inside reference-counted pointers, very handy
// because spawned tasks using a resolver require a 'static bound.
#[async_trait]
impl<R: Resolver + Send + Sync> Resolver for Arc<R> {
    #[inline]
    async fn query(&self, question: Question) -> Result<Response, ResolveError> {
        self.as_ref().query(question).await
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct Response {
    pub code: ResponseCode,
    pub answer: Vec<Record>,
    pub authority: Vec<Record>,
    pub additional: Vec<Record>,
    pub origin: Option<SocketAddr>,
}

#[derive(Error, Debug)]
pub enum ResolveError {
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),
    #[error("query was dropped")]
    Dropped,
}
