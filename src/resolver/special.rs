use crate::{protocol::*, resolver::*};
use async_trait::async_trait;
use std::net::Ipv4Addr;

const SPECIAL_TTL: u32 = 655360;

/// Resolver that handles certain special names internally, without a remote lookup.
///
/// - localhost gets an A record of 127.0.0.1
///
/// - 1.0.0.127.in-addr.arpa gets a PTR record of localhost
///
/// - dotted-decimal domain names get an A record, e.g. domain 192.48.96.2 gets A record 192.48.96.2
pub struct SpecialResolver<R> {
    inner: R,
}

impl<R> SpecialResolver<R> {
    pub fn new(resolver: R) -> Self {
        Self { inner: resolver }
    }
}

#[async_trait]
impl<R: Resolver + Send + Sync> Resolver for SpecialResolver<R> {
    async fn query(&self, question: Question) -> Result<Response, ResolveError> {
        if question.qclass == QuestionClass::IN {
            if question.qtype == QuestionType::PTR {
                if question.domain == "1.0.0.127.in-addr.arpa" {
                    return Ok(special_response(Record::PTR {
                        name: "1.0.0.127.in-addr.arpa".to_string(),
                        class: QuestionClass::IN as u16,
                        ttl: SPECIAL_TTL,
                        ptrdname: "localhost".to_string(),
                    }));
                }
            } else if question.qtype == QuestionType::A {
                if question.domain == "localhost" {
                    return Ok(special_response(Record::A {
                        name: "localhost".to_string(),
                        class: QuestionClass::IN as u16,
                        ttl: SPECIAL_TTL,
                        address: Ipv4Addr::LOCALHOST,
                    }));
                } else if let Ok(ip) = question.domain.parse::<Ipv4Addr>() {
                    return Ok(special_response(Record::A {
                        name: question.domain,
                        class: QuestionClass::IN as u16,
                        ttl: SPECIAL_TTL,
                        address: ip,
                    }));
                }
            }
        }

        self.inner.query(question).await
    }
}

fn special_response(record: Record) -> Response {
    Response {
        code: ResponseCode::NoError,
        answer: vec![record],
        authority: vec![],
        additional: vec![],
        origin: None,
    }
}
