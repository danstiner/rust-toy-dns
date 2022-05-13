use crate::{protocol::*, resolver::*};
use async_trait::async_trait;

/// Resolver that hides TTL values on responses by setting them all to zero
pub struct HideTtl<R> {
    inner: R,
}

impl<R> HideTtl<R> {
    pub fn new(resolver: R) -> Self {
        Self { inner: resolver }
    }
}

#[async_trait]
impl<R: Resolver + Send + Sync> Resolver for HideTtl<R> {
    async fn query(&self, question: Question) -> Result<Response, ResolveError> {
        let mut response = self.inner.query(question).await?;

        for r in &mut response.answer {
            r.set_ttl(0);
        }
        for r in &mut response.authority {
            r.set_ttl(0);
        }
        for r in &mut response.additional {
            r.set_ttl(0);
        }

        Ok(response)
    }
}

#[cfg(test)]
mod tests {

    use std::net::Ipv4Addr;

    use super::*;

    struct MockResolver {
        response: Response,
    }

    impl MockResolver {
        fn new() -> Self {
            Self {
                response: Response {
                    code: ResponseCode::NoError,
                    answer: vec![Record::A {
                        name: "example.com".to_string(),
                        class: 1,
                        ttl: 300,
                        address: Ipv4Addr::new(93, 184, 216, 34),
                    }],
                    authority: vec![],
                    additional: vec![],
                    origin: None,
                },
            }
        }
    }

    #[async_trait]
    impl Resolver for &MockResolver {
        async fn query(&self, _question: Question) -> Result<Response, ResolveError> {
            Ok(self.response.clone())
        }
    }

    #[tokio::test]
    async fn ttls_are_set_to_zero() {
        let mock = MockResolver::new();
        let resolver = HideTtl::new(&mock);
        let mut expected_response = mock.response.clone();
        expected_response.answer.get_mut(0).unwrap().set_ttl(0);

        let response = resolver.lookup_ip4("example.com").await.unwrap();

        assert_eq!(response, expected_response);
    }
}
