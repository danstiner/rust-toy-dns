use crate::{protocol::*, resolver::*};
use async_trait::async_trait;
use std::time::Duration;
use tokio::time::error::Elapsed;

pub struct Timeout<R> {
    inner: R,
    timeout: Duration,
}

impl<R> Timeout<R> {
    pub fn new(resolver: R, timeout: Duration) -> Self {
        Self {
            inner: resolver,
            timeout,
        }
    }
}

#[async_trait]
impl<R: Resolver + Send + Sync> Resolver for Timeout<R> {
    async fn query(&self, question: Question) -> Result<Response, ResolveError> {
        tokio::time::timeout(self.timeout, self.inner.query(question))
            .await
            .map_err(|_: Elapsed| ResolveError::Timeout)?
    }
}

#[cfg(test)]
mod tests {

    use super::*;

    struct MockResolver {
        response: Response,
    }

    impl MockResolver {
        fn new() -> Self {
            Self {
                response: Response {
                    code: ResponseCode::NoError,
                    answer: vec![],
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
            tokio::time::sleep(Duration::from_secs(2)).await;
            Ok(self.response.clone())
        }
    }

    #[tokio::test(start_paused = true)]
    async fn fast_queries_pass_through() {
        let mock = MockResolver::new();
        let resolver = Timeout::new(&mock, Duration::from_secs(10));

        let response = resolver.lookup_ip4("example.com").await.unwrap();

        assert_eq!(response, mock.response);
    }

    #[tokio::test(start_paused = true)]
    async fn slow_queries_are_timed_out() {
        let mock = MockResolver::new();
        let resolver = Timeout::new(&mock, Duration::from_secs(1));

        let result = resolver.lookup_ip4("example.com").await;

        match result {
            Err(ResolveError::Timeout) => (),
            _ => panic!("Expected timeout error"),
        }
    }
}
