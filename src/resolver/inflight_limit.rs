use crate::{protocol::*, resolver::*};
use async_trait::async_trait;
use tokio::sync::Semaphore;
use tracing::warn;

/// Resolver that limits the number of in-flight queries, dropping queries if the limit is reached
pub struct InflightLimitResolver<R> {
    semaphore: Semaphore,
    inner: R,
}

impl<R> InflightLimitResolver<R> {
    pub fn new(resolver: R, limit: usize) -> InflightLimitResolver<R> {
        InflightLimitResolver {
            semaphore: Semaphore::new(limit),
            inner: resolver,
        }
    }
}

#[async_trait]
impl<R: Resolver + Send + Sync> Resolver for InflightLimitResolver<R> {
    async fn query(&self, question: Question) -> Result<Response, ResolveError> {
        // TODO replace semaphore with a simpler counter
        match self.semaphore.try_acquire() {
            Ok(_) => self.inner.query(question).await,
            Err(_) => {
                warn!(?question, "Dropping query due to inflight limit");
                Err(ResolveError::Dropped)
            }
        }
    }
}

#[cfg(test)]
mod tests {

    use std::time::Duration;

    use tokio::try_join;

    use super::*;

    struct NeverResolve;

    #[async_trait]
    impl Resolver for NeverResolve {
        async fn query(&self, _question: Question) -> Result<Response, ResolveError> {
            loop {
                tokio::time::sleep(Duration::MAX).await;
            }
        }
    }

    #[tokio::test]
    async fn queries_over_limit_are_dropped() {
        let resolver = InflightLimitResolver::new(NeverResolve, 1);

        let query1 = async {
            resolver.lookup_ip4("example.com").await.unwrap();
            panic!("First query should never complete or be canceled");
            Ok(())
        };
        let query2 = async { resolver.lookup_ip4("example.com").await };

        let result = try_join!(query1, query2);

        match result.unwrap_err() {
            ResolveError::Dropped => (),
            _ => panic!("Expected drop error"),
        }
    }
}
