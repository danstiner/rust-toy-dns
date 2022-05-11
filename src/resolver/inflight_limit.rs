use crate::{protocol::*, resolver::*};
use async_trait::async_trait;
use std::io;
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
    async fn query(&self, question: Question) -> io::Result<Response> {
        // TODO replace semaphore with a simpler counter
        match self.semaphore.try_acquire() {
            Ok(_) => self.inner.query(question).await,
            Err(_) => {
                warn!(?question, "Dropping query due to inflight limit");
                Ok(Response::EMPTY)
            }
        }
    }
}
