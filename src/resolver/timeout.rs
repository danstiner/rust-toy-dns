use crate::{protocol::*, resolver::*};
use async_trait::async_trait;
use std::{io, time::Duration};

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
    async fn query(&self, question: Question) -> io::Result<Response> {
        tokio::time::timeout(self.timeout, self.inner.query(question))
            .await
            .unwrap()
    }
}
