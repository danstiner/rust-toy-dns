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
