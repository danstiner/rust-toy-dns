use crate::{protocol::*, resolver::*};
use async_trait::async_trait;
use parking_lot::Mutex;
use tracing::info;
use std::cmp::Ordering;
use std::collections::{BinaryHeap, HashMap};
use std::io;
use std::sync::Arc;
use std::time::{Duration, Instant};

/// Resolver that caches responses to queries and uses that cache when feasible
pub struct CachingResolver<R> {
    cache: Mutex<Cache>,
    inner: R,
}

struct Cache {
    data: HashMap<CacheKey, CacheEntry>,
    expirations: BinaryHeap<CacheExpiration>,
    capacity: usize,
}

impl Cache {
    fn new() -> Cache {
        let capacity = 100;
        Cache {
            data: HashMap::with_capacity(capacity),
            expirations: BinaryHeap::with_capacity(capacity),
            capacity,
        }
    }

    fn get(&mut self, key: &CacheKey) -> Option<Response> {
        if let Some(entry) = self.data.get(&key) {
            if entry.is_expired(Instant::now()) {
                self.data.remove(&key);
            } else {
                return Some(entry.response.clone());
            }
        }

        None
    }

    fn put(&mut self, key: CacheKey, response: &Response) {
        // If needed, make space for the new cache item, removing the oldest entries
        while self.data.len() >= self.capacity {
            debug_assert_eq!(self.data.len(), self.expirations.len());
            let expiration = self.expirations.pop().unwrap();
            self.data.remove(&expiration.key);
        }

        let entry = CacheEntry {
            response: response.clone(),
            updated_at: Instant::now(),
        };
        self.expirations.push(CacheExpiration {
            key: key.clone(),
            expires_at: entry.expires_at(),
        });
        self.data.insert(
            key,
            CacheEntry {
                response: response.clone(),
                updated_at: Instant::now(),
            },
        );
    }
}

impl<R> CachingResolver<R> {
    pub fn new(resolver: R) -> CachingResolver<R> {
        CachingResolver {
            cache: Mutex::new(Cache::new()),
            inner: resolver,
        }
    }
}

#[async_trait]
impl<R: Resolver + Send + Sync> Resolver for CachingResolver<R> {
    async fn query(
        &self,
        domain: &str,
        qtype: QuestionType,
        qclass: QuestionClass,
    ) -> io::Result<Response> {
        let key = CacheKey {
            question: Question {
                domain: domain.to_owned(),
                qtype,
                qclass,
            },
        };

        // Check for potential cache entries
        if let Some(response) = self.cache.lock().get(&key) {
            info!("Cached response");
            return Ok(response);
        }

        // If no valid cache entry was found, delegate to the inner resolver
        let response = self.inner.query(domain, qtype, qclass).await?;

        // Update the cache
        self.cache.lock().put(key, &response);

        return Ok(response);
    }
}

#[async_trait]
impl<R: Resolver + Send + Sync> Resolver for Arc<CachingResolver<R>>
{
    #[inline]
    async fn query(
        &self,
        domain: &str,
        qtype: QuestionType,
        qclass: QuestionClass,
    ) -> io::Result<Response> {
        self.as_ref().query(domain, qtype, qclass).await
    }
}
#[derive(Clone, Eq, Hash, PartialEq)]
struct CacheKey {
    question: Question,
}

struct CacheEntry {
    response: Response,
    updated_at: Instant,
}

#[derive(Eq, Hash, PartialEq)]
struct CacheExpiration {
    key: CacheKey,
    expires_at: Instant,
}

// Earliest expiration first, this enables a min-heap priority queue of expiring cache entries
impl Ord for CacheExpiration {
    fn cmp(&self, other: &Self) -> Ordering {
        other.expires_at.cmp(&self.expires_at)
    }
}
impl PartialOrd for CacheExpiration {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl CacheEntry {
    pub fn is_expired(&self, now: Instant) -> bool {
        self.expires_at() <= now
    }

    pub fn expires_at(&self) -> Instant {
        self.updated_at + self.ttl()
    }

    fn ttl(&self) -> Duration {
        self.response
            .answers
            .iter()
            .map(|r| r.ttl_duration())
            .min()
            .unwrap_or(Duration::ZERO)
    }
}
