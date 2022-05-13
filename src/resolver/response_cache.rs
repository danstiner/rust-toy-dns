use crate::{protocol::*, resolver::*};
use async_trait::async_trait;
use parking_lot::Mutex;
use std::cmp::Ordering;
use std::collections::hash_map::Entry;
use std::collections::{BinaryHeap, HashMap};
use std::time::Duration;
use tokio::time::Instant;
use tracing::{info, warn};

// Prevent excessively long TTLs, as suggested in RFC 1035 we limit to one week
// https://datatracker.ietf.org/doc/html/rfc1035#section-7.3
const MAX_TTL: Duration = Duration::from_secs(7 * 24 * 60 * 60);

// Mitigate unreasonably long TTLs that are likely due to bugs or bit flips. As allowed by the
// protocol we ignore such values and use a TTL of zero instead.
const UNREASONABLE_TTL: Duration = Duration::from_secs(1_000_000_000);

const DEFAULT_NEGATIVE_TTL: Duration = Duration::from_secs(1 * 60);

/// Resolver that caches responses to queries and uses that cache when feasible
pub struct ResponseCache<R> {
    cache: Mutex<Cache>,
    inner: R,
}

impl<R> ResponseCache<R> {
    pub fn new(resolver: R, capacity: usize) -> Self {
        Self {
            cache: Mutex::new(Cache::new(capacity)),
            inner: resolver,
        }
    }

    fn update_response_ttls(&self, entry: &CacheEntry, now: Instant) -> Response {
        let mut response = entry.response.clone();

        let age = now.saturating_duration_since(entry.inserted_at);
        let age_sec = age.as_secs().try_into().unwrap_or(u32::MAX);

        for r in &mut response.answer {
            r.set_ttl(r.ttl().saturating_sub(age_sec));
        }
        for r in &mut response.authority {
            r.set_ttl(r.ttl().saturating_sub(age_sec));
        }
        for r in &mut response.additional {
            r.set_ttl(r.ttl().saturating_sub(age_sec));
        }

        response
    }
}

#[async_trait]
impl<R: Resolver + Send + Sync> Resolver for ResponseCache<R> {
    async fn query(&self, question: Question) -> Result<Response, ResolveError> {
        let key = CacheKey::new(&question.clone());
        let now = Instant::now();

        // Check for potential cache entries
        if let Some(entry) = self.cache.lock().get(key.clone(), now) {
            info!("Cached response");
            return Ok(self.update_response_ttls(entry, now));
        }

        // If no valid cache entry was found, delegate to the inner resolver
        let response = self.inner.query(question).await?;

        // Update the cache
        // TODO skip caching type ANY, AXFR
        // TODO check if (!dns_domain_suffix(t1,control)) { i = j; continue; }
        // TODO check if (!roots_same(t1,control)) { i = j; continue; }
        self.cache.lock().put(key, &response);

        Ok(response)
    }
}

// Keep up to `capacity` entries. If the capacity is reached, the least recently used entry is
struct Cache {
    data: HashMap<CacheKey, CacheEntry>,
    expiration_queue: BinaryHeap<CacheExpiration>,
    capacity: usize,
}

impl Cache {
    fn new(capacity: usize) -> Cache {
        assert!(capacity <= 1_000_000_000);
        Cache {
            data: HashMap::with_capacity(capacity),
            expiration_queue: BinaryHeap::with_capacity(capacity),
            capacity,
        }
    }

    fn get(&mut self, key: CacheKey, now: Instant) -> Option<&CacheEntry> {
        if let Entry::Occupied(o) = self.data.entry(key) {
            if o.get().is_expired(now) {
                o.remove();
                None
            } else {
                Some(o.into_mut())
            }
        } else {
            None
        }
    }

    fn put(&mut self, key: CacheKey, response: &Response) {
        // If needed, make space for the new cache item by dropping soonest to expire entries
        // TODO use a more sophisticated algorithm to drop entries, e.g. least recently used
        while self.data.len() >= self.capacity {
            debug_assert_eq!(self.data.len(), self.expiration_queue.len());
            let expiration = self.expiration_queue.pop().unwrap();
            self.data.remove(&expiration.key);
        }

        let entry = CacheEntry::new(response.clone());
        self.expiration_queue.push(CacheExpiration {
            key: key.clone(),
            expires_at: entry.expires_at,
        });
        self.data.insert(key, entry);
    }
}

#[derive(Clone, Eq, Hash, PartialEq)]
struct CacheKey {
    qtype: QuestionType,
    // All comparisons of domain names must be case-insensitive per the official DNS protocol. So
    // here we lowercase the domain name before using it as a key. The protocol requires original
    // casing to be preserved when possible, so this value should not be used in other contexts.
    // Note case-insensitivity only applies to ASCII characters, Unicode is not a consideration.
    // See https://datatracker.ietf.org/doc/html/rfc1035#section-2.3.3
    // See https://datatracker.ietf.org/doc/html/rfc4343#section-3
    domain_ascii_lowercase: String,
}

impl CacheKey {
    fn new(question: &Question) -> Self {
        Self {
            qtype: question.qtype,
            domain_ascii_lowercase: question.domain.to_ascii_lowercase(),
        }
    }
}

struct CacheEntry {
    expires_at: Instant,
    inserted_at: Instant,
    response: Response,
}

impl CacheEntry {
    fn new(response: Response) -> Self {
        let now = Instant::now();
        let min_ttl = Self::ttl(&response);
        let expires_at = now + min_ttl;
        Self {
            expires_at,
            inserted_at: now,
            response,
        }
    }

    fn is_expired(&self, now: Instant) -> bool {
        self.expires_at <= now
    }

    fn ttl(response: &Response) -> Duration {
        let all_records = response
            .answer
            .iter()
            .chain(response.authority.iter())
            .chain(response.additional.iter());

        let min_ttl = all_records
            .map(|r| r.ttl_duration())
            .min()
            .unwrap_or(Duration::ZERO);

        if min_ttl > UNREASONABLE_TTL {
            warn!("Received unreasonably long TTL: {:?}", min_ttl);
            Duration::ZERO
        } else if min_ttl > MAX_TTL {
            MAX_TTL
        } else {
            min_ttl
        }
    }
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

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use super::*;

    struct MockResolver {
        response: Response,
        query_count: Mutex<usize>,
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
                query_count: Mutex::new(0),
            }
        }
    }

    #[async_trait]
    impl Resolver for &MockResolver {
        async fn query(&self, _question: Question) -> Result<Response, ResolveError> {
            *self.query_count.lock() += 1;
            Ok(self.response.clone())
        }
    }

    #[tokio::test(start_paused = true)]
    async fn cache_behavioral_test() {
        let mock = MockResolver::new();
        let resolver = ResponseCache::new(&mock, 1);

        // Initial query will not be cached
        let response = resolver.lookup_ip4("example.com").await.unwrap();
        assert_eq!(*mock.query_count.lock(), 1);
        assert_eq!(response, mock.response);

        // Subsequent queries should be served from cache and not trigger a query on the inner resolver
        let response = resolver.lookup_ip4("example.com").await.unwrap();
        assert_eq!(*mock.query_count.lock(), 1);
        assert_eq!(response, mock.response);

        // After advancing time past the cache expiration, the next query should trigger a query on the inner resolver
        tokio::time::advance(Duration::from_secs(300)).await;
        let response = resolver.lookup_ip4("example.com").await.unwrap();
        assert_eq!(*mock.query_count.lock(), 2);
        assert_eq!(response, mock.response);
    }
}
