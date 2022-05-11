use crate::{protocol::*, resolver::*};
use async_trait::async_trait;
use parking_lot::Mutex;
use std::cmp::Ordering;
use std::collections::hash_map::Entry;
use std::collections::{BinaryHeap, HashMap};
use std::io;
use std::time::{Duration, Instant};
use tracing::{info, warn};

// Prevent excessively long TTLs, as suggested in RFC 1035 we limit to one week
// https://datatracker.ietf.org/doc/html/rfc1035#section-7.3
const MAX_TTL: Duration = Duration::from_secs(7 * 24 * 60 * 60);

// Mitigate unreasonably long TTLs that are likely due to bugs or bit flips. As allowed by the
// protocol we ignore such values and use a TTL of zero instead.
const UNREASONABLE_TTL: Duration = Duration::from_secs(1_000_000_000);

// TODO
const DEFAULT_NEGATIVE_TTL: Duration = Duration::from_secs(1 * 60);

/// Resolver that caches responses to queries and uses that cache when feasible
pub struct ResponseCache<R> {
    cache: Mutex<Cache>,
    inner: R,
    hide_ttl_on_response: bool,
}

impl<R> ResponseCache<R> {
    pub fn new(resolver: R, capacity: usize) -> Self {
        Self {
            cache: Mutex::new(Cache::new(capacity)),
            inner: resolver,
            hide_ttl_on_response: false,
        }
    }
}

#[async_trait]
impl<R: Resolver + Send + Sync> Resolver for ResponseCache<R> {
    async fn query(&self, question: Question) -> io::Result<Response> {
        let key = CacheKey::new(&question.clone());

        // Check for potential cache entries
        if let Some(response) = self.cache.lock().get(key.clone()) {
            info!("Cached response");
            return Ok(response);
        }

        // If no valid cache entry was found, delegate to the inner resolver
        let response = self.inner.query(question).await?;

        // Update the cache
        // TODO skip caching type ANY, AXFR
        // TODO check if (!dns_domain_suffix(t1,control)) { i = j; continue; }
        // TODO check if (!roots_same(t1,control)) { i = j; continue; }
        self.cache.lock().put(key, &response);

        return Ok(response);
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

    fn get(&mut self, key: CacheKey) -> Option<Response> {
        if let Entry::Occupied(o) = self.data.entry(key) {
            if o.get().is_expired() {
                o.remove();
                None
            } else {
                Some(o.get().prepare_response())
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
        let min_ttl = Self::min_ttl(&response);
        let expires_at = now + min_ttl;
        Self {
            expires_at,
            inserted_at: now,
            response,
        }
    }

    fn is_expired(&self) -> bool {
        let now = Instant::now();
        self.expires_at <= now
    }

    fn prepare_response(&self) -> Response {
        let mut response = self.response.clone();

        let age = Instant::now() - self.inserted_at;
        let age_sec = age.as_secs().try_into().unwrap();

        for a in &mut response.answers {
            // if hide_ttl_on_response {
            //     a.set_ttl(0);
            // } else {
            a.reduce_ttl(age_sec);
            // }
        }

        response
    }

    fn min_ttl(response: &Response) -> Duration {
        let all_records = response
            .answers
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
