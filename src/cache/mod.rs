//! Response caching with cache control and ETag support.
//!
//! Implements HTTP response caching with:
//! - Cache-Control header parsing and enforcement
//! - ETag generation and conditional requests (If-None-Match)
//! - Last-Modified and If-Modified-Since support
//! - Configurable cache backends (in-memory, LRU)
//! - Cache invalidation strategies
//! - Stale-while-revalidate and stale-if-error support

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

pub mod store;
pub mod policy;
pub mod etag;
pub mod middleware;

pub use store::{CacheStore, MemoryCacheStore, LruCacheStore, CacheEntry};
pub use policy::{CachePolicy, CacheControl, parse_cache_control};
pub use etag::EtagGenerator;
pub use middleware::CacheMiddleware;

/// Cache error types.
#[derive(Debug, thiserror::Error)]
pub enum CacheError {
    #[error("cache miss for key: {0}")]
    Miss(String),

    #[error("cache entry expired")]
    Expired,

    #[error("cache backend unavailable")]
    BackendUnavailable,

    #[error("cache key too long: {length} > {max}")]
    KeyTooLong { length: usize, max: usize },

    #[error("cache value too large: {size} > {max}")]
    ValueTooLarge { size: usize, max: usize },

    #[error("cache error: {0}")]
    Internal(String),
}

/// Cache lookup result.
#[derive(Debug)]
pub enum CacheLookup {
    /// Fresh cache hit.
    Hit(CacheEntry),
    /// Stale cache hit (can serve while revalidating).
    StaleHit(CacheEntry),
    /// Cache miss - need to fetch from origin.
    Miss,
    /// Conditional hit - client has matching ETag.
    NotModified,
}

/// HTTP cacheable response.
#[derive(Debug, Clone)]
pub struct CacheableResponse {
    pub status_code: u16,
    pub headers: HashMap<String, String>,
    pub body: Vec<u8>,
    pub created_at: SystemTime,
    pub cache_key: String,
}

impl CacheableResponse {
    pub fn new(status_code: u16, headers: HashMap<String, String>, body: Vec<u8>, cache_key: String) -> Self {
        Self {
            status_code,
            headers,
            body,
            created_at: SystemTime::now(),
            cache_key,
        }
    }

    pub fn is_cacheable(&self) -> bool {
        if self.status_code != 200 && self.status_code != 301 && self.status_code != 404 {
            return false;
        }
        if let Some(cache_control) = self.headers.get("cache-control") {
            if cache_control.contains("no-store") || cache_control.contains("private") {
                return false;
            }
        }
        true
    }

    pub fn content_length(&self) -> usize {
        self.body.len()
    }
}

/// Cache configuration.
#[derive(Debug, Clone)]
pub struct CacheConfig {
    pub max_entries: usize,
    pub max_entry_size: usize,
    pub default_ttl: Duration,
    pub max_ttl: Duration,
    pub enable_stale_while_revalidate: bool,
    pub stale_while_revalidate_ttl: Duration,
    pub enable_stale_if_error: bool,
    pub stale_if_error_ttl: Duration,
    pub vary_headers: Vec<String>,
}

impl Default for CacheConfig {
    fn default() -> Self {
        Self {
            max_entries: 10_000,
            max_entry_size: 1024 * 1024, // 1MB
            default_ttl: Duration::from_secs(300), // 5 minutes
            max_ttl: Duration::from_secs(86400),   // 24 hours
            enable_stale_while_revalidate: true,
            stale_while_revalidate_ttl: Duration::from_secs(60),
            enable_stale_if_error: true,
            stale_if_error_ttl: Duration::from_secs(300),
            vary_headers: vec!["Accept".to_string(), "Accept-Encoding".to_string()],
        }
    }
}

/// Global cache metrics.
static CACHE_TOTAL_REQUESTS: AtomicU64 = AtomicU64::new(0);
static CACHE_HITS: AtomicU64 = AtomicU64::new(0);
static CACHE_MISSES: AtomicU64 = AtomicU64::new(0);
static CACHE_STALE_HITS: AtomicU64 = AtomicU64::new(0);
static CACHE_NOT_MODIFIED: AtomicU64 = AtomicU64::new(0);
static CACHE_STORES: AtomicU64 = AtomicU64::new(0);
static CACHE_EVICTIONS: AtomicU64 = AtomicU64::new(0);

pub fn record_cache_request(result: &str) {
    CACHE_TOTAL_REQUESTS.fetch_add(1, Ordering::Relaxed);
    match result {
        "hit" => CACHE_HITS.fetch_add(1, Ordering::Relaxed),
        "miss" => CACHE_MISSES.fetch_add(1, Ordering::Relaxed),
        "stale" => CACHE_STALE_HITS.fetch_add(1, Ordering::Relaxed),
        "not_modified" => CACHE_NOT_MODIFIED.fetch_add(1, Ordering::Relaxed),
        _ => {}
    }
}

pub fn record_cache_store() {
    CACHE_STORES.fetch_add(1, Ordering::Relaxed);
}

pub fn record_cache_eviction() {
    CACHE_EVICTIONS.fetch_add(1, Ordering::Relaxed);
}

#[derive(Debug)]
pub struct CacheMetrics {
    pub total_requests: u64,
    pub hits: u64,
    pub misses: u64,
    pub stale_hits: u64,
    pub not_modified: u64,
    pub stores: u64,
    pub evictions: u64,
    pub hit_rate: f64,
}

pub fn get_cache_metrics() -> CacheMetrics {
    let total = CACHE_TOTAL_REQUESTS.load(Ordering::Relaxed);
    let hits = CACHE_HITS.load(Ordering::Relaxed);
    CacheMetrics {
        total_requests: total,
        hits,
        misses: CACHE_MISSES.load(Ordering::Relaxed),
        stale_hits: CACHE_STALE_HITS.load(Ordering::Relaxed),
        not_modified: CACHE_NOT_MODIFIED.load(Ordering::Relaxed),
        stores: CACHE_STORES.load(Ordering::Relaxed),
        evictions: CACHE_EVICTIONS.load(Ordering::Relaxed),
        hit_rate: if total == 0 { 0.0 } else { hits as f64 / total as f64 },
    }
}

/// Generate cache key from request.
pub fn generate_cache_key(method: &str, uri: &str, headers: &HashMap<String, String>, vary_headers: &[String]) -> String {
    if method != "GET" && method != "HEAD" {
        return format!("__uncacheable__{}__{}", method, uri);
    }

    let mut key = format!("{}:{}", method, uri);
    for header in vary_headers {
        if let Some(value) = headers.get(header) {
            key.push_str(&format!(":{}={}", header, value));
        }
    }
    key
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cacheable_response_is_cacheable() {
        let mut headers = HashMap::new();
        headers.insert("cache-control".to_string(), "public, max-age=300".to_string());
        let response = CacheableResponse::new(200, headers, vec![1, 2, 3], "key".to_string());
        assert!(response.is_cacheable());
    }

    #[test]
    fn test_cacheable_response_no_store() {
        let mut headers = HashMap::new();
        headers.insert("cache-control".to_string(), "no-store".to_string());
        let response = CacheableResponse::new(200, headers, vec![1, 2, 3], "key".to_string());
        assert!(!response.is_cacheable());
    }

    #[test]
    fn test_cacheable_response_private() {
        let mut headers = HashMap::new();
        headers.insert("cache-control".to_string(), "private".to_string());
        let response = CacheableResponse::new(200, headers, vec![1, 2, 3], "key".to_string());
        assert!(!response.is_cacheable());
    }

    #[test]
    fn test_cacheable_response_non_cacheable_status() {
        let headers = HashMap::new();
        let response = CacheableResponse::new(500, headers, vec![1, 2, 3], "key".to_string());
        assert!(!response.is_cacheable());
    }

    #[test]
    fn test_generate_cache_key_get() {
        let mut headers = HashMap::new();
        headers.insert("Accept".to_string(), "application/json".to_string());
        let key = generate_cache_key("GET", "/api/test", &headers, &["Accept".to_string()]);
        assert!(key.contains("GET:/api/test"));
        assert!(key.contains("Accept=application/json"));
    }

    #[test]
    fn test_generate_cache_key_post_uncacheable() {
        let key = generate_cache_key("POST", "/api/test", &HashMap::new(), &[]);
        assert!(key.contains("__uncacheable__"));
    }

    #[test]
    fn test_cache_metrics_initial() {
        let metrics = get_cache_metrics();
        assert_eq!(metrics.total_requests, 0);
        assert_eq!(metrics.hit_rate, 0.0);
    }

    #[test]
    fn test_default_cache_config() {
        let config = CacheConfig::default();
        assert_eq!(config.max_entries, 10_000);
        assert_eq!(config.default_ttl, Duration::from_secs(300));
        assert!(config.enable_stale_while_revalidate);
    }
}
