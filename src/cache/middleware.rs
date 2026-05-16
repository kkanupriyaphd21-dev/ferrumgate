//! Cache middleware for HTTP request/response processing.
//!
//! Integrates response caching into the middleware chain,
//! handling cache lookups, conditional requests, and cache population.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use crate::cache::{
    CacheConfig, CacheStore, MemoryCacheStore, CacheEntry, CacheableResponse,
    CacheLookup, CacheError, generate_cache_key, record_cache_request,
    record_cache_store, CacheControl, CacheMetrics, get_cache_metrics,
    parse_cache_control, parse_request_cache_control, EtagGenerator,
    ConditionalRequest,
};

/// Cache middleware for HTTP responses.
pub struct CacheMiddleware {
    store: Arc<dyn CacheStore>,
    config: CacheConfig,
}

impl CacheMiddleware {
    pub fn new(config: CacheConfig) -> Self {
        Self {
            store: Arc::new(MemoryCacheStore::new(config.clone())),
            config,
        }
    }

    pub fn with_store(config: CacheConfig, store: Arc<dyn CacheStore>) -> Self {
        Self { store, config }
    }

    /// Look up a cached response for the request.
    pub fn lookup(
        &self,
        method: &str,
        uri: &str,
        headers: &HashMap<String, String>,
    ) -> CacheLookup {
        let cache_key = generate_cache_key(method, uri, headers, &self.config.vary_headers);

        if cache_key.starts_with("__uncacheable__") {
            record_cache_request("miss");
            return CacheLookup::Miss;
        }

        // Check request Cache-Control
        if let Some(cache_control) = headers.get("cache-control") {
            let req_cc = parse_request_cache_control(cache_control);
            if req_cc.no_store {
                record_cache_request("miss");
                return CacheLookup::Miss;
            }
            if req_cc.only_if_cached {
                // Return stale if nothing fresh available
            }
        }

        match self.store.get(&cache_key) {
            Ok(Some(entry)) => {
                // Check conditional request
                let cond = ConditionalRequest::from_headers(headers);
                let etag = entry.etag.as_deref();
                let last_modified = entry.last_modified.as_deref();

                if cond.is_not_modified(etag, last_modified) {
                    record_cache_request("not_modified");
                    return CacheLookup::NotModified;
                }

                if entry.is_fresh() {
                    record_cache_request("hit");
                    CacheLookup::Hit(entry)
                } else {
                    // Check stale-while-revalidate
                    let stale_ttl = self.config.stale_while_revalidate_ttl;
                    if self.config.enable_stale_while_revalidate
                        && entry.age() < entry.ttl + stale_ttl
                    {
                        record_cache_request("stale");
                        CacheLookup::StaleHit(entry)
                    } else {
                        record_cache_request("miss");
                        CacheLookup::Miss
                    }
                }
            }
            Ok(None) => {
                record_cache_request("miss");
                CacheLookup::Miss
            }
            Err(_) => {
                record_cache_request("miss");
                CacheLookup::Miss
            }
        }
    }

    /// Store a response in the cache.
    pub fn store(&self, response: CacheableResponse) -> Result<(), CacheError> {
        if !response.is_cacheable() {
            return Ok(());
        }

        // Parse response Cache-Control
        let cache_control = response.headers.get("cache-control")
            .map(|v| parse_cache_control(v))
            .unwrap_or_default();

        if !cache_control.is_cacheable() {
            return Ok(());
        }

        let ttl = cache_control.effective_ttl(self.config.default_ttl, self.config.max_ttl);

        let etag = response.headers.get("etag").cloned()
            .or_else(|| Some(EtagGenerator::generate_strong(&response.body)));

        let last_modified = response.headers.get("last-modified").cloned();

        let entry = CacheEntry {
            response,
            created_at: std::time::Instant::now(),
            ttl,
            access_count: 0,
            last_accessed: std::time::Instant::now(),
            etag,
            last_modified,
        };

        self.store.put(&entry.response.cache_key, entry)?;
        record_cache_store();
        Ok(())
    }

    /// Invalidate a cached entry.
    pub fn invalidate(&self, uri: &str) -> Result<(), CacheError> {
        // Invalidate all cache keys for this URI
        self.store.remove(&format!("GET:{}", uri))?;
        self.store.remove(&format!("HEAD:{}", uri))?;
        Ok(())
    }

    /// Purge all cached entries.
    pub fn purge(&self) -> Result<(), CacheError> {
        self.store.clear()
    }

    /// Get cache metrics.
    pub fn metrics(&self) -> CacheMetrics {
        get_cache_metrics()
    }

    /// Build response headers for cached response.
    pub fn cached_response_headers(&self, entry: &CacheEntry) -> HashMap<String, String> {
        let mut headers = entry.response.headers.clone();
        headers.insert("X-Cache".to_string(), "HIT".to_string());
        headers.insert("Age".to_string(), entry.age().as_secs().to_string());

        if let Some(etag) = &entry.etag {
            headers.insert("ETag".to_string(), etag.clone());
        }

        headers
    }

    /// Build response headers for stale response (revalidating).
    pub fn stale_response_headers(&self, entry: &CacheEntry) -> HashMap<String, String> {
        let mut headers = self.cached_response_headers(entry);
        headers.insert("X-Cache".to_string(), "STALE".to_string());
        headers.insert("Warning".to_string(), "110 - \"Response is stale\"".to_string());
        headers
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_response() -> CacheableResponse {
        let mut headers = HashMap::new();
        headers.insert("cache-control".to_string(), "public, max-age=60".to_string());
        CacheableResponse::new(200, headers, vec![1, 2, 3], "GET:/api/test".to_string())
    }

    #[test]
    fn test_cache_middleware_lookup_miss() {
        let config = CacheConfig::default();
        let middleware = CacheMiddleware::new(config);
        let result = middleware.lookup("GET", "/api/test", &HashMap::new());
        assert!(matches!(result, CacheLookup::Miss));
    }

    #[test]
    fn test_cache_middleware_store_and_lookup() {
        let config = CacheConfig::default();
        let middleware = CacheMiddleware::new(config);
        let response = create_test_response();
        middleware.store(response).unwrap();

        let result = middleware.lookup("GET", "/api/test", &HashMap::new());
        assert!(matches!(result, CacheLookup::Hit(_)));
    }

    #[test]
    fn test_cache_middleware_post_uncacheable() {
        let config = CacheConfig::default();
        let middleware = CacheMiddleware::new(config);
        let result = middleware.lookup("POST", "/api/test", &HashMap::new());
        assert!(matches!(result, CacheLookup::Miss));
    }

    #[test]
    fn test_cache_middleware_no_store_request() {
        let config = CacheConfig::default();
        let middleware = CacheMiddleware::new(config);
        let mut headers = HashMap::new();
        headers.insert("cache-control".to_string(), "no-store".to_string());
        let result = middleware.lookup("GET", "/api/test", &headers);
        assert!(matches!(result, CacheLookup::Miss));
    }

    #[test]
    fn test_cache_middleware_invalidate() {
        let config = CacheConfig::default();
        let middleware = CacheMiddleware::new(config);
        middleware.store(create_test_response()).unwrap();
        middleware.invalidate("/api/test").unwrap();
        let result = middleware.lookup("GET", "/api/test", &HashMap::new());
        assert!(matches!(result, CacheLookup::Miss));
    }

    #[test]
    fn test_cache_middleware_purge() {
        let config = CacheConfig::default();
        let middleware = CacheMiddleware::new(config);
        middleware.store(create_test_response()).unwrap();
        middleware.purge().unwrap();
        let result = middleware.lookup("GET", "/api/test", &HashMap::new());
        assert!(matches!(result, CacheLookup::Miss));
    }

    #[test]
    fn test_cached_response_headers() {
        let config = CacheConfig::default();
        let middleware = CacheMiddleware::new(config);
        middleware.store(create_test_response()).unwrap();

        if let CacheLookup::Hit(entry) = middleware.lookup("GET", "/api/test", &HashMap::new()) {
            let headers = middleware.cached_response_headers(&entry);
            assert_eq!(headers.get("X-Cache"), Some(&"HIT".to_string()));
            assert!(headers.contains_key("Age"));
        }
    }
}
