//! Cache-Control header parsing and cache policy enforcement.
//!
//! Parses HTTP Cache-Control directives and determines
//! cacheability, freshness, and revalidation requirements.

use std::collections::HashMap;
use std::time::Duration;

/// Parsed Cache-Control directives.
#[derive(Debug, Clone, Default)]
pub struct CacheControl {
    pub public: bool,
    pub private: bool,
    pub no_cache: bool,
    pub no_store: bool,
    pub no_transform: bool,
    pub must_revalidate: bool,
    pub proxy_revalidate: bool,
    pub max_age: Option<Duration>,
    pub s_maxage: Option<Duration>,
    pub stale_while_revalidate: Option<Duration>,
    pub stale_if_error: Option<Duration>,
    pub max_stale: Option<Duration>,
    pub min_fresh: Option<Duration>,
    pub immutable: bool,
    pub extensions: HashMap<String, String>,
}

impl CacheControl {
    pub fn is_cacheable(&self) -> bool {
        !self.no_store && !self.private
    }

    pub fn requires_revalidation(&self) -> bool {
        self.no_cache || self.must_revalidate
    }

    pub fn effective_ttl(&self, default: Duration, max: Duration) -> Duration {
        let ttl = self.max_age
            .or(self.s_maxage)
            .unwrap_or(default);
        ttl.min(max)
    }

    pub fn allows_stale_while_revalidate(&self) -> Option<Duration> {
        self.stale_while_revalidate
    }

    pub fn allows_stale_if_error(&self) -> Option<Duration> {
        self.stale_if_error
    }
}

/// Parse Cache-Control header value into directives.
pub fn parse_cache_control(header_value: &str) -> CacheControl {
    let mut cc = CacheControl::default();

    for directive in header_value.split(',') {
        let directive = directive.trim();
        if directive.is_empty() { continue; }

        let parts: Vec<&str> = directive.splitn(2, '=').collect();
        let name = parts[0].trim().to_lowercase();

        match name.as_str() {
            "public" => cc.public = true,
            "private" => cc.private = true,
            "no-cache" => cc.no_cache = true,
            "no-store" => cc.no_store = true,
            "no-transform" => cc.no_transform = true,
            "must-revalidate" => cc.must_revalidate = true,
            "proxy-revalidate" => cc.proxy_revalidate = true,
            "immutable" => cc.immutable = true,
            "max-age" => {
                if let Some(val) = parts.get(1) {
                    if let Ok(secs) = val.trim().parse::<u64>() {
                        cc.max_age = Some(Duration::from_secs(secs));
                    }
                }
            }
            "s-maxage" => {
                if let Some(val) = parts.get(1) {
                    if let Ok(secs) = val.trim().parse::<u64>() {
                        cc.s_maxage = Some(Duration::from_secs(secs));
                    }
                }
            }
            "stale-while-revalidate" => {
                if let Some(val) = parts.get(1) {
                    if let Ok(secs) = val.trim().parse::<u64>() {
                        cc.stale_while_revalidate = Some(Duration::from_secs(secs));
                    }
                }
            }
            "stale-if-error" => {
                if let Some(val) = parts.get(1) {
                    if let Ok(secs) = val.trim().parse::<u64>() {
                        cc.stale_if_error = Some(Duration::from_secs(secs));
                    }
                }
            }
            "max-stale" => {
                if let Some(val) = parts.get(1) {
                    if let Ok(secs) = val.trim().parse::<u64>() {
                        cc.max_stale = Some(Duration::from_secs(secs));
                    }
                }
            }
            "min-fresh" => {
                if let Some(val) = parts.get(1) {
                    if let Ok(secs) = val.trim().parse::<u64>() {
                        cc.min_fresh = Some(Duration::from_secs(secs));
                    }
                }
            }
            _ => {
                if parts.len() == 2 {
                    cc.extensions.insert(name, parts[1].trim().to_string());
                } else {
                    cc.extensions.insert(name, String::new());
                }
            }
        }
    }

    cc
}

/// Request cache directives (from request headers).
#[derive(Debug, Clone, Default)]
pub struct RequestCacheControl {
    pub no_cache: bool,
    pub no_store: bool,
    pub max_age: Option<Duration>,
    pub max_stale: Option<Duration>,
    pub min_fresh: Option<Duration>,
    pub only_if_cached: bool,
}

pub fn parse_request_cache_control(header_value: &str) -> RequestCacheControl {
    let mut cc = RequestCacheControl::default();

    for directive in header_value.split(',') {
        let directive = directive.trim();
        if directive.is_empty() { continue; }

        let parts: Vec<&str> = directive.splitn(2, '=').collect();
        let name = parts[0].trim().to_lowercase();

        match name.as_str() {
            "no-cache" => cc.no_cache = true,
            "no-store" => cc.no_store = true,
            "only-if-cached" => cc.only_if_cached = true,
            "max-age" => {
                if let Some(val) = parts.get(1) {
                    if let Ok(secs) = val.trim().parse::<u64>() {
                        cc.max_age = Some(Duration::from_secs(secs));
                    }
                }
            }
            "max-stale" => {
                if let Some(val) = parts.get(1) {
                    if let Ok(secs) = val.trim().parse::<u64>() {
                        cc.max_stale = Some(Duration::from_secs(secs));
                    }
                }
            }
            "min-fresh" => {
                if let Some(val) = parts.get(1) {
                    if let Ok(secs) = val.trim().parse::<u64>() {
                        cc.min_fresh = Some(Duration::from_secs(secs));
                    }
                }
            }
            _ => {}
        }
    }

    cc
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_cache_control_max_age() {
        let cc = parse_cache_control("public, max-age=3600");
        assert!(cc.public);
        assert_eq!(cc.max_age, Some(Duration::from_secs(3600)));
    }

    #[test]
    fn test_parse_cache_control_no_store() {
        let cc = parse_cache_control("no-store, private");
        assert!(cc.no_store);
        assert!(cc.private);
        assert!(!cc.is_cacheable());
    }

    #[test]
    fn test_parse_cache_control_stale_directives() {
        let cc = parse_cache_control("max-age=60, stale-while-revalidate=30, stale-if-error=120");
        assert_eq!(cc.max_age, Some(Duration::from_secs(60)));
        assert_eq!(cc.stale_while_revalidate, Some(Duration::from_secs(30)));
        assert_eq!(cc.stale_if_error, Some(Duration::from_secs(120)));
    }

    #[test]
    fn test_parse_cache_control_immutable() {
        let cc = parse_cache_control("public, max-age=31536000, immutable");
        assert!(cc.immutable);
        assert!(cc.public);
    }

    #[test]
    fn test_effective_ttl() {
        let cc = parse_cache_control("max-age=300");
        let ttl = cc.effective_ttl(Duration::from_secs(60), Duration::from_secs(3600));
        assert_eq!(ttl, Duration::from_secs(300));
    }

    #[test]
    fn test_effective_ttl_capped() {
        let cc = parse_cache_control("max-age=7200");
        let ttl = cc.effective_ttl(Duration::from_secs(60), Duration::from_secs(3600));
        assert_eq!(ttl, Duration::from_secs(3600));
    }

    #[test]
    fn test_parse_request_cache_control() {
        let cc = parse_request_cache_control("no-cache, max-age=0");
        assert!(cc.no_cache);
        assert_eq!(cc.max_age, Some(Duration::from_secs(0)));
    }

    #[test]
    fn test_parse_request_cache_control_only_if_cached() {
        let cc = parse_request_cache_control("only-if-cached");
        assert!(cc.only_if_cached);
    }

    #[test]
    fn test_requires_revalidation() {
        let cc = parse_cache_control("no-cache");
        assert!(cc.requires_revalidation());

        let cc = parse_cache_control("must-revalidate");
        assert!(cc.requires_revalidation());
    }
}
