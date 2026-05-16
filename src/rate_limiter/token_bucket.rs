//! Token bucket rate limiter.
//!
//! Implements the token bucket algorithm where tokens are added at a fixed
//! rate and each request consumes one token. Allows bursts up to the bucket
//! capacity while maintaining a smooth average rate.

use std::collections::HashMap;
use std::sync::RwLock;
use std::time::{Duration, Instant};

use crate::rate_limiter::{
    RateLimiter, RateLimitConfig, RateLimitResult, RateLimiterMetrics,
    RateLimiterError, record_rl_check, now_secs,
};

struct Bucket {
    tokens: f64,
    max_tokens: f64,
    refill_rate: f64,
    last_refill: Instant,
    limit: RateLimitConfig,
    total_requests: u64,
    allowed_requests: u64,
    denied_requests: u64,
}

impl Bucket {
    fn new(config: &RateLimitConfig) -> Self {
        let max_tokens = config.burst_size as f64;
        let refill_rate = config.max_requests as f64 / config.window_secs as f64;
        Self {
            tokens: max_tokens,
            max_tokens,
            refill_rate,
            last_refill: Instant::now(),
            limit: config.clone(),
            total_requests: 0,
            allowed_requests: 0,
            denied_requests: 0,
        }
    }

    fn refill(&mut self) {
        let now = Instant::now();
        let elapsed = now.duration_since(self.last_refill).as_secs_f64();
        self.tokens = (self.tokens + elapsed * self.refill_rate).min(self.max_tokens);
        self.last_refill = now;
    }

    fn consume(&mut self) -> RateLimitResult {
        self.refill();
        self.total_requests += 1;

        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            self.allowed_requests += 1;
            RateLimitResult::allowed(
                self.limit.max_requests,
                self.tokens.floor() as u64,
                now_secs() + self.limit.window_secs,
            )
        } else {
            self.denied_requests += 1;
            let wait_secs = ((1.0 - self.tokens) / self.refill_rate).ceil() as u64;
            RateLimitResult::denied(
                self.limit.max_requests,
                0,
                now_secs() + self.limit.window_secs,
                wait_secs.max(1),
            )
        }
    }
}

pub struct TokenBucketLimiter {
    buckets: RwLock<HashMap<String, Bucket>>,
    default_config: RwLock<RateLimitConfig>,
}

impl TokenBucketLimiter {
    pub fn new(default_config: RateLimitConfig) -> Self {
        Self {
            buckets: RwLock::new(HashMap::new()),
            default_config: RwLock::new(default_config),
        }
    }
}

impl RateLimiter for TokenBucketLimiter {
    fn name(&self) -> &str { "token_bucket" }

    fn check(&self, key: &str) -> RateLimitResult {
        let config = {
            let buckets = self.buckets.read().unwrap();
            buckets.get(key).map(|b| b.limit.clone())
        };

        let config = config.unwrap_or_else(|| {
            let default = self.default_config.read().unwrap().clone();
            let mut buckets = self.buckets.write().unwrap();
            buckets.entry(key.to_string())
                .or_insert_with(|| Bucket::new(&default));
            default
        });

        let mut buckets = self.buckets.write().unwrap();
        let bucket = buckets.entry(key.to_string())
            .or_insert_with(|| Bucket::new(&config));

        let result = bucket.consume();
        record_rl_check(result.allowed);
        result
    }

    fn get_limit(&self, key: &str) -> Option<RateLimitConfig> {
        self.buckets.read().unwrap().get(key).map(|b| b.limit.clone())
    }

    fn set_limit(&self, key: &str, config: RateLimitConfig) {
        let mut buckets = self.buckets.write().unwrap();
        buckets.insert(key.to_string(), Bucket::new(&config));
    }

    fn remove_limit(&self, key: &str) {
        self.buckets.write().unwrap().remove(key);
    }

    fn reset(&self, key: &str) {
        let mut buckets = self.buckets.write().unwrap();
        if let Some(bucket) = buckets.get_mut(key) {
            let config = bucket.limit.clone();
            *bucket = Bucket::new(&config);
        }
    }

    fn keys(&self) -> Vec<String> {
        self.buckets.read().unwrap().keys().cloned().collect()
    }

    fn metrics(&self) -> RateLimiterMetrics {
        let buckets = self.buckets.read().unwrap();
        let mut total = 0u64;
        let mut allowed = 0u64;
        let mut denied = 0u64;

        for b in buckets.values() {
            total += b.total_requests;
            allowed += b.allowed_requests;
            denied += b.denied_requests;
        }

        RateLimiterMetrics {
            algorithm: "token_bucket".to_string(),
            total_keys: buckets.len(),
            total_requests: total,
            allowed_requests: allowed,
            denied_requests: denied,
            denial_rate: if total == 0 { 0.0 } else { (denied as f64 / total as f64) * 100.0 },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_token_bucket_allows_burst() {
        let config = RateLimitConfig::new(10, 1).with_burst(10);
        let limiter = TokenBucketLimiter::new(config);

        // Should allow burst up to bucket capacity
        for i in 0..10 {
            let result = limiter.check("user-1");
            assert!(result.allowed, "Request {} should be allowed", i);
        }

        // 11th should be denied
        let result = limiter.check("user-1");
        assert!(!result.allowed);
    }

    #[test]
    fn test_token_bucket_different_keys() {
        let config = RateLimitConfig::new(5, 60);
        let limiter = TokenBucketLimiter::new(config);

        assert!(limiter.check("user-1").allowed);
        assert!(limiter.check("user-2").allowed);
        assert!(limiter.check("user-3").allowed);
    }

    #[test]
    fn test_token_bucket_metrics() {
        let config = RateLimitConfig::new(2, 60).with_burst(2);
        let limiter = TokenBucketLimiter::new(config);

        limiter.check("user-1");
        limiter.check("user-1");
        limiter.check("user-1"); // denied

        let metrics = limiter.metrics();
        assert_eq!(metrics.total_requests, 3);
        assert_eq!(metrics.allowed_requests, 2);
        assert_eq!(metrics.denied_requests, 1);
    }

    #[test]
    fn test_token_bucket_remove() {
        let config = RateLimitConfig::new(10, 60);
        let limiter = TokenBucketLimiter::new(config);

        limiter.check("user-1");
        assert_eq!(limiter.keys().len(), 1);

        limiter.remove_limit("user-1");
        assert_eq!(limiter.keys().len(), 0);
    }

    #[test]
    fn test_token_bucket_reset() {
        let config = RateLimitConfig::new(2, 60).with_burst(2);
        let limiter = TokenBucketLimiter::new(config);

        limiter.check("user-1");
        limiter.check("user-1");
        assert!(!limiter.check("user-1").allowed);

        limiter.reset("user-1");
        assert!(limiter.check("user-1").allowed);
    }
}
