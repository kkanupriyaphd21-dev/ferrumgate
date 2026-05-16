//! Sliding window counter rate limiter.
//!
//! Uses a weighted combination of the current and previous window counts
//! to approximate the sliding window. More memory-efficient than the log
//! approach while providing reasonable accuracy.

use std::collections::HashMap;
use std::sync::RwLock;

use crate::rate_limiter::{
    RateLimiter, RateLimitConfig, RateLimitResult, RateLimiterMetrics,
    record_rl_check, now_secs,
};

struct WindowCounter {
    current_window_start: u64,
    current_count: u64,
    previous_count: u64,
    limit: RateLimitConfig,
    total_requests: u64,
    allowed_requests: u64,
    denied_requests: u64,
}

impl WindowCounter {
    fn new(config: &RateLimitConfig) -> Self {
        Self {
            current_window_start: now_secs(),
            current_count: 0,
            previous_count: 0,
            limit: config.clone(),
            total_requests: 0,
            allowed_requests: 0,
            denied_requests: 0,
        }
    }

    fn advance_window(&mut self, now: u64) {
        let elapsed_windows = (now - self.current_window_start) / self.limit.window_secs;
        if elapsed_windows >= 2 {
            self.previous_count = 0;
            self.current_count = 0;
        } else if elapsed_windows == 1 {
            self.previous_count = self.current_count;
            self.current_count = 0;
        }
        self.current_window_start = now;
    }

    fn weighted_count(&self, now: u64) -> f64 {
        let window_progress = if self.limit.window_secs > 0 {
            ((now - self.current_window_start) as f64 / self.limit.window_secs as f64).min(1.0)
        } else {
            1.0
        };

        self.previous_count as f64 * (1.0 - window_progress) + self.current_count as f64
    }

    fn check(&mut self) -> RateLimitResult {
        let now = now_secs();
        self.advance_window(now);

        self.total_requests += 1;
        let weighted = self.weighted_count(now);

        if weighted < self.limit.max_requests as f64 {
            self.current_count += 1;
            self.allowed_requests += 1;
            let remaining = (self.limit.max_requests as f64 - weighted - 1.0).max(0.0) as u64;
            RateLimitResult::allowed(
                self.limit.max_requests,
                remaining,
                now + self.limit.window_secs,
            )
        } else {
            self.denied_requests += 1;
            RateLimitResult::denied(
                self.limit.max_requests,
                0,
                now + self.limit.window_secs,
                self.limit.window_secs,
            )
        }
    }
}

pub struct SlidingWindowCounterLimiter {
    counters: RwLock<HashMap<String, WindowCounter>>,
    default_config: RwLock<RateLimitConfig>,
}

impl SlidingWindowCounterLimiter {
    pub fn new(default_config: RateLimitConfig) -> Self {
        Self {
            counters: RwLock::new(HashMap::new()),
            default_config: RwLock::new(default_config),
        }
    }
}

impl RateLimiter for SlidingWindowCounterLimiter {
    fn name(&self) -> &str { "sliding_window_counter" }

    fn check(&self, key: &str) -> RateLimitResult {
        let config = {
            let counters = self.counters.read().unwrap();
            counters.get(key).map(|c| c.limit.clone())
        }.unwrap_or_else(|| self.default_config.read().unwrap().clone());

        let mut counters = self.counters.write().unwrap();
        let counter = counters.entry(key.to_string())
            .or_insert_with(|| WindowCounter::new(&config));

        let result = counter.check();
        record_rl_check(result.allowed);
        result
    }

    fn get_limit(&self, key: &str) -> Option<RateLimitConfig> {
        self.counters.read().unwrap().get(key).map(|c| c.limit.clone())
    }

    fn set_limit(&self, key: &str, config: RateLimitConfig) {
        let mut counters = self.counters.write().unwrap();
        counters.insert(key.to_string(), WindowCounter::new(&config));
    }

    fn remove_limit(&self, key: &str) {
        self.counters.write().unwrap().remove(key);
    }

    fn reset(&self, key: &str) {
        let mut counters = self.counters.write().unwrap();
        if let Some(counter) = counters.get_mut(key) {
            let config = counter.limit.clone();
            *counter = WindowCounter::new(&config);
        }
    }

    fn keys(&self) -> Vec<String> {
        self.counters.read().unwrap().keys().cloned().collect()
    }

    fn metrics(&self) -> RateLimiterMetrics {
        let counters = self.counters.read().unwrap();
        let mut total = 0u64;
        let mut allowed = 0u64;
        let mut denied = 0u64;

        for c in counters.values() {
            total += c.total_requests;
            allowed += c.allowed_requests;
            denied += c.denied_requests;
        }

        RateLimiterMetrics {
            algorithm: "sliding_window_counter".to_string(),
            total_keys: counters.len(),
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
    fn test_sliding_window_counter_allows_within_limit() {
        let config = RateLimitConfig::new(5, 60);
        let limiter = SlidingWindowCounterLimiter::new(config);

        for i in 0..5 {
            let result = limiter.check("user-1");
            assert!(result.allowed, "Request {} should be allowed", i);
        }
    }

    #[test]
    fn test_sliding_window_counter_different_keys() {
        let config = RateLimitConfig::new(2, 60);
        let limiter = SlidingWindowCounterLimiter::new(config);

        assert!(limiter.check("user-1").allowed);
        assert!(limiter.check("user-2").allowed);
    }

    #[test]
    fn test_sliding_window_counter_metrics() {
        let config = RateLimitConfig::new(2, 60);
        let limiter = SlidingWindowCounterLimiter::new(config);

        limiter.check("user-1");
        limiter.check("user-1");
        limiter.check("user-1");

        let metrics = limiter.metrics();
        assert_eq!(metrics.total_requests, 3);
        assert_eq!(metrics.algorithm, "sliding_window_counter");
    }

    #[test]
    fn test_sliding_window_counter_reset() {
        let config = RateLimitConfig::new(2, 60);
        let limiter = SlidingWindowCounterLimiter::new(config);

        limiter.check("user-1");
        limiter.check("user-1");
        limiter.reset("user-1");
        assert!(limiter.check("user-1").allowed);
    }

    #[test]
    fn test_weighted_count_initial() {
        let config = RateLimitConfig::new(100, 60);
        let mut counter = WindowCounter::new(&config);
        let now = now_secs();

        // At window start, weighted count should be 0
        let weighted = counter.weighted_count(now);
        assert_eq!(weighted, 0.0);
    }
}
