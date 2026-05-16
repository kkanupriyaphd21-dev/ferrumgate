//! Sliding window log rate limiter.
//!
//! Maintains a log of all request timestamps and counts requests within
//! the sliding window. Provides precise rate limiting at the cost of
//! higher memory usage.

use std::collections::HashMap;
use std::sync::RwLock;

use crate::rate_limiter::{
    RateLimiter, RateLimitConfig, RateLimitResult, RateLimiterMetrics,
    record_rl_check, now_secs,
};

struct WindowLog {
    timestamps: Vec<u64>,
    limit: RateLimitConfig,
    total_requests: u64,
    allowed_requests: u64,
    denied_requests: u64,
}

impl WindowLog {
    fn new(config: &RateLimitConfig) -> Self {
        Self {
            timestamps: Vec::new(),
            limit: config.clone(),
            total_requests: 0,
            allowed_requests: 0,
            denied_requests: 0,
        }
    }

    fn check(&mut self) -> RateLimitResult {
        let now = now_secs();
        let window_start = now.saturating_sub(self.limit.window_secs);

        // Remove expired timestamps
        self.timestamps.retain(|&t| t > window_start);

        self.total_requests += 1;
        let remaining = self.limit.max_requests.saturating_sub(self.timestamps.len() as u64);

        if self.timestamps.len() < self.limit.max_requests as usize {
            self.timestamps.push(now);
            self.allowed_requests += 1;
            RateLimitResult::allowed(
                self.limit.max_requests,
                remaining.saturating_sub(1),
                now + self.limit.window_secs,
            )
        } else {
            self.denied_requests += 1;
            let oldest = self.timestamps.iter().min().copied().unwrap_or(now);
            let retry_after = oldest.saturating_add(self.limit.window_secs).saturating_sub(now).max(1);
            RateLimitResult::denied(
                self.limit.max_requests,
                0,
                now + self.limit.window_secs,
                retry_after,
            )
        }
    }
}

pub struct SlidingWindowLogLimiter {
    windows: RwLock<HashMap<String, WindowLog>>,
    default_config: RwLock<RateLimitConfig>,
}

impl SlidingWindowLogLimiter {
    pub fn new(default_config: RateLimitConfig) -> Self {
        Self {
            windows: RwLock::new(HashMap::new()),
            default_config: RwLock::new(default_config),
        }
    }
}

impl RateLimiter for SlidingWindowLogLimiter {
    fn name(&self) -> &str { "sliding_window_log" }

    fn check(&self, key: &str) -> RateLimitResult {
        let config = {
            let windows = self.windows.read().unwrap();
            windows.get(key).map(|w| w.limit.clone())
        }.unwrap_or_else(|| self.default_config.read().unwrap().clone());

        let mut windows = self.windows.write().unwrap();
        let window = windows.entry(key.to_string())
            .or_insert_with(|| WindowLog::new(&config));

        let result = window.check();
        record_rl_check(result.allowed);
        result
    }

    fn get_limit(&self, key: &str) -> Option<RateLimitConfig> {
        self.windows.read().unwrap().get(key).map(|w| w.limit.clone())
    }

    fn set_limit(&self, key: &str, config: RateLimitConfig) {
        let mut windows = self.windows.write().unwrap();
        windows.insert(key.to_string(), WindowLog::new(&config));
    }

    fn remove_limit(&self, key: &str) {
        self.windows.write().unwrap().remove(key);
    }

    fn reset(&self, key: &str) {
        let mut windows = self.windows.write().unwrap();
        if let Some(window) = windows.get_mut(key) {
            let config = window.limit.clone();
            *window = WindowLog::new(&config);
        }
    }

    fn keys(&self) -> Vec<String> {
        self.windows.read().unwrap().keys().cloned().collect()
    }

    fn metrics(&self) -> RateLimiterMetrics {
        let windows = self.windows.read().unwrap();
        let mut total = 0u64;
        let mut allowed = 0u64;
        let mut denied = 0u64;

        for w in windows.values() {
            total += w.total_requests;
            allowed += w.allowed_requests;
            denied += w.denied_requests;
        }

        RateLimiterMetrics {
            algorithm: "sliding_window_log".to_string(),
            total_keys: windows.len(),
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
    fn test_sliding_window_log_allows_within_limit() {
        let config = RateLimitConfig::new(5, 60);
        let limiter = SlidingWindowLogLimiter::new(config);

        for i in 0..5 {
            let result = limiter.check("user-1");
            assert!(result.allowed, "Request {} should be allowed", i);
        }

        let result = limiter.check("user-1");
        assert!(!result.allowed);
    }

    #[test]
    fn test_sliding_window_log_different_keys() {
        let config = RateLimitConfig::new(2, 60);
        let limiter = SlidingWindowLogLimiter::new(config);

        assert!(limiter.check("user-1").allowed);
        assert!(limiter.check("user-1").allowed);
        assert!(!limiter.check("user-1").allowed);

        assert!(limiter.check("user-2").allowed);
    }

    #[test]
    fn test_sliding_window_log_metrics() {
        let config = RateLimitConfig::new(2, 60);
        let limiter = SlidingWindowLogLimiter::new(config);

        limiter.check("user-1");
        limiter.check("user-1");
        limiter.check("user-1");

        let metrics = limiter.metrics();
        assert_eq!(metrics.total_requests, 3);
        assert_eq!(metrics.allowed_requests, 2);
        assert_eq!(metrics.denied_requests, 1);
    }

    #[test]
    fn test_sliding_window_log_reset() {
        let config = RateLimitConfig::new(2, 60);
        let limiter = SlidingWindowLogLimiter::new(config);

        limiter.check("user-1");
        limiter.check("user-1");
        assert!(!limiter.check("user-1").allowed);

        limiter.reset("user-1");
        assert!(limiter.check("user-1").allowed);
    }
}
