//! Rate limiting algorithms for traffic control.
//!
//! This module provides pluggable rate limiting algorithms for protecting
//! backend services from overload and abuse. Three algorithms are supported:
//!
//! - **Token Bucket**: Burst-tolerant rate limiting with smooth replenishment
//! - **Sliding Window Log**: Precise rate limiting with exact request counting
//! - **Sliding Window Counter**: Memory-efficient approximate rate limiting
//!
//! # Architecture
//!
//! All algorithms implement the \`RateLimiter\` trait, which provides a
//! unified interface for checking whether a request should be allowed.
//!
//! # Rate Limit Headers
//!
//! When a request is rate limited, the following headers are included:
//! - \`X-RateLimit-Limit\`: Maximum requests allowed
//! - \`X-RateLimit-Remaining\`: Remaining requests in current window
//! - \`X-RateLimit-Reset\`: Time when the rate limit resets (Unix timestamp)
//! - \`Retry-After\`: Seconds to wait before retrying (for limited requests)
//!
//! # Thread Safety
//!
//! All implementations are \`Send + Sync\` and safe to use across
//! multiple threads.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use thiserror::Error;
use tracing::{info, warn, debug};

pub mod token_bucket;
pub mod sliding_window_log;
pub mod sliding_window_counter;

pub use token_bucket::TokenBucketLimiter;
pub use sliding_window_log::SlidingWindowLogLimiter;
pub use sliding_window_counter::SlidingWindowCounterLimiter;

/// Rate limiter error types.
#[derive(Debug, Error)]
pub enum RateLimiterError {
    #[error("rate limit exceeded for key: {0}")]
    RateLimitExceeded(String),

    #[error("invalid rate configuration: {0}")]
    InvalidRate(String),

    #[error("rate limiter not found for key: {0}")]
    NotFound(String),

    #[error("rate limiter error: {0}")]
    Internal(String),
}

/// Result of a rate limit check.
#[derive(Debug, Clone)]
pub struct RateLimitResult {
    /// Whether the request is allowed.
    pub allowed: bool,

    /// Maximum requests allowed in the window.
    pub limit: u64,

    /// Remaining requests in the current window.
    pub remaining: u64,

    /// Time when the rate limit resets (Unix timestamp seconds).
    pub reset_at: u64,

    /// Time to wait before retrying (seconds), if limited.
    pub retry_after: Option<u64>,
}

impl RateLimitResult {
    /// Create an allowed result.
    pub fn allowed(limit: u64, remaining: u64, reset_at: u64) -> Self {
        Self {
            allowed: true,
            limit,
            remaining,
            reset_at,
            retry_after: None,
        }
    }

    /// Create a denied result.
    pub fn denied(limit: u64, remaining: u64, reset_at: u64, retry_after: u64) -> Self {
        Self {
            allowed: false,
            limit,
            remaining,
            reset_at,
            retry_after: Some(retry_after),
        }
    }
}

/// Rate limiting algorithm selection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RateLimitAlgorithm {
    TokenBucket,
    SlidingWindowLog,
    SlidingWindowCounter,
}

impl RateLimitAlgorithm {
    pub fn as_str(&self) -> &'static str {
        match self {
            RateLimitAlgorithm::TokenBucket => "token_bucket",
            RateLimitAlgorithm::SlidingWindowLog => "sliding_window_log",
            RateLimitAlgorithm::SlidingWindowCounter => "sliding_window_counter",
        }
    }
}

/// Rate limit configuration.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct RateLimitConfig {
    /// Maximum requests allowed in the window.
    pub max_requests: u64,

    /// Window duration in seconds.
    pub window_secs: u64,

    /// Burst size (for token bucket, 0 = same as max_requests).
    pub burst_size: u64,

    /// Algorithm to use.
    pub algorithm: RateLimitAlgorithm,
}

impl RateLimitConfig {
    pub fn new(max_requests: u64, window_secs: u64) -> Self {
        Self {
            max_requests,
            window_secs,
            burst_size: max_requests,
            algorithm: RateLimitAlgorithm::TokenBucket,
        }
    }

    pub fn with_algorithm(mut self, algorithm: RateLimitAlgorithm) -> Self {
        self.algorithm = algorithm;
        self
    }

    pub fn with_burst(mut self, burst: u64) -> Self {
        self.burst_size = burst;
        self
    }
}

/// Rate limiter trait for checking request limits.
pub trait RateLimiter: Send + Sync {
    /// Get the name of this rate limiter algorithm.
    fn name(&self) -> &str;

    /// Check if a request is allowed for the given key.
    fn check(&self, key: &str) -> RateLimitResult;

    /// Get the current rate limit for a key.
    fn get_limit(&self, key: &str) -> Option<RateLimitConfig>;

    /// Set or update the rate limit for a key.
    fn set_limit(&self, key: &str, config: RateLimitConfig);

    /// Remove the rate limit for a key.
    fn remove_limit(&self, key: &str);

    /// Reset the rate limit counters for a key.
    fn reset(&self, key: &str);

    /// Get all tracked keys.
    fn keys(&self) -> Vec<String>;

    /// Get rate limiter metrics.
    fn metrics(&self) -> RateLimiterMetrics;
}

/// Rate limiter metrics.
#[derive(Debug, Clone)]
pub struct RateLimiterMetrics {
    pub algorithm: String,
    pub total_keys: usize,
    pub total_requests: u64,
    pub allowed_requests: u64,
    pub denied_requests: u64,
    pub denial_rate: f64,
}

/// Global rate limiter metrics.
static RL_TOTAL_CHECKS: AtomicU64 = AtomicU64::new(0);
static RL_ALLOWED: AtomicU64 = AtomicU64::new(0);
static RL_DENIED: AtomicU64 = AtomicU64::new(0);

pub fn record_rl_check(allowed: bool) {
    RL_TOTAL_CHECKS.fetch_add(1, Ordering::Relaxed);
    if allowed {
        RL_ALLOWED.fetch_add(1, Ordering::Relaxed);
    } else {
        RL_DENIED.fetch_add(1, Ordering::Relaxed);
    }
}

pub fn get_rl_metrics() -> GlobalRlMetrics {
    let total = RL_TOTAL_CHECKS.load(Ordering::Relaxed);
    let denied = RL_DENIED.load(Ordering::Relaxed);
    GlobalRlMetrics {
        total_checks: total,
        allowed: RL_ALLOWED.load(Ordering::Relaxed),
        denied,
        denial_rate: if total == 0 { 0.0 } else { (denied as f64 / total as f64) * 100.0 },
    }
}

#[derive(Debug, Clone)]
pub struct GlobalRlMetrics {
    pub total_checks: u64,
    pub allowed: u64,
    pub denied: u64,
    pub denial_rate: f64,
}

/// Get current time as Unix timestamp seconds.
fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::ZERO)
        .as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rate_limit_result_allowed() {
        let result = RateLimitResult::allowed(100, 99, 1000);
        assert!(result.allowed);
        assert_eq!(result.limit, 100);
        assert_eq!(result.remaining, 99);
        assert!(result.retry_after.is_none());
    }

    #[test]
    fn test_rate_limit_result_denied() {
        let result = RateLimitResult::denied(100, 0, 1000, 30);
        assert!(!result.allowed);
        assert_eq!(result.limit, 100);
        assert_eq!(result.remaining, 0);
        assert_eq!(result.retry_after, Some(30));
    }

    #[test]
    fn test_rate_limit_config_defaults() {
        let config = RateLimitConfig::new(100, 60);
        assert_eq!(config.max_requests, 100);
        assert_eq!(config.window_secs, 60);
        assert_eq!(config.burst_size, 100);
        assert_eq!(config.algorithm, RateLimitAlgorithm::TokenBucket);
    }

    #[test]
    fn test_rate_limit_config_custom() {
        let config = RateLimitConfig::new(100, 60)
            .with_algorithm(RateLimitAlgorithm::SlidingWindowLog)
            .with_burst(200);

        assert_eq!(config.burst_size, 200);
        assert_eq!(config.algorithm, RateLimitAlgorithm::SlidingWindowLog);
    }

    #[test]
    fn test_algorithm_as_str() {
        assert_eq!(RateLimitAlgorithm::TokenBucket.as_str(), "token_bucket");
        assert_eq!(RateLimitAlgorithm::SlidingWindowLog.as_str(), "sliding_window_log");
        assert_eq!(RateLimitAlgorithm::SlidingWindowCounter.as_str(), "sliding_window_counter");
    }

    #[test]
    fn test_now_secs() {
        let now = now_secs();
        assert!(now > 1_700_000_000); // Reasonable timestamp
    }

    #[test]
    fn test_global_rl_metrics_initial() {
        let metrics = get_rl_metrics();
        assert_eq!(metrics.total_checks, 0);
        assert_eq!(metrics.denial_rate, 0.0);
    }

    #[test]
    fn test_rate_limit_config_serialization() {
        let config = RateLimitConfig::new(100, 60);
        let json = serde_json::to_string(&config).unwrap();
        let deserialized: RateLimitConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.max_requests, 100);
        assert_eq!(deserialized.window_secs, 60);
    }
}
