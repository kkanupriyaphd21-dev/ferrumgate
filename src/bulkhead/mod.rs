//! Bulkhead isolation pattern for service partitions.
//!
//! Prevents cascading failures by partitioning resources
//! between service groups with separate connection pools
//! and concurrency limits per partition.

use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use std::time::Duration;

use thiserror::Error;

pub mod partition;
pub mod middleware;

pub use partition::{BulkheadPartition, PartitionConfig, PartitionMetrics};
pub use middleware::BulkheadMiddleware;

/// Bulkhead error types.
#[derive(Debug, Error)]
pub enum BulkheadError {
    #[error("partition '{0}' is at capacity")]
    AtCapacity(String),

    #[error("partition '{0}' not found")]
    PartitionNotFound(String),

    #[error("request timed out waiting for permit")]
    Timeout,

    #[error("bulkhead error: {0}")]
    Internal(String),
}

/// Bulkhead configuration.
#[derive(Debug, Clone)]
pub struct BulkheadConfig {
    pub max_concurrent_requests: usize,
    pub max_queue_size: usize,
    pub queue_timeout: Duration,
    pub partitions: HashMap<String, PartitionConfig>,
    pub default_partition_config: PartitionConfig,
}

impl Default for BulkheadConfig {
    fn default() -> Self {
        Self {
            max_concurrent_requests: 100,
            max_queue_size: 50,
            queue_timeout: Duration::from_secs(5),
            partitions: HashMap::new(),
            default_partition_config: PartitionConfig::default(),
        }
    }
}

/// Global bulkhead metrics.
static BULKHEAD_TOTAL: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
static BULKHEAD_ALLOWED: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
static BULKHEAD_REJECTED: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
static BULKHEAD_QUEUED: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

pub fn record_bulkhead(result: &str) {
    BULKHEAD_TOTAL.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    match result {
        "allowed" => BULKHEAD_ALLOWED.fetch_add(1, std::sync::atomic::Ordering::Relaxed),
        "rejected" => BULKHEAD_REJECTED.fetch_add(1, std::sync::atomic::Ordering::Relaxed),
        "queued" => BULKHEAD_QUEUED.fetch_add(1, std::sync::atomic::Ordering::Relaxed),
        _ => {}
    }
}

#[derive(Debug)]
pub struct BulkheadMetrics {
    pub total: u64,
    pub allowed: u64,
    pub rejected: u64,
    pub queued: u64,
    pub rejection_rate: f64,
}

pub fn get_bulkhead_metrics() -> BulkheadMetrics {
    let total = BULKHEAD_TOTAL.load(std::sync::atomic::Ordering::Relaxed);
    let rejected = BULKHEAD_REJECTED.load(std::sync::atomic::Ordering::Relaxed);
    BulkheadMetrics {
        total,
        allowed: BULKHEAD_ALLOWED.load(std::sync::atomic::Ordering::Relaxed),
        rejected,
        queued: BULKHEAD_QUEUED.load(std::sync::atomic::Ordering::Relaxed),
        rejection_rate: if total == 0 { 0.0 } else { rejected as f64 / total as f64 },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_bulkhead_config() {
        let config = BulkheadConfig::default();
        assert_eq!(config.max_concurrent_requests, 100);
        assert_eq!(config.max_queue_size, 50);
    }

    #[test]
    fn test_bulkhead_metrics_initial() {
        let metrics = get_bulkhead_metrics();
        assert_eq!(metrics.total, 0);
        assert_eq!(metrics.rejection_rate, 0.0);
    }
}
