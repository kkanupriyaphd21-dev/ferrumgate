//! Bulkhead partition with isolated resource limits.
//!
//! Each partition has its own concurrency limit and queue,
//! preventing failures in one service from affecting others.

use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use crate::bulkhead::{BulkheadError, record_bulkhead};

/// Configuration for a bulkhead partition.
#[derive(Debug, Clone)]
pub struct PartitionConfig {
    pub max_concurrent: usize,
    pub max_queue: usize,
    pub queue_timeout: Duration,
}

impl Default for PartitionConfig {
    fn default() -> Self {
        Self {
            max_concurrent: 50,
            max_queue: 25,
            queue_timeout: Duration::from_secs(5),
        }
    }
}

/// A bulkhead partition with semaphore-based concurrency control.
pub struct BulkheadPartition {
    name: String,
    config: PartitionConfig,
    concurrent: AtomicUsize,
    queued: AtomicUsize,
    total_requests: AtomicU64,
    successful_requests: AtomicU64,
    rejected_requests: AtomicU64,
    queued_requests: AtomicU64,
    max_concurrent_seen: AtomicUsize,
}

impl BulkheadPartition {
    pub fn new(name: &str, config: PartitionConfig) -> Self {
        Self {
            name: name.to_string(),
            config,
            concurrent: AtomicUsize::new(0),
            queued: AtomicUsize::new(0),
            total_requests: AtomicU64::new(0),
            successful_requests: AtomicU64::new(0),
            rejected_requests: AtomicU64::new(0),
            queued_requests: AtomicU64::new(0),
            max_concurrent_seen: AtomicUsize::new(0),
        }
    }

    /// Try to acquire a permit to execute a request.
    pub fn acquire(&self) -> Result<BulkheadPermit, BulkheadError> {
        self.total_requests.fetch_add(1, Ordering::Relaxed);

        // Try to increment concurrent count
        let current = self.concurrent.fetch_add(1, Ordering::Acquire);

        if current < self.config.max_concurrent {
            // Track max concurrent
            let mut max = self.max_concurrent_seen.load(Ordering::Relaxed);
            while current + 1 > max {
                match self.max_concurrent_seen.compare_exchange_weak(
                    max,
                    current + 1,
                    Ordering::AcqRel,
                    Ordering::Relaxed,
                ) {
                    Ok(_) => break,
                    Err(new_max) => max = new_max,
                }
            }
            record_bulkhead("allowed");
            Ok(BulkheadPermit { partition: self })
        } else {
            // Decrement since we couldn't acquire
            self.concurrent.fetch_sub(1, Ordering::Release);

            // Try to queue
            let queued = self.queued.load(Ordering::Relaxed);
            if queued < self.config.max_queue {
                self.queued.fetch_add(1, Ordering::Relaxed);
                self.queued_requests.fetch_add(1, Ordering::Relaxed);
                record_bulkhead("queued");

                // Wait for permit with timeout
                let start = Instant::now();
                loop {
                    if start.elapsed() > self.config.queue_timeout {
                        self.queued.fetch_sub(1, Ordering::Release);
                        self.rejected_requests.fetch_add(1, Ordering::Relaxed);
                        record_bulkhead("rejected");
                        return Err(BulkheadError::Timeout);
                    }

                    let current = self.concurrent.load(Ordering::Relaxed);
                    if current < self.config.max_concurrent {
                        if self.concurrent.compare_exchange(
                            current,
                            current + 1,
                            Ordering::AcqRel,
                            Ordering::Relaxed,
                        ).is_ok() {
                            self.queued.fetch_sub(1, Ordering::Release);
                            record_bulkhead("allowed");
                            return Ok(BulkheadPermit { partition: self });
                        }
                    }

                    std::thread::sleep(Duration::from_millis(10));
                }
            } else {
                self.rejected_requests.fetch_add(1, Ordering::Relaxed);
                record_bulkhead("rejected");
                Err(BulkheadError::AtCapacity(self.name.clone()))
            }
        }
    }

    pub fn name(&self) -> &str { &self.name }

    pub fn current_concurrent(&self) -> usize {
        self.concurrent.load(Ordering::Relaxed)
    }

    pub fn current_queued(&self) -> usize {
        self.queued.load(Ordering::Relaxed)
    }

    pub fn metrics(&self) -> PartitionMetrics {
        let total = self.total_requests.load(Ordering::Relaxed);
        PartitionMetrics {
            name: self.name.clone(),
            max_concurrent: self.config.max_concurrent,
            max_queue: self.config.max_queue,
            current_concurrent: self.concurrent.load(Ordering::Relaxed),
            current_queued: self.queued.load(Ordering::Relaxed),
            total_requests: total,
            successful_requests: self.successful_requests.load(Ordering::Relaxed),
            rejected_requests: self.rejected_requests.load(Ordering::Relaxed),
            queued_requests: self.queued_requests.load(Ordering::Relaxed),
            max_concurrent_seen: self.max_concurrent_seen.load(Ordering::Relaxed),
            utilization: if self.config.max_concurrent == 0 {
                0.0
            } else {
                self.concurrent.load(Ordering::Relaxed) as f64 / self.config.max_concurrent as f64
            },
        }
    }
}

/// RAII permit that releases the bulkhead slot when dropped.
pub struct BulkheadPermit<'a> {
    partition: &'a BulkheadPartition,
}

impl Drop for BulkheadPermit<'_> {
    fn drop(&mut self) {
        self.partition.concurrent.fetch_sub(1, Ordering::Release);
        self.partition.successful_requests.fetch_add(1, Ordering::Relaxed);
    }
}

/// Metrics for a bulkhead partition.
#[derive(Debug)]
pub struct PartitionMetrics {
    pub name: String,
    pub max_concurrent: usize,
    pub max_queue: usize,
    pub current_concurrent: usize,
    pub current_queued: usize,
    pub total_requests: u64,
    pub successful_requests: u64,
    pub rejected_requests: u64,
    pub queued_requests: u64,
    pub max_concurrent_seen: usize,
    pub utilization: f64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_partition_acquire_and_release() {
        let config = PartitionConfig {
            max_concurrent: 2,
            max_queue: 1,
            queue_timeout: Duration::from_millis(100),
        };
        let partition = BulkheadPartition::new("test", config);

        let permit1 = partition.acquire().unwrap();
        assert_eq!(partition.current_concurrent(), 1);
        drop(permit1);
        assert_eq!(partition.current_concurrent(), 0);
    }

    #[test]
    fn test_partition_at_capacity() {
        let config = PartitionConfig {
            max_concurrent: 1,
            max_queue: 0,
            queue_timeout: Duration::from_millis(100),
        };
        let partition = BulkheadPartition::new("test", config);

        let _permit = partition.acquire().unwrap();
        let result = partition.acquire();
        assert!(result.is_err());
    }

    #[test]
    fn test_partition_metrics() {
        let config = PartitionConfig::default();
        let partition = BulkheadPartition::new("test", config);
        let metrics = partition.metrics();
        assert_eq!(metrics.name, "test");
        assert_eq!(metrics.total_requests, 0);
    }
}
