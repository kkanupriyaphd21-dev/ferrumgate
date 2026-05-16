//! Bulkhead middleware for request isolation.
//!
//! Routes requests to appropriate bulkhead partitions
//! based on service grouping.

use std::collections::HashMap;
use std::sync::{Arc, RwLock};

use crate::bulkhead::{
    BulkheadConfig, BulkheadPartition, PartitionConfig, BulkheadError,
    record_bulkhead, get_bulkhead_metrics, BulkheadMetrics,
};

/// Bulkhead middleware that enforces partition isolation.
pub struct BulkheadMiddleware {
    config: BulkheadConfig,
    partitions: RwLock<HashMap<String, Arc<BulkheadPartition>>>,
}

impl BulkheadMiddleware {
    pub fn new(config: BulkheadConfig) -> Self {
        let mut partitions = HashMap::new();

        // Create partitions from config
        for (name, part_config) in &config.partitions {
            partitions.insert(
                name.clone(),
                Arc::new(BulkheadPartition::new(name, part_config.clone())),
            );
        }

        Self {
            config,
            partitions: RwLock::new(partitions),
        }
    }

    /// Get or create a partition for a service.
    pub fn get_partition(&self, service: &str) -> Arc<BulkheadPartition> {
        let partitions = self.partitions.read().unwrap();
        if let Some(partition) = partitions.get(service) {
            return partition.clone();
        }
        drop(partitions);

        // Create with default config
        let mut partitions = self.partitions.write().unwrap();
        partitions
            .entry(service.to_string())
            .or_insert_with(|| {
                Arc::new(BulkheadPartition::new(
                    service,
                    self.config.default_partition_config.clone(),
                ))
            })
            .clone()
    }

    /// Acquire a permit for a service request.
    pub fn acquire(&self, service: &str) -> Result<crate::bulkhead::partition::BulkheadPermit, BulkheadError> {
        let partition = self.get_partition(service);
        partition.acquire()
    }

    /// Get metrics for all partitions.
    pub fn all_metrics(&self) -> HashMap<String, crate::bulkhead::partition::PartitionMetrics> {
        let partitions = self.partitions.read().unwrap();
        partitions.iter()
            .map(|(name, partition)| (name.clone(), partition.metrics()))
            .collect()
    }

    /// Get global bulkhead metrics.
    pub fn metrics(&self) -> BulkheadMetrics {
        get_bulkhead_metrics()
    }

    /// Add a new partition.
    pub fn add_partition(&self, name: &str, config: PartitionConfig) {
        let mut partitions = self.partitions.write().unwrap();
        partitions.insert(
            name.to_string(),
            Arc::new(BulkheadPartition::new(name, config)),
        );
    }

    /// Remove a partition.
    pub fn remove_partition(&self, name: &str) {
        self.partitions.write().unwrap().remove(name);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_middleware_get_default_partition() {
        let config = BulkheadConfig::default();
        let middleware = BulkheadMiddleware::new(config);
        let partition = middleware.get_partition("unknown-service");
        assert_eq!(partition.name(), "unknown-service");
    }

    #[test]
    fn test_middleware_acquire_permit() {
        let config = BulkheadConfig::default();
        let middleware = BulkheadMiddleware::new(config);
        let result = middleware.acquire("test-service");
        assert!(result.is_ok());
    }

    #[test]
    fn test_middleware_add_partition() {
        let config = BulkheadConfig::default();
        let middleware = BulkheadMiddleware::new(config);
        middleware.add_partition("custom", PartitionConfig {
            max_concurrent: 10,
            max_queue: 5,
            queue_timeout: std::time::Duration::from_secs(1),
        });
        let partition = middleware.get_partition("custom");
        assert_eq!(partition.name(), "custom");
    }

    #[test]
    fn test_middleware_metrics() {
        let config = BulkheadConfig::default();
        let middleware = BulkheadMiddleware::new(config);
        let metrics = middleware.metrics();
        assert_eq!(metrics.total, 0);
    }
}
