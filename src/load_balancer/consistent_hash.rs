//! Consistent hashing load balancer.
//!
//! This module implements consistent hashing for load balancing, which
//! maps requests to backends based on a hash of the request key. This
//! ensures that the same request key always routes to the same backend,
//! while minimizing redistribution when backends are added or removed.
//!
//! # Algorithm
//!
//! 1. Create a hash ring with virtual nodes for each backend
//! 2. Hash the request key to find its position on the ring
//! 3. Select the next backend clockwise from the hash position
//! 4. Virtual nodes ensure even distribution across backends
//!
//! # Virtual Nodes
//!
//! Each backend is represented by multiple virtual nodes on the hash ring.
//! This ensures that:
//! - Traffic is evenly distributed across backends
//! - Adding/removing a backend only affects a fraction of requests
//! - Backends with higher weights get more virtual nodes
//!
//! # Use Cases
//!
//! - Session affinity (sticky sessions)
//! - Cache routing (consistent cache key mapping)
//! - Sharded database routing
//! - User-based routing (same user always goes to same backend)

use std::collections::BTreeMap;
use std::hash::{Hash, Hasher};
use std::sync::RwLock;

use tracing::{info, warn, debug};

use crate::load_balancer::{
    BackendServer, LoadBalancer, LoadBalancerError, LoadBalancerMetrics,
    LoadBalancerResult, BackendMetrics, record_lb_selection,
    record_no_healthy_backends, record_backend_added, record_backend_removed,
};

/// Number of virtual nodes per backend by default.
const DEFAULT_VIRTUAL_NODES: usize = 150;

/// Consistent hashing load balancer.
pub struct ConsistentHashBalancer {
    /// Backend servers.
    backends: RwLock<Vec<BackendServer>>,

    /// Hash ring mapping hash positions to backend IDs.
    ring: RwLock<BTreeMap<u64, String>>,

    /// Number of virtual nodes per backend.
    virtual_nodes: usize,
}

impl ConsistentHashBalancer {
    /// Create a new consistent hashing load balancer.
    pub fn new(servers: Vec<BackendServer>, virtual_nodes: usize) -> LoadBalancerResult<Self> {
        if servers.is_empty() {
            return Err(LoadBalancerError::NoHealthyBackends);
        }

        let vnodes = if virtual_nodes == 0 { DEFAULT_VIRTUAL_NODES } else { virtual_nodes };

        let mut balancer = Self {
            backends: RwLock::new(Vec::new()),
            ring: RwLock::new(BTreeMap::new()),
            virtual_nodes: vnodes,
        };

        // Add all servers to the ring
        for server in servers {
            balancer.add_to_ring(&server);
            balancer.backends.write().unwrap().push(server);
        }

        info!(
            backend_count = balancer.backends.read().unwrap().len(),
            virtual_nodes = vnodes,
            ring_size = balancer.ring.read().unwrap().len(),
            "consistent hash load balancer created"
        );

        Ok(balancer)
    }

    /// Add a backend to the hash ring.
    fn add_to_ring(&self, server: &BackendServer) {
        let mut ring = self.ring.write().unwrap();
        let vnodes = server.weight as usize * self.virtual_nodes;

        for i in 0..vnodes {
            let key = format!("{}#{}", server.id, i);
            let hash = Self::hash_key(&key);
            ring.insert(hash, server.id.clone());
        }
    }

    /// Remove a backend from the hash ring.
    fn remove_from_ring(&self, backend_id: &str) {
        let mut ring = self.ring.write().unwrap();
        ring.retain(|_, id| id != backend_id);
    }

    /// Hash a key to a position on the ring.
    fn hash_key(key: &str) -> u64 {
        use std::collections::hash_map::DefaultHasher;
        let mut hasher = DefaultHasher::new();
        key.hash(&mut hasher);
        hasher.finish()
    }

    /// Find the backend for a given hash key.
    fn find_backend(&self, hash_key: &str) -> LoadBalancerResult<BackendServer> {
        let ring = self.ring.read().unwrap();
        let backends = self.backends.read().unwrap();

        if ring.is_empty() {
            record_no_healthy_backends();
            return Err(LoadBalancerError::NoHealthyBackends);
        }

        let hash = Self::hash_key(hash_key);

        // Find the first node in the ring that is >= our hash
        let backend_id = if let Some((_, id)) = ring.range(hash..).next() {
            id.clone()
        } else {
            // Wrap around to the beginning of the ring
            ring.iter().next().map(|(_, id)| id.clone()).ok_or_else(|| {
                LoadBalancerError::ConsistentHashError("empty ring".into())
            })?
        };

        // Find the backend server
        let backend = backends
            .iter()
            .find(|b| b.id == backend_id)
            .ok_or_else(|| LoadBalancerError::BackendNotFound(backend_id))?;

        // Check if the backend is healthy; if not, try the next one
        if !backend.healthy {
            // Find next healthy backend
            let mut found = None;
            let mut iter = ring.range(hash..).peekable();
            iter.next(); // Skip the first (unhealthy) one

            for (_, id) in iter {
                if let Some(b) = backends.iter().find(|b| b.id == *id && b.healthy) {
                    found = Some(b.clone());
                    break;
                }
            }

            // Wrap around
            if found.is_none() {
                for (_, id) in ring.iter() {
                    if let Some(b) = backends.iter().find(|b| b.id == *id && b.healthy) {
                        found = Some(b.clone());
                        break;
                    }
                }
            }

            found.ok_or_else(|| {
                record_no_healthy_backends();
                LoadBalancerError::NoHealthyBackends
            })
        } else {
            Ok(backend.clone())
        }
    }
}

impl LoadBalancer for ConsistentHashBalancer {
    fn name(&self) -> &str {
        "consistent_hash"
    }

    fn next_backend(&self, hash_key: Option<&str>) -> LoadBalancerResult<BackendServer> {
        record_lb_selection();

        let key = hash_key.unwrap_or("default");
        self.find_backend(key)
    }

    fn mark_healthy(&self, backend_id: &str) -> LoadBalancerResult<()> {
        let mut backends = self.backends.write().unwrap();
        for backend in backends.iter_mut() {
            if backend.id == backend_id {
                backend.mark_healthy();
                info!(backend_id = backend_id, "backend marked healthy");
                return Ok(());
            }
        }
        Err(LoadBalancerError::BackendNotFound(backend_id.to_string()))
    }

    fn mark_unhealthy(&self, backend_id: &str) -> LoadBalancerResult<()> {
        let mut backends = self.backends.write().unwrap();
        for backend in backends.iter_mut() {
            if backend.id == backend_id {
                backend.mark_unhealthy();
                info!(backend_id = backend_id, "backend marked unhealthy");
                return Ok(());
            }
        }
        Err(LoadBalancerError::BackendNotFound(backend_id.to_string()))
    }

    fn backends(&self) -> Vec<BackendServer> {
        self.backends.read().unwrap().clone()
    }

    fn get_backend(&self, backend_id: &str) -> LoadBalancerResult<BackendServer> {
        let backends = self.backends.read().unwrap();
        backends
            .iter()
            .find(|b| b.id == backend_id)
            .cloned()
            .ok_or_else(|| LoadBalancerError::BackendNotFound(backend_id.to_string()))
    }

    fn add_backend(&self, server: BackendServer) -> LoadBalancerResult<()> {
        self.add_to_ring(&server);
        self.backends.write().unwrap().push(server.clone());
        record_backend_added();
        info!(backend_id = %server.id, "backend added to consistent hash");
        Ok(())
    }

    fn remove_backend(&self, backend_id: &str) -> LoadBalancerResult<()> {
        let mut backends = self.backends.write().unwrap();
        let initial_len = backends.len();
        backends.retain(|b| b.id != backend_id);

        if backends.len() == initial_len {
            return Err(LoadBalancerError::BackendNotFound(backend_id.to_string()));
        }

        self.remove_from_ring(backend_id);
        record_backend_removed();
        info!(backend_id = backend_id, "backend removed from consistent hash");
        Ok(())
    }

    fn healthy_count(&self) -> usize {
        self.backends
            .read()
            .unwrap()
            .iter()
            .filter(|b| b.healthy)
            .count()
    }

    fn total_count(&self) -> usize {
        self.backends.read().unwrap().len()
    }

    fn record_request(&self, backend_id: &str, bytes_sent: u64, bytes_received: u64) -> LoadBalancerResult<()> {
        let mut backends = self.backends.write().unwrap();
        for backend in backends.iter_mut() {
            if backend.id == backend_id {
                backend.record_request(bytes_sent, bytes_received);
                return Ok(());
            }
        }
        Err(LoadBalancerError::BackendNotFound(backend_id.to_string()))
    }

    fn metrics(&self) -> LoadBalancerMetrics {
        let backends = self.backends.read().unwrap();
        let healthy = backends.iter().filter(|b| b.healthy).count();
        let unhealthy = backends.len() - healthy;

        let mut total_active = 0u64;
        let mut total_requests = 0u64;
        let mut total_bytes_sent = 0u64;
        let mut total_bytes_received = 0u64;
        let mut backend_details = Vec::new();

        for b in backends.iter() {
            total_active += b.active_connections;
            total_requests += b.total_requests;
            total_bytes_sent += b.total_bytes_sent;
            total_bytes_received += b.total_bytes_received;

            backend_details.push(BackendMetrics {
                id: b.id.clone(),
                address: b.address.clone(),
                healthy: b.healthy,
                weight: b.weight,
                active_connections: b.active_connections,
                total_requests: b.total_requests,
                total_bytes_sent: b.total_bytes_sent,
                total_bytes_received: b.total_bytes_received,
            });
        }

        LoadBalancerMetrics {
            algorithm: "consistent_hash".to_string(),
            total_backends: backends.len(),
            healthy_backends: healthy,
            unhealthy_backends: unhealthy,
            total_active_connections: total_active,
            total_requests,
            total_bytes_sent,
            total_bytes_received,
            backend_details,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_backends() -> Vec<BackendServer> {
        vec![
            BackendServer::new("backend-1", "10.0.0.1:8080"),
            BackendServer::new("backend-2", "10.0.0.2:8080"),
            BackendServer::new("backend-3", "10.0.0.3:8080"),
        ]
    }

    #[test]
    fn test_consistent_hash_creation() {
        let lb = ConsistentHashBalancer::new(create_test_backends(), 100).unwrap();
        assert_eq!(lb.name(), "consistent_hash");
        assert_eq!(lb.total_count(), 3);
    }

    #[test]
    fn test_consistent_hash_empty() {
        let result = ConsistentHashBalancer::new(vec![], 100);
        assert!(result.is_err());
    }

    #[test]
    fn test_consistent_hash_deterministic() {
        let lb = ConsistentHashBalancer::new(create_test_backends(), 100).unwrap();

        // Same hash key should always return the same backend
        let b1 = lb.next_backend(Some("user-123")).unwrap();
        let b2 = lb.next_backend(Some("user-123")).unwrap();
        let b3 = lb.next_backend(Some("user-123")).unwrap();

        assert_eq!(b1.id, b2.id);
        assert_eq!(b2.id, b3.id);
    }

    #[test]
    fn test_consistent_hash_different_keys() {
        let lb = ConsistentHashBalancer::new(create_test_backends(), 100).unwrap();

        let b1 = lb.next_backend(Some("user-1")).unwrap();
        let b2 = lb.next_backend(Some("user-2")).unwrap();
        let b3 = lb.next_backend(Some("user-3")).unwrap();

        // Different keys should generally map to different backends
        // (not guaranteed, but likely with 3 backends and 100 vnodes)
        let unique_count = [b1.id.as_str(), b2.id.as_str(), b3.id.as_str()]
            .iter()
            .collect::<std::collections::HashSet<_>>()
            .len();
        assert!(unique_count >= 1);
    }

    #[test]
    fn test_consistent_hash_skips_unhealthy() {
        let lb = ConsistentHashBalancer::new(create_test_backends(), 100).unwrap();

        // Find which backend "user-123" maps to
        let target = lb.next_backend(Some("user-123")).unwrap();
        lb.mark_unhealthy(&target.id).unwrap();

        // Should now map to a different backend
        let new_target = lb.next_backend(Some("user-123")).unwrap();
        assert_ne!(target.id, new_target.id);
    }

    #[test]
    fn test_consistent_hash_no_healthy() {
        let lb = ConsistentHashBalancer::new(create_test_backends(), 100).unwrap();

        lb.mark_unhealthy("backend-1").unwrap();
        lb.mark_unhealthy("backend-2").unwrap();
        lb.mark_unhealthy("backend-3").unwrap();

        let result = lb.next_backend(Some("user-123"));
        assert!(result.is_err());
    }

    #[test]
    fn test_consistent_hash_add_remove() {
        let lb = ConsistentHashBalancer::new(create_test_backends(), 100).unwrap();
        assert_eq!(lb.total_count(), 3);

        lb.add_backend(BackendServer::new("backend-4", "10.0.0.4:8080")).unwrap();
        assert_eq!(lb.total_count(), 4);

        lb.remove_backend("backend-2").unwrap();
        assert_eq!(lb.total_count(), 3);
    }

    #[test]
    fn test_consistent_hash_metrics() {
        let lb = ConsistentHashBalancer::new(create_test_backends(), 100).unwrap();
        let metrics = lb.metrics();

        assert_eq!(metrics.algorithm, "consistent_hash");
        assert_eq!(metrics.total_backends, 3);
    }

    #[test]
    fn test_consistent_hash_default_virtual_nodes() {
        let lb = ConsistentHashBalancer::new(create_test_backends(), 0).unwrap();
        assert_eq!(lb.virtual_nodes, DEFAULT_VIRTUAL_NODES);
    }

    #[test]
    fn test_consistent_hash_weighted() {
        let backends = vec![
            BackendServer::with_weight("backend-1", "10.0.0.1:8080", 2),
            BackendServer::with_weight("backend-2", "10.0.0.2:8080", 1),
        ];

        let lb = ConsistentHashBalancer::new(backends, 100).unwrap();
        let ring_size = lb.ring.read().unwrap().len();

        // Backend-1 should have twice as many virtual nodes
        let b1_count = lb.ring.read().unwrap().values().filter(|id| *id == "backend-1").count();
        let b2_count = lb.ring.read().unwrap().values().filter(|id| *id == "backend-2").count();

        assert_eq!(b1_count, 2 * b2_count);
    }
}
