//! Least connections load balancer.
//!
//! This module implements the least connections load balancing algorithm,
//! which routes requests to the backend with the fewest active connections.
//! This is particularly effective for long-lived connections where request
//! duration varies significantly.
//!
//! # Algorithm
//!
//! 1. Track active connections for each backend
//! 2. On each request, select the healthy backend with the fewest connections
//! 3. If multiple backends have the same count, use round-robin among them
//! 4. Unhealthy backends are excluded from selection
//!
//! # Use Cases
//!
//! - Database connection routing
//! - WebSocket proxying
//! - Long-running API requests
//! - Variable-duration workloads

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::RwLock;

use tracing::{info, warn, debug};

use crate::load_balancer::{
    BackendServer, LoadBalancer, LoadBalancerError, LoadBalancerMetrics,
    LoadBalancerResult, BackendMetrics, record_lb_selection,
    record_no_healthy_backends, record_backend_added, record_backend_removed,
};

/// Least connections load balancer.
pub struct LeastConnectionsBalancer {
    /// Backend servers.
    backends: RwLock<Vec<BackendServer>>,

    /// Tie-breaker index for round-robin among equal backends.
    tie_breaker: AtomicUsize,
}

impl LeastConnectionsBalancer {
    /// Create a new least connections load balancer.
    pub fn new(servers: Vec<BackendServer>) -> LoadBalancerResult<Self> {
        if servers.is_empty() {
            return Err(LoadBalancerError::NoHealthyBackends);
        }

        info!(
            backend_count = servers.len(),
            "least connections load balancer created"
        );

        Ok(Self {
            backends: RwLock::new(servers),
            tie_breaker: AtomicUsize::new(0),
        })
    }

    /// Select the backend with the fewest active connections.
    fn select_next(&self) -> LoadBalancerResult<BackendServer> {
        let backends = self.backends.read().unwrap();
        let healthy_backends: Vec<&BackendServer> = backends
            .iter()
            .filter(|b| b.healthy)
            .collect();

        if healthy_backends.is_empty() {
            record_no_healthy_backends();
            return Err(LoadBalancerError::NoHealthyBackends);
        }

        // Find the minimum connection count
        let min_connections = healthy_backends
            .iter()
            .map(|b| b.active_connections)
            .min()
            .unwrap_or(0);

        // Collect all backends with the minimum connection count
        let candidates: Vec<&BackendServer> = healthy_backends
            .iter()
            .filter(|b| b.active_connections == min_connections)
            .cloned()
            .collect();

        // If multiple candidates, use round-robin tie-breaking
        let selected = if candidates.len() == 1 {
            candidates[0].clone()
        } else {
            let index = self.tie_breaker.fetch_add(1, Ordering::SeqCst) % candidates.len();
            candidates[index].clone()
        };

        debug!(
            backend_id = %selected.id,
            active_connections = selected.active_connections,
            min_connections = min_connections,
            candidate_count = candidates.len(),
            "selected backend via least connections"
        );

        Ok(selected)
    }
}

impl LoadBalancer for LeastConnectionsBalancer {
    fn name(&self) -> &str {
        "least_connections"
    }

    fn next_backend(&self, _hash_key: Option<&str>) -> LoadBalancerResult<BackendServer> {
        record_lb_selection();
        self.select_next()
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
        let mut backends = self.backends.write().unwrap();
        backends.push(server.clone());
        record_backend_added();
        info!(backend_id = %server.id, "backend added to least connections");
        Ok(())
    }

    fn remove_backend(&self, backend_id: &str) -> LoadBalancerResult<()> {
        let mut backends = self.backends.write().unwrap();
        let initial_len = backends.len();
        backends.retain(|b| b.id != backend_id);

        if backends.len() == initial_len {
            return Err(LoadBalancerError::BackendNotFound(backend_id.to_string()));
        }

        record_backend_removed();
        info!(backend_id = backend_id, "backend removed from least connections");
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
            algorithm: "least_connections".to_string(),
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
    fn test_least_connections_creation() {
        let lb = LeastConnectionsBalancer::new(create_test_backends()).unwrap();
        assert_eq!(lb.name(), "least_connections");
        assert_eq!(lb.total_count(), 3);
    }

    #[test]
    fn test_least_connections_empty() {
        let result = LeastConnectionsBalancer::new(vec![]);
        assert!(result.is_err());
    }

    #[test]
    fn test_least_connections_selects_minimum() {
        let mut backends = create_test_backends();
        backends[0].active_connections = 5;
        backends[1].active_connections = 2;
        backends[2].active_connections = 8;

        let lb = LeastConnectionsBalancer::new(backends).unwrap();
        let selected = lb.next_backend(None).unwrap();

        assert_eq!(selected.id, "backend-2");
        assert_eq!(selected.active_connections, 2);
    }

    #[test]
    fn test_least_connections_tie_breaking() {
        let backends = create_test_backends();
        // All have 0 connections - should use round-robin tie-breaking
        let lb = LeastConnectionsBalancer::new(backends).unwrap();

        let b1 = lb.next_backend(None).unwrap();
        let b2 = lb.next_backend(None).unwrap();
        let b3 = lb.next_backend(None).unwrap();

        // All should be different (round-robin among ties)
        assert_ne!(b1.id, b2.id);
        assert_ne!(b2.id, b3.id);
    }

    #[test]
    fn test_least_connections_skips_unhealthy() {
        let mut backends = create_test_backends();
        backends[0].active_connections = 1;
        backends[1].active_connections = 0;
        backends[2].active_connections = 0;

        let lb = LeastConnectionsBalancer::new(backends).unwrap();
        lb.mark_unhealthy("backend-2").unwrap();
        lb.mark_unhealthy("backend-3").unwrap();

        // Should select backend-1 even though it has more connections
        let selected = lb.next_backend(None).unwrap();
        assert_eq!(selected.id, "backend-1");
    }

    #[test]
    fn test_least_connections_no_healthy() {
        let lb = LeastConnectionsBalancer::new(create_test_backends()).unwrap();

        lb.mark_unhealthy("backend-1").unwrap();
        lb.mark_unhealthy("backend-2").unwrap();
        lb.mark_unhealthy("backend-3").unwrap();

        let result = lb.next_backend(None);
        assert!(result.is_err());
    }

    #[test]
    fn test_least_connections_add_remove() {
        let lb = LeastConnectionsBalancer::new(create_test_backends()).unwrap();
        assert_eq!(lb.total_count(), 3);

        lb.add_backend(BackendServer::new("backend-4", "10.0.0.4:8080")).unwrap();
        assert_eq!(lb.total_count(), 4);

        lb.remove_backend("backend-2").unwrap();
        assert_eq!(lb.total_count(), 3);
    }

    #[test]
    fn test_least_connections_metrics() {
        let lb = LeastConnectionsBalancer::new(create_test_backends()).unwrap();
        let metrics = lb.metrics();

        assert_eq!(metrics.algorithm, "least_connections");
        assert_eq!(metrics.total_backends, 3);
        assert_eq!(metrics.healthy_backends, 3);
    }
}
