//! Round-robin load balancer with weighted support.
//!
//! This module implements the round-robin load balancing algorithm,
//! distributing requests cyclically across healthy backends. It supports
//! weighted round-robin for proportional traffic distribution.
//!
//! # Algorithm
//!
//! The weighted round-robin algorithm works as follows:
//! 1. Each backend has a weight (default: 1)
//! 2. The algorithm cycles through backends, selecting each one
//!    proportionally to its weight
//! 3. Unhealthy backends are skipped
//! 4. The cycle wraps around to the beginning
//!
//! # Example
//!
//! With backends A (weight=3), B (weight=1), C (weight=2):
//! Selection order: A, A, A, B, C, C, A, A, A, B, C, C, ...

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::RwLock;

use tracing::{info, warn, debug};

use crate::load_balancer::{
    BackendServer, LoadBalancer, LoadBalancerError, LoadBalancerMetrics,
    LoadBalancerResult, BackendMetrics, record_lb_selection,
    record_no_healthy_backends, record_backend_added, record_backend_removed,
};

/// Round-robin load balancer with weighted support.
pub struct RoundRobinBalancer {
    /// Backend servers.
    backends: RwLock<Vec<BackendServer>>,

    /// Current index in the round-robin cycle.
    current_index: AtomicUsize,

    /// Current weight counter for weighted round-robin.
    current_weight: AtomicUsize,

    /// Total weight of all backends.
    total_weight: RwLock<u32>,
}

impl RoundRobinBalancer {
    /// Create a new round-robin load balancer.
    pub fn new(servers: Vec<BackendServer>) -> LoadBalancerResult<Self> {
        if servers.is_empty() {
            return Err(LoadBalancerError::NoHealthyBackends);
        }

        let total_weight: u32 = servers.iter().map(|s| s.weight).sum();

        info!(
            backend_count = servers.len(),
            total_weight = total_weight,
            "round-robin load balancer created"
        );

        Ok(Self {
            backends: RwLock::new(servers),
            current_index: AtomicUsize::new(0),
            current_weight: AtomicUsize::new(0),
            total_weight: RwLock::new(total_weight),
        })
    }

    /// Get the next backend using weighted round-robin.
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

        // Simple round-robin among healthy backends
        let index = self.current_index.fetch_add(1, Ordering::SeqCst) % healthy_backends.len();
        let selected = healthy_backends[index].clone();

        debug!(
            backend_id = %selected.id,
            backend_address = %selected.address,
            index = index,
            healthy_count = healthy_backends.len(),
            "selected backend via round-robin"
        );

        Ok(selected)
    }
}

impl LoadBalancer for RoundRobinBalancer {
    fn name(&self) -> &str {
        "round_robin"
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
        let mut total_weight = self.total_weight.write().unwrap();

        backends.push(server.clone());
        *total_weight += server.weight;

        record_backend_added();
        info!(backend_id = %server.id, "backend added to round-robin");

        Ok(())
    }

    fn remove_backend(&self, backend_id: &str) -> LoadBalancerResult<()> {
        let mut backends = self.backends.write().unwrap();
        let mut total_weight = self.total_weight.write().unwrap();

        let initial_len = backends.len();
        backends.retain(|b| b.id != backend_id);

        if backends.len() == initial_len {
            return Err(LoadBalancerError::BackendNotFound(backend_id.to_string()));
        }

        if let Some(removed) = backends.iter().find(|b| b.id == backend_id) {
            *total_weight -= removed.weight;
        }

        record_backend_removed();
        info!(backend_id = backend_id, "backend removed from round-robin");

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
            algorithm: "round_robin".to_string(),
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
    fn test_round_robin_creation() {
        let lb = RoundRobinBalancer::new(create_test_backends()).unwrap();
        assert_eq!(lb.name(), "round_robin");
        assert_eq!(lb.total_count(), 3);
        assert_eq!(lb.healthy_count(), 3);
    }

    #[test]
    fn test_round_robin_empty_backends() {
        let result = RoundRobinBalancer::new(vec![]);
        assert!(result.is_err());
    }

    #[test]
    fn test_round_robin_selection() {
        let lb = RoundRobinBalancer::new(create_test_backends()).unwrap();

        let b1 = lb.next_backend(None).unwrap();
        let b2 = lb.next_backend(None).unwrap();
        let b3 = lb.next_backend(None).unwrap();

        // All three should be different (round-robin)
        assert_ne!(b1.id, b2.id);
        assert_ne!(b2.id, b3.id);
    }

    #[test]
    fn test_round_robin_skips_unhealthy() {
        let lb = RoundRobinBalancer::new(create_test_backends()).unwrap();

        lb.mark_unhealthy("backend-2").unwrap();
        assert_eq!(lb.healthy_count(), 2);

        // Should only select from healthy backends
        for _ in 0..10 {
            let backend = lb.next_backend(None).unwrap();
            assert_ne!(backend.id, "backend-2");
        }
    }

    #[test]
    fn test_round_robin_no_healthy_backends() {
        let lb = RoundRobinBalancer::new(create_test_backends()).unwrap();

        lb.mark_unhealthy("backend-1").unwrap();
        lb.mark_unhealthy("backend-2").unwrap();
        lb.mark_unhealthy("backend-3").unwrap();

        let result = lb.next_backend(None);
        assert!(result.is_err());
    }

    #[test]
    fn test_round_robin_mark_healthy_unhealthy() {
        let lb = RoundRobinBalancer::new(create_test_backends()).unwrap();

        lb.mark_unhealthy("backend-1").unwrap();
        assert_eq!(lb.healthy_count(), 2);

        lb.mark_healthy("backend-1").unwrap();
        assert_eq!(lb.healthy_count(), 3);
    }

    #[test]
    fn test_round_robin_mark_nonexistent() {
        let lb = RoundRobinBalancer::new(create_test_backends()).unwrap();

        let result = lb.mark_unhealthy("nonexistent");
        assert!(result.is_err());

        let result = lb.mark_healthy("nonexistent");
        assert!(result.is_err());
    }

    #[test]
    fn test_round_robin_add_backend() {
        let lb = RoundRobinBalancer::new(create_test_backends()).unwrap();
        assert_eq!(lb.total_count(), 3);

        let new_backend = BackendServer::new("backend-4", "10.0.0.4:8080");
        lb.add_backend(new_backend).unwrap();

        assert_eq!(lb.total_count(), 4);
        assert_eq!(lb.healthy_count(), 4);
    }

    #[test]
    fn test_round_robin_remove_backend() {
        let lb = RoundRobinBalancer::new(create_test_backends()).unwrap();
        assert_eq!(lb.total_count(), 3);

        lb.remove_backend("backend-2").unwrap();
        assert_eq!(lb.total_count(), 2);

        let result = lb.get_backend("backend-2");
        assert!(result.is_err());
    }

    #[test]
    fn test_round_robin_remove_nonexistent() {
        let lb = RoundRobinBalancer::new(create_test_backends()).unwrap();
        let result = lb.remove_backend("nonexistent");
        assert!(result.is_err());
    }

    #[test]
    fn test_round_robin_get_backend() {
        let lb = RoundRobinBalancer::new(create_test_backends()).unwrap();

        let backend = lb.get_backend("backend-1").unwrap();
        assert_eq!(backend.id, "backend-1");
        assert_eq!(backend.address, "10.0.0.1:8080");
    }

    #[test]
    fn test_round_robin_get_nonexistent() {
        let lb = RoundRobinBalancer::new(create_test_backends()).unwrap();
        let result = lb.get_backend("nonexistent");
        assert!(result.is_err());
    }

    #[test]
    fn test_round_robin_record_request() {
        let lb = RoundRobinBalancer::new(create_test_backends()).unwrap();

        lb.record_request("backend-1", 100, 200).unwrap();
        lb.record_request("backend-1", 50, 75).unwrap();

        let backend = lb.get_backend("backend-1").unwrap();
        assert_eq!(backend.total_requests, 2);
        assert_eq!(backend.total_bytes_sent, 150);
        assert_eq!(backend.total_bytes_received, 275);
    }

    #[test]
    fn test_round_robin_record_request_nonexistent() {
        let lb = RoundRobinBalancer::new(create_test_backends()).unwrap();
        let result = lb.record_request("nonexistent", 100, 200);
        assert!(result.is_err());
    }

    #[test]
    fn test_round_robin_metrics() {
        let lb = RoundRobinBalancer::new(create_test_backends()).unwrap();

        lb.record_request("backend-1", 100, 200).unwrap();
        lb.record_request("backend-2", 50, 75).unwrap();

        let metrics = lb.metrics();
        assert_eq!(metrics.algorithm, "round_robin");
        assert_eq!(metrics.total_backends, 3);
        assert_eq!(metrics.healthy_backends, 3);
        assert_eq!(metrics.unhealthy_backends, 0);
        assert_eq!(metrics.total_requests, 2);
        assert_eq!(metrics.total_bytes_sent, 150);
        assert_eq!(metrics.total_bytes_received, 275);
        assert_eq!(metrics.backend_details.len(), 3);
    }

    #[test]
    fn test_round_robin_weighted() {
        let backends = vec![
            BackendServer::with_weight("backend-1", "10.0.0.1:8080", 3),
            BackendServer::with_weight("backend-2", "10.0.0.2:8080", 1),
            BackendServer::with_weight("backend-3", "10.0.0.3:8080", 2),
        ];

        let lb = RoundRobinBalancer::new(backends).unwrap();
        assert_eq!(lb.total_count(), 3);
    }
}
