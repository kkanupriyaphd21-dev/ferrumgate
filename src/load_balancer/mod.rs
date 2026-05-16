//! Load balancer algorithms for traffic distribution.
//!
//! This module provides pluggable load balancing algorithms for distributing
//! traffic across backend servers. Three algorithms are supported:
//!
//! - **Round-Robin**: Cyclic distribution with optional weights
//! - **Least Connections**: Route to server with fewest active connections
//! - **Consistent Hashing**: Hash-based routing with minimal redistribution
//!
//! # Architecture
//!
//! All algorithms implement the \`LoadBalancer\` trait, which provides a
//! unified interface for selecting the next backend server. The trait
//! is designed to be extensible, allowing new algorithms to be added
//! without modifying existing code.
//!
//! # Health Awareness
//!
//! All algorithms are health-aware: they skip unhealthy backends and
//! only route to servers that are marked as healthy. If no healthy
//! backends are available, the algorithm returns an error.
//!
//! # Thread Safety
//!
//! All implementations are \`Send + Sync\` and safe to use across
//! multiple threads. Internal state is protected by appropriate
//! synchronization primitives.
//!
//! # Example
//!
//! \`\`\`rust
//! use ferrumgate::load_balancer::{LoadBalancer, Algorithm, BackendServer};
//!
//! let servers = vec![
//!     BackendServer::new("backend-1", "10.0.0.1:8080"),
//!     BackendServer::new("backend-2", "10.0.0.2:8080"),
//!     BackendServer::new("backend-3", "10.0.0.3:8080"),
//! ];
//!
//! let lb = Algorithm::RoundRobin.build(servers)?;
//! let next = lb.next_backend(None)?;
//! \`\`\`

use std::collections::HashMap;
use std::fmt;
use std::hash::{Hash, Hasher};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, AtomicU64, Ordering};
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use thiserror::Error;
use tracing::{info, warn, error, debug};

pub mod round_robin;
pub mod least_connections;
pub mod consistent_hash;

// Re-exports
pub use round_robin::RoundRobinBalancer;
pub use least_connections::LeastConnectionsBalancer;
pub use consistent_hash::ConsistentHashBalancer;

/// Load balancer error types.
#[derive(Debug, Error)]
pub enum LoadBalancerError {
    #[error("no healthy backends available")]
    NoHealthyBackends,

    #[error("backend not found: {0}")]
    BackendNotFound(String),

    #[error("invalid weight configuration: {0}")]
    InvalidWeight(String),

    #[error("consistent hash error: {0}")]
    ConsistentHashError(String),

    #[error("load balancer is not initialized")]
    NotInitialized,

    #[error("backend server error: {0}")]
    BackendError(String),
}

/// Result type for load balancer operations.
pub type LoadBalancerResult<T> = Result<T, LoadBalancerError>;

/// Backend server representation.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct BackendServer {
    /// Unique identifier for this backend.
    pub id: String,

    /// Address of the backend server.
    pub address: String,

    /// Weight for weighted load balancing (higher = more traffic).
    pub weight: u32,

    /// Whether this backend is currently healthy.
    pub healthy: bool,

    /// Number of active connections to this backend.
    pub active_connections: u64,

    /// Total requests routed to this backend.
    pub total_requests: u64,

    /// Total bytes sent to this backend.
    pub total_bytes_sent: u64,

    /// Total bytes received from this backend.
    pub total_bytes_received: u64,

    /// Timestamp when this backend was last marked healthy.
    pub last_healthy_at: Option<SystemTime>,

    /// Timestamp when this backend was last marked unhealthy.
    pub last_unhealthy_at: Option<SystemTime>,

    /// Metadata for this backend.
    pub metadata: HashMap<String, String>,
}

impl BackendServer {
    /// Create a new backend server with default values.
    pub fn new(id: &str, address: &str) -> Self {
        Self {
            id: id.to_string(),
            address: address.to_string(),
            weight: 1,
            healthy: true,
            active_connections: 0,
            total_requests: 0,
            total_bytes_sent: 0,
            total_bytes_received: 0,
            last_healthy_at: Some(SystemTime::now()),
            last_unhealthy_at: None,
            metadata: HashMap::new(),
        }
    }

    /// Create a new backend server with a specific weight.
    pub fn with_weight(id: &str, address: &str, weight: u32) -> Self {
        let mut server = Self::new(id, address);
        server.weight = weight;
        server
    }

    /// Mark this backend as healthy.
    pub fn mark_healthy(&mut self) {
        self.healthy = true;
        self.last_healthy_at = Some(SystemTime::now());
    }

    /// Mark this backend as unhealthy.
    pub fn mark_unhealthy(&mut self) {
        self.healthy = false;
        self.last_unhealthy_at = Some(SystemTime::now());
    }

    /// Increment active connections.
    pub fn increment_connections(&mut self) {
        self.active_connections += 1;
    }

    /// Decrement active connections.
    pub fn decrement_connections(&mut self) {
        if self.active_connections > 0 {
            self.active_connections -= 1;
        }
    }

    /// Record a completed request.
    pub fn record_request(&mut self, bytes_sent: u64, bytes_received: u64) {
        self.total_requests += 1;
        self.total_bytes_sent += bytes_sent;
        self.total_bytes_received += bytes_received;
    }

    /// Parse address into SocketAddr.
    pub fn parse_address(&self) -> Result<SocketAddr, std::net::AddrParseError> {
        self.address.parse()
    }
}

impl PartialEq for BackendServer {
    fn eq(&self, other: &Self) -> bool {
        self.id == other.id
    }
}

impl Eq for BackendServer {}

impl Hash for BackendServer {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.id.hash(state);
    }
}

/// Load balancer algorithm selection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Algorithm {
    RoundRobin,
    LeastConnections,
    ConsistentHash,
}

impl Algorithm {
    /// Build a load balancer from the algorithm type.
    pub fn build(&self, servers: Vec<BackendServer>) -> LoadBalancerResult<Box<dyn LoadBalancer>> {
        match self {
            Algorithm::RoundRobin => {
                let lb = RoundRobinBalancer::new(servers)?;
                Ok(Box::new(lb))
            }
            Algorithm::LeastConnections => {
                let lb = LeastConnectionsBalancer::new(servers)?;
                Ok(Box::new(lb))
            }
            Algorithm::ConsistentHash => {
                let lb = ConsistentHashBalancer::new(servers, 150)?;
                Ok(Box::new(lb))
            }
        }
    }

    /// Get the string representation.
    pub fn as_str(&self) -> &'static str {
        match self {
            Algorithm::RoundRobin => "round_robin",
            Algorithm::LeastConnections => "least_connections",
            Algorithm::ConsistentHash => "consistent_hash",
        }
    }
}

impl fmt::Display for Algorithm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// Load balancer trait for selecting backend servers.
///
/// All load balancer algorithms implement this trait, providing a
/// unified interface for backend selection.
pub trait LoadBalancer: Send + Sync {
    /// Get the name of this load balancer algorithm.
    fn name(&self) -> &str;

    /// Select the next backend server to route a request to.
    ///
    /// The optional hash key is used by consistent hashing algorithms.
    /// For other algorithms, it is ignored.
    fn next_backend(&self, hash_key: Option<&str>) -> LoadBalancerResult<BackendServer>;

    /// Mark a backend as healthy.
    fn mark_healthy(&self, backend_id: &str) -> LoadBalancerResult<()>;

    /// Mark a backend as unhealthy.
    fn mark_unhealthy(&self, backend_id: &str) -> LoadBalancerResult<()>;

    /// Get all backend servers.
    fn backends(&self) -> Vec<BackendServer>;

    /// Get a specific backend server by ID.
    fn get_backend(&self, backend_id: &str) -> LoadBalancerResult<BackendServer>;

    /// Add a new backend server.
    fn add_backend(&self, server: BackendServer) -> LoadBalancerResult<()>;

    /// Remove a backend server by ID.
    fn remove_backend(&self, backend_id: &str) -> LoadBalancerResult<()>;

    /// Get the number of healthy backends.
    fn healthy_count(&self) -> usize;

    /// Get the total number of backends.
    fn total_count(&self) -> usize;

    /// Record that a request was routed to a backend.
    fn record_request(&self, backend_id: &str, bytes_sent: u64, bytes_received: u64) -> LoadBalancerResult<()>;

    /// Get load balancer metrics.
    fn metrics(&self) -> LoadBalancerMetrics;
}

/// Load balancer metrics.
#[derive(Debug, Clone)]
pub struct LoadBalancerMetrics {
    pub algorithm: String,
    pub total_backends: usize,
    pub healthy_backends: usize,
    pub unhealthy_backends: usize,
    pub total_active_connections: u64,
    pub total_requests: u64,
    pub total_bytes_sent: u64,
    pub total_bytes_received: u64,
    pub backend_details: Vec<BackendMetrics>,
}

/// Metrics for a single backend.
#[derive(Debug, Clone)]
pub struct BackendMetrics {
    pub id: String,
    pub address: String,
    pub healthy: bool,
    pub weight: u32,
    pub active_connections: u64,
    pub total_requests: u64,
    pub total_bytes_sent: u64,
    pub total_bytes_received: u64,
}

/// Global load balancer metrics counters.
static LB_SELECTIONS_TOTAL: AtomicU64 = AtomicU64::new(0);
static LB_NO_HEALTHY_BACKENDS: AtomicU64 = AtomicU64::new(0);
static LB_BACKEND_ADDED: AtomicU64 = AtomicU64::new(0);
static LB_BACKEND_REMOVED: AtomicU64 = AtomicU64::new(0);

/// Record a backend selection.
pub fn record_lb_selection() {
    LB_SELECTIONS_TOTAL.fetch_add(1, Ordering::Relaxed);
}

/// Record no healthy backends error.
pub fn record_no_healthy_backends() {
    LB_NO_HEALTHY_BACKENDS.fetch_add(1, Ordering::Relaxed);
}

/// Record a backend added.
pub fn record_backend_added() {
    LB_BACKEND_ADDED.fetch_add(1, Ordering::Relaxed);
}

/// Record a backend removed.
pub fn record_backend_removed() {
    LB_BACKEND_REMOVED.fetch_add(1, Ordering::Relaxed);
}

/// Get global load balancer metrics.
pub fn get_lb_metrics() -> GlobalLbMetrics {
    GlobalLbMetrics {
        selections_total: LB_SELECTIONS_TOTAL.load(Ordering::Relaxed),
        no_healthy_backends: LB_NO_HEALTHY_BACKENDS.load(Ordering::Relaxed),
        backend_added: LB_BACKEND_ADDED.load(Ordering::Relaxed),
        backend_removed: LB_BACKEND_REMOVED.load(Ordering::Relaxed),
    }
}

/// Global load balancer metrics.
#[derive(Debug, Clone)]
pub struct GlobalLbMetrics {
    pub selections_total: u64,
    pub no_healthy_backends: u64,
    pub backend_added: u64,
    pub backend_removed: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_backend_server_creation() {
        let server = BackendServer::new("backend-1", "10.0.0.1:8080");
        assert_eq!(server.id, "backend-1");
        assert_eq!(server.address, "10.0.0.1:8080");
        assert_eq!(server.weight, 1);
        assert!(server.healthy);
        assert_eq!(server.active_connections, 0);
    }

    #[test]
    fn test_backend_server_with_weight() {
        let server = BackendServer::with_weight("backend-1", "10.0.0.1:8080", 5);
        assert_eq!(server.weight, 5);
    }

    #[test]
    fn test_backend_server_health_transitions() {
        let mut server = BackendServer::new("backend-1", "10.0.0.1:8080");
        assert!(server.healthy);

        server.mark_unhealthy();
        assert!(!server.healthy);
        assert!(server.last_unhealthy_at.is_some());

        server.mark_healthy();
        assert!(server.healthy);
        assert!(server.last_healthy_at.is_some());
    }

    #[test]
    fn test_backend_server_connection_tracking() {
        let mut server = BackendServer::new("backend-1", "10.0.0.1:8080");
        assert_eq!(server.active_connections, 0);

        server.increment_connections();
        server.increment_connections();
        assert_eq!(server.active_connections, 2);

        server.decrement_connections();
        assert_eq!(server.active_connections, 1);

        server.decrement_connections();
        assert_eq!(server.active_connections, 0);

        // Should not go negative
        server.decrement_connections();
        assert_eq!(server.active_connections, 0);
    }

    #[test]
    fn test_backend_server_request_recording() {
        let mut server = BackendServer::new("backend-1", "10.0.0.1:8080");
        assert_eq!(server.total_requests, 0);

        server.record_request(100, 200);
        assert_eq!(server.total_requests, 1);
        assert_eq!(server.total_bytes_sent, 100);
        assert_eq!(server.total_bytes_received, 200);

        server.record_request(50, 75);
        assert_eq!(server.total_requests, 2);
        assert_eq!(server.total_bytes_sent, 150);
        assert_eq!(server.total_bytes_received, 275);
    }

    #[test]
    fn test_backend_server_parse_address() {
        let server = BackendServer::new("backend-1", "10.0.0.1:8080");
        let addr = server.parse_address().unwrap();
        assert_eq!(addr.ip().to_string(), "10.0.0.1");
        assert_eq!(addr.port(), 8080);
    }

    #[test]
    fn test_algorithm_as_str() {
        assert_eq!(Algorithm::RoundRobin.as_str(), "round_robin");
        assert_eq!(Algorithm::LeastConnections.as_str(), "least_connections");
        assert_eq!(Algorithm::ConsistentHash.as_str(), "consistent_hash");
    }

    #[test]
    fn test_algorithm_display() {
        assert_eq!(format!("{}", Algorithm::RoundRobin), "round_robin");
        assert_eq!(format!("{}", Algorithm::LeastConnections), "least_connections");
        assert_eq!(format!("{}", Algorithm::ConsistentHash), "consistent_hash");
    }

    #[test]
    fn test_backend_server_equality() {
        let s1 = BackendServer::new("backend-1", "10.0.0.1:8080");
        let s2 = BackendServer::new("backend-1", "10.0.0.2:9090");
        let s3 = BackendServer::new("backend-2", "10.0.0.1:8080");

        assert_eq!(s1, s2);
        assert_ne!(s1, s3);
    }

    #[test]
    fn test_backend_server_metadata() {
        let mut server = BackendServer::new("backend-1", "10.0.0.1:8080");
        server.metadata.insert("region".to_string(), "us-east-1".to_string());
        server.metadata.insert("zone".to_string(), "us-east-1a".to_string());

        assert_eq!(server.metadata.get("region"), Some(&"us-east-1".to_string()));
        assert_eq!(server.metadata.get("zone"), Some(&"us-east-1a".to_string()));
    }

    #[test]
    fn test_global_lb_metrics_initial_state() {
        let metrics = get_lb_metrics();
        assert_eq!(metrics.selections_total, 0);
        assert_eq!(metrics.no_healthy_backends, 0);
        assert_eq!(metrics.backend_added, 0);
        assert_eq!(metrics.backend_removed, 0);
    }

    #[test]
    fn test_backend_server_serialization() {
        let server = BackendServer::new("backend-1", "10.0.0.1:8080");
        let json = serde_json::to_string(&server).unwrap();
        let deserialized: BackendServer = serde_json::from_str(&json).unwrap();

        assert_eq!(deserialized.id, "backend-1");
        assert_eq!(deserialized.address, "10.0.0.1:8080");
        assert_eq!(deserialized.weight, 1);
    }
}
