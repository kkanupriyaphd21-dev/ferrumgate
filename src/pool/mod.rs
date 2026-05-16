use crate::errors::{GatewayError, GatewayResult, ConnectionError};
use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

#[derive(Debug, Clone)]
pub struct ConnectionInfo {
    pub id: usize,
    pub addr: String,
    pub created_at: Instant,
    pub last_used: Instant,
    pub is_healthy: bool,
}

impl ConnectionInfo {
    pub fn new(id: usize, addr: &str) -> Self {
        let now = Instant::now();
        Self {
            id,
            addr: addr.to_string(),
            created_at: now,
            last_used: now,
            is_healthy: true,
        }
    }

    pub fn age(&self) -> Duration {
        self.created_at.elapsed()
    }

    pub fn idle_time(&self) -> Duration {
        self.last_used.elapsed()
    }
}

pub struct ConnectionPool {
    connections: Arc<std::sync::Mutex<HashMap<usize, ConnectionInfo>>>,
    max_size: usize,
    idle_timeout: Duration,
    max_age: Duration,
    next_id: AtomicUsize,
    active_count: AtomicUsize,
    total_created: AtomicUsize,
    total_released: AtomicUsize,
    total_leaked: AtomicUsize,
}

impl ConnectionPool {
    pub fn new(max_size: usize, idle_timeout: Duration, max_age: Duration) -> Self {
        Self {
            connections: Arc::new(std::sync::Mutex::new(HashMap::new())),
            max_size,
            idle_timeout,
            max_age,
            next_id: AtomicUsize::new(0),
            active_count: AtomicUsize::new(0),
            total_created: AtomicUsize::new(0),
            total_released: AtomicUsize::new(0),
            total_leaked: AtomicUsize::new(0),
        }
    }

    pub fn acquire(&self, addr: &str) -> GatewayResult<usize> {
        let active = self.active_count.load(Ordering::Relaxed);
        if active >= self.max_size {
            return Err(GatewayError::Connection(ConnectionError::MaxConnectionsExceeded {
                limit: self.max_size,
                current: active,
            }));
        }

        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let conn = ConnectionInfo::new(id, addr);

        let mut connections = self.connections.lock().unwrap();
        connections.insert(id, conn);
        self.active_count.fetch_add(1, Ordering::Relaxed);
        self.total_created.fetch_add(1, Ordering::Relaxed);

        tracing::debug!(
            connection_id = id,
            addr = addr,
            active = self.active_count.load(Ordering::Relaxed),
            "connection acquired"
        );

        Ok(id)
    }

    pub fn release(&self, id: usize) -> GatewayResult<()> {
        let mut connections = self.connections.lock().unwrap();
        if let Some(conn) = connections.remove(&id) {
            self.active_count.fetch_sub(1, Ordering::Relaxed);
            self.total_released.fetch_add(1, Ordering::Relaxed);

            tracing::debug!(
                connection_id = id,
                addr = %conn.addr,
                age_ms = conn.age().as_millis(),
                "connection released"
            );

            Ok(())
        } else {
            Err(GatewayError::Internal(format!(
                "connection {} not found in pool",
                id
            )))
        }
    }

    pub fn mark_healthy(&self, id: usize) -> GatewayResult<()> {
        let mut connections = self.connections.lock().unwrap();
        if let Some(conn) = connections.get_mut(&id) {
            conn.last_used = Instant::now();
            conn.is_healthy = true;
            Ok(())
        } else {
            Err(GatewayError::Internal(format!(
                "connection {} not found in pool",
                id
            )))
        }
    }

    pub fn mark_unhealthy(&self, id: usize) -> GatewayResult<()> {
        let mut connections = self.connections.lock().unwrap();
        if let Some(conn) = connections.get_mut(&id) {
            conn.is_healthy = false;
            Ok(())
        } else {
            Err(GatewayError::Internal(format!(
                "connection {} not found in pool",
                id
            )))
        }
    }

    pub fn reclaim_idle(&self) -> Vec<usize> {
        let mut connections = self.connections.lock().unwrap();
        let mut reclaimed = Vec::new();

        let to_remove: Vec<usize> = connections
            .iter()
            .filter(|(_, conn)| conn.idle_time() > self.idle_timeout)
            .map(|(id, _)| *id)
            .collect();

        for id in to_remove {
            connections.remove(&id);
            self.active_count.fetch_sub(1, Ordering::Relaxed);
            self.total_leaked.fetch_add(1, Ordering::Relaxed);
            reclaimed.push(id);
        }

        if !reclaimed.is_empty() {
            tracing::warn!(
                count = reclaimed.len(),
                "reclaimed idle connections"
            );
        }

        reclaimed
    }

    pub fn reclaim_expired(&self) -> Vec<usize> {
        let mut connections = self.connections.lock().unwrap();
        let mut reclaimed = Vec::new();

        let to_remove: Vec<usize> = connections
            .iter()
            .filter(|(_, conn)| conn.age() > self.max_age)
            .map(|(id, _)| *id)
            .collect();

        for id in to_remove {
            connections.remove(&id);
            self.active_count.fetch_sub(1, Ordering::Relaxed);
            self.total_leaked.fetch_add(1, Ordering::Relaxed);
            reclaimed.push(id);
        }

        if !reclaimed.is_empty() {
            tracing::warn!(
                count = reclaimed.len(),
                "reclaimed expired connections"
            );
        }

        reclaimed
    }

    pub fn active_count(&self) -> usize {
        self.active_count.load(Ordering::Relaxed)
    }

    pub fn metrics(&self) -> PoolMetrics {
        PoolMetrics {
            active: self.active_count.load(Ordering::Relaxed),
            max_size: self.max_size,
            total_created: self.total_created.load(Ordering::Relaxed),
            total_released: self.total_released.load(Ordering::Relaxed),
            total_leaked: self.total_leaked.load(Ordering::Relaxed),
        }
    }
}

#[derive(Debug, Clone)]
pub struct PoolMetrics {
    pub active: usize,
    pub max_size: usize,
    pub total_created: usize,
    pub total_released: usize,
    pub total_leaked: usize,
}

impl PoolMetrics {
    pub fn leak_rate(&self) -> f64 {
        if self.total_created == 0 {
            return 0.0;
        }
        self.total_leaked as f64 / self.total_created as f64
    }

    pub fn utilization(&self) -> f64 {
        if self.max_size == 0 {
            return 0.0;
        }
        self.active as f64 / self.max_size as f64
    }
}

pub struct ManagedConnection {
    pool: Arc<ConnectionPool>,
    id: usize,
    addr: String,
}

impl ManagedConnection {
    pub fn new(pool: Arc<ConnectionPool>, addr: &str) -> GatewayResult<Self> {
        let id = pool.acquire(addr)?;
        Ok(Self {
            pool,
            id,
            addr: addr.to_string(),
        })
    }

    pub fn id(&self) -> usize {
        self.id
    }

    pub fn addr(&self) -> &str {
        &self.addr
    }
}

impl Drop for ManagedConnection {
    fn drop(&mut self) {
        if let Err(e) = self.pool.release(self.id) {
            tracing::error!(
                connection_id = self.id,
                error = %e,
                "failed to release connection on drop"
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pool_acquire_release() {
        let pool = ConnectionPool::new(10, Duration::from_secs(60), Duration::from_secs(300));
        let id = pool.acquire("127.0.0.1:8080").unwrap();
        assert_eq!(pool.active_count(), 1);
        pool.release(id).unwrap();
        assert_eq!(pool.active_count(), 0);
    }

    #[test]
    fn test_pool_max_size() {
        let pool = ConnectionPool::new(2, Duration::from_secs(60), Duration::from_secs(300));
        let id1 = pool.acquire("127.0.0.1:8080").unwrap();
        let id2 = pool.acquire("127.0.0.1:8081").unwrap();
        let result = pool.acquire("127.0.0.1:8082");
        assert!(result.is_err());
        pool.release(id1).unwrap();
        pool.release(id2).unwrap();
    }

    #[test]
    fn test_managed_connection_auto_release() {
        let pool = Arc::new(ConnectionPool::new(10, Duration::from_secs(60), Duration::from_secs(300)));
        {
            let conn = ManagedConnection::new(pool.clone(), "127.0.0.1:8080").unwrap();
            assert_eq!(pool.active_count(), 1);
            let _ = conn.id();
        }
        assert_eq!(pool.active_count(), 0);
    }

    #[test]
    fn test_pool_metrics() {
        let pool = ConnectionPool::new(10, Duration::from_secs(60), Duration::from_secs(300));
        let id = pool.acquire("127.0.0.1:8080").unwrap();
        pool.release(id).unwrap();

        let metrics = pool.metrics();
        assert_eq!(metrics.total_created, 1);
        assert_eq!(metrics.total_released, 1);
        assert_eq!(metrics.total_leaked, 0);
        assert_eq!(metrics.active, 0);
    }

    #[test]
    fn test_leak_rate_calculation() {
        let metrics = PoolMetrics {
            active: 0,
            max_size: 10,
            total_created: 100,
            total_released: 90,
            total_leaked: 10,
        };
        assert!((metrics.leak_rate() - 0.1).abs() < 0.001);
    }

    #[test]
    fn test_utilization_calculation() {
        let metrics = PoolMetrics {
            active: 5,
            max_size: 10,
            total_created: 10,
            total_released: 5,
            total_leaked: 0,
        };
        assert!((metrics.utilization() - 0.5).abs() < 0.001);
    }

    #[test]
    fn test_connection_info_age() {
        let conn = ConnectionInfo::new(0, "127.0.0.1:8080");
        std::thread::sleep(Duration::from_millis(10));
        assert!(conn.age() >= Duration::from_millis(10));
    }

    #[test]
    fn test_connection_info_idle_time() {
        let conn = ConnectionInfo::new(0, "127.0.0.1:8080");
        std::thread::sleep(Duration::from_millis(10));
        assert!(conn.idle_time() >= Duration::from_millis(10));
    }
}
