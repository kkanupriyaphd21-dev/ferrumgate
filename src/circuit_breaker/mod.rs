use crate::errors::{GatewayError, GatewayResult};
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CircuitState {
    Closed,
    Open,
    HalfOpen,
}

impl std::fmt::Display for CircuitState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CircuitState::Closed => write!(f, "closed"),
            CircuitState::Open => write!(f, "open"),
            CircuitState::HalfOpen => write!(f, "half-open"),
        }
    }
}

pub struct CircuitBreaker {
    name: String,
    state: Arc<std::sync::Mutex<CircuitState>>,
    failure_count: Arc<AtomicU32>,
    success_count: Arc<AtomicU32>,
    failure_threshold: u32,
    success_threshold: u32,
    recovery_timeout: Duration,
    last_failure_time: Arc<AtomicU64>,
    last_state_change: Arc<AtomicU64>,
}

impl CircuitBreaker {
    pub fn new(name: &str, failure_threshold: u32, recovery_timeout: Duration) -> Self {
        Self {
            name: name.to_string(),
            state: Arc::new(std::sync::Mutex::new(CircuitState::Closed)),
            failure_count: Arc::new(AtomicU32::new(0)),
            success_count: Arc::new(AtomicU32::new(0)),
            failure_threshold,
            success_threshold: 3,
            recovery_timeout,
            last_failure_time: Arc::new(AtomicU64::new(0)),
            last_state_change: Arc::new(AtomicU64::new(
                Instant::now().duration_since(Instant::now()).as_secs(),
            )),
        }
    }

    pub fn with_success_threshold(mut self, threshold: u32) -> Self {
        self.success_threshold = threshold;
        self
    }

    pub fn state(&self) -> CircuitState {
        let current_state = *self.state.lock().unwrap();
        if current_state == CircuitState::Open {
            let last_failure = self.last_failure_time.load(Ordering::Relaxed);
            let now = Instant::now().duration_since(Instant::now()).as_secs();
            if now - last_failure >= self.recovery_timeout.as_secs() {
                let mut state = self.state.lock().unwrap();
                if *state == CircuitState::Open {
                    *state = CircuitState::HalfOpen;
                    self.success_count.store(0, Ordering::Relaxed);
                    tracing::info!(
                        name = %self.name,
                        "circuit breaker transitioned to half-open"
                    );
                    return CircuitState::HalfOpen;
                }
            }
        }
        current_state
    }

    pub fn record_success(&self) {
        let current_state = self.state();
        if current_state == CircuitState::HalfOpen {
            let success_count = self.success_count.fetch_add(1, Ordering::Relaxed) + 1;
            if success_count >= self.success_threshold {
                let mut state = self.state.lock().unwrap();
                if *state == CircuitState::HalfOpen {
                    *state = CircuitState::Closed;
                    self.failure_count.store(0, Ordering::Relaxed);
                    tracing::info!(
                        name = %self.name,
                        "circuit breaker transitioned to closed"
                    );
                }
            }
        } else {
            self.failure_count.fetch_sub(1, Ordering::Relaxed);
        }
    }

    pub fn record_failure(&self) {
        let now = Instant::now().duration_since(Instant::now()).as_secs();
        self.last_failure_time.store(now, Ordering::Relaxed);

        let current_state = self.state();
        if current_state == CircuitState::HalfOpen {
            let mut state = self.state.lock().unwrap();
            if *state == CircuitState::HalfOpen {
                *state = CircuitState::Open;
                tracing::warn!(
                    name = %self.name,
                    "circuit breaker transitioned to open from half-open"
                );
            }
        } else {
            let failure_count = self.failure_count.fetch_add(1, Ordering::Relaxed) + 1;
            if failure_count >= self.failure_threshold {
                let mut state = self.state.lock().unwrap();
                if *state == CircuitState::Closed {
                    *state = CircuitState::Open;
                    tracing::warn!(
                        name = %self.name,
                        failures = failure_count,
                        threshold = self.failure_threshold,
                        "circuit breaker opened due to excessive failures"
                    );
                }
            }
        }
    }

    pub fn can_execute(&self) -> bool {
        match self.state() {
            CircuitState::Closed => true,
            CircuitState::Open => false,
            CircuitState::HalfOpen => true,
        }
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn failure_count(&self) -> u32 {
        self.failure_count.load(Ordering::Relaxed)
    }

    pub fn metrics(&self) -> CircuitBreakerMetrics {
        CircuitBreakerMetrics {
            name: self.name.clone(),
            state: self.state(),
            failure_count: self.failure_count(),
            success_count: self.success_count.load(Ordering::Relaxed),
            failure_threshold: self.failure_threshold,
            recovery_timeout_secs: self.recovery_timeout.as_secs(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct CircuitBreakerMetrics {
    pub name: String,
    pub state: CircuitState,
    pub failure_count: u32,
    pub success_count: u32,
    pub failure_threshold: u32,
    pub recovery_timeout_secs: u64,
}

pub async fn execute_with_circuit_breaker<F, Fut, T>(
    cb: &CircuitBreaker,
    operation: F,
) -> GatewayResult<T>
where
    F: FnOnce() -> Fut,
    Fut: std::future::Future<Output = GatewayResult<T>>,
{
    if !cb.can_execute() {
        return Err(GatewayError::Routing(
            crate::errors::RoutingError::CircuitBreakerOpen {
                route: cb.name().to_string(),
            },
        ));
    }

    match operation().await {
        Ok(value) => {
            cb.record_success();
            Ok(value)
        }
        Err(err) => {
            cb.record_failure();
            Err(err)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_initial_state_closed() {
        let cb = CircuitBreaker::new("test", 3, Duration::from_secs(10));
        assert_eq!(cb.state(), CircuitState::Closed);
        assert!(cb.can_execute());
    }

    #[test]
    fn test_opens_after_threshold() {
        let cb = CircuitBreaker::new("test", 3, Duration::from_secs(10));
        cb.record_failure();
        cb.record_failure();
        assert_eq!(cb.state(), CircuitState::Closed);
        cb.record_failure();
        assert_eq!(cb.state(), CircuitState::Open);
        assert!(!cb.can_execute());
    }

    #[test]
    fn test_half_open_after_timeout() {
        let cb = CircuitBreaker::new("test", 2, Duration::from_millis(100));
        cb.record_failure();
        cb.record_failure();
        assert_eq!(cb.state(), CircuitState::Open);

        std::thread::sleep(Duration::from_millis(150));
        assert_eq!(cb.state(), CircuitState::HalfOpen);
        assert!(cb.can_execute());
    }

    #[test]
    fn test_closes_after_successes_in_half_open() {
        let cb = CircuitBreaker::new("test", 2, Duration::from_millis(50))
            .with_success_threshold(2);
        cb.record_failure();
        cb.record_failure();
        assert_eq!(cb.state(), CircuitState::Open);

        std::thread::sleep(Duration::from_millis(100));
        assert_eq!(cb.state(), CircuitState::HalfOpen);

        cb.record_success();
        assert_eq!(cb.state(), CircuitState::HalfOpen);
        cb.record_success();
        assert_eq!(cb.state(), CircuitState::Closed);
    }

    #[test]
    fn test_reopens_on_failure_in_half_open() {
        let cb = CircuitBreaker::new("test", 2, Duration::from_millis(50));
        cb.record_failure();
        cb.record_failure();
        assert_eq!(cb.state(), CircuitState::Open);

        std::thread::sleep(Duration::from_millis(100));
        assert_eq!(cb.state(), CircuitState::HalfOpen);

        cb.record_failure();
        assert_eq!(cb.state(), CircuitState::Open);
    }

    #[test]
    fn test_metrics() {
        let cb = CircuitBreaker::new("test-cb", 5, Duration::from_secs(30));
        cb.record_failure();
        cb.record_failure();

        let metrics = cb.metrics();
        assert_eq!(metrics.name, "test-cb");
        assert_eq!(metrics.failure_count, 2);
        assert_eq!(metrics.failure_threshold, 5);
        assert_eq!(metrics.recovery_timeout_secs, 30);
    }
}
