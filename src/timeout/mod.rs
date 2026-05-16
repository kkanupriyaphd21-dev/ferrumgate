use crate::errors::{GatewayError, GatewayResult, TimeoutError};
use std::time::Duration;

#[derive(Debug, Clone)]
pub struct TimeoutConfig {
    pub request_timeout: Duration,
    pub connect_timeout: Duration,
    pub idle_timeout: Duration,
}

impl Default for TimeoutConfig {
    fn default() -> Self {
        Self {
            request_timeout: Duration::from_secs(30),
            connect_timeout: Duration::from_secs(5),
            idle_timeout: Duration::from_secs(60),
        }
    }
}

impl TimeoutConfig {
    pub fn with_request_timeout(mut self, timeout: Duration) -> Self {
        self.request_timeout = timeout;
        self
    }

    pub fn with_connect_timeout(mut self, timeout: Duration) -> Self {
        self.connect_timeout = timeout;
        self
    }

    pub fn with_idle_timeout(mut self, timeout: Duration) -> Self {
        self.idle_timeout = timeout;
        self
    }
}

pub async fn with_request_timeout<F, Fut, T>(
    config: &TimeoutConfig,
    operation: F,
) -> GatewayResult<T>
where
    F: FnOnce() -> Fut,
    Fut: std::future::Future<Output = GatewayResult<T>>,
{
    match tokio::time::timeout(config.request_timeout, operation()).await {
        Ok(result) => result,
        Err(_) => Err(GatewayError::Timeout(TimeoutError::RequestTimeout {
            duration_ms: config.request_timeout.as_millis() as u64,
        })),
    }
}

pub async fn with_connect_timeout<F, Fut, T>(
    config: &TimeoutConfig,
    operation: F,
) -> GatewayResult<T>
where
    F: FnOnce() -> Fut,
    Fut: std::future::Future<Output = GatewayResult<T>>,
{
    match tokio::time::timeout(config.connect_timeout, operation()).await {
        Ok(result) => result,
        Err(_) => Err(GatewayError::Timeout(TimeoutError::ConnectionTimeout {
            duration_ms: config.connect_timeout.as_millis() as u64,
        })),
    }
}

pub struct IdleWatcher {
    idle_timeout: Duration,
    last_activity: std::sync::atomic::AtomicU64,
}

impl IdleWatcher {
    pub fn new(idle_timeout: Duration) -> Self {
        Self {
            idle_timeout,
            last_activity: std::sync::atomic::AtomicU64::new(
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs(),
            ),
        }
    }

    pub fn record_activity(&self) {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        self.last_activity.store(now, std::sync::atomic::Ordering::Relaxed);
    }

    pub fn is_idle(&self) -> bool {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let last = self.last_activity.load(std::sync::atomic::Ordering::Relaxed);
        now - last >= self.idle_timeout.as_secs()
    }

    pub fn check_idle(&self) -> GatewayResult<()> {
        if self.is_idle() {
            Err(GatewayError::Timeout(TimeoutError::IdleTimeout {
                duration_ms: self.idle_timeout.as_millis() as u64,
            }))
        } else {
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = TimeoutConfig::default();
        assert_eq!(config.request_timeout, Duration::from_secs(30));
        assert_eq!(config.connect_timeout, Duration::from_secs(5));
        assert_eq!(config.idle_timeout, Duration::from_secs(60));
    }

    #[test]
    fn test_builder_pattern() {
        let config = TimeoutConfig::default()
            .with_request_timeout(Duration::from_secs(10))
            .with_connect_timeout(Duration::from_secs(2))
            .with_idle_timeout(Duration::from_secs(30));

        assert_eq!(config.request_timeout, Duration::from_secs(10));
        assert_eq!(config.connect_timeout, Duration::from_secs(2));
        assert_eq!(config.idle_timeout, Duration::from_secs(30));
    }

    #[test]
    fn test_idle_watcher_not_idle_initially() {
        let watcher = IdleWatcher::new(Duration::from_secs(60));
        assert!(!watcher.is_idle());
        assert!(watcher.check_idle().is_ok());
    }

    #[test]
    fn test_idle_watcher_detects_idle() {
        let watcher = IdleWatcher::new(Duration::from_millis(50));
        std::thread::sleep(Duration::from_millis(100));
        assert!(watcher.is_idle());
        assert!(watcher.check_idle().is_err());
    }

    #[test]
    fn test_idle_watcher_resets_on_activity() {
        let watcher = IdleWatcher::new(Duration::from_millis(100));
        std::thread::sleep(Duration::from_millis(50));
        watcher.record_activity();
        assert!(!watcher.is_idle());
    }

    #[tokio::test]
    async fn test_request_timeout_success() {
        let config = TimeoutConfig::default()
            .with_request_timeout(Duration::from_secs(5));

        let result = with_request_timeout(&config, || async {
            Ok("success")
        })
        .await;

        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_request_timeout_expires() {
        let config = TimeoutConfig::default()
            .with_request_timeout(Duration::from_millis(50));

        let result = with_request_timeout(&config, || async {
            tokio::time::sleep(Duration::from_secs(10)).await;
            Ok("success")
        })
        .await;

        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), GatewayError::Timeout(_)));
    }

    #[tokio::test]
    async fn test_connect_timeout_expires() {
        let config = TimeoutConfig::default()
            .with_connect_timeout(Duration::from_millis(50));

        let result = with_connect_timeout(&config, || async {
            tokio::time::sleep(Duration::from_secs(10)).await;
            Ok("connected")
        })
        .await;

        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), GatewayError::Timeout(TimeoutError::ConnectionTimeout { .. })));
    }
}
