use serde::Serialize;
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone, Serialize)]
pub struct HealthStatus {
    pub status: String,
    pub version: String,
    pub uptime_secs: u64,
    pub timestamp: u64,
    pub checks: HashMap<String, ComponentHealth>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ComponentHealth {
    pub status: String,
    pub details: Option<String>,
}

#[derive(Debug, Clone)]
pub enum HealthState {
    Healthy,
    Degraded,
    Unhealthy,
}

pub struct HealthChecker {
    start_time: u64,
    request_count: Arc<AtomicU64>,
    active_connections: Arc<AtomicU64>,
    last_error: Arc<std::sync::Mutex<Option<String>>>,
}

impl HealthChecker {
    pub fn new() -> Self {
        let start_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        Self {
            start_time,
            request_count: Arc::new(AtomicU64::new(0)),
            active_connections: Arc::new(AtomicU64::new(0)),
            last_error: Arc::new(std::sync::Mutex::new(None)),
        }
    }

    pub fn record_request(&self) {
        self.request_count.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_connection_open(&self) {
        self.active_connections.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_connection_close(&self) {
        self.active_connections.fetch_sub(1, Ordering::Relaxed);
    }

    pub fn record_error(&self, error: &str) {
        let mut last_error = self.last_error.lock().unwrap();
        *last_error = Some(error.to_string());
    }

    pub fn liveness(&self) -> HealthStatus {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let mut checks = HashMap::new();
        checks.insert(
            "runtime".to_string(),
            ComponentHealth {
                status: "healthy".to_string(),
                details: Some("Tokio runtime is running".to_string()),
            },
        );

        HealthStatus {
            status: "healthy".to_string(),
            version: env!("CARGO_PKG_VERSION").to_string(),
            uptime_secs: now - self.start_time,
            timestamp: now,
            checks,
        }
    }

    pub fn readiness(&self) -> HealthStatus {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let mut checks = HashMap::new();
        let active_conns = self.active_connections.load(Ordering::Relaxed);

        checks.insert(
            "connections".to_string(),
            ComponentHealth {
                status: if active_conns < 10000 {
                    "healthy".to_string()
                } else {
                    "degraded".to_string()
                },
                details: Some(format!("{} active connections", active_conns)),
            },
        );

        checks.insert(
            "memory".to_string(),
            ComponentHealth {
                status: "healthy".to_string(),
                details: Some(format!(
                    "RSS: {} MB",
                    self.get_memory_usage_mb()
                )),
            },
        );

        let overall_status = if checks.values().all(|c| c.status == "healthy") {
            "healthy"
        } else if checks.values().any(|c| c.status == "unhealthy") {
            "unhealthy"
        } else {
            "degraded"
        };

        HealthStatus {
            status: overall_status.to_string(),
            version: env!("CARGO_PKG_VERSION").to_string(),
            uptime_secs: now - self.start_time,
            timestamp: now,
            checks,
        }
    }

    pub fn detailed(&self) -> HealthStatus {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let mut checks = HashMap::new();
        let total_requests = self.request_count.load(Ordering::Relaxed);
        let active_conns = self.active_connections.load(Ordering::Relaxed);

        checks.insert(
            "runtime".to_string(),
            ComponentHealth {
                status: "healthy".to_string(),
                details: Some("Tokio runtime is running".to_string()),
            },
        );

        checks.insert(
            "connections".to_string(),
            ComponentHealth {
                status: if active_conns < 10000 {
                    "healthy".to_string()
                } else {
                    "degraded".to_string()
                },
                details: Some(format!("{} active connections", active_conns)),
            },
        );

        checks.insert(
            "requests".to_string(),
            ComponentHealth {
                status: "healthy".to_string(),
                details: Some(format!("{} total requests processed", total_requests)),
            },
        );

        checks.insert(
            "memory".to_string(),
            ComponentHealth {
                status: "healthy".to_string(),
                details: Some(format!(
                    "RSS: {} MB",
                    self.get_memory_usage_mb()
                )),
            },
        );

        let last_error = self.last_error.lock().unwrap();
        if let Some(ref err) = *last_error {
            checks.insert(
                "last_error".to_string(),
                ComponentHealth {
                    status: "warning".to_string(),
                    details: Some(err.clone()),
                },
            );
        }

        let overall_status = if checks.values().any(|c| c.status == "unhealthy") {
            "unhealthy"
        } else if checks.values().any(|c| c.status == "degraded" || c.status == "warning") {
            "degraded"
        } else {
            "healthy"
        };

        HealthStatus {
            status: overall_status.to_string(),
            version: env!("CARGO_PKG_VERSION").to_string(),
            uptime_secs: now - self.start_time,
            timestamp: now,
            checks,
        }
    }

    fn get_memory_usage_mb(&self) -> u64 {
        #[cfg(target_os = "linux")]
        {
            if let Ok(status) = std::fs::read_to_string("/proc/self/status") {
                for line in status.lines() {
                    if line.starts_with("VmRSS:") {
                        if let Some(kb_str) = line.split_whitespace().nth(1) {
                            if let Ok(kb) = kb_str.parse::<u64>() {
                                return kb / 1024;
                            }
                        }
                    }
                }
            }
        }

        #[cfg(target_os = "macos")]
        {
            use std::process::Command;
            if let Ok(output) = Command::new("ps")
                .args(["-o", "rss=", "-p", &std::process::id().to_string()])
                .output()
            {
                if let Ok(rss_str) = String::from_utf8(output.stdout) {
                    if let Ok(kb) = rss_str.trim().parse::<u64>() {
                        return kb / 1024;
                    }
                }
            }
        }

        0
    }
}

impl Default for HealthChecker {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_liveness_check() {
        let checker = HealthChecker::new();
        let status = checker.liveness();
        assert_eq!(status.status, "healthy");
        assert!(status.checks.contains_key("runtime"));
    }

    #[test]
    fn test_readiness_check() {
        let checker = HealthChecker::new();
        let status = checker.readiness();
        assert_eq!(status.status, "healthy");
        assert!(status.checks.contains_key("connections"));
        assert!(status.checks.contains_key("memory"));
    }

    #[test]
    fn test_detailed_check() {
        let checker = HealthChecker::new();
        checker.record_request();
        checker.record_connection_open();

        let status = checker.detailed();
        assert_eq!(status.status, "healthy");
        assert!(status.checks.contains_key("requests"));
        assert!(status.checks.contains_key("connections"));
    }

    #[test]
    fn test_error_recording() {
        let checker = HealthChecker::new();
        checker.record_error("test error");

        let status = checker.detailed();
        assert_eq!(status.status, "degraded");
        assert!(status.checks.contains_key("last_error"));
    }

    #[test]
    fn test_uptime_increases() {
        let checker = HealthChecker::new();
        let status1 = checker.liveness();
        std::thread::sleep(std::time::Duration::from_millis(10));
        let status2 = checker.liveness();
        assert!(status2.uptime_secs >= status1.uptime_secs);
    }
}
