//! Request logging middleware for the middleware chain.
//!
//! This module provides middleware that automatically logs all requests
//! passing through the middleware chain, capturing:
//!
//! - HTTP method and request path
//! - Response status code
//! - Request latency (total, connect, and processing time)
//! - Request ID for correlation across log entries
//! - Slow request detection with configurable thresholds
//! - Error context for failed requests
//!
//! # Request Lifecycle
//!
//! The middleware captures the following lifecycle events:
//!
//! 1. **Request Start**: When a request enters the middleware chain
//! 2. **Request Complete**: When a request exits with a response
//! 3. **Slow Request**: When a request exceeds the configured threshold
//! 4. **Error**: When a request fails with an error status
//!
//! # Log Entry Format
//!
//! Each request produces a structured log entry with the following fields:
//!
//! ```json
//! {
//!   "timestamp": "2024-01-15T10:30:00.000Z",
//!   "level": "info",
//!   "message": "request completed",
//!   "method": "GET",
//!   "path": "/api/v1/sessions",
//!   "status": 200,
//!   "latency_ms": 45,
//!   "request_id": "550e8400-e29b-41d4-a716-446655440000",
//!   "component": "request_logger",
//!   "slow": false
//! }
//! ```
//!
//! # Slow Request Detection
//!
//! Requests that exceed the configured `slow_request_threshold_ms` are logged
//! at WARN level instead of INFO, making them easier to identify in log
//! aggregation systems. The threshold is configurable per deployment.
//!
//! # Integration
//!
//! This middleware integrates with:
//! - The existing middleware chain architecture
//! - Request ID generation middleware
//! - Prometheus metrics for request latency histograms
//! - Circuit breaker state tracking

use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use tracing::{info, warn, error, debug, Span};

use crate::middleware::{Middleware, MiddlewareChain, MiddlewareContext, MiddlewareResult};
use crate::logging::{increment_requests_logged, LoggingConfig};

/// Metrics counters for request logging.
static TOTAL_REQUESTS: AtomicU64 = AtomicU64::new(0);
static TOTAL_SLOW_REQUESTS: AtomicU64 = AtomicU64::new(0);
static TOTAL_ERRORS: AtomicU64 = AtomicU64::new(0);
static TOTAL_LATENCY_MS: AtomicU64 = AtomicU64::new(0);

/// Request logging middleware that captures request/response lifecycle events.
///
/// This middleware wraps the inner middleware chain and logs:
/// - Request method and path
/// - Response status code
/// - Total request latency
/// - Whether the request was slow
/// - Error context for failed requests
///
/// # Example
///
/// ```rust
/// use ferrumgate::logging::middleware::RequestLogMiddleware;
/// use ferrumgate::middleware::MiddlewareChain;
///
/// let config = LoggingConfig::builder()
///     .slow_request_threshold_ms(500)
///     .build();
///
/// let logger = RequestLogMiddleware::new(config);
/// chain.add(Box::new(logger));
/// ```
#[derive(Debug)]
pub struct RequestLogMiddleware {
    /// Threshold in milliseconds for slow request detection.
    slow_threshold_ms: u64,

    /// Whether to log request headers.
    log_headers: bool,

    /// Whether to log response body size.
    log_response_size: bool,

    /// Paths to exclude from logging (e.g., health checks).
    excluded_paths: Vec<String>,

    /// Paths to always log at DEBUG level regardless of status.
    debug_paths: Vec<String>,
}

impl RequestLogMiddleware {
    /// Create a new request logging middleware with the given configuration.
    pub fn new(config: LoggingConfig) -> Self {
        Self {
            slow_threshold_ms: config.slow_request_threshold_ms,
            log_headers: false,
            log_response_size: true,
            excluded_paths: vec![
                "/health".to_string(),
                "/health/live".to_string(),
                "/health/ready".to_string(),
                "/metrics".to_string(),
                "/favicon.ico".to_string(),
            ],
            debug_paths: vec![
                "/health".to_string(),
                "/health/live".to_string(),
                "/health/ready".to_string(),
            ],
        }
    }

    /// Create a new request logging middleware with custom configuration.
    pub fn with_config(
        slow_threshold_ms: u64,
        log_headers: bool,
        log_response_size: bool,
        excluded_paths: Vec<String>,
        debug_paths: Vec<String>,
    ) -> Self {
        Self {
            slow_threshold_ms,
            log_headers,
            log_response_size,
            excluded_paths,
            debug_paths,
        }
    }

    /// Check if a path should be excluded from logging.
    fn is_excluded(&self, path: &str) -> bool {
        self.excluded_paths.iter().any(|p| path.starts_with(p.as_str()))
    }

    /// Check if a path should always be logged at DEBUG level.
    fn is_debug_path(&self, path: &str) -> bool {
        self.debug_paths.iter().any(|p| path.starts_with(p.as_str()))
    }

    /// Determine the appropriate log level for a request.
    fn log_level_for_status(&self, status: u16, path: &str) -> &'static str {
        if self.is_debug_path(path) {
            return "debug";
        }

        if status >= 500 {
            "error"
        } else if status >= 400 {
            "warn"
        } else {
            "info"
        }
    }

    /// Format latency as a human-readable string.
    fn format_latency(duration: Duration) -> String {
        let ms = duration.as_millis();
        if ms < 1 {
            format!("{}µs", duration.as_micros())
        } else if ms < 1000 {
            format!("{}ms", ms)
        } else {
            format!("{:.2}s", duration.as_secs_f64())
        }
    }

    /// Get request logging metrics.
    pub fn get_metrics() -> RequestLogMetrics {
        RequestLogMetrics {
            total_requests: TOTAL_REQUESTS.load(Ordering::Relaxed),
            total_slow_requests: TOTAL_SLOW_REQUESTS.load(Ordering::Relaxed),
            total_errors: TOTAL_ERRORS.load(Ordering::Relaxed),
            total_latency_ms: TOTAL_LATENCY_MS.load(Ordering::Relaxed),
            avg_latency_ms: {
                let total = TOTAL_REQUESTS.load(Ordering::Relaxed);
                if total == 0 {
                    0.0
                } else {
                    TOTAL_LATENCY_MS.load(Ordering::Relaxed) as f64 / total as f64
                }
            },
        }
    }

    /// Reset all request logging metrics.
    pub fn reset_metrics() {
        TOTAL_REQUESTS.store(0, Ordering::Relaxed);
        TOTAL_SLOW_REQUESTS.store(0, Ordering::Relaxed);
        TOTAL_ERRORS.store(0, Ordering::Relaxed);
        TOTAL_LATENCY_MS.store(0, Ordering::Relaxed);
    }
}

/// Metrics snapshot for request logging.
#[derive(Debug, Clone)]
pub struct RequestLogMetrics {
    pub total_requests: u64,
    pub total_slow_requests: u64,
    pub total_errors: u64,
    pub total_latency_ms: u64,
    pub avg_latency_ms: f64,
}

impl Middleware for RequestLogMiddleware {
    fn name(&self) -> &str {
        "RequestLogger"
    }

    fn execute<'a>(
        &'a self,
        ctx: &'a mut MiddlewareContext,
        next: Pin<Box<dyn Future<Output = MiddlewareResult> + Send + 'a>>,
    ) -> Pin<Box<dyn Future<Output = MiddlewareResult> + Send + 'a>> {
        Box::pin(async move {
            let start = Instant::now();
            let path = ctx.request.path.clone();
            let method = ctx.request.method.clone();
            let request_id = ctx.request.id.clone();

            // Skip logging for excluded paths
            if self.is_excluded(&path) {
                debug!(
                    method = %method,
                    path = %path,
                    request_id = %request_id,
                    component = "request_logger",
                    "request skipped (excluded path)"
                );
                return next.await;
            }

            // Log request start
            debug!(
                method = %method,
                path = %path,
                request_id = %request_id,
                component = "request_logger",
                "request started"
            );

            // Execute the inner middleware chain
            let result = next.await;

            let elapsed = start.elapsed();
            let latency_ms = elapsed.as_millis() as u64;
            let is_slow = latency_ms > self.slow_threshold_ms;

            // Update metrics
            TOTAL_REQUESTS.fetch_add(1, Ordering::Relaxed);
            TOTAL_LATENCY_MS.fetch_add(latency_ms, Ordering::Relaxed);
            increment_requests_logged();

            if is_slow {
                TOTAL_SLOW_REQUESTS.fetch_add(1, Ordering::Relaxed);
            }

            // Extract status code from response
            let status = result.as_ref().map(|r| r.status).unwrap_or(0);

            if status >= 500 {
                TOTAL_ERRORS.fetch_add(1, Ordering::Relaxed);
            }

            // Determine log level
            let level = self.log_level_for_status(status, &path);

            // Build the log entry
            let latency_str = Self::format_latency(elapsed);

            match level {
                "error" => {
                    error!(
                        method = %method,
                        path = %path,
                        status = status,
                        latency_ms = latency_ms,
                        latency = latency_str,
                        request_id = %request_id,
                        slow = is_slow,
                        component = "request_logger",
                        "request failed"
                    );
                }
                "warn" => {
                    if is_slow {
                        warn!(
                            method = %method,
                            path = %path,
                            status = status,
                            latency_ms = latency_ms,
                            latency = latency_str,
                            request_id = %request_id,
                            slow = true,
                            component = "request_logger",
                            "slow request completed"
                        );
                    } else {
                        warn!(
                            method = %method,
                            path = %path,
                            status = status,
                            latency_ms = latency_ms,
                            latency = latency_str,
                            request_id = %request_id,
                            slow = false,
                            component = "request_logger",
                            "request completed with client error"
                        );
                    }
                }
                "info" => {
                    if is_slow {
                        warn!(
                            method = %method,
                            path = %path,
                            status = status,
                            latency_ms = latency_ms,
                            latency = latency_str,
                            request_id = %request_id,
                            slow = true,
                            component = "request_logger",
                            "slow request completed"
                        );
                    } else {
                        info!(
                            method = %method,
                            path = %path,
                            status = status,
                            latency_ms = latency_ms,
                            latency = latency_str,
                            request_id = %request_id,
                            slow = false,
                            component = "request_logger",
                            "request completed"
                        );
                    }
                }
                "debug" => {
                    debug!(
                        method = %method,
                        path = %path,
                        status = status,
                        latency_ms = latency_ms,
                        latency = latency_str,
                        request_id = %request_id,
                        slow = is_slow,
                        component = "request_logger",
                        "health check completed"
                    );
                }
                _ => {}
            }

            result
        })
    }

    fn priority(&self) -> u8 {
        // Low priority so this runs outermost (first in, last out)
        0
    }
}

/// Middleware that logs errors with full context for debugging.
#[derive(Debug, Default)]
pub struct ErrorLogMiddleware;

impl ErrorLogMiddleware {
    pub fn new() -> Self {
        Self
    }
}

impl Middleware for ErrorLogMiddleware {
    fn name(&self) -> &str {
        "ErrorLogger"
    }

    fn execute<'a>(
        &'a self,
        ctx: &'a mut MiddlewareContext,
        next: Pin<Box<dyn Future<Output = MiddlewareResult> + Send + 'a>>,
    ) -> Pin<Box<dyn Future<Output = MiddlewareResult> + Send + 'a>> {
        Box::pin(async move {
            let result = next.await;

            if let Err(ref e) = result {
                error!(
                    error = %e,
                    method = %ctx.request.method,
                    path = %ctx.request.path,
                    request_id = %ctx.request.id,
                    component = "error_logger",
                    "middleware error occurred"
                );
            }

            result
        })
    }

    fn priority(&self) -> u8 {
        1
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_request_log_middleware_creation() {
        let config = LoggingConfig::builder()
            .slow_request_threshold_ms(1000)
            .build();

        let middleware = RequestLogMiddleware::new(config);
        assert_eq!(middleware.slow_threshold_ms, 1000);
        assert_eq!(middleware.name(), "RequestLogger");
        assert_eq!(middleware.priority(), 0);
    }

    #[test]
    fn test_request_log_middleware_custom_config() {
        let middleware = RequestLogMiddleware::with_config(
            2000,
            true,
            false,
            vec!["/ping".to_string()],
            vec!["/status".to_string()],
        );

        assert_eq!(middleware.slow_threshold_ms, 2000);
        assert!(middleware.log_headers);
        assert!(!middleware.log_response_size);
        assert!(middleware.is_excluded("/ping"));
        assert!(middleware.is_debug_path("/status"));
    }

    #[test]
    fn test_excluded_paths() {
        let config = LoggingConfig::builder().build();
        let middleware = RequestLogMiddleware::new(config);

        assert!(middleware.is_excluded("/health"));
        assert!(middleware.is_excluded("/health/live"));
        assert!(middleware.is_excluded("/health/ready"));
        assert!(middleware.is_excluded("/metrics"));
        assert!(middleware.is_excluded("/favicon.ico"));
        assert!(!middleware.is_excluded("/api/v1/sessions"));
    }

    #[test]
    fn test_debug_paths() {
        let config = LoggingConfig::builder().build();
        let middleware = RequestLogMiddleware::new(config);

        assert!(middleware.is_debug_path("/health"));
        assert!(middleware.is_debug_path("/health/live"));
        assert!(!middleware.is_debug_path("/api/v1/sessions"));
    }

    #[test]
    fn test_log_level_for_status() {
        let config = LoggingConfig::builder().build();
        let middleware = RequestLogMiddleware::new(config);

        assert_eq!(middleware.log_level_for_status(200, "/api"), "info");
        assert_eq!(middleware.log_level_for_status(201, "/api"), "info");
        assert_eq!(middleware.log_level_for_status(301, "/api"), "info");
        assert_eq!(middleware.log_level_for_status(400, "/api"), "warn");
        assert_eq!(middleware.log_level_for_status(404, "/api"), "warn");
        assert_eq!(middleware.log_level_for_status(500, "/api"), "error");
        assert_eq!(middleware.log_level_for_status(503, "/api"), "error");

        // Debug paths override status-based level
        assert_eq!(middleware.log_level_for_status(200, "/health"), "debug");
        assert_eq!(middleware.log_level_for_status(500, "/health"), "debug");
    }

    #[test]
    fn test_format_latency() {
        assert_eq!(RequestLogMiddleware::format_latency(Duration::from_micros(500)), "500µs");
        assert_eq!(RequestLogMiddleware::format_latency(Duration::from_millis(1)), "1ms");
        assert_eq!(RequestLogMiddleware::format_latency(Duration::from_millis(45)), "45ms");
        assert_eq!(RequestLogMiddleware::format_latency(Duration::from_millis(999)), "999ms");
        assert_eq!(RequestLogMiddleware::format_latency(Duration::from_millis(1500)), "1.50s");
        assert_eq!(RequestLogMiddleware::format_latency(Duration::from_secs(5)), "5.00s");
    }

    #[test]
    fn test_metrics_initial_state() {
        RequestLogMiddleware::reset_metrics();
        let metrics = RequestLogMiddleware::get_metrics();
        assert_eq!(metrics.total_requests, 0);
        assert_eq!(metrics.total_slow_requests, 0);
        assert_eq!(metrics.total_errors, 0);
        assert_eq!(metrics.total_latency_ms, 0);
        assert_eq!(metrics.avg_latency_ms, 0.0);
    }

    #[test]
    fn test_metrics_after_requests() {
        RequestLogMiddleware::reset_metrics();
        TOTAL_REQUESTS.fetch_add(10, Ordering::Relaxed);
        TOTAL_LATENCY_MS.fetch_add(5000, Ordering::Relaxed);

        let metrics = RequestLogMiddleware::get_metrics();
        assert_eq!(metrics.total_requests, 10);
        assert_eq!(metrics.avg_latency_ms, 500.0);
    }

    #[test]
    fn test_error_log_middleware_creation() {
        let middleware = ErrorLogMiddleware::new();
        assert_eq!(middleware.name(), "ErrorLogger");
        assert_eq!(middleware.priority(), 1);
    }
}
