//! Structured logging and tracing infrastructure for ferrumgate.
//!
//! This module provides a comprehensive logging system built on the `tracing`
//! ecosystem, offering:
//!
//! - Environment-aware subscriber configuration (JSON for production, pretty for dev)
//! - Request/response logging with latency tracking and slow request detection
//! - File-based logging with rotation policies (size and time-based)
//! - Integration with existing error types, metrics, and circuit breakers
//! - Request ID correlation across distributed log entries
//!
//! # Configuration
//!
//! Logging behavior is controlled via the `LoggingConfig` struct, which can be
//! loaded from environment variables or configuration files:
//!
//! ```rust
//! use ferrumgate::logging::{LoggingConfig, LogLevel, LogFormat, init_tracing};
//!
//! let config = LoggingConfig::builder()
//!     .level(LogLevel::Info)
//!     .format(LogFormat::Json)
//!     .file_output("/var/log/ferrumgate/server.log")
//!     .max_files(10)
//!     .max_file_size_mb(100)
//!     .slow_request_threshold_ms(500)
//!     .build();
//!
//! init_tracing(&config)?;
//! ```
//!
//! # Request Logging
//!
//! The `RequestLogMiddleware` automatically logs all requests passing through
//! the middleware chain, capturing method, path, status code, latency, and
//! request ID for correlation.
//!
//! # Log Rotation
//!
//! File-based loggers support both size-based and time-based rotation with
//! configurable retention policies. Rotated files are compressed using gzip
//! and stored alongside the active log file.

use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use thiserror::Error;
use tracing_subscriber::{
    fmt::{format::JsonFields, time::UtcTime},
    layer::SubscriberExt,
    util::SubscriberInitExt,
    EnvFilter, Layer,
};
use tracing::{info, warn, error, debug, trace, Span};

pub mod middleware;
pub mod rotation;
pub mod subscribers;

// Re-exports for convenience
pub use middleware::RequestLogMiddleware;
pub use rotation::{LogRotationConfig, LogRotationPolicy};
pub use subscribers::{SubscriberConfig, SubscriberType};

/// Logging-specific error types.
#[derive(Debug, Error)]
pub enum LoggingError {
    #[error("failed to initialize tracing subscriber: {0}")]
    SubscriberInit(String),

    #[error("invalid log level: {0}")]
    InvalidLogLevel(String),

    #[error("failed to create log directory: {path}")]
    LogDirectoryCreation { path: PathBuf },

    #[error("log rotation configuration error: {0}")]
    RotationConfig(String),

    #[error("file output path is not writable: {path}")]
    UnwritablePath { path: PathBuf },
}

/// Available log levels mapped to tracing equivalents.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum LogLevel {
    Trace,
    Debug,
    Info,
    Warn,
    Error,
}

impl LogLevel {
    /// Convert to the string representation expected by EnvFilter.
    pub fn as_str(&self) -> &'static str {
        match self {
            LogLevel::Trace => "trace",
            LogLevel::Debug => "debug",
            LogLevel::Info => "info",
            LogLevel::Warn => "warn",
            LogLevel::Error => "error",
        }
    }

    /// Parse from a string, case-insensitive.
    pub fn from_str(s: &str) -> Result<Self, LoggingError> {
        match s.to_lowercase().as_str() {
            "trace" => Ok(LogLevel::Trace),
            "debug" => Ok(LogLevel::Debug),
            "info" | "information" => Ok(LogLevel::Info),
            "warn" | "warning" => Ok(LogLevel::Warn),
            "error" => Ok(LogLevel::Error),
            _ => Err(LoggingError::InvalidLogLevel(s.to_string())),
        }
    }
}

impl Default for LogLevel {
    fn default() -> Self {
        LogLevel::Info
    }
}

/// Output format for log entries.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum LogFormat {
    /// Human-readable pretty format (development).
    Pretty,
    /// Compact JSON format (production).
    Json,
    /// Minimal format with only message and timestamp.
    Compact,
}

impl Default for LogFormat {
    fn default() -> Self {
        LogFormat::Pretty
    }
}

/// Time-based rotation policy for log files.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RotationSchedule {
    /// Rotate daily at midnight UTC.
    Daily,
    /// Rotate hourly.
    Hourly,
    /// Rotate every minute (testing only).
    Minutely,
    /// Never rotate based on time (size-based only).
    Never,
}

impl Default for RotationSchedule {
    fn default() -> Self {
        RotationSchedule::Daily
    }
}

/// Complete logging configuration.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct LoggingConfig {
    /// Minimum log level to emit.
    pub level: LogLevel,

    /// Output format for log entries.
    pub format: LogFormat,

    /// Optional file path for log output.
    /// If None, logs are written to stdout only.
    pub file_output: Option<PathBuf>,

    /// Maximum number of rotated log files to retain.
    pub max_files: usize,

    /// Maximum size of a single log file in MB before rotation.
    pub max_file_size_mb: u64,

    /// Time-based rotation schedule.
    pub rotation_schedule: RotationSchedule,

    /// Whether to include ANSI color codes in output.
    pub enable_colors: bool,

    /// Whether to include thread IDs in log entries.
    pub include_thread_ids: bool,

    /// Whether to include target module paths in log entries.
    pub include_targets: bool,

    /// Threshold in milliseconds for slow request detection.
    pub slow_request_threshold_ms: u64,

    /// Environment filter string (overrides level if set).
    pub env_filter: Option<String>,

    /// Whether to enable JSON field formatting for structured data.
    pub json_flatten_fields: bool,

    /// Whether to log the current span context with each event.
    pub log_span_context: bool,
}

impl LoggingConfig {
    /// Create a new builder for constructing a LoggingConfig.
    pub fn builder() -> LoggingConfigBuilder {
        LoggingConfigBuilder::default()
    }

    /// Load configuration from environment variables.
    ///
    /// Recognized variables:
    /// - `FERRUMGATE_LOG_LEVEL`: trace, debug, info, warn, error
    /// - `FERRUMGATE_LOG_FORMAT`: pretty, json, compact
    /// - `FERRUMGATE_LOG_FILE`: path to log file
    /// - `FERRUMGATE_LOG_MAX_FILES`: max rotated files to retain
    /// - `FERRUMGATE_LOG_MAX_SIZE_MB`: max file size before rotation
    /// - `FERRUMGATE_LOG_SLOW_THRESHOLD_MS`: slow request threshold
    pub fn from_env() -> Result<Self, LoggingError> {
        let mut builder = LoggingConfigBuilder::default();

        if let Ok(level) = std::env::var("FERRUMGATE_LOG_LEVEL") {
            builder = builder.level(LogLevel::from_str(&level)?);
        }

        if let Ok(format) = std::env::var("FERRUMGATE_LOG_FORMAT") {
            match format.to_lowercase().as_str() {
                "pretty" => builder = builder.format(LogFormat::Pretty),
                "json" => builder = builder.format(LogFormat::Json),
                "compact" => builder = builder.format(LogFormat::Compact),
                _ => {}
            }
        }

        if let Ok(file) = std::env::var("FERRUMGATE_LOG_FILE") {
            builder = builder.file_output(PathBuf::from(file));
        }

        if let Ok(max_files) = std::env::var("FERRUMGATE_LOG_MAX_FILES") {
            if let Ok(n) = max_files.parse::<usize>() {
                builder = builder.max_files(n);
            }
        }

        if let Ok(max_size) = std::env::var("FERRUMGATE_LOG_MAX_SIZE_MB") {
            if let Ok(n) = max_size.parse::<u64>() {
                builder = builder.max_file_size_mb(n);
            }
        }

        if let Ok(threshold) = std::env::var("FERRUMGATE_LOG_SLOW_THRESHOLD_MS") {
            if let Ok(n) = threshold.parse::<u64>() {
                builder = builder.slow_request_threshold_ms(n);
            }
        }

        Ok(builder.build())
    }

    /// Determine if this configuration targets production deployment.
    pub fn is_production(&self) -> bool {
        self.format == LogFormat::Json && self.file_output.is_some()
    }

    /// Get the effective EnvFilter string.
    pub fn env_filter_string(&self) -> String {
        self.env_filter
            .clone()
            .unwrap_or_else(|| format!("ferrumgate={}", self.level.as_str()))
    }
}

/// Builder for constructing LoggingConfig with fluent API.
#[derive(Debug, Default)]
pub struct LoggingConfigBuilder {
    level: LogLevel,
    format: LogFormat,
    file_output: Option<PathBuf>,
    max_files: usize,
    max_file_size_mb: u64,
    rotation_schedule: RotationSchedule,
    enable_colors: bool,
    include_thread_ids: bool,
    include_targets: bool,
    slow_request_threshold_ms: u64,
    env_filter: Option<String>,
    json_flatten_fields: bool,
    log_span_context: bool,
}

impl LoggingConfigBuilder {
    pub fn level(mut self, level: LogLevel) -> Self {
        self.level = level;
        self
    }

    pub fn format(mut self, format: LogFormat) -> Self {
        self.format = format;
        self
    }

    pub fn file_output(mut self, path: PathBuf) -> Self {
        self.file_output = Some(path);
        self
    }

    pub fn max_files(mut self, n: usize) -> Self {
        self.max_files = n;
        self
    }

    pub fn max_file_size_mb(mut self, mb: u64) -> Self {
        self.max_file_size_mb = mb;
        self
    }

    pub fn rotation_schedule(mut self, schedule: RotationSchedule) -> Self {
        self.rotation_schedule = schedule;
        self
    }

    pub fn enable_colors(mut self, enabled: bool) -> Self {
        self.enable_colors = enabled;
        self
    }

    pub fn include_thread_ids(mut self, enabled: bool) -> Self {
        self.include_thread_ids = enabled;
        self
    }

    pub fn include_targets(mut self, enabled: bool) -> Self {
        self.include_targets = enabled;
        self
    }

    pub fn slow_request_threshold_ms(mut self, ms: u64) -> Self {
        self.slow_request_threshold_ms = ms;
        self
    }

    pub fn env_filter(mut self, filter: String) -> Self {
        self.env_filter = Some(filter);
        self
    }

    pub fn json_flatten_fields(mut self, enabled: bool) -> Self {
        self.json_flatten_fields = enabled;
        self
    }

    pub fn log_span_context(mut self, enabled: bool) -> Self {
        self.log_span_context = enabled;
        self
    }

    pub fn build(self) -> LoggingConfig {
        LoggingConfig {
            level: self.level,
            format: self.format,
            file_output: self.file_output,
            max_files: if self.max_files == 0 { 10 } else { self.max_files },
            max_file_size_mb: if self.max_file_size_mb == 0 {
                100
            } else {
                self.max_file_size_mb
            },
            rotation_schedule: self.rotation_schedule,
            enable_colors: self.enable_colors,
            include_thread_ids: self.include_thread_ids,
            include_targets: self.include_targets,
            slow_request_threshold_ms: if self.slow_request_threshold_ms == 0 {
                500
            } else {
                self.slow_request_threshold_ms
            },
            env_filter: self.env_filter,
            json_flatten_fields: self.json_flatten_fields,
            log_span_context: self.log_span_context,
        }
    }
}

/// Initialize the global tracing subscriber with the given configuration.
///
/// This function should be called once at application startup, before any
/// other logging occurs. It configures the subscriber based on the provided
/// LoggingConfig, setting up appropriate layers for output format, file
/// rotation, and environment filtering.
///
/// # Errors
///
/// Returns a `LoggingError` if:
/// - The log directory cannot be created
/// - The log file path is not writable
/// - The tracing subscriber fails to initialize
pub fn init_tracing(config: &LoggingConfig) -> Result<(), LoggingError> {
    // Validate and create log directory if file output is configured
    if let Some(ref path) = config.file_output {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(|_| LoggingError::LogDirectoryCreation {
                path: parent.to_path_buf(),
            })?;
        }

        // Verify writability
        if let Err(e) = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
        {
            return Err(LoggingError::UnwritablePath {
                path: path.clone(),
            });
        }
    }

    // Build the EnvFilter layer
    let env_filter = EnvFilter::try_new(config.env_filter_string())
        .unwrap_or_else(|_| EnvFilter::new("ferrumgate=info"));

    // Build subscriber stack based on configuration
    match config.format {
        LogFormat::Json => {
            let json_layer = subscribers::build_json_layer(config)?;
            let file_layer = if config.file_output.is_some() {
                Some(subscribers::build_file_json_layer(config)?)
            } else {
                None
            };

            let subscriber = tracing_subscriber::registry()
                .with(env_filter)
                .with(json_layer)
                .with(file_layer);

            subscriber.init();
        }
        LogFormat::Pretty => {
            let pretty_layer = subscribers::build_pretty_layer(config)?;
            let file_layer = if config.file_output.is_some() {
                Some(subscribers::build_file_pretty_layer(config)?)
            } else {
                None
            };

            let subscriber = tracing_subscriber::registry()
                .with(env_filter)
                .with(pretty_layer)
                .with(file_layer);

            subscriber.init();
        }
        LogFormat::Compact => {
            let compact_layer = subscribers::build_compact_layer(config)?;
            let file_layer = if config.file_output.is_some() {
                Some(subscribers::build_file_compact_layer(config)?)
            } else {
                None
            };

            let subscriber = tracing_subscriber::registry()
                .with(env_filter)
                .with(compact_layer)
                .with(file_layer);

            subscriber.init();
        }
    }

    info!(
        level = config.level.as_str(),
        format = ?config.format,
        file_output = ?config.file_output,
        slow_threshold_ms = config.slow_request_threshold_ms,
        "tracing subscriber initialized"
    );

    Ok(())
}

/// Log a session lifecycle event with structured context.
pub fn log_session_event(event: &str, session_id: &str, details: &str) {
    info!(
        event = event,
        session_id = session_id,
        component = "session",
        details = details,
        "session lifecycle event"
    );
}

/// Log a connection pool operation with metrics.
pub fn log_pool_event(
    operation: &str,
    pool_name: &str,
    active_connections: usize,
    idle_connections: usize,
    max_connections: usize,
) {
    debug!(
        operation = operation,
        pool = pool_name,
        active = active_connections,
        idle = idle_connections,
        max = max_connections,
        utilization_pct = format!("{:.1}", (active_connections as f64 / max_connections as f64) * 100.0),
        "connection pool event"
    );
}

/// Log a circuit breaker state transition.
pub fn log_circuit_breaker_event(
    service: &str,
    old_state: &str,
    new_state: &str,
    failure_count: u64,
    success_count: u64,
) {
    warn!(
        service = service,
        old_state = old_state,
        new_state = new_state,
        failures = failure_count,
        successes = success_count,
        component = "circuit_breaker",
        "circuit breaker state transition"
    );
}

/// Log an error with full context for debugging.
pub fn log_error_with_context(
    error: &dyn std::error::Error,
    context: &str,
    operation: &str,
    recoverable: bool,
) {
    let mut chain = Vec::new();
    let mut source = Some(error);
    while let Some(e) = source {
        chain.push(e.to_string());
        source = e.source();
    }

    if recoverable {
        warn!(
            error_chain = ?chain,
            context = context,
            operation = operation,
            recoverable = true,
            component = "error_handler",
            "recoverable error occurred"
        );
    } else {
        error!(
            error_chain = ?chain,
            context = context,
            operation = operation,
            recoverable = false,
            component = "error_handler",
            "unrecoverable error occurred"
        );
    }
}

/// Global counter for total requests logged.
static TOTAL_REQUESTS_LOGGED: AtomicU64 = AtomicU64::new(0);

/// Get the total number of requests that have been logged.
pub fn total_requests_logged() -> u64 {
    TOTAL_REQUESTS_LOGGED.load(Ordering::Relaxed)
}

/// Increment the total requests logged counter.
pub fn increment_requests_logged() {
    TOTAL_REQUESTS_LOGGED.fetch_add(1, Ordering::Relaxed);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_log_level_from_str() {
        assert_eq!(LogLevel::from_str("trace").unwrap(), LogLevel::Trace);
        assert_eq!(LogLevel::from_str("DEBUG").unwrap(), LogLevel::Debug);
        assert_eq!(LogLevel::from_str("Info").unwrap(), LogLevel::Info);
        assert_eq!(LogLevel::from_str("WARN").unwrap(), LogLevel::Warn);
        assert_eq!(LogLevel::from_str("error").unwrap(), LogLevel::Error);
        assert_eq!(LogLevel::from_str("information").unwrap(), LogLevel::Info);
        assert_eq!(LogLevel::from_str("warning").unwrap(), LogLevel::Warn);
    }

    #[test]
    fn test_log_level_from_str_invalid() {
        assert!(LogLevel::from_str("verbose").is_err());
        assert!(LogLevel::from_str("critical").is_err());
        assert!(LogLevel::from_str("").is_err());
    }

    #[test]
    fn test_log_level_as_str() {
        assert_eq!(LogLevel::Trace.as_str(), "trace");
        assert_eq!(LogLevel::Debug.as_str(), "debug");
        assert_eq!(LogLevel::Info.as_str(), "info");
        assert_eq!(LogLevel::Warn.as_str(), "warn");
        assert_eq!(LogLevel::Error.as_str(), "error");
    }

    #[test]
    fn test_logging_config_builder_defaults() {
        let config = LoggingConfig::builder().build();
        assert_eq!(config.level, LogLevel::Info);
        assert_eq!(config.format, LogFormat::Pretty);
        assert_eq!(config.max_files, 10);
        assert_eq!(config.max_file_size_mb, 100);
        assert_eq!(config.slow_request_threshold_ms, 500);
        assert!(config.file_output.is_none());
        assert!(config.env_filter.is_none());
    }

    #[test]
    fn test_logging_config_builder_custom() {
        let config = LoggingConfig::builder()
            .level(LogLevel::Debug)
            .format(LogFormat::Json)
            .file_output(PathBuf::from("/tmp/test.log"))
            .max_files(5)
            .max_file_size_mb(50)
            .slow_request_threshold_ms(1000)
            .enable_colors(false)
            .include_thread_ids(true)
            .build();

        assert_eq!(config.level, LogLevel::Debug);
        assert_eq!(config.format, LogFormat::Json);
        assert_eq!(config.file_output, Some(PathBuf::from("/tmp/test.log")));
        assert_eq!(config.max_files, 5);
        assert_eq!(config.max_file_size_mb, 50);
        assert_eq!(config.slow_request_threshold_ms, 1000);
        assert!(!config.enable_colors);
        assert!(config.include_thread_ids);
    }

    #[test]
    fn test_logging_config_is_production() {
        let dev_config = LoggingConfig::builder()
            .format(LogFormat::Pretty)
            .build();
        assert!(!dev_config.is_production());

        let prod_config = LoggingConfig::builder()
            .format(LogFormat::Json)
            .file_output(PathBuf::from("/var/log/app.log"))
            .build();
        assert!(prod_config.is_production());

        let json_stdout = LoggingConfig::builder()
            .format(LogFormat::Json)
            .build();
        assert!(!json_stdout.is_production());
    }

    #[test]
    fn test_logging_config_env_filter_string() {
        let config = LoggingConfig::builder()
            .level(LogLevel::Debug)
            .build();
        assert_eq!(config.env_filter_string(), "ferrumgate=debug");

        let config = LoggingConfig::builder()
            .env_filter("ferrumgate=trace,hyper=warn".to_string())
            .build();
        assert_eq!(config.env_filter_string(), "ferrumgate=trace,hyper=warn");
    }

    #[test]
    fn test_rotation_schedule_defaults() {
        assert_eq!(RotationSchedule::default(), RotationSchedule::Daily);
    }

    #[test]
    fn test_log_format_defaults() {
        assert_eq!(LogFormat::default(), LogFormat::Pretty);
    }

    #[test]
    fn test_log_level_defaults() {
        assert_eq!(LogLevel::default(), LogLevel::Info);
    }

    #[test]
    fn test_request_counter() {
        let initial = total_requests_logged();
        increment_requests_logged();
        increment_requests_logged();
        increment_requests_logged();
        assert_eq!(total_requests_logged(), initial + 3);
    }

    #[test]
    fn test_logging_config_serialization() {
        let config = LoggingConfig::builder()
            .level(LogLevel::Warn)
            .format(LogFormat::Json)
            .max_files(7)
            .build();

        let json = serde_json::to_string(&config).unwrap();
        let deserialized: LoggingConfig = serde_json::from_str(&json).unwrap();

        assert_eq!(deserialized.level, LogLevel::Warn);
        assert_eq!(deserialized.format, LogFormat::Json);
        assert_eq!(deserialized.max_files, 7);
    }
}
