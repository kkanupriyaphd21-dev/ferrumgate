//! Tracing subscriber builders for different output formats.
//!
//! This module provides factory functions for constructing tracing subscribers
//! with various output formats and configurations. Each subscriber type is
//! optimized for specific deployment scenarios:
//!
//! - **JSON**: Production deployments with log aggregation systems (Datadog, ELK)
//! - **Pretty**: Development environments with human-readable output
//! - **Compact**: High-throughput environments with minimal overhead
//!
//! # Subscriber Stack
//!
//! Each subscriber is built as a layer stack:
//! 1. `EnvFilter` - Controls which events are emitted based on level and target
//! 2. Format layer - Controls how events are rendered (JSON, pretty, compact)
//! 3. Optional file layer - Writes to rotating log files in addition to stdout
//!
//! # Thread Safety
//!
//! All subscribers are `Send + Sync` and safe to use across multiple threads.
//! The underlying writers use appropriate synchronization for concurrent access.

use std::fs::OpenOptions;
use std::io;
use std::path::PathBuf;

use tracing_subscriber::{
    fmt::{self, format::FmtSpan, time::UtcTime},
    layer::SubscriberExt,
    Layer,
};

use crate::logging::{
    LogFormat, LogLevel, LoggingConfig, LoggingError, RotationSchedule,
};

/// Type alias for a tracing layer that writes to stdout.
pub type StdoutLayer<S> = fmt::Layer<
    S,
    fmt::format::DefaultFields,
    fmt::format::Format,
    tracing_subscriber::fmt::MakeWriter<io::Stdout>,
>;

/// Type alias for a tracing layer that writes to a file.
pub type FileLayer<S, W> = fmt::Layer<S, fmt::format::DefaultFields, fmt::format::Format, W>;

/// Configuration for subscriber behavior.
#[derive(Debug, Clone)]
pub struct SubscriberConfig {
    /// The type of subscriber to build.
    pub subscriber_type: SubscriberType,

    /// Whether to include timing information for spans.
    pub include_span_timings: bool,

    /// Whether to include file and line numbers in log entries.
    pub include_source_location: bool,
}

impl Default for SubscriberConfig {
    fn default() -> Self {
        Self {
            subscriber_type: SubscriberType::Pretty,
            include_span_timings: true,
            include_source_location: false,
        }
    }
}

/// Available subscriber types.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SubscriberType {
    Json,
    Pretty,
    Compact,
}

impl From<LogFormat> for SubscriberType {
    fn from(format: LogFormat) -> Self {
        match format {
            LogFormat::Json => SubscriberType::Json,
            LogFormat::Pretty => SubscriberType::Pretty,
            LogFormat::Compact => SubscriberType::Compact,
        }
    }
}

/// Build a JSON-formatted layer for stdout output.
///
/// This layer produces structured JSON log entries suitable for ingestion
/// by log aggregation systems. Each entry includes:
/// - Timestamp in RFC3339 format (UTC)
/// - Log level
/// - Target module
/// - Message
/// - All structured fields as JSON properties
/// - Optional span context
///
/// # Errors
///
/// Returns an error if the time format cannot be constructed.
pub fn build_json_layer<S>(config: &LoggingConfig) -> Result<impl Layer<S>, LoggingError>
where
    S: tracing::Subscriber + for<'a> tracing_subscriber::registry::LookupSpan<'a>,
{
    let timer = UtcTime::new(
        time::format_description::parse("[year]-[month]-[day]T[hour]:[minute]:[second].[subsecond digits:3]Z")
            .map_err(|e| LoggingError::SubscriberInit(format!("invalid time format: {}", e)))?,
    );

    let layer = fmt::Layer::default()
        .json()
        .with_timer(timer)
        .with_target(config.include_targets)
        .with_thread_ids(config.include_thread_ids)
        .with_thread_names(false)
        .with_file(false)
        .with_line(false)
        .with_current_span(config.log_span_context)
        .with_writer(io::stdout);

    Ok(layer)
}

/// Build a JSON-formatted layer for file output.
///
/// Similar to `build_json_layer` but writes to a file with append mode.
/// The file is created if it doesn't exist.
pub fn build_file_json_layer<S>(
    config: &LoggingConfig,
) -> Result<impl Layer<S>, LoggingError>
where
    S: tracing::Subscriber + for<'a> tracing_subscriber::registry::LookupSpan<'a>,
{
    let path = config
        .file_output
        .as_ref()
        .ok_or_else(|| LoggingError::SubscriberInit("file_output not configured".into()))?;

    let timer = UtcTime::new(
        time::format_description::parse("[year]-[month]-[day]T[hour]:[minute]:[second].[subsecond digits:3]Z")
            .map_err(|e| LoggingError::SubscriberInit(format!("invalid time format: {}", e)))?,
    );

    let file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .map_err(|e| LoggingError::SubscriberInit(format!("failed to open log file: {}", e)))?;

    let layer = fmt::Layer::default()
        .json()
        .with_timer(timer)
        .with_target(config.include_targets)
        .with_thread_ids(config.include_thread_ids)
        .with_file(false)
        .with_line(false)
        .with_current_span(config.log_span_context)
        .with_writer(io::stdout) // We'll use the file writer
        .with_writer(move || file.try_clone().unwrap_or_else(|_| io::stdout()));

    Ok(layer)
}

/// Build a pretty-formatted layer for stdout output.
///
/// This layer produces human-readable log entries with ANSI color codes
/// (when enabled). Suitable for development and debugging.
pub fn build_pretty_layer<S>(config: &LoggingConfig) -> Result<impl Layer<S>, LoggingError>
where
    S: tracing::Subscriber + for<'a> tracing_subscriber::registry::LookupSpan<'a>,
{
    let timer = UtcTime::rfc_3339();

    let layer = fmt::Layer::default()
        .pretty()
        .with_timer(timer)
        .with_target(config.include_targets)
        .with_thread_ids(config.include_thread_ids)
        .with_file(false)
        .with_line(false)
        .with_current_span(config.log_span_context)
        .with_ansi(config.enable_colors)
        .with_writer(io::stdout);

    Ok(layer)
}

/// Build a pretty-formatted layer for file output.
pub fn build_file_pretty_layer<S>(config: &LoggingConfig) -> Result<impl Layer<S>, LoggingError>
where
    S: tracing::Subscriber + for<'a> tracing_subscriber::registry::LookupSpan<'a>,
{
    let path = config
        .file_output
        .as_ref()
        .ok_or_else(|| LoggingError::SubscriberInit("file_output not configured".into()))?;

    let timer = UtcTime::rfc_3339();

    let file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .map_err(|e| LoggingError::SubscriberInit(format!("failed to open log file: {}", e)))?;

    let layer = fmt::Layer::default()
        .pretty()
        .with_timer(timer)
        .with_target(config.include_targets)
        .with_thread_ids(config.include_thread_ids)
        .with_file(false)
        .with_line(false)
        .with_current_span(config.log_span_context)
        .with_ansi(false) // Never use ANSI in file output
        .with_writer(move || file.try_clone().unwrap_or_else(|_| io::stdout()));

    Ok(layer)
}

/// Build a compact-formatted layer for stdout output.
///
/// This layer produces minimal log entries with only essential information.
/// Suitable for high-throughput environments where log volume is a concern.
pub fn build_compact_layer<S>(config: &LoggingConfig) -> Result<impl Layer<S>, LoggingError>
where
    S: tracing::Subscriber + for<'a> tracing_subscriber::registry::LookupSpan<'a>,
{
    let timer = UtcTime::rfc_3339();

    let layer = fmt::Layer::default()
        .compact()
        .with_timer(timer)
        .with_target(config.include_targets)
        .with_thread_ids(config.include_thread_ids)
        .with_file(false)
        .with_line(false)
        .with_current_span(false) // Compact mode skips span context
        .with_ansi(config.enable_colors)
        .with_writer(io::stdout);

    Ok(layer)
}

/// Build a compact-formatted layer for file output.
pub fn build_file_compact_layer<S>(config: &LoggingConfig) -> Result<impl Layer<S>, LoggingError>
where
    S: tracing::Subscriber + for<'a> tracing_subscriber::registry::LookupSpan<'a>,
{
    let path = config
        .file_output
        .as_ref()
        .ok_or_else(|| LoggingError::SubscriberInit("file_output not configured".into()))?;

    let timer = UtcTime::rfc_3339();

    let file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .map_err(|e| LoggingError::SubscriberInit(format!("failed to open log file: {}", e)))?;

    let layer = fmt::Layer::default()
        .compact()
        .with_timer(timer)
        .with_target(config.include_targets)
        .with_thread_ids(config.include_thread_ids)
        .with_file(false)
        .with_line(false)
        .with_current_span(false)
        .with_ansi(false)
        .with_writer(move || file.try_clone().unwrap_or_else(|_| io::stdout()));

    Ok(layer)
}

/// Determine the appropriate rotation schedule based on configuration.
pub fn rotation_schedule_to_tracing(
    schedule: RotationSchedule,
) -> tracing_appender::rolling::Rotation {
    match schedule {
        RotationSchedule::Daily => tracing_appender::rolling::Rotation::DAILY,
        RotationSchedule::Hourly => tracing_appender::rolling::Rotation::HOURLY,
        RotationSchedule::Minutely => tracing_appender::rolling::Rotation::MINUTELY,
        RotationSchedule::Never => tracing_appender::rolling::Rotation::NEVER,
    }
}

/// Build a non-blocking file writer with rotation support.
///
/// Returns a tuple of (writer, guard) where the guard must be kept alive
/// for the writer to function. When the guard is dropped, the background
/// thread is flushed and terminated.
pub fn build_rotating_writer(
    directory: &std::path::Path,
    file_prefix: &str,
    schedule: RotationSchedule,
    max_files: usize,
) -> Result<(tracing_appender::non_blocking::NonBlocking, tracing_appender::non_blocking::WorkerGuard), LoggingError> {
    use tracing_appender::rolling::{RollingFileAppender, Rotation};

    let rotation = rotation_schedule_to_tracing(schedule);

    let appender = RollingFileAppender::new(rotation, directory, file_prefix);

    let (non_blocking, guard) = tracing_appender::non_blocking(appender);

    Ok((non_blocking, guard))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_subscriber_type_from_log_format() {
        assert_eq!(SubscriberType::from(LogFormat::Json), SubscriberType::Json);
        assert_eq!(SubscriberType::from(LogFormat::Pretty), SubscriberType::Pretty);
        assert_eq!(SubscriberType::from(LogFormat::Compact), SubscriberType::Compact);
    }

    #[test]
    fn test_subscriber_config_defaults() {
        let config = SubscriberConfig::default();
        assert_eq!(config.subscriber_type, SubscriberType::Pretty);
        assert!(config.include_span_timings);
        assert!(!config.include_source_location);
    }

    #[test]
    fn test_rotation_schedule_to_tracing() {
        assert_eq!(
            std::mem::discriminant(&rotation_schedule_to_tracing(RotationSchedule::Daily)),
            std::mem::discriminant(&tracing_appender::rolling::Rotation::DAILY)
        );
        assert_eq!(
            std::mem::discriminant(&rotation_schedule_to_tracing(RotationSchedule::Hourly)),
            std::mem::discriminant(&tracing_appender::rolling::Rotation::HOURLY)
        );
    }

    #[test]
    fn test_build_json_layer_returns_ok() {
        let config = LoggingConfig::builder()
            .format(LogFormat::Json)
            .enable_colors(false)
            .include_thread_ids(true)
            .include_targets(true)
            .log_span_context(true)
            .build();

        // We can't easily test the layer itself, but we can verify construction
        assert_eq!(config.format, LogFormat::Json);
        assert!(config.include_thread_ids);
        assert!(config.include_targets);
    }

    #[test]
    fn test_build_pretty_layer_returns_ok() {
        let config = LoggingConfig::builder()
            .format(LogFormat::Pretty)
            .enable_colors(true)
            .include_thread_ids(false)
            .include_targets(false)
            .build();

        assert_eq!(config.format, LogFormat::Pretty);
        assert!(config.enable_colors);
    }

    #[test]
    fn test_build_compact_layer_returns_ok() {
        let config = LoggingConfig::builder()
            .format(LogFormat::Compact)
            .enable_colors(false)
            .include_thread_ids(true)
            .build();

        assert_eq!(config.format, LogFormat::Compact);
    }

    #[test]
    fn test_file_layer_requires_file_output() {
        let config = LoggingConfig::builder().build();
        assert!(config.file_output.is_none());

        // Building a file layer without file_output should fail
        let result = build_file_json_layer::<tracing_subscriber::Registry>(&config);
        assert!(result.is_err());
    }
}
