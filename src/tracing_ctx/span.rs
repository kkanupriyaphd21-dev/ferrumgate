//! Span implementation for distributed tracing.
//!
//! Provides span creation, lifecycle management, and attribute tracking
//! following OpenTelemetry span semantics.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use crate::tracing_ctx::{
    TraceId, SpanId, TraceContext, record_span_created,
};

/// Span kind indicating the role of the span.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SpanKind {
    /// Server-side handling of a request.
    Server,
    /// Client-side request to a remote service.
    Client,
    /// Producer sending a message.
    Producer,
    /// Consumer receiving a message.
    Consumer,
    /// Internal operation within a service.
    Internal,
}

impl std::fmt::Display for SpanKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SpanKind::Server => write!(f, "server"),
            SpanKind::Client => write!(f, "client"),
            SpanKind::Producer => write!(f, "producer"),
            SpanKind::Consumer => write!(f, "consumer"),
            SpanKind::Internal => write!(f, "internal"),
        }
    }
}

/// Span status indicating the outcome.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SpanStatus {
    /// Operation completed successfully.
    Ok,
    /// Operation completed with an error.
    Error,
    /// Status not set (default).
    Unset,
}

impl std::fmt::Display for SpanStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SpanStatus::Ok => write!(f, "ok"),
            SpanStatus::Error => write!(f, "error"),
            SpanStatus::Unset => write!(f, "unset"),
        }
    }
}

/// Represents a single operation in a trace.
#[derive(Debug, Clone)]
pub struct SpanData {
    pub trace_id: TraceId,
    pub span_id: SpanId,
    pub parent_span_id: Option<SpanId>,
    pub name: String,
    pub kind: SpanKind,
    pub status: SpanStatus,
    pub start_time: SystemTime,
    pub end_time: Option<SystemTime>,
    pub duration: Option<Duration>,
    pub attributes: HashMap<String, String>,
    pub events: Vec<SpanEvent>,
    pub error_message: Option<String>,
}

impl SpanData {
    pub fn new(ctx: &TraceContext, name: &str, kind: SpanKind) -> Self {
        record_span_created();
        Self {
            trace_id: ctx.trace_id.clone(),
            span_id: ctx.span_id.clone(),
            parent_span_id: ctx.parent_span_id.clone(),
            name: name.to_string(),
            kind,
            status: SpanStatus::Unset,
            start_time: SystemTime::now(),
            end_time: None,
            duration: None,
            attributes: HashMap::new(),
            events: Vec::new(),
            error_message: None,
        }
    }

    pub fn set_attribute(&mut self, key: &str, value: &str) {
        self.attributes.insert(key.to_string(), value.to_string());
    }

    pub fn get_attribute(&self, key: &str) -> Option<&String> {
        self.attributes.get(key)
    }

    pub fn add_event(&mut self, name: &str) {
        self.events.push(SpanEvent {
            name: name.to_string(),
            timestamp: SystemTime::now(),
            attributes: HashMap::new(),
        });
    }

    pub fn set_status(&mut self, status: SpanStatus) {
        self.status = status;
    }

    pub fn set_error(&mut self, message: &str) {
        self.status = SpanStatus::Error;
        self.error_message = Some(message.to_string());
    }

    pub fn end(&mut self) {
        let end_time = SystemTime::now();
        self.end_time = Some(end_time);
        self.duration = end_time.duration_since(self.start_time).ok();
    }

    pub fn is_completed(&self) -> bool {
        self.end_time.is_some()
    }

    pub fn duration_ms(&self) -> Option<f64> {
        self.duration.map(|d| d.as_secs_f64() * 1000.0)
    }
}

/// Represents an event that occurred during a span.
#[derive(Debug, Clone)]
pub struct SpanEvent {
    pub name: String,
    pub timestamp: SystemTime,
    pub attributes: HashMap<String, String>,
}

/// Active span tracker with lifecycle management.
pub struct ActiveSpan {
    pub data: SpanData,
    start_instant: Instant,
}

impl ActiveSpan {
    pub fn new(ctx: &TraceContext, name: &str, kind: SpanKind) -> Self {
        Self {
            data: SpanData::new(ctx, name, kind),
            start_instant: Instant::now(),
        }
    }

    pub fn set_attribute(&mut self, key: &str, value: &str) {
        self.data.set_attribute(key, value);
    }

    pub fn add_event(&mut self, name: &str) {
        self.data.add_event(name);
    }

    pub fn set_status(&mut self, status: SpanStatus) {
        self.data.set_status(status);
    }

    pub fn set_error(&mut self, message: &str) {
        self.data.set_error(message);
    }

    pub fn end(mut self) -> SpanData {
        self.data.end();
        self.data
    }
}

/// Span builder for fluent construction.
pub struct SpanBuilder {
    name: String,
    kind: SpanKind,
    context: Option<TraceContext>,
    attributes: HashMap<String, String>,
}

impl SpanBuilder {
    pub fn new(name: &str) -> Self {
        Self {
            name: name.to_string(),
            kind: SpanKind::Internal,
            context: None,
            attributes: HashMap::new(),
        }
    }

    pub fn kind(mut self, kind: SpanKind) -> Self {
        self.kind = kind;
        self
    }

    pub fn context(mut self, ctx: TraceContext) -> Self {
        self.context = Some(ctx);
        self
    }

    pub fn attribute(mut self, key: &str, value: &str) -> Self {
        self.attributes.insert(key.to_string(), value.to_string());
        self
    }

    pub fn build(self) -> Option<ActiveSpan> {
        let ctx = self.context.unwrap_or_else(TraceContext::new_root);
        if !ctx.is_sampled() {
            return None;
        }
        let mut span = ActiveSpan::new(&ctx, &self.name, self.kind);
        for (k, v) in self.attributes {
            span.set_attribute(&k, &v);
        }
        Some(span)
    }
}

/// Global span metrics.
static SPANS_TOTAL: AtomicU64 = AtomicU64::new(0);
static SPANS_COMPLETED: AtomicU64 = AtomicU64::new(0);
static SPANS_ERRORED: AtomicU64 = AtomicU64::new(0);

pub fn record_span_completed(is_error: bool) {
    SPANS_COMPLETED.fetch_add(1, Ordering::Relaxed);
    if is_error {
        SPANS_ERRORED.fetch_add(1, Ordering::Relaxed);
    }
}

#[derive(Debug)]
pub struct SpanMetrics {
    pub total: u64,
    pub completed: u64,
    pub errored: u64,
    pub in_progress: u64,
}

pub fn get_span_metrics() -> SpanMetrics {
    let total = record_span_created() as u64;
    let completed = SPANS_COMPLETED.load(Ordering::Relaxed);
    SpanMetrics {
        total,
        completed,
        errored: SPANS_ERRORED.load(Ordering::Relaxed),
        in_progress: total.saturating_sub(completed),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_span_creation() {
        let ctx = TraceContext::new_root();
        let span = ActiveSpan::new(&ctx, "test-operation", SpanKind::Internal);
        assert_eq!(span.data.name, "test-operation");
        assert!(!span.data.is_completed());
    }

    #[test]
    fn test_span_lifecycle() {
        let ctx = TraceContext::new_root();
        let mut span = ActiveSpan::new(&ctx, "test-operation", SpanKind::Server);
        span.set_attribute("http.method", "GET");
        span.set_attribute("http.url", "/api/test");
        span.add_event("request_received");
        span.set_status(SpanStatus::Ok);
        let data = span.end();

        assert!(data.is_completed());
        assert!(data.duration.is_some());
        assert_eq!(data.status, SpanStatus::Ok);
    }

    #[test]
    fn test_span_error() {
        let ctx = TraceContext::new_root();
        let mut span = ActiveSpan::new(&ctx, "failing-operation", SpanKind::Client);
        span.set_error("connection refused");
        let data = span.end();

        assert_eq!(data.status, SpanStatus::Error);
        assert_eq!(data.error_message, Some("connection refused".to_string()));
    }

    #[test]
    fn test_span_builder() {
        let ctx = TraceContext::new_root();
        let span = SpanBuilder::new("built-span")
            .kind(SpanKind::Server)
            .context(ctx)
            .attribute("key", "value")
            .build();

        assert!(span.is_some());
        let span = span.unwrap();
        assert_eq!(span.data.get_attribute("key"), Some(&"value".to_string()));
    }

    #[test]
    fn test_span_builder_not_sampled() {
        let mut ctx = TraceContext::new_root();
        ctx.set_sampled(false);

        let span = SpanBuilder::new("dropped-span")
            .context(ctx)
            .build();

        assert!(span.is_none());
    }

    #[test]
    fn test_span_kind_display() {
        assert_eq!(format!("{}", SpanKind::Server), "server");
        assert_eq!(format!("{}", SpanKind::Client), "client");
        assert_eq!(format!("{}", SpanKind::Internal), "internal");
    }

    #[test]
    fn test_span_status_display() {
        assert_eq!(format!("{}", SpanStatus::Ok), "ok");
        assert_eq!(format!("{}", SpanStatus::Error), "error");
        assert_eq!(format!("{}", SpanStatus::Unset), "unset");
    }
}
