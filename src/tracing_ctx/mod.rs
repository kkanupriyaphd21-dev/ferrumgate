//! Distributed request tracing with W3C Trace Context propagation.
//!
//! This module implements the W3C Trace Context specification for
//! distributed tracing across service boundaries. It provides:
//!
//! - Trace context extraction and injection (traceparent/tracestate headers)
//! - Span creation with parent-child relationships
//! - Trace sampling with configurable rates
//! - Baggage propagation for cross-cutting concerns
//! - Integration with the existing tracing ecosystem
//!
//! # W3C Trace Context
//!
//! The module follows the W3C Trace Context specification:
//! - \`traceparent\`: Contains trace ID, parent span ID, and flags
//! - \`tracestate\`: Vendor-specific trace context
//!
//! # Example
//!
//! \`\`\`
//! traceparent: 00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01
//!              ^^ ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ ^^^^^^^^^^^^^^^^ ^^
//!              version trace-id                     parent-span-id   flags
//! \`\`\`

use std::collections::HashMap;
use std::fmt;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use thiserror::Error;
use tracing::{info, debug, warn, Span};
use uuid::Uuid;

pub mod context;
pub mod span;
pub mod sampler;
pub mod middleware;

pub use context::TraceContext;
pub use span::{SpanData, SpanKind, SpanStatus};
pub use sampler::{Sampler, AlwaysOnSampler, AlwaysOffSampler, ProbabilitySampler};
pub use middleware::TracingMiddleware;

/// Tracing error types.
#[derive(Debug, Error)]
pub enum TracingError {
    #[error("invalid traceparent header: {0}")]
    InvalidTraceParent(String),

    #[error("invalid tracestate header: {0}")]
    InvalidTraceState(String),

    #[error("trace context not found")]
    ContextNotFound,

    #[error("sampling decision: trace not sampled")]
    NotSampled,

    #[error("tracing error: {0}")]
    Internal(String),
}

/// Trace ID (16 bytes, 32 hex characters).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct TraceId(pub [u8; 16]);

impl TraceId {
    pub fn generate() -> Self {
        let uuid = Uuid::new_v4();
        let bytes = *uuid.as_bytes();
        TraceId(bytes)
    }

    pub fn from_hex(hex: &str) -> Result<Self, TracingError> {
        if hex.len() != 32 {
            return Err(TracingError::InvalidTraceParent(format!("invalid trace id length: {}", hex.len())));
        }
        let bytes = hex::decode(hex)
            .map_err(|e| TracingError::InvalidTraceParent(format!("invalid hex: {}", e)))?;
        let mut array = [0u8; 16];
        array.copy_from_slice(&bytes);
        Ok(TraceId(array))
    }

    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }

    pub fn is_valid(&self) -> bool {
        self.0.iter().any(|&b| b != 0)
    }
}

impl fmt::Display for TraceId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_hex())
    }
}

/// Span ID (8 bytes, 16 hex characters).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SpanId(pub [u8; 8]);

impl SpanId {
    pub fn generate() -> Self {
        let uuid = Uuid::new_v4();
        let bytes = *uuid.as_bytes();
        let mut array = [0u8; 8];
        array.copy_from_slice(&bytes[..8]);
        SpanId(array)
    }

    pub fn from_hex(hex: &str) -> Result<Self, TracingError> {
        if hex.len() != 16 {
            return Err(TracingError::InvalidTraceParent(format!("invalid span id length: {}", hex.len())));
        }
        let bytes = hex::decode(hex)
            .map_err(|e| TracingError::InvalidTraceParent(format!("invalid hex: {}", e)))?;
        let mut array = [0u8; 8];
        array.copy_from_slice(&bytes);
        Ok(SpanId(array))
    }

    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }

    pub fn is_valid(&self) -> bool {
        self.0.iter().any(|&b| b != 0)
    }
}

impl fmt::Display for SpanId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_hex())
    }
}

/// Trace flags.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TraceFlags(pub u8);

impl TraceFlags {
    pub const SAMPLED: u8 = 0x01;

    pub fn is_sampled(&self) -> bool {
        self.0 & Self::SAMPLED != 0
    }

    pub fn sampled() -> Self {
        TraceFlags(Self::SAMPLED)
    }

    pub fn not_sampled() -> Self {
        TraceFlags(0)
    }
}

/// Trace state for vendor-specific context.
#[derive(Debug, Clone, Default)]
pub struct TraceState(pub HashMap<String, String>);

impl TraceState {
    pub fn get(&self, key: &str) -> Option<&String> {
        self.0.get(key)
    }

    pub fn set(&mut self, key: String, value: String) {
        self.0.insert(key, value);
    }

    pub fn to_header(&self) -> String {
        self.0.iter()
            .map(|(k, v)| format!("{}={}", k, v))
            .collect::<Vec<_>>()
            .join(",")
    }

    pub fn from_header(header: &str) -> Result<Self, TracingError> {
        let mut state = HashMap::new();
        for pair in header.split(',') {
            let parts: Vec<&str> = pair.splitn(2, '=').collect();
            if parts.len() == 2 {
                state.insert(parts[0].trim().to_string(), parts[1].trim().to_string());
            } else {
                return Err(TracingError::InvalidTraceState(format!("invalid pair: {}", pair)));
            }
        }
        Ok(TraceState(state))
    }
}

/// Baggage for cross-cutting concern propagation.
#[derive(Debug, Clone, Default)]
pub struct Baggage(pub HashMap<String, String>);

impl Baggage {
    pub fn get(&self, key: &str) -> Option<&String> {
        self.0.get(key)
    }

    pub fn set(&mut self, key: String, value: String) {
        self.0.insert(key, value);
    }

    pub fn to_header(&self) -> String {
        self.0.iter()
            .map(|(k, v)| format!("{}={}", k, v))
            .collect::<Vec<_>>()
            .join(",")
    }
}

/// Sampling decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SamplingDecision {
    RecordAndSample,
    RecordOnly,
    Drop,
}

/// Global tracing metrics.
static TRACING_TOTAL_TRACES: AtomicU64 = AtomicU64::new(0);
static TRACING_SAMPLED: AtomicU64 = AtomicU64::new(0);
static TRACING_DROPPED: AtomicU64 = AtomicU64::new(0);
static TRACING_SPANS_CREATED: AtomicU64 = AtomicU64::new(0);

pub fn record_trace_start(sampled: bool) {
    TRACING_TOTAL_TRACES.fetch_add(1, Ordering::Relaxed);
    if sampled {
        TRACING_SAMPLED.fetch_add(1, Ordering::Relaxed);
    } else {
        TRACING_DROPPED.fetch_add(1, Ordering::Relaxed);
    }
}

pub fn record_span_created() {
    TRACING_SPANS_CREATED.fetch_add(1, Ordering::Relaxed);
}

#[derive(Debug, Clone)]
pub struct GlobalTracingMetrics {
    pub total_traces: u64,
    pub sampled: u64,
    pub dropped: u64,
    pub spans_created: u64,
    pub sample_rate: f64,
}

pub fn get_tracing_metrics() -> GlobalTracingMetrics {
    let total = TRACING_TOTAL_TRACES.load(Ordering::Relaxed);
    let sampled = TRACING_SAMPLED.load(Ordering::Relaxed);
    GlobalTracingMetrics {
        total_traces: total,
        sampled,
        dropped: TRACING_DROPPED.load(Ordering::Relaxed),
        spans_created: TRACING_SPANS_CREATED.load(Ordering::Relaxed),
        sample_rate: if total == 0 { 0.0 } else { sampled as f64 / total as f64 },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_trace_id_generation() {
        let id = TraceId::generate();
        assert!(id.is_valid());
        assert_eq!(id.to_hex().len(), 32);
    }

    #[test]
    fn test_trace_id_from_hex() {
        let id = TraceId::from_hex("4bf92f3577b34da6a3ce929d0e0e4736").unwrap();
        assert_eq!(id.to_hex(), "4bf92f3577b34da6a3ce929d0e0e4736");
    }

    #[test]
    fn test_trace_id_invalid_hex() {
        assert!(TraceId::from_hex("invalid").is_err());
        assert!(TraceId::from_hex("4bf92f3577b34da6a3ce929d0e0e473").is_err()); // too short
    }

    #[test]
    fn test_span_id_generation() {
        let id = SpanId::generate();
        assert!(id.is_valid());
        assert_eq!(id.to_hex().len(), 16);
    }

    #[test]
    fn test_span_id_from_hex() {
        let id = SpanId::from_hex("00f067aa0ba902b7").unwrap();
        assert_eq!(id.to_hex(), "00f067aa0ba902b7");
    }

    #[test]
    fn test_trace_flags() {
        assert!(TraceFlags::sampled().is_sampled());
        assert!(!TraceFlags::not_sampled().is_sampled());
    }

    #[test]
    fn test_trace_state() {
        let mut state = TraceState::default();
        state.set("vendor1".to_string(), "value1".to_string());
        state.set("vendor2".to_string(), "value2".to_string());

        let header = state.to_header();
        let parsed = TraceState::from_header(&header).unwrap();
        assert_eq!(parsed.get("vendor1"), Some(&"value1".to_string()));
    }

    #[test]
    fn test_baggage() {
        let mut baggage = Baggage::default();
        baggage.set("user_id".to_string(), "12345".to_string());
        baggage.set("tenant".to_string(), "acme".to_string());

        assert_eq!(baggage.get("user_id"), Some(&"12345".to_string()));
    }

    #[test]
    fn test_global_tracing_metrics_initial() {
        let metrics = get_tracing_metrics();
        assert_eq!(metrics.total_traces, 0);
        assert_eq!(metrics.sample_rate, 0.0);
    }
}
