//! W3C Trace Context implementation.
//!
//! Handles extraction and injection of trace context from HTTP headers
//! following the W3C Trace Context specification.

use std::collections::HashMap;

use crate::tracing_ctx::{
    TraceId, SpanId, TraceFlags, TraceState, Baggage, TracingError,
    record_trace_start,
};

/// W3C Trace Context header names.
pub const TRACEPARENT_HEADER: &str = "traceparent";
pub const TRACESTATE_HEADER: &str = "tracestate";
pub const BAGGAGE_HEADER: &str = "baggage";

/// Represents a complete trace context that can be propagated across services.
#[derive(Debug, Clone)]
pub struct TraceContext {
    pub trace_id: TraceId,
    pub parent_span_id: Option<SpanId>,
    pub span_id: SpanId,
    pub flags: TraceFlags,
    pub trace_state: TraceState,
    pub baggage: Baggage,
    pub is_root: bool,
}

impl TraceContext {
    /// Create a new root trace context.
    pub fn new_root() -> Self {
        let trace_id = TraceId::generate();
        let span_id = SpanId::generate();
        Self {
            trace_id,
            parent_span_id: None,
            span_id,
            flags: TraceFlags::sampled(),
            trace_state: TraceState::default(),
            baggage: Baggage::default(),
            is_root: true,
        }
    }

    /// Create a child context from a parent.
    pub fn child(&self) -> Self {
        Self {
            trace_id: self.trace_id.clone(),
            parent_span_id: Some(self.span_id.clone()),
            span_id: SpanId::generate(),
            flags: self.flags,
            trace_state: self.trace_state.clone(),
            baggage: self.baggage.clone(),
            is_root: false,
        }
    }

    /// Extract trace context from HTTP headers.
    pub fn from_headers(headers: &HashMap<String, String>) -> Result<Option<Self>, TracingError> {
        let traceparent = headers.get(TRACEPARENT_HEADER);

        match traceparent {
            Some(tp) => {
                let parts: Vec<&str> = tp.split('-').collect();
                if parts.len() < 4 {
                    return Err(TracingError::InvalidTraceParent(format!("invalid format: {}", tp)));
                }

                let version = parts[0];
                if version != "00" {
                    return Err(TracingError::InvalidTraceParent(format!("unsupported version: {}", version)));
                }

                let trace_id = TraceId::from_hex(parts[1])?;
                let parent_span_id = SpanId::from_hex(parts[2])?;
                let flags = TraceFlags(u8::from_str_radix(parts[3], 16)
                    .map_err(|e| TracingError::InvalidTraceParent(format!("invalid flags: {}", e)))?);

                let trace_state = headers.get(TRACESTATE_HEADER)
                    .map(|ts| TraceState::from_header(ts))
                    .transpose()?
                    .unwrap_or_default();

                let baggage = headers.get(BAGGAGE_HEADER)
                    .map(|b| {
                        let mut baggage = Baggage::default();
                        for pair in b.split(',') {
                            let kv: Vec<&str> = pair.splitn(2, '=').collect();
                            if kv.len() == 2 {
                                baggage.set(kv[0].trim().to_string(), kv[1].trim().to_string());
                            }
                        }
                        baggage
                    })
                    .unwrap_or_default();

                record_trace_start(flags.is_sampled());

                Ok(Some(Self {
                    trace_id,
                    parent_span_id: Some(parent_span_id),
                    span_id: SpanId::generate(),
                    flags,
                    trace_state,
                    baggage,
                    is_root: false,
                }))
            }
            None => Ok(None),
        }
    }

    /// Inject trace context into HTTP headers.
    pub fn inject_headers(&self, headers: &mut HashMap<String, String>) {
        let traceparent = format!(
            "00-{}-{}-{:02x}",
            self.trace_id.to_hex(),
            self.span_id.to_hex(),
            self.flags.0
        );
        headers.insert(TRACEPARENT_HEADER.to_string(), traceparent);

        if !self.trace_state.0.is_empty() {
            headers.insert(TRACESTATE_HEADER.to_string(), self.trace_state.to_header());
        }

        if !self.baggage.0.is_empty() {
            headers.insert(BAGGAGE_HEADER.to_string(), self.baggage.to_header());
        }
    }

    /// Check if this trace is sampled.
    pub fn is_sampled(&self) -> bool {
        self.flags.is_sampled()
    }

    /// Set the sampling flag.
    pub fn set_sampled(&mut self, sampled: bool) {
        self.flags = if sampled {
            TraceFlags::sampled()
        } else {
            TraceFlags::not_sampled()
        };
        record_trace_start(sampled);
    }

    /// Add baggage item.
    pub fn add_baggage(&mut self, key: String, value: String) {
        self.baggage.set(key, value);
    }

    /// Get baggage item.
    pub fn get_baggage(&self, key: &str) -> Option<&String> {
        self.baggage.get(key)
    }

    /// Add trace state.
    pub fn add_trace_state(&mut self, key: String, value: String) {
        self.trace_state.set(key, value);
    }

    /// Get trace state.
    pub fn get_trace_state(&self, key: &str) -> Option<&String> {
        self.trace_state.get(key)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_root_context() {
        let ctx = TraceContext::new_root();
        assert!(ctx.is_root);
        assert!(ctx.parent_span_id.is_none());
        assert!(ctx.is_sampled());
    }

    #[test]
    fn test_child_context() {
        let parent = TraceContext::new_root();
        let child = parent.child();

        assert!(!child.is_root);
        assert_eq!(child.trace_id, parent.trace_id);
        assert_eq!(child.parent_span_id, Some(parent.span_id));
    }

    #[test]
    fn test_inject_and_extract_headers() {
        let ctx = TraceContext::new_root();
        let mut headers = HashMap::new();
        ctx.inject_headers(&mut headers);

        assert!(headers.contains_key(TRACEPARENT_HEADER));

        let extracted = TraceContext::from_headers(&headers).unwrap().unwrap();
        assert_eq!(extracted.trace_id, ctx.trace_id);
        assert_eq!(extracted.span_id, ctx.span_id);
    }

    #[test]
    fn test_no_traceparent_returns_none() {
        let headers = HashMap::new();
        let result = TraceContext::from_headers(&headers).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn test_invalid_traceparent() {
        let mut headers = HashMap::new();
        headers.insert(TRACEPARENT_HEADER.to_string(), "invalid".to_string());
        assert!(TraceContext::from_headers(&headers).is_err());
    }

    #[test]
    fn test_baggage_propagation() {
        let mut ctx = TraceContext::new_root();
        ctx.add_baggage("user_id".to_string(), "12345".to_string());
        ctx.add_baggage("tenant".to_string(), "acme".to_string());

        let mut headers = HashMap::new();
        ctx.inject_headers(&mut headers);

        let extracted = TraceContext::from_headers(&headers).unwrap().unwrap();
        assert_eq!(extracted.get_baggage("user_id"), Some(&"12345".to_string()));
    }

    #[test]
    fn test_trace_state_propagation() {
        let mut ctx = TraceContext::new_root();
        ctx.add_trace_state("vendor".to_string(), "value".to_string());

        let mut headers = HashMap::new();
        ctx.inject_headers(&mut headers);

        let extracted = TraceContext::from_headers(&headers).unwrap().unwrap();
        assert_eq!(extracted.get_trace_state("vendor"), Some(&"value".to_string()));
    }
}
