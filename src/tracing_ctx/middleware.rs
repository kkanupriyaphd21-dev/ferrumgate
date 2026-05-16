//! Tracing middleware for HTTP request processing.
//!
//! Integrates distributed tracing into the middleware chain,
//! automatically extracting context, creating spans, and injecting
//! trace headers into responses.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Instant;

use crate::tracing_ctx::{
    TraceContext, TraceId, SpanId, TraceFlags, TraceState, Baggage,
    TracingError, SamplingDecision, Sampler, AlwaysOnSampler,
    SpanBuilder, SpanKind, SpanStatus, ActiveSpan, SpanData,
    apply_sampling,
};

/// Configuration for the tracing middleware.
#[derive(Debug, Clone)]
pub struct TracingConfig {
    pub service_name: String,
    pub service_version: String,
    pub environment: String,
    pub sampler: Arc<dyn Sampler>,
    pub include_headers: bool,
    pub include_body: bool,
    pub max_attribute_length: usize,
    pub slow_threshold_ms: f64,
}

impl Default for TracingConfig {
    fn default() -> Self {
        Self {
            service_name: "ferrumgate".to_string(),
            service_version: "0.1.0".to_string(),
            environment: "development".to_string(),
            sampler: Arc::new(AlwaysOnSampler),
            include_headers: true,
            include_body: false,
            max_attribute_length: 1024,
            slow_threshold_ms: 1000.0,
        }
    }
}

/// HTTP request representation for tracing.
#[derive(Debug, Clone)]
pub struct TracedRequest {
    pub method: String,
    pub uri: String,
    pub headers: HashMap<String, String>,
    pub source_ip: String,
}

/// HTTP response representation for tracing.
#[derive(Debug, Clone)]
pub struct TracedResponse {
    pub status_code: u16,
    pub headers: HashMap<String, String>,
    pub body_size: Option<usize>,
}

/// Result of tracing middleware processing.
#[derive(Debug)]
pub struct TracingResult {
    pub span_data: Option<SpanData>,
    pub response_headers: HashMap<String, String>,
    pub is_sampled: bool,
}

/// Middleware that handles distributed tracing for HTTP requests.
pub struct TracingMiddleware {
    config: TracingConfig,
}

impl TracingMiddleware {
    pub fn new(config: TracingConfig) -> Self {
        Self { config }
    }

    /// Process an incoming request and create a trace span.
    pub fn process_request(&self, request: &TracedRequest) -> (TraceContext, ActiveSpan) {
        let ctx = self.extract_context(request);
        let span = self.create_span(&ctx, request);
        (ctx, span)
    }

    /// Process an outgoing response and finalize the span.
    pub fn process_response(
        &self,
        mut span: ActiveSpan,
        ctx: &TraceContext,
        response: &TracedResponse,
        duration_ms: f64,
    ) -> TracingResult {
        self.add_response_attributes(&mut span, response, duration_ms);

        let is_slow = duration_ms > self.config.slow_threshold_ms;
        if is_slow {
            span.add_event("slow_request_detected");
        }

        if response.status_code >= 400 {
            span.set_status(SpanStatus::Error);
        } else {
            span.set_status(SpanStatus::Ok);
        }

        let span_data = span.end();
        let mut response_headers = HashMap::new();

        if ctx.is_sampled() {
            ctx.inject_headers(&mut response_headers);
        }

        response_headers.insert(
            "X-Response-Time".to_string(),
            format!("{:.2}ms", duration_ms),
        );

        if is_slow {
            response_headers.insert(
                "X-Slow-Request".to_string(),
                "true".to_string(),
            );
        }

        TracingResult {
            span_data: Some(span_data),
            response_headers,
            is_sampled: ctx.is_sampled(),
        }
    }

    fn extract_context(&self, request: &TracedRequest) -> TraceContext {
        match TraceContext::from_headers(&request.headers) {
            Ok(Some(mut ctx)) => {
                apply_sampling(&mut ctx, self.config.sampler.as_ref());
                ctx
            }
            Ok(None) => {
                let mut ctx = TraceContext::new_root();
                apply_sampling(&mut ctx, self.config.sampler.as_ref());
                ctx
            }
            Err(_) => {
                let mut ctx = TraceContext::new_root();
                apply_sampling(&mut ctx, self.config.sampler.as_ref());
                ctx
            }
        }
    }

    fn create_span(&self, ctx: &TraceContext, request: &TracedRequest) -> ActiveSpan {
        let mut span = SpanBuilder::new(&format!("{} {}", request.method, request.uri))
            .kind(SpanKind::Server)
            .context(ctx.clone())
            .attribute("http.method", &request.method)
            .attribute("http.url", &request.uri)
            .attribute("http.source_ip", &request.source_ip)
            .attribute("service.name", &self.config.service_name)
            .attribute("service.version", &self.config.service_version)
            .attribute("deployment.environment", &self.config.environment)
            .build()
            .unwrap_or_else(|| {
                let root_ctx = TraceContext::new_root();
                ActiveSpan::new(&root_ctx, &format!("{} {}", request.method, request.uri), SpanKind::Server)
            });

        if self.config.include_headers {
            for (key, value) in &request.headers {
                if key.to_lowercase().starts_with("x-") || key.to_lowercase() == "content-type" {
                    let truncated = if value.len() > self.config.max_attribute_length {
                        format!("{}...", &value[..self.config.max_attribute_length])
                    } else {
                        value.clone()
                    };
                    span.set_attribute(&format!("http.request.header.{}", key), &truncated);
                }
            }
        }

        span
    }

    fn add_response_attributes(
        &self,
        span: &mut ActiveSpan,
        response: &TracedResponse,
        duration_ms: f64,
    ) {
        span.set_attribute("http.status_code", &response.status_code.to_string());
        span.set_attribute("http.duration_ms", &format!("{:.2}", duration_ms));

        if let Some(body_size) = response.body_size {
            span.set_attribute("http.response_content_length", &body_size.to_string());
        }

        for (key, value) in &response.headers {
            if key.to_lowercase().starts_with("x-") {
                span.set_attribute(&format!("http.response.header.{}", key), value);
            }
        }
    }

    /// Create a client span for outbound requests.
    pub fn create_client_span(
        &self,
        parent_ctx: &TraceContext,
        method: &str,
        url: &str,
    ) -> Option<ActiveSpan> {
        if !parent_ctx.is_sampled() {
            return None;
        }

        let child_ctx = parent_ctx.child();
        let mut span = SpanBuilder::new(&format!("{} {}", method, url))
            .kind(SpanKind::Client)
            .context(child_ctx)
            .attribute("http.method", method)
            .attribute("http.url", url)
            .build()?;

        span
    }
}

/// Trace context manager for request-scoped tracing.
pub struct TraceManager {
    middleware: TracingMiddleware,
}

impl TraceManager {
    pub fn new(config: TracingConfig) -> Self {
        Self {
            middleware: TracingMiddleware::new(config),
        }
    }

    pub fn start_trace(&self, request: &TracedRequest) -> (TraceContext, ActiveSpan) {
        self.middleware.process_request(request)
    }

    pub fn end_trace(
        &self,
        span: ActiveSpan,
        ctx: &TraceContext,
        response: &TracedResponse,
        duration_ms: f64,
    ) -> TracingResult {
        self.middleware.process_response(span, ctx, response, duration_ms)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_request() -> TracedRequest {
        let mut headers = HashMap::new();
        headers.insert("content-type".to_string(), "application/json".to_string());
        headers.insert("x-request-id".to_string(), "req-123".to_string());

        TracedRequest {
            method: "GET".to_string(),
            uri: "/api/test".to_string(),
            headers,
            source_ip: "127.0.0.1".to_string(),
        }
    }

    fn create_test_response() -> TracedResponse {
        let mut headers = HashMap::new();
        headers.insert("content-type".to_string(), "application/json".to_string());

        TracedResponse {
            status_code: 200,
            headers,
            body_size: Some(1024),
        }
    }

    #[test]
    fn test_tracing_middleware_request_processing() {
        let config = TracingConfig::default();
        let middleware = TracingMiddleware::new(config);
        let request = create_test_request();

        let (ctx, span) = middleware.process_request(&request);
        assert!(ctx.is_sampled());
        assert!(!span.data.is_completed());
    }

    #[test]
    fn test_tracing_middleware_response_processing() {
        let config = TracingConfig::default();
        let middleware = TracingMiddleware::new(config);
        let request = create_test_request();
        let response = create_test_response();

        let (ctx, span) = middleware.process_request(&request);
        let result = middleware.process_response(span, &ctx, &response, 50.0);

        assert!(result.is_sampled);
        assert!(result.span_data.is_some());
        let span_data = result.span_data.unwrap();
        assert!(span_data.is_completed());
        assert_eq!(span_data.status, SpanStatus::Ok);
    }

    #[test]
    fn test_tracing_middleware_error_response() {
        let config = TracingConfig::default();
        let middleware = TracingMiddleware::new(config);
        let request = create_test_request();
        let response = TracedResponse {
            status_code: 500,
            headers: HashMap::new(),
            body_size: None,
        };

        let (ctx, span) = middleware.process_request(&request);
        let result = middleware.process_response(span, &ctx, &response, 100.0);

        let span_data = result.span_data.unwrap();
        assert_eq!(span_data.status, SpanStatus::Error);
    }

    #[test]
    fn test_tracing_middleware_slow_request() {
        let config = TracingConfig {
            slow_threshold_ms: 100.0,
            ..Default::default()
        };
        let middleware = TracingMiddleware::new(config);
        let request = create_test_request();
        let response = create_test_response();

        let (ctx, span) = middleware.process_request(&request);
        let result = middleware.process_response(span, &ctx, &response, 500.0);

        assert!(result.response_headers.contains_key("X-Slow-Request"));
    }

    #[test]
    fn test_trace_context_propagation() {
        let config = TracingConfig::default();
        let middleware = TracingMiddleware::new(config);
        let request = create_test_request();

        let (ctx, _) = middleware.process_request(&request);
        let mut response_headers = HashMap::new();
        ctx.inject_headers(&mut response_headers);

        assert!(response_headers.contains_key("traceparent"));
    }

    #[test]
    fn test_client_span_creation() {
        let config = TracingConfig::default();
        let middleware = TracingMiddleware::new(config);
        let request = create_test_request();

        let (ctx, _) = middleware.process_request(&request);
        let client_span = middleware.create_client_span(&ctx, "POST", "http://backend/api");

        assert!(client_span.is_some());
    }

    #[test]
    fn test_trace_manager() {
        let config = TracingConfig::default();
        let manager = TraceManager::new(config);
        let request = create_test_request();
        let response = create_test_response();

        let (ctx, span) = manager.start_trace(&request);
        let result = manager.end_trace(span, &ctx, &response, 75.0);

        assert!(result.is_sampled);
        assert!(result.span_data.is_some());
    }
}
