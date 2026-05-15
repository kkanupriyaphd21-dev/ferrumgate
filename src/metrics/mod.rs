use prometheus_client::encoding::text::encode;
use prometheus_client::metrics::counter::Counter;
use prometheus_client::metrics::family::Family;
use prometheus_client::metrics::gauge::Gauge;
use prometheus_client::metrics::histogram::Histogram;
use prometheus_client::registry::Registry;
use std::sync::Arc;

#[derive(Clone, Debug, Hash, PartialEq, Eq)]
pub struct RequestLabels {
    pub method: String,
    pub path: String,
    pub status: String,
}

#[derive(Clone, Debug, Hash, PartialEq, Eq)]
pub struct UpstreamLabels {
    pub upstream: String,
    pub status: String,
}

pub struct GatewayMetrics {
    registry: Arc<Registry>,
    pub request_total: Family<RequestLabels, Counter>,
    pub request_duration_seconds: Family<RequestLabels, Histogram>,
    pub request_size_bytes: Family<RequestLabels, Histogram>,
    pub response_size_bytes: Family<RequestLabels, Histogram>,
    pub active_connections: Gauge,
    pub upstream_requests_total: Family<UpstreamLabels, Counter>,
    pub upstream_latency_seconds: Family<UpstreamLabels, Histogram>,
    pub errors_total: Family<RequestLabels, Counter>,
    pub rate_limited_requests: Family<RequestLabels, Counter>,
    pub circuit_breaker_state: Family<UpstreamLabels, Gauge>,
}

impl GatewayMetrics {
    pub fn new() -> Self {
        let mut registry = Registry::default();

        let request_total = Family::<RequestLabels, Counter>::default();
        registry.register(
            "http_requests_total",
            "Total number of HTTP requests",
            request_total.clone(),
        );

        let request_duration_seconds = Family::<RequestLabels, Histogram>::new_with_constructor(|| {
            Histogram::new([0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0].into_iter())
        });
        registry.register(
            "http_request_duration_seconds",
            "HTTP request duration in seconds",
            request_duration_seconds.clone(),
        );

        let request_size_bytes = Family::<RequestLabels, Histogram>::new_with_constructor(|| {
            Histogram::new([100, 500, 1000, 5000, 10000, 50000, 100000, 500000, 1000000].into_iter())
        });
        registry.register(
            "http_request_size_bytes",
            "HTTP request size in bytes",
            request_size_bytes.clone(),
        );

        let response_size_bytes = Family::<RequestLabels, Histogram>::new_with_constructor(|| {
            Histogram::new([100, 500, 1000, 5000, 10000, 50000, 100000, 500000, 1000000].into_iter())
        });
        registry.register(
            "http_response_size_bytes",
            "HTTP response size in bytes",
            response_size_bytes.clone(),
        );

        let active_connections = Gauge::default();
        registry.register(
            "active_connections",
            "Number of active connections",
            active_connections.clone(),
        );

        let upstream_requests_total = Family::<UpstreamLabels, Counter>::default();
        registry.register(
            "upstream_requests_total",
            "Total number of upstream requests",
            upstream_requests_total.clone(),
        );

        let upstream_latency_seconds = Family::<UpstreamLabels, Histogram>::new_with_constructor(|| {
            Histogram::new([0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0].into_iter())
        });
        registry.register(
            "upstream_latency_seconds",
            "Upstream request latency in seconds",
            upstream_latency_seconds.clone(),
        );

        let errors_total = Family::<RequestLabels, Counter>::default();
        registry.register(
            "http_errors_total",
            "Total number of HTTP errors",
            errors_total.clone(),
        );

        let rate_limited_requests = Family::<RequestLabels, Counter>::default();
        registry.register(
            "rate_limited_requests_total",
            "Total number of rate-limited requests",
            rate_limited_requests.clone(),
        );

        let circuit_breaker_state = Family::<UpstreamLabels, Gauge>::default();
        registry.register(
            "circuit_breaker_state",
            "Circuit breaker state (0=closed, 1=open, 2=half-open)",
            circuit_breaker_state.clone(),
        );

        Self {
            registry: Arc::new(registry),
            request_total,
            request_duration_seconds,
            request_size_bytes,
            response_size_bytes,
            active_connections,
            upstream_requests_total,
            upstream_latency_seconds,
            errors_total,
            rate_limited_requests,
            circuit_breaker_state,
        }
    }

    pub fn encode(&self) -> Result<String, std::fmt::Error> {
        let mut buffer = String::new();
        encode(&mut buffer, &self.registry).map_err(|_| std::fmt::Error)?;
        Ok(buffer)
    }

    pub fn registry(&self) -> &Registry {
        &self.registry
    }
}

impl Default for GatewayMetrics {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_metrics_creation() {
        let metrics = GatewayMetrics::new();
        assert!(metrics.encode().unwrap().contains("http_requests_total"));
        assert!(metrics.encode().unwrap().contains("http_request_duration_seconds"));
    }

    #[test]
    fn test_counter_increment() {
        let metrics = GatewayMetrics::new();
        let labels = RequestLabels {
            method: "GET".to_string(),
            path: "/test".to_string(),
            status: "200".to_string(),
        };
        metrics.request_total.get_or_create(&labels).inc();
        let output = metrics.encode().unwrap();
        assert!(output.contains("http_requests_total"));
    }

    #[test]
    fn test_gauge_update() {
        let metrics = GatewayMetrics::new();
        metrics.active_connections.set(42);
        let output = metrics.encode().unwrap();
        assert!(output.contains("active_connections 42"));
    }

    #[test]
    fn test_histogram_observation() {
        let metrics = GatewayMetrics::new();
        let labels = RequestLabels {
            method: "POST".to_string(),
            path: "/api".to_string(),
            status: "201".to_string(),
        };
        metrics
            .request_duration_seconds
            .get_or_create(&labels)
            .observe(0.125);
        let output = metrics.encode().unwrap();
        assert!(output.contains("http_request_duration_seconds"));
    }
}
