mod circuit_breaker;
mod errors;
mod health;
mod load_balancer;
mod logging;
mod metrics;
mod middleware;
mod pool;
mod retry;
mod runtime;
mod signal;
mod timeout;
mod tls;

use circuit_breaker::CircuitBreaker;
use errors::{GatewayError, GatewayResult};
use health::HealthChecker;
use logging::{LoggingConfig, init_tracing, log_session_event, log_pool_event, log_circuit_breaker_event, log_error_with_context};
use metrics::GatewayMetrics;
use middleware::{LoggingMiddleware, MiddlewareChain, RequestIdMiddleware, TimeoutMiddleware};
use pool::ConnectionPool;
use retry::RetryPolicy;
use runtime::{RuntimeConfig, RuntimeStats};
use signal::{ShutdownCoordinator, ShutdownReason};
use timeout::TimeoutConfig;
use tracing::{info, error, warn};

struct GatewayApp {
    config: RuntimeConfig,
    stats: RuntimeStats,
    health: HealthChecker,
    metrics: GatewayMetrics,
}

impl GatewayApp {
    fn new(config: RuntimeConfig) -> Self {
        let stats = RuntimeStats::new(config.worker_threads, config.max_blocking_threads);
        let health = HealthChecker::new();
        let metrics = GatewayMetrics::new();
        Self { config, stats, health, metrics }
    }

    async fn run(self) -> Result<(), anyhow::Error> {
        info!("Starting FerrumGate v{}", env!("CARGO_PKG_VERSION"));
        info!("Runtime config: workers={}, blocking={}, shutdown_timeout={}s",
            self.config.worker_threads,
            self.config.max_blocking_threads,
            self.config.shutdown_timeout_secs,
        );

        let liveness = self.health.liveness();
        info!("Liveness check: status={}", liveness.status);

        let readiness = self.health.readiness();
        info!("Readiness check: status={}", readiness.status);

        let metrics_output = self.metrics.encode().unwrap_or_default();
        let metric_count = metrics_output.lines().filter(|l| !l.starts_with('#') && !l.trim().is_empty()).count();
        info!("Prometheus metrics initialized: {} metrics registered", metric_count);

        info!("Gateway runtime initialized successfully");
        info!("Health endpoints: /health/live, /health/ready, /health/detailed");
        info!("Metrics endpoint: /metrics");
        info!("Listening for shutdown signals...");

        Ok(())
    }

    async fn shutdown(self, reason: ShutdownReason) {
        info!("Shutting down gateway: {}", reason);
        info!("Active tasks: {}", self.stats.active_tasks);
        info!("Total tasks spawned: {}", self.stats.total_tasks_spawned);

        let detailed = self.health.detailed();
        info!("Final health status: {}", detailed.status);

        let metrics_output = self.metrics.encode().unwrap_or_default();
        info!("Final metrics snapshot:\n{}", metrics_output);

        info!("Gateway shutdown complete");
    }
}

fn init_tracing_from_config() -> Result<(), anyhow::Error> {
    let config = LoggingConfig::from_env()?;
    init_tracing(&config)?;
    Ok(())
}

fn main() -> Result<(), anyhow::Error> {
    init_tracing_from_config()?;

    let config = RuntimeConfig::default();
    info!("Initializing Tokio runtime with {} worker threads", config.worker_threads);

    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(config.worker_threads)
        .max_blocking_threads(config.max_blocking_threads)
        .thread_name("ferrumgate-worker")
        .enable_all()
        .build()?;

    info!("Tokio runtime started successfully");

    rt.block_on(async {
        let app = GatewayApp::new(config.clone());
        let shutdown_coordinator = ShutdownCoordinator::new(config.shutdown_timeout_secs);

        let signal_fut = signal::wait_for_shutdown_signal();
        let (app_result, _) = tokio::join!(
            app.run(),
            async {
                let reason = signal_fut.await;
                let app = GatewayApp::new(config);
                shutdown_coordinator.coordinate(async { reason }, |r| async move {
                    app.shutdown(r).await;
                }).await;
            }
        );

        if let Err(e) = app_result {
            error!("Gateway runtime error: {}", e);
            std::process::exit(1);
        }

        info!("Gateway exited cleanly");
    });

    Ok(())
}
