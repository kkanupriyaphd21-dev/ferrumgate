mod runtime;
mod signal;

use runtime::{RuntimeConfig, RuntimeStats};
use signal::{ShutdownCoordinator, ShutdownReason};
use tracing::{info, error, warn};
use tracing_subscriber::{EnvFilter, fmt};

struct GatewayApp {
    config: RuntimeConfig,
    stats: RuntimeStats,
}

impl GatewayApp {
    fn new(config: RuntimeConfig) -> Self {
        let stats = RuntimeStats::new(config.worker_threads, config.max_blocking_threads);
        Self { config, stats }
    }

    async fn run(self) -> Result<(), anyhow::Error> {
        info!("Starting FerrumGate v{}", env!("CARGO_PKG_VERSION"));
        info!("Runtime config: workers={}, blocking={}, shutdown_timeout={}s",
            self.config.worker_threads,
            self.config.max_blocking_threads,
            self.config.shutdown_timeout_secs,
        );

        info!("Gateway runtime initialized successfully");
        info!("Listening for shutdown signals...");

        Ok(())
    }

    async fn shutdown(self, reason: ShutdownReason) {
        info!("Shutting down gateway: {}", reason);
        info!("Active tasks: {}", self.stats.active_tasks);
        info!("Total tasks spawned: {}", self.stats.total_tasks_spawned);
        info!("Gateway shutdown complete");
    }
}

fn init_tracing() {
    let env_filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("info,ferrumgate=debug"));

    fmt()
        .with_env_filter(env_filter)
        .with_target(false)
        .with_thread_ids(true)
        .with_file(true)
        .with_line_number(true)
        .init();
}

fn main() -> Result<(), anyhow::Error> {
    init_tracing();

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
