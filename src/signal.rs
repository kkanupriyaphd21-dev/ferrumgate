use tokio::signal;
use tracing::{info, warn};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShutdownReason {
    Sigint,
    Sigterm,
    UserInitiated,
}

impl std::fmt::Display for ShutdownReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ShutdownReason::Sigint => write!(f, "SIGINT received"),
            ShutdownReason::Sigterm => write!(f, "SIGTERM received"),
            ShutdownReason::UserInitiated => write!(f, "user-initiated shutdown"),
        }
    }
}

pub async fn wait_for_shutdown_signal() -> ShutdownReason {
    let mut sigint = signal::unix::signal(signal::unix::SignalKind::interrupt())
        .expect("failed to install SIGINT handler");
    let mut sigterm = signal::unix::signal(signal::unix::SignalKind::terminate())
        .expect("failed to install SIGTERM handler");

    tokio::select! {
        _ = sigint.recv() => {
            info!("Received SIGINT, initiating graceful shutdown");
            ShutdownReason::Sigint
        }
        _ = sigterm.recv() => {
            info!("Received SIGTERM, initiating graceful shutdown");
            ShutdownReason::Sigterm
        }
    }
}

pub struct ShutdownCoordinator {
    reason: Option<ShutdownReason>,
    shutdown_timeout_secs: u64,
}

impl ShutdownCoordinator {
    pub fn new(shutdown_timeout_secs: u64) -> Self {
        Self {
            reason: None,
            shutdown_timeout_secs,
        }
    }

    pub async fn coordinate<F, Fut>(self, signal_fut: impl std::future::Future<Output = ShutdownReason>, shutdown_fn: F)
    where
        F: FnOnce(ShutdownReason) -> Fut,
        Fut: std::future::Future<Output = ()>,
    {
        let reason = signal_fut.await;
        info!("Shutdown initiated: {}", reason);

        let timeout = tokio::time::Duration::from_secs(self.shutdown_timeout_secs);
        match tokio::time::timeout(timeout, shutdown_fn(reason)).await {
            Ok(_) => info!("Graceful shutdown completed"),
            Err(_) => warn!("Shutdown timed out after {}s, forcing exit", self.shutdown_timeout_secs),
        }
    }

    pub fn initiate_user_shutdown(self) -> ShutdownReason {
        ShutdownReason::UserInitiated
    }
}
