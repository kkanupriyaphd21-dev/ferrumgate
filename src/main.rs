// FerrumGate - Async API gateway and reverse proxy built on Tokio with zero-copy I/O, TLS termination, and pluggable middleware
use anyhow::Result;

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::init();
    tracing::info!("FerrumGate starting...");
    Ok(())
}
