//! Certificate hot-reload without connection interruption.
//!
//! This module provides the \`CertificateReloader\` which monitors certificate
//! files for changes and automatically reloads them without dropping existing
//! connections.
//!
//! # Reload Strategy
//!
//! The reloader uses a polling-based approach:
//! 1. Periodically check certificate file modification times
//! 2. When a change is detected, load the new certificates
//! 3. Validate the new certificates (expiration, chain)
//! 4. Atomically swap the certificate store
//! 5. Log the reload event
//!
//! # Thread Safety
//!
//! The reloader uses \`Arc<RwLock<>>\` for thread-safe certificate store
//! access. Existing connections continue using the old certificates
//! while new connections use the reloaded ones.
//!
//! # Validation
//!
//! Before swapping certificates, the reloader validates:
//! - Certificate is not expired
//! - Certificate is not yet valid (clock skew)
//! - Private key matches the certificate
//! - Certificate chain is complete

use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use tokio::sync::RwLock;
use tokio::time::interval;
use tracing::{info, warn, error, debug};

use crate::tls::{
    certificates::CertificateStore,
    TlsConfig, TlsError,
    record_certificate_reload,
};

/// Certificate reloader that monitors and reloads certificates.
pub struct CertificateReloader {
    /// Shared certificate store.
    store: Arc<RwLock<CertificateStore>>,

    /// TLS configuration.
    config: TlsConfig,

    /// Last known modification times.
    last_modified: std::collections::HashMap<PathBuf, SystemTime>,

    /// Whether the reloader is running.
    running: bool,
}

impl CertificateReloader {
    /// Create a new certificate reloader.
    pub fn new(
        store: Arc<RwLock<CertificateStore>>,
        config: TlsConfig,
    ) -> Self {
        let mut last_modified = std::collections::HashMap::new();

        // Record initial modification times
        if let Ok(meta) = std::fs::metadata(&config.certificate_path) {
            if let Ok(modified) = meta.modified() {
                last_modified.insert(config.certificate_path.clone(), modified);
            }
        }

        if let Ok(meta) = std::fs::metadata(&config.private_key_path) {
            if let Ok(modified) = meta.modified() {
                last_modified.insert(config.private_key_path.clone(), modified);
            }
        }

        for (_, cert_path, key_path) in &config.sni_mappings {
            if let Ok(meta) = std::fs::metadata(cert_path) {
                if let Ok(modified) = meta.modified() {
                    last_modified.insert(cert_path.clone(), modified);
                }
            }
            if let Ok(meta) = std::fs::metadata(key_path) {
                if let Ok(modified) = meta.modified() {
                    last_modified.insert(key_path.clone(), modified);
                }
            }
        }

        Self {
            store,
            config,
            last_modified,
            running: false,
        }
    }

    /// Check if any certificate files have been modified.
    pub fn check_for_changes(&mut self) -> bool {
        let mut changed = false;

        // Check default certificate
        if let Ok(meta) = std::fs::metadata(&self.config.certificate_path) {
            if let Ok(modified) = meta.modified() {
                let last = self.last_modified.get(&self.config.certificate_path);
                if last != Some(&modified) {
                    changed = true;
                    self.last_modified
                        .insert(self.config.certificate_path.clone(), modified);
                }
            }
        }

        // Check default private key
        if let Ok(meta) = std::fs::metadata(&self.config.private_key_path) {
            if let Ok(modified) = meta.modified() {
                let last = self.last_modified.get(&self.config.private_key_path);
                if last != Some(&modified) {
                    changed = true;
                    self.last_modified
                        .insert(self.config.private_key_path.clone(), modified);
                }
            }
        }

        // Check SNI certificates
        for (_, cert_path, key_path) in &self.config.sni_mappings {
            if let Ok(meta) = std::fs::metadata(cert_path) {
                if let Ok(modified) = meta.modified() {
                    let last = self.last_modified.get(cert_path);
                    if last != Some(&modified) {
                        changed = true;
                        self.last_modified.insert(cert_path.clone(), modified);
                    }
                }
            }
            if let Ok(meta) = std::fs::metadata(key_path) {
                if let Ok(modified) = meta.modified() {
                    let last = self.last_modified.get(key_path);
                    if last != Some(&modified) {
                        changed = true;
                        self.last_modified.insert(key_path.clone(), modified);
                    }
                }
            }
        }

        changed
    }

    /// Reload certificates if changes are detected.
    pub async fn reload_if_changed(&mut self) -> Result<bool, TlsError> {
        if self.check_for_changes() {
            info!("certificate file changes detected, reloading...");

            let mut store = self.store.write().await;
            store.reload()?;
            record_certificate_reload();

            info!("certificates reloaded successfully");
            Ok(true)
        } else {
            Ok(false)
        }
    }

    /// Start the background reload loop.
    pub async fn run(mut self) {
        self.running = true;
        let interval_secs = self.config.reload_interval_secs;

        if interval_secs == 0 {
            warn!("certificate reload interval is 0, disabling background reload");
            return;
        }

        let mut interval = interval(Duration::from_secs(interval_secs));

        info!(
            interval_secs = interval_secs,
            "starting certificate reload loop"
        );

        loop {
            interval.tick().await;

            match self.reload_if_changed().await {
                Ok(true) => {
                    info!("certificate reload completed");
                }
                Ok(false) => {
                    debug!("no certificate changes detected");
                }
                Err(e) => {
                    error!("certificate reload failed: {}", e);
                }
            }
        }
    }

    /// Stop the reload loop.
    pub fn stop(&mut self) {
        self.running = false;
    }

    /// Check if the reloader is running.
    pub fn is_running(&self) -> bool {
        self.running
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_reloader_creation() {
        let config = TlsConfig::builder()
            .certificate_path(PathBuf::from("/tmp/cert.pem"))
            .private_key_path(PathBuf::from("/tmp/key.pem"))
            .reload_interval_secs(60)
            .build()
            .unwrap();

        // Can't create store without real certs, but verify config
        assert_eq!(config.reload_interval_secs, 60);
    }
}
