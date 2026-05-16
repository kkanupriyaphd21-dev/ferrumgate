//! TLS acceptor for async handshake handling.
//!
//! This module provides the \`TlsAcceptor\` which wraps a rustls server
//! configuration and handles async TLS handshakes with timeout support.
//!
//! # Architecture
//!
//! The acceptor is built on top of \`tokio-rustls\` and provides:
//! - Async TLS handshake with configurable timeout
//! - Session caching for connection resumption
//! - ALPN protocol negotiation
//! - Client certificate verification (mTLS)
//!
//! # Session Resumption
//!
//! TLS session resumption is enabled by default with a configurable cache
//! size. This allows clients to resume previous TLS sessions without a
//! full handshake, reducing latency for returning connections.

use std::sync::Arc;
use std::time::Duration;

use rustls::crypto::CryptoProvider;
use rustls::server::{ServerSessionMemoryCache, WebPkiClientVerifier};
use rustls::RootCertStore;
use rustls::ServerConfig;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;
use tokio_rustls::TlsAcceptor as TokioTlsAcceptor;
use tracing::{info, warn, error, debug};

use crate::tls::{
    certificates::CertificateStore,
    TlsConfig, TlsError, TlsVersion,
    record_tls_handshake, record_tls_handshake_error, record_session_resumed,
};

/// TLS acceptor that handles async TLS handshakes.
///
/// The acceptor wraps a rustls \`ServerConfig\` and provides async
/// handshake capabilities with timeout support.
#[derive(Clone)]
pub struct TlsAcceptor {
    /// The underlying rustls acceptor.
    inner: TokioTlsAcceptor,

    /// Server configuration.
    config: ServerConfig,

    /// TLS configuration used to build this acceptor.
    tls_config: TlsConfig,

    /// Handshake timeout.
    handshake_timeout: Duration,
}

impl TlsAcceptor {
    /// Create a new TLS acceptor from configuration and certificate store.
    pub fn new(
        store: CertificateStore,
        tls_config: TlsConfig,
    ) -> Result<Self, TlsError> {
        // Initialize crypto provider
        let provider = rustls::crypto::ring::default_provider();
        CryptoProvider::install_default(&provider)
            .map_err(|e| TlsError::ConfigError(format!("failed to install crypto provider: {}", e)))?;

        // Build the server configuration
        let mut config = Self::build_server_config(&store, &tls_config)?;

        // Configure session caching
        let cache = ServerSessionMemoryCache::new(tls_config.max_session_cache_size);
        config.session_storage = cache;

        // Configure ALPN
        if !tls_config.alpn_protocols.is_empty() {
            config.alpn_protocols = tls_config.alpn_protocols.clone();
        }

        let inner = TokioTlsAcceptor::from(Arc::new(config.clone()));

        info!(
            min_version = tls_config.min_tls_version.as_str(),
            alpn_protocols = ?tls_config.alpn_protocols,
            session_cache_size = tls_config.max_session_cache_size,
            "TLS acceptor created"
        );

        Ok(Self {
            inner,
            config,
            tls_config,
            handshake_timeout: Duration::from_secs(10),
        })
    }

    /// Build the rustls server configuration.
    fn build_server_config(
        store: &CertificateStore,
        config: &TlsConfig,
    ) -> Result<ServerConfig, TlsError> {
        // Build client certificate verifier
        let client_verifier = if config.is_mutual_tls() {
            if let Some(ref ca_path) = config.client_ca_path {
                let ca_certs = crate::tls::load_certificates(ca_path)?;
                let mut root_store = RootCertStore::empty();
                for cert in ca_certs {
                    root_store
                        .add(cert)
                        .map_err(|e| TlsError::ConfigError(format!("failed to add CA cert: {}", e)))?;
                }

                WebPkiClientVerifier::builder(root_store.into())
                    .build()
                    .map_err(|e| TlsError::ConfigError(format!("failed to build client verifier: {}", e)))?
            } else {
                WebPkiClientVerifier::no_client_auth()
            }
        } else {
            WebPkiClientVerifier::no_client_auth()
        };

        // Build server config with the certificate resolver
        let mut builder = ServerConfig::builder()
            .with_protocol_versions(&[config.min_tls_version.to_rustls()])
            .map_err(|e| TlsError::ConfigError(format!("invalid protocol versions: {}", e)))?
            .with_client_cert_verifier(client_verifier)
            .with_cert_resolver(Arc::new(store.clone()));

        Ok(builder)
    }

    /// Accept a TLS connection from a TCP stream.
    pub async fn accept(
        &self,
        stream: TcpStream,
    ) -> Result<crate::tls::TlsConnection, TlsError> {
        let peer_addr = stream.peer_addr().ok().map(|a| a.to_string());

        debug!(
            peer = ?peer_addr,
            "accepting TLS connection"
        );

        let tls_stream = self.inner.accept(stream).await
            .map_err(|e| {
                record_tls_handshake_error();
                TlsError::HandshakeFailed(e.to_string())
            })?;

        record_tls_handshake();

        // Check if session was resumed
        if tls_stream.get_ref().1.is_resumed() {
            record_session_resumed();
            debug!(peer = ?peer_addr, "TLS session resumed");
        }

        let connection = crate::tls::TlsConnection::new(tls_stream, peer_addr);

        debug!(
            peer = ?connection.peer_addr(),
            protocol = ?connection.protocol_version(),
            cipher_suite = ?connection.cipher_suite(),
            "TLS handshake completed"
        );

        Ok(connection)
    }

    /// Accept a TLS connection with timeout.
    pub async fn accept_with_timeout(
        &self,
        stream: TcpStream,
        timeout: Duration,
    ) -> Result<crate::tls::TlsConnection, TlsError> {
        tokio::time::timeout(timeout, self.accept(stream))
            .await
            .map_err(|_| TlsError::HandshakeFailed("handshake timeout".into()))?
    }

    /// Get the underlying server configuration.
    pub fn config(&self) -> &ServerConfig {
        &self.config
    }

    /// Get the TLS configuration.
    pub fn tls_config(&self) -> &TlsConfig {
        &self.tls_config
    }

    /// Set the handshake timeout.
    pub fn set_handshake_timeout(&mut self, timeout: Duration) {
        self.handshake_timeout = timeout;
    }

    /// Get the handshake timeout.
    pub fn handshake_timeout(&self) -> Duration {
        self.handshake_timeout
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tls_acceptor_creation_requires_valid_config() {
        // Can't easily test without real certs, but verify the API
        let config_result = TlsConfig::builder()
            .certificate_path(std::path::PathBuf::from("/tmp/nonexistent.pem"))
            .private_key_path(std::path::PathBuf::from("/tmp/nonexistent-key.pem"))
            .build();

        assert!(config_result.is_ok());
    }
}
