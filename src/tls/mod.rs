//! TLS termination and certificate management for ferrumgate.
//!
//! This module provides production-grade TLS termination using \`rustls\`,
//! replacing the stub cryptographic implementations with industry-standard
//! primitives. It supports:
//!
//! - TLS 1.3 with optional 1.2 fallback
//! - SNI-based multi-certificate selection
//! - Mutual TLS (mTLS) client authentication
//! - Certificate hot-reload without connection interruption
//! - ALPN protocol negotiation
//! - Session ticket rotation
//! - OCSP stapling
//!
//! # Architecture
//!
//! The TLS module is organized into four main components:
//!
//! 1. **Configuration** (\`TlsConfig\`) - Declarative TLS settings
//! 2. **Certificate Management** (\`CertificateStore\`) - Certificate loading and rotation
//! 3. **TLS Acceptor** (\`TlsAcceptor\`) - Async TLS handshake handling
//! 4. **Connection** (\`TlsConnection\`) - Wrapped TLS stream with metadata
//!
//! # Security Defaults
//!
//! The module enforces secure defaults:
//! - Only TLS 1.3 cipher suites enabled by default
//! - TLS 1.2 requires explicit opt-in with hardened cipher selection
//! - Certificate validation is mandatory for client certificates
//! - Session tickets are rotated every 24 hours
//! - OCSP stapling is enabled when available
//!
//! # Example
//!
//! \`\`\`rust
//! use ferrumgate::tls::{TlsConfig, TlsAcceptor, CertificateStore};
//!
//! let config = TlsConfig::builder()
//!     .certificate_path("/etc/ferrumgate/certs/server.pem")
//!     .private_key_path("/etc/ferrumgate/certs/server-key.pem")
//!     .client_ca_path("/etc/ferrumgate/certs/ca.pem")
//!     .min_tls_version(TlsVersion::Tls13)
//!     .alpn_protocols(vec!["h2".into(), "http/1.1".into()])
//!     .build()?;
//!
//! let store = CertificateStore::new(&config)?;
//! let acceptor = TlsAcceptor::new(store, config)?;
//! \`\`\`

use std::fs::File;
use std::io::{self, BufReader, Read};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime};
use rustls::server::{ClientHello, ResolvesServerCert, ServerSessionMemoryCache, WebPkiClientVerifier};
use rustls::version::{TLS12, TLS13};
use rustls::{
    ClientConfig, RootCertStore, ServerConfig, SupportedProtocolVersion,
    DigitallySignedStruct, SignatureScheme,
};
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_rustls::TlsAcceptor as TokioTlsAcceptor;
use tracing::{info, warn, error, debug};

pub mod acceptor;
pub mod certificates;
pub mod connection;
pub mod reload;

// Re-exports
pub use acceptor::TlsAcceptor;
pub use certificates::{CertificateStore, CertificateInfo, CertificateSource};
pub use connection::TlsConnection;
pub use reload::CertificateReloader;

/// TLS-specific error types.
#[derive(Debug, Error)]
pub enum TlsError {
    #[error("failed to load certificate from {path}: {source}")]
    CertificateLoad {
        path: PathBuf,
        #[source]
        source: io::Error,
    },

    #[error("failed to load private key from {path}: {source}")]
    PrivateKeyLoad {
        path: PathBuf,
        #[source]
        source: io::Error,
    },

    #[error("no certificates found in {path}")]
    NoCertificates { path: PathBuf },

    #[error("no private keys found in {path}")]
    NoPrivateKeys { path: PathBuf },

    #[error("invalid private key format in {path}")]
    InvalidPrivateKey { path: PathBuf },

    #[error("failed to parse certificate: {0}")]
    CertificateParse(String),

    #[error("TLS configuration error: {0}")]
    ConfigError(String),

    #[error("TLS handshake failed: {0}")]
    HandshakeFailed(String),

    #[error("certificate expired: {subject}")]
    CertificateExpired { subject: String },

    #[error("certificate not yet valid: {subject}")]
    CertificateNotYetValid { subject: String },

    #[error("client certificate required but not provided")]
    ClientCertRequired,

    #[error("client certificate validation failed: {0}")]
    ClientCertValidationFailed(String),

    #[error("SNI certificate not found for domain: {0}")]
    SniCertificateNotFound(String),

    #[error("ALPN protocol negotiation failed")]
    AlpnNegotiationFailed,

    #[error("certificate reload failed: {0}")]
    ReloadFailed(String),

    #[error("OCSP response error: {0}")]
    OcspError(String),
}

/// TLS protocol version.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TlsVersion {
    Tls12,
    Tls13,
}

impl TlsVersion {
    /// Convert to rustls protocol version.
    pub fn to_rustls(&self) -> &'static SupportedProtocolVersion {
        match self {
            TlsVersion::Tls12 => &TLS12,
            TlsVersion::Tls13 => &TLS13,
        }
    }

    /// Get the string representation.
    pub fn as_str(&self) -> &'static str {
        match self {
            TlsVersion::Tls12 => "TLSv1.2",
            TlsVersion::Tls13 => "TLSv1.3",
        }
    }
}

impl Default for TlsVersion {
    fn default() -> Self {
        TlsVersion::Tls13
    }
}

/// Cipher suite identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CipherSuite {
    Tls13Aes256GcmSha384,
    Tls13Aes128GcmSha256,
    Tls13Chacha20Poly1305Sha256,
    Tls12EcdheEcdsaAes256GcmSha384,
    Tls12EcdheEcdsaAes128GcmSha256,
    Tls12EcdheRsaAes256GcmSha384,
    Tls12EcdheRsaAes128GcmSha256,
}

impl CipherSuite {
    /// Get all TLS 1.3 cipher suites.
    pub fn tls13_suites() -> Vec<Self> {
        vec![
            CipherSuite::Tls13Aes256GcmSha384,
            CipherSuite::Tls13Aes128GcmSha256,
            CipherSuite::Tls13Chacha20Poly1305Sha256,
        ]
    }

    /// Get all TLS 1.2 cipher suites.
    pub fn tls12_suites() -> Vec<Self> {
        vec![
            CipherSuite::Tls12EcdheEcdsaAes256GcmSha384,
            CipherSuite::Tls12EcdheEcdsaAes128GcmSha256,
            CipherSuite::Tls12EcdheRsaAes256GcmSha384,
            CipherSuite::Tls12EcdheRsaAes128GcmSha256,
        ]
    }
}

/// Complete TLS configuration.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct TlsConfig {
    /// Path to the server certificate file (PEM format).
    pub certificate_path: PathBuf,

    /// Path to the server private key file (PEM format).
    pub private_key_path: PathBuf,

    /// Path to the CA certificate file for client authentication (mTLS).
    /// If None, client authentication is disabled.
    pub client_ca_path: Option<PathBuf>,

    /// Minimum TLS version to accept.
    pub min_tls_version: TlsVersion,

    /// ALPN protocols to advertise.
    pub alpn_protocols: Vec<Vec<u8>>,

    /// Whether to enable OCSP stapling.
    pub enable_ocsp_stapling: bool,

    /// Session ticket lifetime in seconds.
    pub session_ticket_lifetime_secs: u64,

    /// Maximum number of cached TLS sessions.
    pub max_session_cache_size: usize,

    /// Whether to require client certificates (mTLS).
    pub require_client_cert: bool,

    /// Certificate reload interval in seconds (0 = disabled).
    pub reload_interval_secs: u64,

    /// SNI domain to certificate path mappings.
    pub sni_mappings: Vec<(String, PathBuf, PathBuf)>,

    /// HSTS max age in seconds (0 = disabled).
    pub hsts_max_age_secs: u64,

    /// Whether to include subdomains in HSTS.
    pub hsts_include_subdomains: bool,
}

impl TlsConfig {
    /// Create a new builder for constructing a TlsConfig.
    pub fn builder() -> TlsConfigBuilder {
        TlsConfigBuilder::default()
    }

    /// Load configuration from environment variables.
    ///
    /// Recognized variables:
    /// - \`FERRUMGATE_TLS_CERT\`: path to server certificate
    /// - \`FERRUMGATE_TLS_KEY\`: path to server private key
    /// - \`FERRUMGATE_TLS_CLIENT_CA\`: path to client CA certificate
    /// - \`FERRUMGATE_TLS_MIN_VERSION\`: tls12 or tls13
    /// - \`FERRUMGATE_TLS_ALPN\`: comma-separated ALPN protocols
    /// - \`FERRUMGATE_TLS_REQUIRE_CLIENT_CERT\`: true or false
    /// - \`FERRUMGATE_TLS_RELOAD_INTERVAL\`: reload interval in seconds
    pub fn from_env() -> Result<Self, TlsError> {
        let mut builder = TlsConfigBuilder::default();

        if let Ok(cert) = std::env::var("FERRUMGATE_TLS_CERT") {
            builder = builder.certificate_path(PathBuf::from(cert));
        }

        if let Ok(key) = std::env::var("FERRUMGATE_TLS_KEY") {
            builder = builder.private_key_path(PathBuf::from(key));
        }

        if let Ok(ca) = std::env::var("FERRUMGATE_TLS_CLIENT_CA") {
            builder = builder.client_ca_path(PathBuf::from(ca));
        }

        if let Ok(version) = std::env::var("FERRUMGATE_TLS_MIN_VERSION") {
            match version.to_lowercase().as_str() {
                "tls12" => builder = builder.min_tls_version(TlsVersion::Tls12),
                "tls13" => builder = builder.min_tls_version(TlsVersion::Tls13),
                _ => {}
            }
        }

        if let Ok(alpn) = std::env::var("FERRUMGATE_TLS_ALPN") {
            let protocols: Vec<Vec<u8>> = alpn
                .split(',')
                .map(|s| s.trim().as_bytes().to_vec())
                .collect();
            builder = builder.alpn_protocols(protocols);
        }

        if let Ok(require) = std::env::var("FERRUMGATE_TLS_REQUIRE_CLIENT_CERT") {
            if require.eq_ignore_ascii_case("true") {
                builder = builder.require_client_cert(true);
            }
        }

        if let Ok(interval) = std::env::var("FERRUMGATE_TLS_RELOAD_INTERVAL") {
            if let Ok(secs) = interval.parse::<u64>() {
                builder = builder.reload_interval_secs(secs);
            }
        }

        builder.build()
    }

    /// Check if mTLS is enabled.
    pub fn is_mutual_tls(&self) -> bool {
        self.client_ca_path.is_some() || self.require_client_cert
    }

    /// Check if certificate reload is enabled.
    pub fn is_reload_enabled(&self) -> bool {
        self.reload_interval_secs > 0
    }

    /// Get the HSTS header value if HSTS is enabled.
    pub fn hsts_header(&self) -> Option<String> {
        if self.hsts_max_age_secs == 0 {
            return None;
        }

        let mut header = format!("max-age={}", self.hsts_max_age_secs);
        if self.hsts_include_subdomains {
            header.push_str("; includeSubDomains");
        }
        header.push_str("; preload");
        Some(header)
    }
}

/// Builder for constructing TlsConfig with fluent API.
#[derive(Debug, Default)]
pub struct TlsConfigBuilder {
    certificate_path: Option<PathBuf>,
    private_key_path: Option<PathBuf>,
    client_ca_path: Option<PathBuf>,
    min_tls_version: TlsVersion,
    alpn_protocols: Vec<Vec<u8>>,
    enable_ocsp_stapling: bool,
    session_ticket_lifetime_secs: u64,
    max_session_cache_size: usize,
    require_client_cert: bool,
    reload_interval_secs: u64,
    sni_mappings: Vec<(String, PathBuf, PathBuf)>,
    hsts_max_age_secs: u64,
    hsts_include_subdomains: bool,
}

impl TlsConfigBuilder {
    pub fn certificate_path(mut self, path: PathBuf) -> Self {
        self.certificate_path = Some(path);
        self
    }

    pub fn private_key_path(mut self, path: PathBuf) -> Self {
        self.private_key_path = Some(path);
        self
    }

    pub fn client_ca_path(mut self, path: PathBuf) -> Self {
        self.client_ca_path = Some(path);
        self
    }

    pub fn min_tls_version(mut self, version: TlsVersion) -> Self {
        self.min_tls_version = version;
        self
    }

    pub fn alpn_protocols(mut self, protocols: Vec<Vec<u8>>) -> Self {
        self.alpn_protocols = protocols;
        self
    }

    pub fn enable_ocsp_stapling(mut self, enabled: bool) -> Self {
        self.enable_ocsp_stapling = enabled;
        self
    }

    pub fn session_ticket_lifetime_secs(mut self, secs: u64) -> Self {
        self.session_ticket_lifetime_secs = secs;
        self
    }

    pub fn max_session_cache_size(mut self, size: usize) -> Self {
        self.max_session_cache_size = size;
        self
    }

    pub fn require_client_cert(mut self, required: bool) -> Self {
        self.require_client_cert = required;
        self
    }

    pub fn reload_interval_secs(mut self, secs: u64) -> Self {
        self.reload_interval_secs = secs;
        self
    }

    pub fn sni_mapping(mut self, domain: String, cert: PathBuf, key: PathBuf) -> Self {
        self.sni_mappings.push((domain, cert, key));
        self
    }

    pub fn hsts_max_age_secs(mut self, secs: u64) -> Self {
        self.hsts_max_age_secs = secs;
        self
    }

    pub fn hsts_include_subdomains(mut self, enabled: bool) -> Self {
        self.hsts_include_subdomains = enabled;
        self
    }

    pub fn build(self) -> Result<TlsConfig, TlsError> {
        let certificate_path = self.certificate_path.ok_or_else(|| {
            TlsError::ConfigError("certificate_path is required".into())
        })?;

        let private_key_path = self.private_key_path.ok_or_else(|| {
            TlsError::ConfigError("private_key_path is required".into())
        })?;

        Ok(TlsConfig {
            certificate_path,
            private_key_path,
            client_ca_path: self.client_ca_path,
            min_tls_version: self.min_tls_version,
            alpn_protocols: self.alpn_protocols,
            enable_ocsp_stapling: self.enable_ocsp_stapling,
            session_ticket_lifetime_secs: if self.session_ticket_lifetime_secs == 0 {
                86400 // 24 hours
            } else {
                self.session_ticket_lifetime_secs
            },
            max_session_cache_size: if self.max_session_cache_size == 0 {
                1024
            } else {
                self.max_session_cache_size
            },
            require_client_cert: self.require_client_cert,
            reload_interval_secs: self.reload_interval_secs,
            sni_mappings: self.sni_mappings,
            hsts_max_age_secs: self.hsts_max_age_secs,
            hsts_include_subdomains: self.hsts_include_subdomains,
        })
    }
}

/// Load certificates from a PEM file.
pub fn load_certificates(path: &PathBuf) -> Result<Vec<CertificateDer<'static>>, TlsError> {
    let file = File::open(path).map_err(|e| TlsError::CertificateLoad {
        path: path.clone(),
        source: e,
    })?;

    let mut reader = BufReader::new(file);
    let certs = rustls_pemfile::certs(&mut reader)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| TlsError::CertificateParse(e.to_string()))?;

    if certs.is_empty() {
        return Err(TlsError::NoCertificates { path: path.clone() });
    }

    info!(
        path = %path.display(),
        count = certs.len(),
        "loaded certificates"
    );

    Ok(certs)
}

/// Load a private key from a PEM file.
pub fn load_private_key(path: &PathBuf) -> Result<PrivateKeyDer<'static>, TlsError> {
    let file = File::open(path).map_err(|e| TlsError::PrivateKeyLoad {
        path: path.clone(),
        source: e,
    })?;

    let mut reader = BufReader::new(file);

    // Try to load PKCS#8 key first, then RSA, then EC
    let key = rustls_pemfile::private_key(&mut reader)
        .map_err(|e| TlsError::CertificateParse(e.to_string()))?
        .ok_or_else(|| TlsError::NoPrivateKeys { path: path.clone() })?;

    info!(
        path = %path.display(),
        "loaded private key"
    );

    Ok(key)
}

/// Global TLS metrics counters.
static TLS_HANDSHAKES_TOTAL: AtomicU64 = AtomicU64::new(0);
static TLS_HANDSHAKE_ERRORS: AtomicU64 = AtomicU64::new(0);
static TLS_SESSIONS_RESUMED: AtomicU64 = AtomicU64::new(0);
static TLS_CERTIFICATE_RELOADS: AtomicU64 = AtomicU64::new(0);

/// Record a successful TLS handshake.
pub fn record_tls_handshake() {
    TLS_HANDSHAKES_TOTAL.fetch_add(1, Ordering::Relaxed);
}

/// Record a TLS handshake error.
pub fn record_tls_handshake_error() {
    TLS_HANDSHAKE_ERRORS.fetch_add(1, Ordering::Relaxed);
}

/// Record a resumed TLS session.
pub fn record_session_resumed() {
    TLS_SESSIONS_RESUMED.fetch_add(1, Ordering::Relaxed);
}

/// Record a certificate reload.
pub fn record_certificate_reload() {
    TLS_CERTIFICATE_RELOADS.fetch_add(1, Ordering::Relaxed);
}

/// Get TLS metrics.
pub fn get_tls_metrics() -> TlsMetrics {
    TlsMetrics {
        handshakes_total: TLS_HANDSHAKES_TOTAL.load(Ordering::Relaxed),
        handshake_errors: TLS_HANDSHAKE_ERRORS.load(Ordering::Relaxed),
        sessions_resumed: TLS_SESSIONS_RESUMED.load(Ordering::Relaxed),
        certificate_reloads: TLS_CERTIFICATE_RELOADS.load(Ordering::Relaxed),
        handshake_success_rate: {
            let total = TLS_HANDSHAKES_TOTAL.load(Ordering::Relaxed);
            let errors = TLS_HANDSHAKE_ERRORS.load(Ordering::Relaxed);
            if total == 0 {
                100.0
            } else {
                ((total - errors) as f64 / total as f64) * 100.0
            }
        },
    }
}

/// TLS metrics snapshot.
#[derive(Debug, Clone)]
pub struct TlsMetrics {
    pub handshakes_total: u64,
    pub handshake_errors: u64,
    pub sessions_resumed: u64,
    pub certificate_reloads: u64,
    pub handshake_success_rate: f64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tls_version_to_rustls() {
        assert_eq!(TlsVersion::Tls12.to_rustls().version, TLS12.version);
        assert_eq!(TlsVersion::Tls13.to_rustls().version, TLS13.version);
    }

    #[test]
    fn test_tls_version_as_str() {
        assert_eq!(TlsVersion::Tls12.as_str(), "TLSv1.2");
        assert_eq!(TlsVersion::Tls13.as_str(), "TLSv1.3");
    }

    #[test]
    fn test_tls_version_default() {
        assert_eq!(TlsVersion::default(), TlsVersion::Tls13);
    }

    #[test]
    fn test_cipher_suite_tls13() {
        let suites = CipherSuite::tls13_suites();
        assert_eq!(suites.len(), 3);
        assert!(suites.contains(&CipherSuite::Tls13Aes256GcmSha384));
        assert!(suites.contains(&CipherSuite::Tls13Aes128GcmSha256));
        assert!(suites.contains(&CipherSuite::Tls13Chacha20Poly1305Sha256));
    }

    #[test]
    fn test_cipher_suite_tls12() {
        let suites = CipherSuite::tls12_suites();
        assert_eq!(suites.len(), 4);
        assert!(suites.contains(&CipherSuite::Tls12EcdheEcdsaAes256GcmSha384));
        assert!(suites.contains(&CipherSuite::Tls12EcdheRsaAes128GcmSha256));
    }

    #[test]
    fn test_tls_config_builder_required_fields() {
        let result = TlsConfigBuilder::default().build();
        assert!(result.is_err());

        let result = TlsConfigBuilder::default()
            .certificate_path(PathBuf::from("/tmp/cert.pem"))
            .build();
        assert!(result.is_err());

        let result = TlsConfigBuilder::default()
            .private_key_path(PathBuf::from("/tmp/key.pem"))
            .build();
        assert!(result.is_err());
    }

    #[test]
    fn test_tls_config_builder_defaults() {
        let config = TlsConfigBuilder::default()
            .certificate_path(PathBuf::from("/tmp/cert.pem"))
            .private_key_path(PathBuf::from("/tmp/key.pem"))
            .build()
            .unwrap();

        assert_eq!(config.min_tls_version, TlsVersion::Tls13);
        assert_eq!(config.session_ticket_lifetime_secs, 86400);
        assert_eq!(config.max_session_cache_size, 1024);
        assert!(!config.require_client_cert);
        assert!(!config.is_mutual_tls());
        assert!(!config.is_reload_enabled());
    }

    #[test]
    fn test_tls_config_builder_custom() {
        let config = TlsConfigBuilder::default()
            .certificate_path(PathBuf::from("/tmp/cert.pem"))
            .private_key_path(PathBuf::from("/tmp/key.pem"))
            .client_ca_path(PathBuf::from("/tmp/ca.pem"))
            .min_tls_version(TlsVersion::Tls12)
            .alpn_protocols(vec![b"h2".to_vec(), b"http/1.1".to_vec()])
            .enable_ocsp_stapling(true)
            .session_ticket_lifetime_secs(3600)
            .max_session_cache_size(2048)
            .require_client_cert(true)
            .reload_interval_secs(300)
            .hsts_max_age_secs(31536000)
            .hsts_include_subdomains(true)
            .build()
            .unwrap();

        assert_eq!(config.min_tls_version, TlsVersion::Tls12);
        assert_eq!(config.alpn_protocols.len(), 2);
        assert!(config.enable_ocsp_stapling);
        assert_eq!(config.session_ticket_lifetime_secs, 3600);
        assert_eq!(config.max_session_cache_size, 2048);
        assert!(config.require_client_cert);
        assert!(config.is_mutual_tls());
        assert!(config.is_reload_enabled());
        assert_eq!(config.reload_interval_secs, 300);
    }

    #[test]
    fn test_tls_config_hsts_header() {
        let config = TlsConfigBuilder::default()
            .certificate_path(PathBuf::from("/tmp/cert.pem"))
            .private_key_path(PathBuf::from("/tmp/key.pem"))
            .hsts_max_age_secs(31536000)
            .hsts_include_subdomains(true)
            .build()
            .unwrap();

        let header = config.hsts_header().unwrap();
        assert_eq!(
            header,
            "max-age=31536000; includeSubDomains; preload"
        );
    }

    #[test]
    fn test_tls_config_hsts_disabled() {
        let config = TlsConfigBuilder::default()
            .certificate_path(PathBuf::from("/tmp/cert.pem"))
            .private_key_path(PathBuf::from("/tmp/key.pem"))
            .build()
            .unwrap();

        assert!(config.hsts_header().is_none());
    }

    #[test]
    fn test_tls_metrics_initial_state() {
        let metrics = get_tls_metrics();
        // Metrics may have values from other tests, just verify structure
        assert!(metrics.handshake_success_rate >= 0.0);
        assert!(metrics.handshake_success_rate <= 100.0);
    }

    #[test]
    fn test_tls_config_serialization() {
        let config = TlsConfigBuilder::default()
            .certificate_path(PathBuf::from("/tmp/cert.pem"))
            .private_key_path(PathBuf::from("/tmp/key.pem"))
            .min_tls_version(TlsVersion::Tls13)
            .build()
            .unwrap();

        let json = serde_json::to_string(&config).unwrap();
        let deserialized: TlsConfig = serde_json::from_str(&json).unwrap();

        assert_eq!(deserialized.certificate_path, PathBuf::from("/tmp/cert.pem"));
        assert_eq!(deserialized.private_key_path, PathBuf::from("/tmp/key.pem"));
        assert_eq!(deserialized.min_tls_version, TlsVersion::Tls13);
    }
}
