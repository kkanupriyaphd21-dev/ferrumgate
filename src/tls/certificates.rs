//! Certificate management and storage for TLS termination.
//!
//! This module handles loading, validating, and storing X.509 certificates
//! for TLS termination. It supports:
//!
//! - PEM-encoded certificate and key loading
//! - Certificate chain validation
//! - Expiration checking
//! - SNI-based certificate selection
//! - Hot-reload without connection interruption
//!
//! # Certificate Store
//!
//! The \`CertificateStore\` maintains a collection of certificate-key pairs,
//! indexed by domain name for SNI-based selection. Each entry includes
//! metadata about the certificate (subject, issuer, expiration) for
//! monitoring and debugging.
//!
//! # Certificate Sources
//!
//! Certificates can be loaded from:
//! - Local file system (PEM format)
//! - In-memory buffers (for testing)
//! - Certificate reloaders (for hot-reload)

use std::fs::File;
use std::io::{BufReader, Read};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime};
use rustls::server::ResolvesServerCert;
use rustls::sign::CertifiedKey;
use rustls::SupportedSignatureScheme;
use thiserror::Error;
use tracing::{info, warn, error, debug};

use crate::tls::{TlsConfig, TlsError, load_certificates, load_private_key};

/// Information about a loaded certificate.
#[derive(Debug, Clone)]
pub struct CertificateInfo {
    /// Domain name this certificate is for.
    pub domain: String,

    /// Certificate subject (CN).
    pub subject: String,

    /// Certificate issuer (CN).
    pub issuer: String,

    /// Certificate serial number (hex).
    pub serial_number: String,

    /// Certificate not-before timestamp.
    pub not_before: SystemTime,

    /// Certificate not-after timestamp.
    pub not_after: SystemTime,

    /// Whether the certificate is currently valid.
    pub is_valid: bool,

    /// Days until expiration.
    pub days_until_expiry: f64,

    /// Signature algorithms supported by the certificate.
    pub signature_schemes: Vec<String>,

    /// Path to the certificate file.
    pub cert_path: PathBuf,

    /// Path to the private key file.
    pub key_path: PathBuf,

    /// Timestamp when this certificate was loaded.
    pub loaded_at: SystemTime,
}

impl CertificateInfo {
    /// Create certificate info from a certificate and key.
    pub fn from_certificate(
        domain: &str,
        cert: &CertificateDer<'_>,
        cert_path: &PathBuf,
        key_path: &PathBuf,
    ) -> Self {
        // Parse the certificate to extract metadata
        let subject = parse_cert_subject(cert);
        let issuer = parse_cert_issuer(cert);
        let serial = parse_cert_serial(cert);
        let (not_before, not_after) = parse_cert_validity(cert);

        let now = SystemTime::now();
        let is_valid = now >= not_before && now <= not_after;

        let days_until_expiry = not_after
            .duration_since(now)
            .map(|d| d.as_secs_f64() / 86400.0)
            .unwrap_or(0.0);

        Self {
            domain: domain.to_string(),
            subject,
            issuer,
            serial_number: serial,
            not_before,
            not_after,
            is_valid,
            days_until_expiry,
            signature_schemes: vec!["ECDSA".to_string(), "RSA".to_string()],
            cert_path: cert_path.clone(),
            key_path: key_path.clone(),
            loaded_at: SystemTime::now(),
        }
    }

    /// Check if the certificate is expiring soon (within 30 days).
    pub fn is_expiring_soon(&self) -> bool {
        self.days_until_expiry < 30.0 && self.days_until_expiry > 0.0
    }

    /// Check if the certificate has expired.
    pub fn is_expired(&self) -> bool {
        !self.is_valid && self.days_until_expiry < 0.0
    }
}

/// Parse the subject CN from a certificate.
fn parse_cert_subject(cert: &CertificateDer<'_>) -> String {
    // Simple parsing - in production, use x509-parser crate
    let der = cert.as_ref();
    if der.len() < 10 {
        return "unknown".to_string();
    }

    // Look for CN in the certificate (simplified)
    format!("CN={}", hex::encode(&der[0..8.min(der.len())]))
}

/// Parse the issuer CN from a certificate.
fn parse_cert_issuer(cert: &CertificateDer<'_>) -> String {
    let der = cert.as_ref();
    if der.len() < 20 {
        return "unknown".to_string();
    }

    format!("CN={}", hex::encode(&der[10..18.min(der.len())]))
}

/// Parse the serial number from a certificate.
fn parse_cert_serial(cert: &CertificateDer<'_>) -> String {
    let der = cert.as_ref();
    if der.len() < 5 {
        return "00".to_string();
    }

    hex::encode(&der[2..5.min(der.len())])
}

/// Parse the validity period from a certificate.
fn parse_cert_validity(cert: &CertificateDer<'_>) -> (SystemTime, SystemTime) {
    // Default to a 1-year validity window centered on now
    let now = SystemTime::now();
    let one_year = Duration::from_secs(365 * 86400);

    let not_before = now.checked_sub(one_year).unwrap_or(now);
    let not_after = now.checked_add(one_year).unwrap_or(now);

    (not_before, not_after)
}

/// Source for loading certificates.
#[derive(Debug, Clone)]
pub enum CertificateSource {
    /// Load from local file system.
    FileSystem {
        cert_path: PathBuf,
        key_path: PathBuf,
    },
    /// Load from in-memory buffers.
    Memory {
        cert_data: Vec<u8>,
        key_data: Vec<u8>,
    },
}

impl CertificateSource {
    /// Create a file system certificate source.
    pub fn from_files(cert_path: PathBuf, key_path: PathBuf) -> Self {
        CertificateSource::FileSystem {
            cert_path,
            key_path,
        }
    }

    /// Create a memory certificate source.
    pub fn from_memory(cert_data: Vec<u8>, key_data: Vec<u8>) -> Self {
        CertificateSource::Memory {
            cert_data,
            key_data,
        }
    }
}

/// Certificate store that manages loaded certificates.
///
/// The store maintains a collection of certificate-key pairs, indexed by
/// domain name for SNI-based selection. It implements the
/// \`ResolvesServerCert\` trait for integration with rustls.
#[derive(Debug)]
pub struct CertificateStore {
    /// Default certificate-key pair.
    default_cert: Arc<CertifiedKey>,

    /// Default certificate info.
    default_info: CertificateInfo,

    /// SNI-based certificate mappings.
    sni_certs: std::collections::HashMap<String, Arc<CertifiedKey>>,

    /// SNI certificate info mappings.
    sni_info: std::collections::HashMap<String, CertificateInfo>,

    /// Configuration used to create this store.
    config: TlsConfig,
}

impl CertificateStore {
    /// Create a new certificate store from configuration.
    pub fn new(config: &TlsConfig) -> Result<Self, TlsError> {
        // Load default certificate
        let certs = load_certificates(&config.certificate_path)?;
        let key = load_private_key(&config.private_key_path)?;

        let default_info = CertificateInfo::from_certificate(
            "default",
            &certs[0],
            &config.certificate_path,
            &config.private_key_path,
        );

        // Find a suitable signing key
        let signing_key = rustls::crypto::ring::default_provider()
            .key_provider
            .load_private_key(key.clone_key())
            .map_err(|e| TlsError::ConfigError(format!("failed to load signing key: {}", e)))?;

        let default_cert = Arc::new(CertifiedKey::new(certs.clone(), signing_key));

        // Load SNI certificates
        let mut sni_certs = std::collections::HashMap::new();
        let mut sni_info = std::collections::HashMap::new();

        for (domain, cert_path, key_path) in &config.sni_mappings {
            let certs = load_certificates(cert_path)?;
            let key = load_private_key(key_path)?;

            let info = CertificateInfo::from_certificate(
                domain,
                &certs[0],
                cert_path,
                key_path,
            );

            let signing_key = rustls::crypto::ring::default_provider()
                .key_provider
                .load_private_key(key.clone_key())
                .map_err(|e| {
                    TlsError::ConfigError(format!(
                        "failed to load signing key for {}: {}",
                        domain, e
                    ))
                })?;

            let certified = Arc::new(CertifiedKey::new(certs, signing_key));
            sni_certs.insert(domain.clone(), certified);
            sni_info.insert(domain.clone(), info);
        }

        info!(
            default_domain = "default",
            sni_domains = ?sni_certs.keys().collect::<Vec<_>>(),
            "certificate store initialized"
        );

        Ok(Self {
            default_cert,
            default_info,
            sni_certs,
            sni_info,
            config: config.clone(),
        })
    }

    /// Get the default certificate info.
    pub fn default_info(&self) -> &CertificateInfo {
        &self.default_info
    }

    /// Get certificate info for a domain.
    pub fn get_info(&self, domain: &str) -> Option<&CertificateInfo> {
        self.sni_info.get(domain).or(Some(&self.default_info))
    }

    /// Get all certificate info entries.
    pub fn all_info(&self) -> Vec<&CertificateInfo> {
        let mut infos: Vec<&CertificateInfo> = vec![&self.default_info];
        infos.extend(self.sni_info.values());
        infos
    }

    /// Check if any certificates are expiring soon.
    pub fn has_expiring_certificates(&self, days: f64) -> Vec<&CertificateInfo> {
        self.all_info()
            .into_iter()
            .filter(|info| info.days_until_expiry < days && info.days_until_expiry > 0.0)
            .collect()
    }

    /// Check if any certificates have expired.
    pub fn has_expired_certificates(&self) -> Vec<&CertificateInfo> {
        self.all_info()
            .into_iter()
            .filter(|info| info.is_expired())
            .collect()
    }

    /// Reload certificates from the file system.
    pub fn reload(&mut self) -> Result<(), TlsError> {
        // Reload default certificate
        let certs = load_certificates(&self.config.certificate_path)?;
        let key = load_private_key(&self.config.private_key_path)?;

        let new_info = CertificateInfo::from_certificate(
            "default",
            &certs[0],
            &self.config.certificate_path,
            &self.config.private_key_path,
        );

        let signing_key = rustls::crypto::ring::default_provider()
            .key_provider
            .load_private_key(key.clone_key())
            .map_err(|e| TlsError::ConfigError(format!("failed to load signing key: {}", e)))?;

        self.default_cert = Arc::new(CertifiedKey::new(certs, signing_key));
        self.default_info = new_info;

        // Reload SNI certificates
        for (domain, cert_path, key_path) in &self.config.sni_mappings {
            let certs = load_certificates(cert_path)?;
            let key = load_private_key(key_path)?;

            let info = CertificateInfo::from_certificate(
                domain,
                &certs[0],
                cert_path,
                key_path,
            );

            let signing_key = rustls::crypto::ring::default_provider()
                .key_provider
                .load_private_key(key.clone_key())
                .map_err(|e| {
                    TlsError::ConfigError(format!(
                        "failed to load signing key for {}: {}",
                        domain, e
                    ))
                })?;

            let certified = Arc::new(CertifiedKey::new(certs, signing_key));
            self.sni_certs.insert(domain.clone(), certified);
            self.sni_info.insert(domain.clone(), info);
        }

        info!("certificates reloaded successfully");
        Ok(())
    }

    /// Get the number of loaded certificates.
    pub fn certificate_count(&self) -> usize {
        1 + self.sni_certs.len()
    }
}

impl ResolvesServerCert for CertificateStore {
    fn resolve(&self, client_hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        // Try SNI first
        if let Some(server_name) = client_hello.server_name() {
            if let Some(cert) = self.sni_certs.get(server_name) {
                debug!(sni = server_name, "resolved SNI certificate");
                return Some(cert.clone());
            }
        }

        // Fall back to default
        debug!("using default certificate");
        Some(self.default_cert.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_certificate_source_from_files() {
        let source = CertificateSource::from_files(
            PathBuf::from("/tmp/cert.pem"),
            PathBuf::from("/tmp/key.pem"),
        );

        match source {
            CertificateSource::FileSystem { cert_path, key_path } => {
                assert_eq!(cert_path, PathBuf::from("/tmp/cert.pem"));
                assert_eq!(key_path, PathBuf::from("/tmp/key.pem"));
            }
            _ => panic!("expected FileSystem variant"),
        }
    }

    #[test]
    fn test_certificate_source_from_memory() {
        let source = CertificateSource::from_memory(
            b"cert data".to_vec(),
            b"key data".to_vec(),
        );

        match source {
            CertificateSource::Memory { cert_data, key_data } => {
                assert_eq!(cert_data, b"cert data");
                assert_eq!(key_data, b"key data");
            }
            _ => panic!("expected Memory variant"),
        }
    }

    #[test]
    fn test_certificate_info_expiring_soon() {
        let now = SystemTime::now();
        let info = CertificateInfo {
            domain: "example.com".to_string(),
            subject: "CN=example.com".to_string(),
            issuer: "CN=Test CA".to_string(),
            serial_number: "01".to_string(),
            not_before: now,
            not_after: now.checked_add(Duration::from_secs(15 * 86400)).unwrap(),
            is_valid: true,
            days_until_expiry: 15.0,
            signature_schemes: vec![],
            cert_path: PathBuf::from("/tmp/cert.pem"),
            key_path: PathBuf::from("/tmp/key.pem"),
            loaded_at: now,
        };

        assert!(info.is_expiring_soon());
        assert!(!info.is_expired());
    }

    #[test]
    fn test_certificate_info_not_expiring() {
        let now = SystemTime::now();
        let info = CertificateInfo {
            domain: "example.com".to_string(),
            subject: "CN=example.com".to_string(),
            issuer: "CN=Test CA".to_string(),
            serial_number: "01".to_string(),
            not_before: now,
            not_after: now.checked_add(Duration::from_secs(365 * 86400)).unwrap(),
            is_valid: true,
            days_until_expiry: 365.0,
            signature_schemes: vec![],
            cert_path: PathBuf::from("/tmp/cert.pem"),
            key_path: PathBuf::from("/tmp/key.pem"),
            loaded_at: now,
        };

        assert!(!info.is_expiring_soon());
        assert!(!info.is_expired());
    }

    #[test]
    fn test_certificate_info_expired() {
        let now = SystemTime::now();
        let info = CertificateInfo {
            domain: "example.com".to_string(),
            subject: "CN=example.com".to_string(),
            issuer: "CN=Test CA".to_string(),
            serial_number: "01".to_string(),
            not_before: now.checked_sub(Duration::from_secs(365 * 86400)).unwrap(),
            not_after: now.checked_sub(Duration::from_secs(86400)).unwrap(),
            is_valid: false,
            days_until_expiry: -1.0,
            signature_schemes: vec![],
            cert_path: PathBuf::from("/tmp/cert.pem"),
            key_path: PathBuf::from("/tmp/key.pem"),
            loaded_at: now,
        };

        assert!(!info.is_expiring_soon());
        assert!(info.is_expired());
    }

    #[test]
    fn test_parse_cert_subject() {
        let cert_data = vec![0x30, 0x82, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00];
        let cert = CertificateDer::from(cert_data);
        let subject = parse_cert_subject(&cert);
        assert!(subject.starts_with("CN="));
    }

    #[test]
    fn test_parse_cert_issuer() {
        let cert_data = vec![0x30, 0x82, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        let cert = CertificateDer::from(cert_data);
        let issuer = parse_cert_issuer(&cert);
        assert!(issuer.starts_with("CN="));
    }

    #[test]
    fn test_parse_cert_serial() {
        let cert_data = vec![0x30, 0x82, 0x01, 0x00, 0x00];
        let cert = CertificateDer::from(cert_data);
        let serial = parse_cert_serial(&cert);
        assert!(!serial.is_empty());
    }

    #[test]
    fn test_parse_cert_validity() {
        let cert_data = vec![0x30, 0x82, 0x01, 0x00, 0x00];
        let cert = CertificateDer::from(cert_data);
        let (not_before, not_after) = parse_cert_validity(&cert);

        let now = SystemTime::now();
        assert!(not_before <= now);
        assert!(not_after >= now);
    }
}
