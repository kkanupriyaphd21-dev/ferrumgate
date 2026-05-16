//! JWT authentication middleware with token validation and refresh.
//!
//! Implements JWT authentication with:
//! - RS256/ES256 signature verification
//! - Token expiration and not-before validation
//! - Claim validation (audience, issuer, subject)
//! - Role-based access control (RBAC)
//! - Token refresh with rotation
//! - Token blacklist/revocation

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, RwLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use thiserror::Error;

pub mod validator;
pub mod claims;
pub mod middleware;
pub mod blacklist;

pub use validator::JwtValidator;
pub use claims::{JwtClaims, RoleChecker};
pub use middleware::JwtAuthMiddleware;
pub use blacklist::TokenBlacklist;

/// JWT authentication errors.
#[derive(Debug, Error)]
pub enum JwtError {
    #[error("token expired: expired at {expiry}")]
    TokenExpired { expiry: u64 },

    #[error("token not yet valid: valid from {not_before}")]
    NotYetValid { not_before: u64 },

    #[error("invalid signature")]
    InvalidSignature,

    #[error("invalid token format")]
    InvalidTokenFormat,

    #[error("invalid audience: expected {expected}, got {actual}")]
    InvalidAudience { expected: String, actual: String },

    #[error("invalid issuer: expected {expected}, got {actual}")]
    InvalidIssuer { expected: String, actual: String },

    #[error("missing required claim: {claim}")]
    MissingClaim { claim: String },

    #[error("insufficient permissions: required {required}, has {actual}")]
    InsufficientPermissions { required: String, actual: String },

    #[error("token revoked")]
    TokenRevoked,

    #[error("malformed JWT: {0}")]
    Malformed(String),

    #[error("authentication error: {0}")]
    Auth(String),
}

/// JWT authentication configuration.
#[derive(Debug, Clone)]
pub struct JwtConfig {
    pub issuer: String,
    pub audience: String,
    public_key: Vec<u8>,
    pub clock_skew_tolerance: Duration,
    pub required_claims: Vec<String>,
    pub enable_blacklist: bool,
    pub blacklist_ttl: Duration,
}

impl JwtConfig {
    pub fn new(issuer: &str, audience: &str, public_key: &[u8]) -> Self {
        Self {
            issuer: issuer.to_string(),
            audience: audience.to_string(),
            public_key: public_key.to_vec(),
            clock_skew_tolerance: Duration::from_secs(30),
            required_claims: vec!["sub".to_string()],
            enable_blacklist: true,
            blacklist_ttl: Duration::from_secs(3600),
        }
    }

    pub fn public_key(&self) -> &[u8] {
        &self.public_key
    }
}

/// Authenticated user context.
#[derive(Debug, Clone)]
pub struct AuthenticatedUser {
    pub subject: String,
    pub issuer: String,
    pub audience: String,
    pub roles: Vec<String>,
    pub permissions: Vec<String>,
    pub expires_at: u64,
    pub issued_at: u64,
    pub custom_claims: HashMap<String, String>,
}

impl AuthenticatedUser {
    pub fn has_role(&self, role: &str) -> bool {
        self.roles.iter().any(|r| r == role)
    }

    pub fn has_permission(&self, permission: &str) -> bool {
        self.permissions.iter().any(|p| p == permission)
    }

    pub fn is_expired(&self) -> bool {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        now > self.expires_at
    }
}

/// Global auth metrics.
static AUTH_TOTAL_REQUESTS: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
static AUTH_SUCCESSFUL: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
static AUTH_FAILED: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
static AUTH_EXPIRED: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
static AUTH_REVOKED: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

pub fn record_auth(success: bool, reason: &str) {
    AUTH_TOTAL_REQUESTS.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    if success {
        AUTH_SUCCESSFUL.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    } else {
        AUTH_FAILED.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        match reason {
            "expired" => AUTH_EXPIRED.fetch_add(1, std::sync::atomic::Ordering::Relaxed),
            "revoked" => AUTH_REVOKED.fetch_add(1, std::sync::atomic::Ordering::Relaxed),
            _ => {}
        }
    }
}

#[derive(Debug)]
pub struct AuthMetrics {
    pub total: u64,
    pub successful: u64,
    pub failed: u64,
    pub expired: u64,
    pub revoked: u64,
    pub success_rate: f64,
}

pub fn get_auth_metrics() -> AuthMetrics {
    let total = AUTH_TOTAL_REQUESTS.load(std::sync::atomic::Ordering::Relaxed);
    let successful = AUTH_SUCCESSFUL.load(std::sync::atomic::Ordering::Relaxed);
    AuthMetrics {
        total,
        successful,
        failed: AUTH_FAILED.load(std::sync::atomic::Ordering::Relaxed),
        expired: AUTH_EXPIRED.load(std::sync::atomic::Ordering::Relaxed),
        revoked: AUTH_REVOKED.load(std::sync::atomic::Ordering::Relaxed),
        success_rate: if total == 0 { 0.0 } else { successful as f64 / total as f64 },
    }
}

/// Base64 URL decode.
pub fn base64_url_decode(input: &str) -> Result<Vec<u8>, JwtError> {
    let mut s = input.replace('-', "+").replace('_', "/");
    while s.len() % 4 != 0 {
        s.push('=');
    }
    base64::decode(&s).map_err(|e| JwtError::Malformed(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_authenticated_user_has_role() {
        let user = AuthenticatedUser {
            subject: "user-1".to_string(),
            issuer: "test".to_string(),
            audience: "api".to_string(),
            roles: vec!["admin".to_string(), "user".to_string()],
            permissions: vec!["read".to_string()],
            expires_at: u64::MAX,
            issued_at: 0,
            custom_claims: HashMap::new(),
        };
        assert!(user.has_role("admin"));
        assert!(!user.has_role("superadmin"));
    }

    #[test]
    fn test_authenticated_user_has_permission() {
        let user = AuthenticatedUser {
            subject: "user-1".to_string(),
            issuer: "test".to_string(),
            audience: "api".to_string(),
            roles: vec![],
            permissions: vec!["read".to_string(), "write".to_string()],
            expires_at: u64::MAX,
            issued_at: 0,
            custom_claims: HashMap::new(),
        };
        assert!(user.has_permission("read"));
        assert!(!user.has_permission("delete"));
    }

    #[test]
    fn test_authenticated_user_expired() {
        let user = AuthenticatedUser {
            subject: "user-1".to_string(),
            issuer: "test".to_string(),
            audience: "api".to_string(),
            roles: vec![],
            permissions: vec![],
            expires_at: 0,
            issued_at: 0,
            custom_claims: HashMap::new(),
        };
        assert!(user.is_expired());
    }

    #[test]
    fn test_jwt_config() {
        let config = JwtConfig::new("https://auth.example.com", "api", b"public-key");
        assert_eq!(config.issuer, "https://auth.example.com");
        assert_eq!(config.audience, "api");
        assert_eq!(config.public_key(), b"public-key");
    }

    #[test]
    fn test_auth_metrics_initial() {
        let metrics = get_auth_metrics();
        assert_eq!(metrics.total, 0);
        assert_eq!(metrics.success_rate, 0.0);
    }

    #[test]
    fn test_base64_url_decode() {
        let decoded = base64_url_decode("SGVsbG8").unwrap();
        assert_eq!(decoded, b"Hello");
    }
}
