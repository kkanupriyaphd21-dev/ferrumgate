//! JWT authentication middleware.
//!
//! Validates JWT tokens from Authorization header and
//! enforces access control policies.

use std::collections::HashMap;
use std::sync::Arc;

use crate::jwt_auth::{
    JwtConfig, JwtValidator, JwtError, AuthenticatedUser, TokenBlacklist,
    RoleChecker, record_auth, get_auth_metrics, AuthMetrics,
};

/// JWT authentication middleware.
pub struct JwtAuthMiddleware {
    validator: JwtValidator,
    blacklist: Option<Arc<TokenBlacklist>>,
    role_checker: Option<RoleChecker>,
    public_paths: Vec<String>,
}

impl JwtAuthMiddleware {
    pub fn new(config: JwtConfig) -> Self {
        Self {
            validator: JwtValidator::new(config),
            blacklist: None,
            role_checker: None,
            public_paths: Vec::new(),
        }
    }

    pub fn with_blacklist(mut self, blacklist: Arc<TokenBlacklist>) -> Self {
        self.blacklist = Some(blacklist);
        self
    }

    pub fn with_role_checker(mut self, checker: RoleChecker) -> Self {
        self.role_checker = Some(checker);
        self
    }

    pub fn with_public_paths(mut self, paths: Vec<&str>) -> Self {
        self.public_paths = paths.into_iter().map(String::from).collect();
        self
    }

    /// Authenticate a request.
    pub fn authenticate(
        &self,
        uri: &str,
        headers: &HashMap<String, String>,
    ) -> Result<AuthenticatedUser, JwtError> {
        // Check if path is public
        if self.is_public_path(uri) {
            return Ok(AuthenticatedUser {
                subject: "anonymous".to_string(),
                issuer: String::new(),
                audience: String::new(),
                roles: vec![],
                permissions: vec![],
                expires_at: u64::MAX,
                issued_at: 0,
                custom_claims: HashMap::new(),
            });
        }

        // Extract token from Authorization header
        let auth_header = headers.get("authorization")
            .ok_or_else(|| JwtError::Auth("missing authorization header".to_string()))?;

        let token = Self::extract_bearer_token(auth_header)?;

        // Validate token
        let user = self.validator.validate(token)?;

        // Check blacklist
        if let Some(blacklist) = &self.blacklist {
            if blacklist.is_revoked(&user.subject) {
                record_auth(false, "revoked");
                return Err(JwtError::TokenRevoked);
            }
        }

        // Check expiration
        if user.is_expired() {
            record_auth(false, "expired");
            return Err(JwtError::TokenExpired { expiry: user.expires_at });
        }

        record_auth(true, "");
        Ok(user)
    }

    /// Check if user has required permission.
    pub fn authorize(&self, user: &AuthenticatedUser, permission: &str) -> bool {
        if let Some(checker) = &self.role_checker {
            checker.check(user, permission)
        } else {
            true // No role checker configured, allow all authenticated
        }
    }

    fn is_public_path(&self, uri: &str) -> bool {
        self.public_paths.iter().any(|p| uri.starts_with(p))
    }

    fn extract_bearer_token(auth_header: &str) -> Result<&str, JwtError> {
        if !auth_header.starts_with("Bearer ") {
            return Err(JwtError::Auth("invalid authorization scheme".to_string()));
        }
        Ok(&auth_header[7..])
    }

    /// Get auth metrics.
    pub fn metrics(&self) -> AuthMetrics {
        get_auth_metrics()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_middleware_public_path() {
        let config = JwtConfig::new("issuer", "audience", b"key");
        let middleware = JwtAuthMiddleware::new(config)
            .with_public_paths(vec!["/health", "/public"]);

        let result = middleware.authenticate("/health", &HashMap::new());
        assert!(result.is_ok());
        assert_eq!(result.unwrap().subject, "anonymous");
    }

    #[test]
    fn test_middleware_missing_auth_header() {
        let config = JwtConfig::new("issuer", "audience", b"key");
        let middleware = JwtAuthMiddleware::new(config);

        let result = middleware.authenticate("/api/protected", &HashMap::new());
        assert!(result.is_err());
    }

    #[test]
    fn test_middleware_invalid_auth_scheme() {
        let config = JwtConfig::new("issuer", "audience", b"key");
        let middleware = JwtAuthMiddleware::new(config);

        let mut headers = HashMap::new();
        headers.insert("authorization".to_string(), "Basic token".to_string());
        let result = middleware.authenticate("/api/protected", &headers);
        assert!(result.is_err());
    }

    #[test]
    fn test_middleware_metrics() {
        let config = JwtConfig::new("issuer", "audience", b"key");
        let middleware = JwtAuthMiddleware::new(config);
        let metrics = middleware.metrics();
        assert_eq!(metrics.total, 0);
    }
}
