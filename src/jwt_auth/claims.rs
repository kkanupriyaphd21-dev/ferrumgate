//! JWT claims validation and role-based access control.
//!
//! Provides claim extraction, validation, and RBAC enforcement.

use std::collections::{HashMap, HashSet};

use crate::jwt_auth::AuthenticatedUser;

/// Validates JWT claims against policies.
pub struct JwtClaims {
    required_claims: HashSet<String>,
    allowed_issuers: HashSet<String>,
    allowed_audiences: HashSet<String>,
}

impl JwtClaims {
    pub fn new() -> Self {
        Self {
            required_claims: HashSet::new(),
            allowed_issuers: HashSet::new(),
            allowed_audiences: HashSet::new(),
        }
    }

    pub fn require_claim(mut self, claim: &str) -> Self {
        self.required_claims.insert(claim.to_string());
        self
    }

    pub fn allow_issuer(mut self, issuer: &str) -> Self {
        self.allowed_issuers.insert(issuer.to_string());
        self
    }

    pub fn allow_audience(mut self, audience: &str) -> Self {
        self.allowed_audiences.insert(audience.to_string());
        self
    }

    pub fn validate(&self, user: &AuthenticatedUser) -> Result<(), String> {
        if !self.allowed_issuers.is_empty() && !self.allowed_issuers.contains(&user.issuer) {
            return Err(format!("issuer '{}' not allowed", user.issuer));
        }
        if !self.allowed_audiences.is_empty() && !self.allowed_audiences.contains(&user.audience) {
            return Err(format!("audience '{}' not allowed", user.audience));
        }
        Ok(())
    }
}

/// Role-based access control checker.
pub struct RoleChecker {
    role_permissions: HashMap<String, HashSet<String>>,
}

impl RoleChecker {
    pub fn new() -> Self {
        Self {
            role_permissions: HashMap::new(),
        }
    }

    pub fn add_role(mut self, role: &str, permissions: Vec<&str>) -> Self {
        self.role_permissions.insert(
            role.to_string(),
            permissions.into_iter().map(String::from).collect(),
        );
        self
    }

    pub fn check(&self, user: &AuthenticatedUser, required_permission: &str) -> bool {
        // Check direct permissions
        if user.has_permission(required_permission) {
            return true;
        }

        // Check role-based permissions
        for role in &user.roles {
            if let Some(perms) = self.role_permissions.get(role) {
                if perms.contains(required_permission) {
                    return true;
                }
            }
        }

        false
    }

    pub fn check_any(&self, user: &AuthenticatedUser, permissions: &[&str]) -> bool {
        permissions.iter().any(|p| self.check(user, p))
    }

    pub fn check_all(&self, user: &AuthenticatedUser, permissions: &[&str]) -> bool {
        permissions.iter().all(|p| self.check(user, p))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_user() -> AuthenticatedUser {
        AuthenticatedUser {
            subject: "user-1".to_string(),
            issuer: "https://auth.example.com".to_string(),
            audience: "api".to_string(),
            roles: vec!["editor".to_string()],
            permissions: vec!["read".to_string()],
            expires_at: u64::MAX,
            issued_at: 0,
            custom_claims: HashMap::new(),
        }
    }

    #[test]
    fn test_jwt_claims_validation() {
        let claims = JwtClaims::new()
            .allow_issuer("https://auth.example.com")
            .allow_audience("api");

        let user = create_test_user();
        assert!(claims.validate(&user).is_ok());
    }

    #[test]
    fn test_jwt_claims_invalid_issuer() {
        let claims = JwtClaims::new()
            .allow_issuer("https://other-auth.com");

        let user = create_test_user();
        assert!(claims.validate(&user).is_err());
    }

    #[test]
    fn test_role_checker_direct_permission() {
        let checker = RoleChecker::new();
        let user = create_test_user();
        assert!(checker.check(&user, "read"));
    }

    #[test]
    fn test_role_checker_role_permission() {
        let checker = RoleChecker::new()
            .add_role("editor", vec!["read", "write", "update"]);

        let user = create_test_user();
        assert!(checker.check(&user, "write"));
        assert!(checker.check(&user, "update"));
        assert!(!checker.check(&user, "delete"));
    }

    #[test]
    fn test_role_checker_check_any() {
        let checker = RoleChecker::new()
            .add_role("editor", vec!["write"]);

        let user = create_test_user();
        assert!(checker.check_any(&user, &["delete", "write"]));
        assert!(!checker.check_any(&user, &["delete", "admin"]));
    }

    #[test]
    fn test_role_checker_check_all() {
        let checker = RoleChecker::new()
            .add_role("editor", vec!["read", "write"]);

        let user = create_test_user();
        assert!(checker.check_all(&user, &["read", "write"]));
        assert!(!checker.check_all(&user, &["read", "delete"]));
    }
}
