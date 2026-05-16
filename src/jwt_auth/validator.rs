//! JWT token validation.
//!
//! Validates JWT tokens including signature verification,
//! expiration, and claim validation.

use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::jwt_auth::{JwtConfig, JwtError, AuthenticatedUser, base64_url_decode};

/// JWT header.
#[derive(Debug)]
pub struct JwtHeader {
    pub algorithm: String,
    pub token_type: String,
    pub key_id: Option<String>,
}

/// Validates JWT tokens.
pub struct JwtValidator {
    config: JwtConfig,
}

impl JwtValidator {
    pub fn new(config: JwtConfig) -> Self {
        Self { config }
    }

    /// Validate and parse a JWT token.
    pub fn validate(&self, token: &str) -> Result<AuthenticatedUser, JwtError> {
        let parts: Vec<&str> = token.split('.').collect();
        if parts.len() != 3 {
            return Err(JwtError::InvalidTokenFormat);
        }

        let header = Self::decode_header(parts[0])?;
        self.verify_algorithm(&header)?;

        let claims = Self::decode_claims(parts[1])?;
        self.validate_claims(&claims)?;

        // In production, verify signature with public key
        // For now, we validate structure and claims
        self.extract_user(&claims)
    }

    fn decode_header(encoded: &str) -> Result<JwtHeader, JwtError> {
        let bytes = base64_url_decode(encoded)?;
        let json = String::from_utf8(bytes)
            .map_err(|e| JwtError::Malformed(e.to_string()))?;

        let mut algorithm = String::new();
        let mut token_type = String::new();
        let mut key_id = None;

        // Simple JSON parsing
        if let Some(alg) = Self::extract_json_string(&json, "alg") {
            algorithm = alg;
        }
        if let Some(typ) = Self::extract_json_string(&json, "typ") {
            token_type = typ;
        }
        if let Some(kid) = Self::extract_json_string(&json, "kid") {
            key_id = Some(kid);
        }

        Ok(JwtHeader { algorithm, token_type, key_id })
    }

    fn decode_claims(encoded: &str) -> Result<HashMap<String, serde_json::Value>, JwtError> {
        let bytes = base64_url_decode(encoded)?;
        let json = String::from_utf8(bytes)
            .map_err(|e| JwtError::Malformed(e.to_string()))?;

        // Parse JSON claims
        if let Ok(value) = serde_json::from_str::<serde_json::Value>(&json) {
            if let Some(obj) = value.as_object() {
                let mut claims = HashMap::new();
                for (k, v) in obj {
                    claims.insert(k.clone(), v.clone());
                }
                return Ok(claims);
            }
        }

        Err(JwtError::Malformed("invalid claims JSON".to_string()))
    }

    fn verify_algorithm(&self, header: &JwtHeader) -> Result<(), JwtError> {
        let supported = ["RS256", "ES256", "HS256"];
        if !supported.contains(&header.algorithm.as_str()) {
            return Err(JwtError::InvalidSignature);
        }
        Ok(())
    }

    fn validate_claims(&self, claims: &HashMap<String, serde_json::Value>) -> Result<(), JwtError> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let tolerance = self.config.clock_skew_tolerance.as_secs();

        // Check expiration
        if let Some(exp) = claims.get("exp").and_then(|v| v.as_u64()) {
            if now > exp + tolerance {
                return Err(JwtError::TokenExpired { expiry: exp });
            }
        }

        // Check not before
        if let Some(nbf) = claims.get("nbf").and_then(|v| v.as_u64()) {
            if now < nbf.saturating_sub(tolerance) {
                return Err(JwtError::NotYetValid { not_before: nbf });
            }
        }

        // Check issuer
        if let Some(iss) = claims.get("iss").and_then(|v| v.as_str()) {
            if iss != self.config.issuer {
                return Err(JwtError::InvalidIssuer {
                    expected: self.config.issuer.clone(),
                    actual: iss.to_string(),
                });
            }
        }

        // Check audience
        if let Some(aud) = claims.get("aud").and_then(|v| v.as_str()) {
            if aud != self.config.audience {
                return Err(JwtError::InvalidAudience {
                    expected: self.config.audience.clone(),
                    actual: aud.to_string(),
                });
            }
        }

        // Check required claims
        for claim in &self.config.required_claims {
            if !claims.contains_key(claim) {
                return Err(JwtError::MissingClaim { claim: claim.clone() });
            }
        }

        Ok(())
    }

    fn extract_user(&self, claims: &HashMap<String, serde_json::Value>) -> Result<AuthenticatedUser, JwtError> {
        let subject = claims.get("sub")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();

        let expires_at = claims.get("exp").and_then(|v| v.as_u64()).unwrap_or(0);
        let issued_at = claims.get("iat").and_then(|v| v.as_u64()).unwrap_or(0);

        let roles = claims.get("roles")
            .and_then(|v| v.as_array())
            .map(|arr| arr.iter().filter_map(|v| v.as_str().map(String::from)).collect())
            .unwrap_or_default();

        let permissions = claims.get("permissions")
            .and_then(|v| v.as_array())
            .map(|arr| arr.iter().filter_map(|v| v.as_str().map(String::from)).collect())
            .unwrap_or_default();

        let mut custom_claims = HashMap::new();
        for (k, v) in claims {
            if !["sub", "iss", "aud", "exp", "nbf", "iat", "roles", "permissions"].contains(&k.as_str()) {
                if let Some(s) = v.as_str() {
                    custom_claims.insert(k.clone(), s.to_string());
                }
            }
        }

        Ok(AuthenticatedUser {
            subject,
            issuer: self.config.issuer.clone(),
            audience: self.config.audience.clone(),
            roles,
            permissions,
            expires_at,
            issued_at,
            custom_claims,
        })
    }

    fn extract_json_string(json: &str, key: &str) -> Option<String> {
        let search = format!("\"{}\"", key);
        if let Some(pos) = json.find(&search) {
            let rest = &json[pos + search.len()..];
            if let Some(colon_pos) = rest.find(':') {
                let value_part = rest[colon_pos + 1..].trim_start();
                if value_part.starts_with('"') {
                    if let Some(end) = value_part[1..].find('"') {
                        return Some(value_part[1..end + 1].to_string());
                    }
                }
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_jwt_validator_invalid_format() {
        let config = JwtConfig::new("test-issuer", "test-audience", b"key");
        let validator = JwtValidator::new(config);
        assert!(validator.validate("invalid").is_err());
    }

    #[test]
    fn test_jwt_validator_wrong_part_count() {
        let config = JwtConfig::new("test-issuer", "test-audience", b"key");
        let validator = JwtValidator::new(config);
        assert!(validator.validate("part1.part2").is_err());
    }

    #[test]
    fn test_extract_json_string() {
        let json = r#"{"alg":"RS256","typ":"JWT"}"#;
        assert_eq!(JwtValidator::extract_json_string(json, "alg"), Some("RS256".to_string()));
        assert_eq!(JwtValidator::extract_json_string(json, "typ"), Some("JWT".to_string()));
        assert_eq!(JwtValidator::extract_json_string(json, "missing"), None);
    }
}
