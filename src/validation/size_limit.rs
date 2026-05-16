//! Request body size limit validation.
//!
//! Enforces maximum request body sizes to prevent memory exhaustion
//! and denial-of-service attacks.

use crate::validation::{ValidationRequest, ValidationResult, ValidationError, ValidationRule};

/// Validates request body size against a configured limit.
pub struct SizeLimitValidator {
    max_size: usize,
}

impl SizeLimitValidator {
    pub fn new(max_size: usize) -> Self {
        Self { max_size }
    }

    pub fn with_limit_mb(mb: usize) -> Self {
        Self { max_size: mb * 1024 * 1024 }
    }
}

impl ValidationRule for SizeLimitValidator {
    fn validate(&self, request: &ValidationRequest) -> ValidationResult {
        if request.content_length > self.max_size {
            ValidationResult::error(ValidationError::BodyTooLarge {
                size: request.content_length,
                limit: self.max_size,
            })
        } else {
            ValidationResult::ok()
        }
    }

    fn name(&self) -> &str { "size_limit" }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn create_request(size: usize) -> ValidationRequest {
        ValidationRequest {
            method: "POST".to_string(),
            uri: "/api/test".to_string(),
            headers: HashMap::new(),
            query_params: HashMap::new(),
            path_params: HashMap::new(),
            body: None,
            content_length: size,
        }
    }

    #[test]
    fn test_within_limit() {
        let validator = SizeLimitValidator::new(1024);
        let request = create_request(512);
        assert!(validator.validate(&request).is_valid);
    }

    #[test]
    fn test_exceeds_limit() {
        let validator = SizeLimitValidator::new(1024);
        let request = create_request(2048);
        let result = validator.validate(&request);
        assert!(!result.is_valid);
    }

    #[test]
    fn test_exact_limit() {
        let validator = SizeLimitValidator::new(1024);
        let request = create_request(1024);
        assert!(validator.validate(&request).is_valid);
    }

    #[test]
    fn test_zero_size() {
        let validator = SizeLimitValidator::new(1024);
        let request = create_request(0);
        assert!(validator.validate(&request).is_valid);
    }
}
