//! Content-Type validation for HTTP requests.
//!
//! Enforces allowed content types and rejects requests with
//! unsupported or malicious content types.

use std::collections::HashSet;

use crate::validation::{ValidationRequest, ValidationResult, ValidationError, ValidationRule};

/// Validates Content-Type headers against an allowed list.
pub struct ContentTypeValidator {
    allowed_types: HashSet<String>,
    reject_unknown: bool,
}

impl ContentTypeValidator {
    pub fn new(allowed_types: Vec<String>, reject_unknown: bool) -> Self {
        Self {
            allowed_types: allowed_types.into_iter().collect(),
            reject_unknown,
        }
    }

    pub fn with_types(types: Vec<&str>) -> Self {
        Self {
            allowed_types: types.into_iter().map(|s| s.to_string()).collect(),
            reject_unknown: true,
        }
    }

    fn parse_content_type(content_type: &str) -> String {
        content_type.split(';').next().unwrap_or("").trim().to_lowercase()
    }

    fn is_valid_content_type(content_type: &str) -> bool {
        let parts: Vec<&str> = content_type.split('/').collect();
        parts.len() == 2 && !parts[0].is_empty() && !parts[1].is_empty()
    }
}

impl ValidationRule for ContentTypeValidator {
    fn validate(&self, request: &ValidationRequest) -> ValidationResult {
        let content_type = match request.headers.get("content-type") {
            Some(ct) => ct,
            None => {
                if request.content_length > 0 {
                    return ValidationResult::error(ValidationError::MissingHeader {
                        header: "content-type".to_string(),
                    });
                }
                return ValidationResult::ok();
            }
        };

        let parsed_type = Self::parse_content_type(content_type);

        if !Self::is_valid_content_type(&parsed_type) {
            return ValidationResult::error(ValidationError::InvalidContentType {
                expected: "valid content type".to_string(),
                actual: content_type.clone(),
            });
        }

        if self.reject_unknown && !self.allowed_types.contains(&parsed_type) {
            return ValidationResult::error(ValidationError::InvalidContentType {
                expected: self.allowed_types.iter().cloned().collect::<Vec<_>>().join(", "),
                actual: content_type.clone(),
            });
        }

        ValidationResult::ok()
    }

    fn name(&self) -> &str { "content_type" }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn create_request(content_type: Option<&str>, body_size: usize) -> ValidationRequest {
        let mut headers = HashMap::new();
        if let Some(ct) = content_type {
            headers.insert("content-type".to_string(), ct.to_string());
        }
        ValidationRequest {
            method: "POST".to_string(),
            uri: "/api/test".to_string(),
            headers,
            query_params: HashMap::new(),
            path_params: HashMap::new(),
            body: None,
            content_length: body_size,
        }
    }

    #[test]
    fn test_valid_content_type() {
        let validator = ContentTypeValidator::with_types(vec!["application/json", "application/xml"]);
        let request = create_request(Some("application/json"), 100);
        let result = validator.validate(&request);
        assert!(result.is_valid);
    }

    #[test]
    fn test_invalid_content_type() {
        let validator = ContentTypeValidator::with_types(vec!["application/json"]);
        let request = create_request(Some("text/html"), 100);
        let result = validator.validate(&request);
        assert!(!result.is_valid);
    }

    #[test]
    fn test_missing_content_type_with_body() {
        let validator = ContentTypeValidator::with_types(vec!["application/json"]);
        let request = create_request(None, 100);
        let result = validator.validate(&request);
        assert!(!result.is_valid);
    }

    #[test]
    fn test_missing_content_type_without_body() {
        let validator = ContentTypeValidator::with_types(vec!["application/json"]);
        let request = create_request(None, 0);
        let result = validator.validate(&request);
        assert!(result.is_valid);
    }

    #[test]
    fn test_content_type_with_parameters() {
        let validator = ContentTypeValidator::with_types(vec!["application/json"]);
        let request = create_request(Some("application/json; charset=utf-8"), 100);
        let result = validator.validate(&request);
        assert!(result.is_valid);
    }

    #[test]
    fn test_case_insensitive() {
        let validator = ContentTypeValidator::with_types(vec!["application/json"]);
        let request = create_request(Some("APPLICATION/JSON"), 100);
        let result = validator.validate(&request);
        assert!(result.is_valid);
    }

    #[test]
    fn test_invalid_format() {
        let validator = ContentTypeValidator::with_types(vec!["application/json"]);
        let request = create_request(Some("invalid"), 100);
        let result = validator.validate(&request);
        assert!(!result.is_valid);
    }
}
