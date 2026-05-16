//! Validation middleware for HTTP request processing.
//!
//! Chains multiple validation rules and provides comprehensive
//! request validation before business logic execution.

use std::collections::HashMap;
use std::sync::Arc;

use crate::validation::{
    ValidationRequest, ValidationResult, ValidationError, ValidationRule,
    ValidationConfig, record_validation, get_validation_metrics,
    ContentTypeValidator, SizeLimitValidator, SchemaValidator,
};

/// Validation middleware that chains multiple validators.
pub struct ValidationMiddleware {
    config: ValidationConfig,
    rules: Vec<Arc<dyn ValidationRule>>,
    schema_validator: Arc<SchemaValidator>,
}

impl ValidationMiddleware {
    pub fn new(config: ValidationConfig) -> Self {
        let schema_validator = Arc::new(SchemaValidator::new());
        let mut rules: Vec<Arc<dyn ValidationRule>> = vec![
            Arc::new(ContentTypeValidator::new(
                config.allowed_content_types.clone(),
                config.reject_unknown_content_types,
            )),
            Arc::new(SizeLimitValidator::new(config.max_body_size)),
        ];
        rules.push(schema_validator.clone());

        Self {
            config,
            rules,
            schema_validator,
        }
    }

    pub fn with_rule(mut self, rule: Arc<dyn ValidationRule>) -> Self {
        self.rules.push(rule);
        self
    }

    pub fn validate(&self, request: &ValidationRequest) -> ValidationResult {
        let mut all_errors = Vec::new();
        let mut all_warnings = Vec::new();

        for rule in &self.rules {
            let result = rule.validate(request);
            if !result.is_valid {
                all_errors.extend(result.errors);
            }
            all_warnings.extend(result.warnings);
        }

        let is_valid = all_errors.is_empty();
        record_validation(is_valid);

        if is_valid {
            ValidationResult {
                is_valid: true,
                errors: Vec::new(),
                warnings: all_warnings,
            }
        } else {
            ValidationResult {
                is_valid: false,
                errors: all_errors,
                warnings: all_warnings,
            }
        }
    }

    pub fn get_schema_validator(&self) -> Arc<SchemaValidator> {
        self.schema_validator.clone()
    }

    pub fn format_error_response(&self, result: &ValidationResult) -> HashMap<String, String> {
        let mut response = HashMap::new();

        if result.is_valid {
            response.insert("status".to_string(), "valid".to_string());
        } else {
            response.insert("status".to_string(), "invalid".to_string());
            response.insert("error_count".to_string(), result.errors.len().to_string());

            let error_messages: Vec<String> = result.errors.iter().map(|e| e.to_string()).collect();
            response.insert("errors".to_string(), error_messages.join("; "));
        }

        if !result.warnings.is_empty() {
            response.insert("warnings".to_string(), result.warnings.join("; "));
        }

        response
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_request(content_type: &str, body_size: usize) -> ValidationRequest {
        let mut headers = HashMap::new();
        headers.insert("content-type".to_string(), content_type.to_string());
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
    fn test_validation_middleware_valid_request() {
        let config = ValidationConfig::default();
        let middleware = ValidationMiddleware::new(config);
        let request = create_test_request("application/json", 100);
        let result = middleware.validate(&request);
        assert!(result.is_valid);
    }

    #[test]
    fn test_validation_middleware_invalid_content_type() {
        let config = ValidationConfig::default();
        let middleware = ValidationMiddleware::new(config);
        let request = create_test_request("text/html", 100);
        let result = middleware.validate(&request);
        assert!(!result.is_valid);
    }

    #[test]
    fn test_validation_middleware_body_too_large() {
        let config = ValidationConfig {
            max_body_size: 50,
            ..Default::default()
        };
        let middleware = ValidationMiddleware::new(config);
        let request = create_test_request("application/json", 100);
        let result = middleware.validate(&request);
        assert!(!result.is_valid);
    }

    #[test]
    fn test_validation_middleware_error_response() {
        let config = ValidationConfig::default();
        let middleware = ValidationMiddleware::new(config);
        let request = create_test_request("text/html", 100);
        let result = middleware.validate(&request);
        let response = middleware.format_error_response(&result);

        assert_eq!(response.get("status"), Some(&"invalid".to_string()));
        assert!(response.contains_key("errors"));
    }

    #[test]
    fn test_validation_middleware_with_custom_rule() {
        struct TestRule;
        impl ValidationRule for TestRule {
            fn validate(&self, _request: &ValidationRequest) -> ValidationResult {
                ValidationResult::ok().with_warning("test warning".to_string())
            }
            fn name(&self) -> &str { "test" }
        }

        let config = ValidationConfig::default();
        let middleware = ValidationMiddleware::new(config)
            .with_rule(Arc::new(TestRule));

        let request = create_test_request("application/json", 100);
        let result = middleware.validate(&request);
        assert!(result.is_valid);
        assert_eq!(result.warnings.len(), 1);
    }
}
