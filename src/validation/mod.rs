//! Request validation middleware with schema enforcement.
//!
//! Provides comprehensive request validation including:
//! - Content-Type enforcement
//! - Request body size limits
//! - JSON schema validation
//! - Header validation
//! - Query parameter validation
//! - Path parameter validation
//! - Detailed validation error responses

use std::collections::HashMap;
use std::sync::RwLock;

use thiserror::Error;

pub mod content_type;
pub mod size_limit;
pub mod schema;
pub mod middleware;

pub use content_type::ContentTypeValidator;
pub use size_limit::SizeLimitValidator;
pub use schema::SchemaValidator;
pub use middleware::ValidationMiddleware;

/// Validation error types.
#[derive(Debug, Error)]
pub enum ValidationError {
    #[error("invalid content type: expected {expected}, got {actual}")]
    InvalidContentType { expected: String, actual: String },

    #[error("request body too large: {size} bytes exceeds limit of {limit} bytes")]
    BodyTooLarge { size: usize, limit: usize },

    #[error("missing required header: {header}")]
    MissingHeader { header: String },

    #[error("invalid header value: {header} = {value}")]
    InvalidHeaderValue { header: String, value: String },

    #[error("missing required query parameter: {param}")]
    MissingQueryParam { param: String },

    #[error("invalid query parameter: {param} = {value}")]
    InvalidQueryParam { param: String, value: String },

    #[error("schema validation failed: {errors}")]
    SchemaValidationFailed { errors: Vec<String> },

    #[error("invalid JSON: {message}")]
    InvalidJson { message: String },

    #[error("validation error: {message}")]
    Generic { message: String },
}

/// Validation result.
#[derive(Debug)]
pub struct ValidationResult {
    pub is_valid: bool,
    pub errors: Vec<ValidationError>,
    pub warnings: Vec<String>,
}

impl ValidationResult {
    pub fn ok() -> Self {
        Self {
            is_valid: true,
            errors: Vec::new(),
            warnings: Vec::new(),
        }
    }

    pub fn error(error: ValidationError) -> Self {
        Self {
            is_valid: false,
            errors: vec![error],
            warnings: Vec::new(),
        }
    }

    pub fn errors(errors: Vec<ValidationError>) -> Self {
        Self {
            is_valid: false,
            errors,
            warnings: Vec::new(),
        }
    }

    pub fn with_warning(mut self, warning: String) -> Self {
        self.warnings.push(warning);
        self
    }
}

/// HTTP request representation for validation.
#[derive(Debug, Clone)]
pub struct ValidationRequest {
    pub method: String,
    pub uri: String,
    pub headers: HashMap<String, String>,
    pub query_params: HashMap<String, String>,
    pub path_params: HashMap<String, String>,
    pub body: Option<Vec<u8>>,
    pub content_length: usize,
}

/// Validation rule trait.
pub trait ValidationRule: Send + Sync {
    fn validate(&self, request: &ValidationRequest) -> ValidationResult;
    fn name(&self) -> &str;
}

/// Validation configuration.
#[derive(Debug, Clone)]
pub struct ValidationConfig {
    pub max_body_size: usize,
    pub allowed_content_types: Vec<String>,
    pub required_headers: Vec<String>,
    pub reject_unknown_content_types: bool,
}

impl Default for ValidationConfig {
    fn default() -> Self {
        Self {
            max_body_size: 10 * 1024 * 1024, // 10MB
            allowed_content_types: vec![
                "application/json".to_string(),
                "application/xml".to_string(),
                "text/plain".to_string(),
            ],
            required_headers: vec![],
            reject_unknown_content_types: true,
        }
    }
}

/// Global validation metrics.
static VALIDATION_TOTAL: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
static VALIDATION_PASSED: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
static VALIDATION_FAILED: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

pub fn record_validation(passed: bool) {
    VALIDATION_TOTAL.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    if passed {
        VALIDATION_PASSED.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    } else {
        VALIDATION_FAILED.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }
}

#[derive(Debug)]
pub struct ValidationMetrics {
    pub total: u64,
    pub passed: u64,
    pub failed: u64,
    pub pass_rate: f64,
}

pub fn get_validation_metrics() -> ValidationMetrics {
    let total = VALIDATION_TOTAL.load(std::sync::atomic::Ordering::Relaxed);
    let passed = VALIDATION_PASSED.load(std::sync::atomic::Ordering::Relaxed);
    ValidationMetrics {
        total,
        passed,
        failed: VALIDATION_FAILED.load(std::sync::atomic::Ordering::Relaxed),
        pass_rate: if total == 0 { 0.0 } else { passed as f64 / total as f64 },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validation_result_ok() {
        let result = ValidationResult::ok();
        assert!(result.is_valid);
        assert!(result.errors.is_empty());
    }

    #[test]
    fn test_validation_result_error() {
        let error = ValidationError::InvalidContentType {
            expected: "application/json".to_string(),
            actual: "text/html".to_string(),
        };
        let result = ValidationResult::error(error);
        assert!(!result.is_valid);
        assert_eq!(result.errors.len(), 1);
    }

    #[test]
    fn test_validation_result_with_warning() {
        let result = ValidationResult::ok().with_warning("deprecated header".to_string());
        assert!(result.is_valid);
        assert_eq!(result.warnings.len(), 1);
    }

    #[test]
    fn test_default_validation_config() {
        let config = ValidationConfig::default();
        assert_eq!(config.max_body_size, 10 * 1024 * 1024);
        assert!(config.allowed_content_types.contains(&"application/json".to_string()));
    }

    #[test]
    fn test_validation_metrics_initial() {
        let metrics = get_validation_metrics();
        assert_eq!(metrics.total, 0);
        assert_eq!(metrics.pass_rate, 0.0);
    }
}
