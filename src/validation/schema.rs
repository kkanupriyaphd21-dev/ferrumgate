//! JSON Schema validation for request bodies.
//!
//! Validates JSON request bodies against predefined schemas
//! to ensure data integrity and type safety.

use std::collections::{HashMap, HashSet};
use std::sync::RwLock;

use crate::validation::{ValidationRequest, ValidationResult, ValidationError, ValidationRule};

/// JSON value representation for schema validation.
#[derive(Debug, Clone)]
pub enum JsonValue {
    Null,
    Bool(bool),
    Number(f64),
    String(String),
    Array(Vec<JsonValue>),
    Object(HashMap<String, JsonValue>),
}

/// JSON Schema definition.
#[derive(Debug, Clone)]
pub struct JsonSchema {
    pub schema_type: SchemaType,
    pub required_fields: HashSet<String>,
    pub properties: HashMap<String, PropertySchema>,
    pub additional_properties: bool,
}

#[derive(Debug, Clone)]
pub enum SchemaType {
    Object,
    Array,
    String,
    Number,
    Boolean,
    Null,
}

#[derive(Debug, Clone)]
pub struct PropertySchema {
    pub prop_type: SchemaType,
    pub required: bool,
    pub min_length: Option<usize>,
    pub max_length: Option<usize>,
    pub min_value: Option<f64>,
    pub max_value: Option<f64>,
    pub pattern: Option<String>,
    pub enum_values: Option<Vec<String>>,
}

/// Validates JSON bodies against a schema.
pub struct SchemaValidator {
    schemas: RwLock<HashMap<String, JsonSchema>>,
}

impl SchemaValidator {
    pub fn new() -> Self {
        Self {
            schemas: RwLock::new(HashMap::new()),
        }
    }

    pub fn register_schema(&self, path: &str, schema: JsonSchema) {
        self.schemas.write().unwrap().insert(path.to_string(), schema);
    }

    pub fn remove_schema(&self, path: &str) {
        self.schemas.write().unwrap().remove(path);
    }

    fn parse_json(body: &[u8]) -> Result<JsonValue, String> {
        let text = String::from_utf8_lossy(body);
        Self::parse_value(&text)
    }

    fn parse_value(text: &str) -> Result<JsonValue, String> {
        let trimmed = text.trim();
        if trimmed.is_empty() {
            return Err("empty input".to_string());
        }

        if trimmed == "null" {
            return Ok(JsonValue::Null);
        }
        if trimmed == "true" {
            return Ok(JsonValue::Bool(true));
        }
        if trimmed == "false" {
            return Ok(JsonValue::Bool(false));
        }
        if trimmed.starts_with('"') && trimmed.ends_with('"') && trimmed.len() >= 2 {
            return Ok(JsonValue::String(trimmed[1..trimmed.len()-1].to_string()));
        }
        if trimmed.starts_with('[') && trimmed.ends_with(']') {
            return Ok(JsonValue::Array(vec![]));
        }
        if trimmed.starts_with('{') && trimmed.ends_with('}') {
            return Self::parse_object(trimmed);
        }
        if let Ok(n) = trimmed.parse::<f64>() {
            return Ok(JsonValue::Number(n));
        }

        Err(format!("invalid JSON: {}", trimmed))
    }

    fn parse_object(text: &str) -> Result<JsonValue, String> {
        let inner = text[1..text.len()-1].trim();
        if inner.is_empty() {
            return Ok(JsonValue::Object(HashMap::new()));
        }

        let mut map = HashMap::new();
        let mut current_key: Option<String> = None;

        for part in inner.split(',') {
            let part = part.trim();
            if part.is_empty() { continue; }

            if let Some(key) = current_key.take() {
                let value = Self::parse_value(part)?;
                map.insert(key, value);
            } else {
                if part.starts_with('"') && part.contains(':') {
                    let kv: Vec<&str> = part.splitn(2, ':').collect();
                    if kv.len() == 2 {
                        let key = kv[0].trim().trim_matches('"');
                        current_key = Some(key.to_string());
                        let value = Self::parse_value(kv[1].trim())?;
                        map.insert(key.to_string(), value);
                    }
                }
            }
        }

        Ok(JsonValue::Object(map))
    }

    fn validate_value(value: &JsonValue, schema: &PropertySchema) -> Vec<String> {
        let mut errors = Vec::new();

        match (value, &schema.prop_type) {
            (JsonValue::String(s), SchemaType::String) => {
                if let Some(min) = schema.min_length {
                    if s.len() < min {
                        errors.push(format!("string length {} < min {}", s.len(), min));
                    }
                }
                if let Some(max) = schema.max_length {
                    if s.len() > max {
                        errors.push(format!("string length {} > max {}", s.len(), max));
                    }
                }
                if let Some(pattern) = &schema.pattern {
                    if !s.contains(pattern) {
                        errors.push(format!("string '{}' doesn't match pattern '{}'", s, pattern));
                    }
                }
                if let Some(enums) = &schema.enum_values {
                    if !enums.contains(s) {
                        errors.push(format!("value '{}' not in allowed values", s));
                    }
                }
            }
            (JsonValue::Number(n), SchemaType::Number) => {
                if let Some(min) = schema.min_value {
                    if *n < min {
                        errors.push(format!("number {} < min {}", n, min));
                    }
                }
                if let Some(max) = schema.max_value {
                    if *n > max {
                        errors.push(format!("number {} > max {}", n, max));
                    }
                }
            }
            (JsonValue::Bool(_), SchemaType::Boolean) => {}
            (JsonValue::Null, SchemaType::Null) => {}
            (JsonValue::Array(_), SchemaType::Array) => {}
            (JsonValue::Object(_), SchemaType::Object) => {}
            (v, expected_type) => {
                errors.push(format!("type mismatch: expected {:?}, got {:?}", expected_type, v));
            }
        }

        errors
    }
}

impl ValidationRule for SchemaValidator {
    fn validate(&self, request: &ValidationRequest) -> ValidationResult {
        let body = match &request.body {
            Some(b) => b,
            None => return ValidationResult::ok(),
        };

        let schema = {
            let schemas = self.schemas.read().unwrap();
            schemas.get(&request.uri).cloned()
        };

        let schema = match schema {
            Some(s) => s,
            None => return ValidationResult::ok(),
        };

        let json = match Self::parse_json(body) {
            Ok(j) => j,
            Err(e) => return ValidationResult::error(ValidationError::InvalidJson { message: e }),
        };

        let mut errors = Vec::new();

        if let JsonValue::Object(map) = &json {
            for field in &schema.required_fields {
                if !map.contains_key(field) {
                    errors.push(format!("missing required field: {}", field));
                }
            }

            for (key, value) in map {
                if let Some(prop_schema) = schema.properties.get(key) {
                    let prop_errors = Self::validate_value(value, prop_schema);
                    errors.extend(prop_errors);
                } else if !schema.additional_properties {
                    errors.push(format!("unknown field: {}", key));
                }
            }
        }

        if errors.is_empty() {
            ValidationResult::ok()
        } else {
            ValidationResult::error(ValidationError::SchemaValidationFailed { errors })
        }
    }

    fn name(&self) -> &str { "schema" }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_schema_validator_no_schema() {
        let validator = SchemaValidator::new();
        let request = ValidationRequest {
            method: "POST".to_string(),
            uri: "/unknown".to_string(),
            headers: HashMap::new(),
            query_params: HashMap::new(),
            path_params: HashMap::new(),
            body: Some(b"{}".to_vec()),
            content_length: 2,
        };
        assert!(validator.validate(&request).is_valid);
    }

    #[test]
    fn test_schema_validator_valid_json() {
        let validator = SchemaValidator::new();
        let schema = JsonSchema {
            schema_type: SchemaType::Object,
            required_fields: HashSet::new(),
            properties: HashMap::new(),
            additional_properties: true,
        };
        validator.register_schema("/api/test", schema);

        let request = ValidationRequest {
            method: "POST".to_string(),
            uri: "/api/test".to_string(),
            headers: HashMap::new(),
            query_params: HashMap::new(),
            path_params: HashMap::new(),
            body: Some(b"{\"name\": \"test\"}".to_vec()),
            content_length: 18,
        };
        assert!(validator.validate(&request).is_valid);
    }

    #[test]
    fn test_schema_validator_invalid_json() {
        let validator = SchemaValidator::new();
        let request = ValidationRequest {
            method: "POST".to_string(),
            uri: "/api/test".to_string(),
            headers: HashMap::new(),
            query_params: HashMap::new(),
            path_params: HashMap::new(),
            body: Some(b"not json".to_vec()),
            content_length: 8,
        };
        assert!(!validator.validate(&request).is_valid);
    }

    #[test]
    fn test_json_parsing() {
        assert!(matches!(SchemaValidator::parse_value("null"), Ok(JsonValue::Null)));
        assert!(matches!(SchemaValidator::parse_value("true"), Ok(JsonValue::Bool(true))));
        assert!(matches!(SchemaValidator::parse_value("42"), Ok(JsonValue::Number(42.0))));
        assert!(matches!(SchemaValidator::parse_value("\"hello\""), Ok(JsonValue::String(s)) if s == "hello"));
    }
}
