//! ETag generation and conditional request handling.
//!
//! Implements ETag generation for responses and handles
//! conditional requests using If-None-Match and If-Modified-Since.

use std::collections::HashMap;
use std::time::SystemTime;

/// ETag generator for response content.
pub struct EtagGenerator;

impl EtagGenerator {
    /// Generate a strong ETag from response body.
    pub fn generate_strong(body: &[u8]) -> String {
        let hash = Self::compute_hash(body);
        format!("\"{}\"", hash)
    }

    /// Generate a weak ETag (indicates semantic equivalence).
    pub fn generate_weak(body: &[u8]) -> String {
        let hash = Self::compute_hash(body);
        format!("W/\"{}\"", hash)
    }

    fn compute_hash(body: &[u8]) -> String {
        // Simple hash for ETag - in production, use a proper hash like BLAKE3
        let mut h1: u64 = 0x517cc1b727220a95;
        let mut h2: u64 = 0x7697a3f4e9c8d6b2;

        for (i, &byte) in body.iter().enumerate() {
            h1 = h1.wrapping_add(byte as u64).wrapping_mul(0x5bd1e995);
            h1 ^= h1.wrapping_shr(47);
            h2 = h2.wrapping_add(byte as u64).wrapping_mul(0x85ebca6b);
            h2 ^= h2.wrapping_shr(31);
        }

        let combined = h1 ^ h2;
        format!("{:016x}", combined)
    }

    /// Check if ETag matches.
    pub fn matches(etag: &str, if_none_match: &str) -> bool {
        if if_none_match == "*" {
            return true;
        }

        for tag in if_none_match.split(',') {
            let tag = tag.trim();
            // Weak comparison: ignore W/ prefix
            let clean_tag = tag.strip_prefix("W/").unwrap_or(tag);
            let clean_etag = etag.strip_prefix("W/").unwrap_or(etag);

            if clean_tag == clean_etag {
                return true;
            }
        }

        false
    }
}

/// Conditional request evaluator.
pub struct ConditionalRequest {
    pub if_none_match: Option<String>,
    pub if_modified_since: Option<String>,
}

impl ConditionalRequest {
    pub fn from_headers(headers: &HashMap<String, String>) -> Self {
        Self {
            if_none_match: headers.get("if-none-match").cloned(),
            if_modified_since: headers.get("if-modified-since").cloned(),
        }
    }

    pub fn is_not_modified(&self, etag: Option<&str>, last_modified: Option<&str>) -> bool {
        // If-None-Match takes precedence
        if let Some(if_none_match) = &self.if_none_match {
            if let Some(etag) = etag {
                return EtagGenerator::matches(etag, if_none_match);
            }
        }

        // Fall back to If-Modified-Since
        if let Some(if_modified_since) = &self.if_modified_since {
            if let Some(last_mod) = last_modified {
                return Self::compare_dates(if_modified_since, last_mod);
            }
        }

        false
    }

    fn compare_dates(if_modified_since: &str, last_modified: &str) -> bool {
        // Simple string comparison for HTTP dates
        // In production, parse and compare properly
        if_modified_since.trim() == last_modified.trim()
    }
}

/// Format Last-Modified header value.
pub fn format_last_modified(time: SystemTime) -> String {
    // Simplified HTTP date format
    // In production, use proper HTTP date formatting
    format!("{:?}", time)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_etag_generation() {
        let body = b"hello world";
        let etag = EtagGenerator::generate_strong(body);
        assert!(etag.starts_with('"'));
        assert!(etag.ends_with('"'));
        assert_eq!(etag.len(), 18); // " + 16 hex + "
    }

    #[test]
    fn test_weak_etag_generation() {
        let body = b"hello world";
        let etag = EtagGenerator::generate_weak(body);
        assert!(etag.starts_with("W/\""));
        assert!(etag.ends_with('"'));
    }

    #[test]
    fn test_etag_match_strong() {
        assert!(EtagGenerator::matches("\"abc123\"", "\"abc123\""));
        assert!(!EtagGenerator::matches("\"abc123\"", "\"def456\""));
    }

    #[test]
    fn test_etag_match_weak_comparison() {
        assert!(EtagGenerator::matches("\"abc123\"", "W/\"abc123\""));
        assert!(EtagGenerator::matches("W/\"abc123\"", "\"abc123\""));
    }

    #[test]
    fn test_etag_match_wildcard() {
        assert!(EtagGenerator::matches("\"abc123\"", "*"));
    }

    #[test]
    fn test_etag_match_multiple() {
        assert!(EtagGenerator::matches("\"abc123\"", "\"def456\", \"abc123\", \"ghi789\""));
    }

    #[test]
    fn test_conditional_request_not_modified() {
        let mut headers = HashMap::new();
        headers.insert("if-none-match".to_string(), "\"abc123\"".to_string());
        let cond = ConditionalRequest::from_headers(&headers);
        assert!(cond.is_not_modified(Some("\"abc123\""), None));
    }

    #[test]
    fn test_conditional_request_modified() {
        let mut headers = HashMap::new();
        headers.insert("if-none-match".to_string(), "\"def456\"".to_string());
        let cond = ConditionalRequest::from_headers(&headers);
        assert!(!cond.is_not_modified(Some("\"abc123\""), None));
    }

    #[test]
    fn test_conditional_request_no_headers() {
        let cond = ConditionalRequest::from_headers(&HashMap::new());
        assert!(!cond.is_not_modified(Some("\"abc123\""), None));
    }
}
