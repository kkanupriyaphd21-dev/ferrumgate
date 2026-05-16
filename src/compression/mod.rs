//! Request/response compression with brotli, gzip, and zstd.
//!
//! Implements automatic content negotiation, compression,
//! and decompression for HTTP payloads.

use std::collections::HashMap;

use thiserror::Error;

pub mod encoder;
pub mod decoder;
pub mod middleware;

pub use encoder::ResponseCompressor;
pub use decoder::RequestDecompressor;
pub use middleware::CompressionMiddleware;

/// Compression error types.
#[derive(Debug, Error)]
pub enum CompressionError {
    #[error("unsupported encoding: {0}")]
    UnsupportedEncoding(String),

    #[error("compression failed: {0}")]
    CompressionFailed(String),

    #[error("decompression failed: {0}")]
    DecompressionFailed(String),

    #[error("payload too large: {size} > {max}")]
    PayloadTooLarge { size: usize, max: usize },

    #[error("invalid compressed data")]
    InvalidData,
}

/// Supported compression algorithms.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CompressionAlgorithm {
    Brotli,
    Gzip,
    Deflate,
    Zstd,
    Identity,
}

impl CompressionAlgorithm {
    pub fn from_name(name: &str) -> Option<Self> {
        match name.to_lowercase().as_str() {
            "br" | "brotli" => Some(CompressionAlgorithm::Brotli),
            "gzip" => Some(CompressionAlgorithm::Gzip),
            "deflate" => Some(CompressionAlgorithm::Deflate),
            "zstd" | "zstandard" => Some(CompressionAlgorithm::Zstd),
            "identity" => Some(CompressionAlgorithm::Identity),
            _ => None,
        }
    }

    pub fn content_encoding(&self) -> &str {
        match self {
            CompressionAlgorithm::Brotli => "br",
            CompressionAlgorithm::Gzip => "gzip",
            CompressionAlgorithm::Deflate => "deflate",
            CompressionAlgorithm::Zstd => "zstd",
            CompressionAlgorithm::Identity => "identity",
        }
    }
}

/// Parse Accept-Encoding header and return prioritized algorithms.
pub fn parse_accept_encoding(header: &str) -> Vec<(CompressionAlgorithm, f32)> {
    let mut algorithms = Vec::new();

    for part in header.split(',') {
        let part = part.trim();
        if part.is_empty() { continue; }

        let parts: Vec<&str> = part.splitn(2, ';').collect();
        let name = parts[0].trim();
        let quality = if parts.len() == 2 {
            let q_part = parts[1].trim();
            if q_part.starts_with("q=") {
                q_part[2..].parse::<f32>().unwrap_or(1.0)
            } else {
                1.0
            }
        } else {
            1.0
        };

        if let Some(algo) = CompressionAlgorithm::from_name(name) {
            if quality > 0.0 {
                algorithms.push((algo, quality));
            }
        }
    }

    algorithms.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));
    algorithms
}

/// Compression configuration.
#[derive(Debug, Clone)]
pub struct CompressionConfig {
    pub enabled_algorithms: Vec<CompressionAlgorithm>,
    pub min_size: usize,
    pub max_size: usize,
    pub compression_level: u32,
    pub compressible_content_types: Vec<String>,
}

impl Default for CompressionConfig {
    fn default() -> Self {
        Self {
            enabled_algorithms: vec![
                CompressionAlgorithm::Brotli,
                CompressionAlgorithm::Gzip,
                CompressionAlgorithm::Zstd,
            ],
            min_size: 1024, // 1KB minimum
            max_size: 50 * 1024 * 1024, // 50MB max
            compression_level: 4,
            compressible_content_types: vec![
                "text/html".to_string(),
                "text/css".to_string(),
                "text/plain".to_string(),
                "text/xml".to_string(),
                "application/json".to_string(),
                "application/javascript".to_string(),
                "application/xml".to_string(),
            ],
        }
    }
}

/// Global compression metrics.
static COMPRESSION_TOTAL_REQUESTS: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
static COMPRESSION_COMPRESSED: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
static COMPRESSION_DECOMPRESSED: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
static COMPRESSION_BYTES_SAVED: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
static COMPRESSION_SKIPPED: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

pub fn record_compression(original: usize, compressed: usize) {
    COMPRESSION_TOTAL_REQUESTS.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    COMPRESSION_COMPRESSED.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    if original > compressed {
        COMPRESSION_BYTES_SAVED.fetch_add((original - compressed) as u64, std::sync::atomic::Ordering::Relaxed);
    }
}

pub fn record_decompression() {
    COMPRESSION_DECOMPRESSED.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
}

pub fn record_skipped() {
    COMPRESSION_SKIPPED.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
}

#[derive(Debug)]
pub struct CompressionMetrics {
    pub total_requests: u64,
    pub compressed: u64,
    pub decompressed: u64,
    pub skipped: u64,
    pub bytes_saved: u64,
}

pub fn get_compression_metrics() -> CompressionMetrics {
    CompressionMetrics {
        total_requests: COMPRESSION_TOTAL_REQUESTS.load(std::sync::atomic::Ordering::Relaxed),
        compressed: COMPRESSION_COMPRESSED.load(std::sync::atomic::Ordering::Relaxed),
        decompressed: COMPRESSION_DECOMPRESSED.load(std::sync::atomic::Ordering::Relaxed),
        skipped: COMPRESSION_SKIPPED.load(std::sync::atomic::Ordering::Relaxed),
        bytes_saved: COMPRESSION_BYTES_SAVED.load(std::sync::atomic::Ordering::Relaxed),
    }
}

/// Check if content type is compressible.
pub fn is_compressible(content_type: &str, compressible_types: &[String]) -> bool {
    let ct = content_type.split(';').next().unwrap_or("").trim().to_lowercase();
    compressible_types.iter().any(|t| {
        let target = t.split(';').next().unwrap_or("").trim().to_lowercase();
        ct == target || ct.starts_with(&target) || target.starts_with(&ct)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_accept_encoding_prioritized() {
        let algos = parse_accept_encoding("br;q=1.0, gzip;q=0.8, deflate;q=0.5");
        assert_eq!(algos[0].0, CompressionAlgorithm::Brotli);
        assert_eq!(algos[0].1, 1.0);
        assert_eq!(algos[1].0, CompressionAlgorithm::Gzip);
        assert_eq!(algos[1].1, 0.8);
    }

    #[test]
    fn test_parse_accept_encoding_default_quality() {
        let algos = parse_accept_encoding("gzip, br");
        assert_eq!(algos.len(), 2);
        assert_eq!(algos[0].1, 1.0);
    }

    #[test]
    fn test_parse_accept_encoding_zero_quality() {
        let algos = parse_accept_encoding("gzip;q=0, br");
        assert_eq!(algos.len(), 1);
        assert_eq!(algos[0].0, CompressionAlgorithm::Brotli);
    }

    #[test]
    fn test_compression_algorithm_from_name() {
        assert_eq!(CompressionAlgorithm::from_name("br"), Some(CompressionAlgorithm::Brotli));
        assert_eq!(CompressionAlgorithm::from_name("gzip"), Some(CompressionAlgorithm::Gzip));
        assert_eq!(CompressionAlgorithm::from_name("zstd"), Some(CompressionAlgorithm::Zstd));
        assert_eq!(CompressionAlgorithm::from_name("unknown"), None);
    }

    #[test]
    fn test_is_compressible() {
        let types = vec!["text/html".to_string(), "application/json".to_string()];
        assert!(is_compressible("text/html", &types));
        assert!(is_compressible("application/json; charset=utf-8", &types));
        assert!(!is_compressible("image/png", &types));
    }

    #[test]
    fn test_default_compression_config() {
        let config = CompressionConfig::default();
        assert!(config.enabled_algorithms.contains(&CompressionAlgorithm::Brotli));
        assert_eq!(config.min_size, 1024);
    }

    #[test]
    fn test_compression_metrics_initial() {
        let metrics = get_compression_metrics();
        assert_eq!(metrics.total_requests, 0);
        assert_eq!(metrics.bytes_saved, 0);
    }
}
