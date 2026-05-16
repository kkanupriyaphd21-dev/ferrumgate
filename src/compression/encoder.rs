//! Response compression encoder.
//!
//! Compresses response bodies using brotli, gzip, or zstd
//! based on client Accept-Encoding preferences.

use std::collections::HashMap;
use std::io::Write;

use crate::compression::{
    CompressionAlgorithm, CompressionConfig, CompressionError,
    parse_accept_encoding, record_compression, record_skipped,
    is_compressible,
};

/// Compresses response bodies.
pub struct ResponseCompressor {
    config: CompressionConfig,
}

impl ResponseCompressor {
    pub fn new(config: CompressionConfig) -> Self {
        Self { config }
    }

    /// Compress body using best algorithm from Accept-Encoding.
    pub fn compress(
        &self,
        body: &[u8],
        accept_encoding: &str,
        content_type: &str,
    ) -> Result<CompressedResponse, CompressionError> {
        // Check size thresholds
        if body.len() < self.config.min_size {
            record_skipped();
            return Ok(CompressedResponse::uncompressed(body.to_vec()));
        }
        if body.len() > self.config.max_size {
            record_skipped();
            return Ok(CompressedResponse::uncompressed(body.to_vec()));
        }

        // Check content type
        if !is_compressible(content_type, &self.config.compressible_content_types) {
            record_skipped();
            return Ok(CompressedResponse::uncompressed(body.to_vec()));
        }

        // Parse Accept-Encoding and try each algorithm
        let algos = parse_accept_encoding(accept_encoding);
        for (algo, _quality) in algos {
            if !self.config.enabled_algorithms.contains(&algo) {
                continue;
            }
            if algo == CompressionAlgorithm::Identity {
                continue;
            }

            match self.compress_with(body, algo) {
                Ok(compressed) => {
                    // Only use compression if it actually saves space
                    if compressed.len() < body.len() {
                        record_compression(body.len(), compressed.len());
                        return Ok(CompressedResponse::compressed(compressed, algo));
                    }
                }
                Err(_) => continue,
            }
        }

        record_skipped();
        Ok(CompressedResponse::uncompressed(body.to_vec()))
    }

    fn compress_with(&self, body: &[u8], algo: CompressionAlgorithm) -> Result<Vec<u8>, CompressionError> {
        match algo {
            CompressionAlgorithm::Brotli => self.compress_brotli(body),
            CompressionAlgorithm::Gzip => self.compress_gzip(body),
            CompressionAlgorithm::Zstd => self.compress_zstd(body),
            CompressionAlgorithm::Deflate => self.compress_deflate(body),
            CompressionAlgorithm::Identity => Ok(body.to_vec()),
        }
    }

    fn compress_brotli(&self, body: &[u8]) -> Result<Vec<u8>, CompressionError> {
        let mut encoder = brotli::CompressorWriter::new(Vec::new(), body.len(), self.config.compression_level as u32, 22);
        encoder.write_all(body).map_err(|e| CompressionError::CompressionFailed(e.to_string()))?;
        Ok(encoder.into_inner())
    }

    fn compress_gzip(&self, body: &[u8]) -> Result<Vec<u8>, CompressionError> {
        let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::new(self.config.compression_level));
        encoder.write_all(body).map_err(|e| CompressionError::CompressionFailed(e.to_string()))?;
        encoder.finish().map_err(|e| CompressionError::CompressionFailed(e.to_string()))
    }

    fn compress_zstd(&self, body: &[u8]) -> Result<Vec<u8>, CompressionError> {
        zstd::stream::encode_all(body, self.config.compression_level as i32)
            .map_err(|e| CompressionError::CompressionFailed(e.to_string()))
    }

    fn compress_deflate(&self, body: &[u8]) -> Result<Vec<u8>, CompressionError> {
        let mut encoder = flate2::write::DeflateEncoder::new(Vec::new(), flate2::Compression::new(self.config.compression_level));
        encoder.write_all(body).map_err(|e| CompressionError::CompressionFailed(e.to_string()))?;
        encoder.finish().map_err(|e| CompressionError::CompressionFailed(e.to_string()))
    }
}

/// Result of compression.
#[derive(Debug)]
pub struct CompressedResponse {
    pub body: Vec<u8>,
    pub algorithm: Option<CompressionAlgorithm>,
    pub original_size: usize,
    pub compressed_size: usize,
}

impl CompressedResponse {
    fn uncompressed(body: Vec<u8>) -> Self {
        let size = body.len();
        Self {
            body,
            algorithm: None,
            original_size: size,
            compressed_size: size,
        }
    }

    fn compressed(body: Vec<u8>, algo: CompressionAlgorithm) -> Self {
        let compressed_size = body.len();
        Self {
            body,
            algorithm: Some(algo),
            original_size: 0, // Would be set from context
            compressed_size,
        }
    }

    pub fn compression_ratio(&self) -> f64 {
        if self.original_size == 0 {
            return 1.0;
        }
        self.compressed_size as f64 / self.original_size as f64
    }

    pub fn add_headers(&self, headers: &mut HashMap<String, String>) {
        if let Some(algo) = &self.algorithm {
            headers.insert("Content-Encoding".to_string(), algo.content_encoding().to_string());
            headers.insert("Vary".to_string(), "Accept-Encoding".to_string());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_compress_small_body_skipped() {
        let config = CompressionConfig::default();
        let compressor = ResponseCompressor::new(config);
        let body = b"small";
        let result = compressor.compress(body, "gzip", "text/html").unwrap();
        assert!(result.algorithm.is_none());
    }

    #[test]
    fn test_compress_non_compressible_type() {
        let config = CompressionConfig::default();
        let compressor = ResponseCompressor::new(config);
        let body = vec![0u8; 2048];
        let result = compressor.compress(&body, "gzip", "image/png").unwrap();
        assert!(result.algorithm.is_none());
    }

    #[test]
    fn test_compress_json_with_gzip() {
        let config = CompressionConfig::default();
        let compressor = ResponseCompressor::new(config);
        let body = vec![b'x'; 2048];
        let result = compressor.compress(&body, "gzip", "application/json").unwrap();
        assert!(result.algorithm.is_some());
    }

    #[test]
    fn test_compress_brotli_priority() {
        let config = CompressionConfig::default();
        let compressor = ResponseCompressor::new(config);
        let body = vec![b'x'; 2048];
        let result = compressor.compress(&body, "br;q=1.0, gzip;q=0.8", "application/json").unwrap();
        assert_eq!(result.algorithm, Some(CompressionAlgorithm::Brotli));
    }

    #[test]
    fn test_compressed_response_headers() {
        let mut headers = HashMap::new();
        let response = CompressedResponse::compressed(vec![1, 2, 3], CompressionAlgorithm::Gzip);
        response.add_headers(&mut headers);
        assert_eq!(headers.get("Content-Encoding"), Some(&"gzip".to_string()));
    }
}
