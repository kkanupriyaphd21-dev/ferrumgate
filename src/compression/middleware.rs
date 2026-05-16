//! Compression middleware for HTTP request/response processing.
//!
//! Automatically compresses responses and decompresses requests
//! based on content negotiation.

use std::collections::HashMap;

use crate::compression::{
    CompressionConfig, CompressionError, ResponseCompressor, RequestDecompressor,
    get_compression_metrics, CompressionMetrics, CompressedResponse,
};

/// Compression middleware.
pub struct CompressionMiddleware {
    compressor: ResponseCompressor,
}

impl CompressionMiddleware {
    pub fn new(config: CompressionConfig) -> Self {
        Self {
            compressor: ResponseCompressor::new(config),
        }
    }

    /// Process response - compress if appropriate.
    pub fn process_response(
        &self,
        body: &[u8],
        accept_encoding: &str,
        content_type: &str,
    ) -> Result<CompressedResponse, CompressionError> {
        self.compressor.compress(body, accept_encoding, content_type)
    }

    /// Process request - decompress if encoded.
    pub fn process_request(
        &self,
        body: &[u8],
        content_encoding: Option<&str>,
    ) -> Result<Vec<u8>, CompressionError> {
        match content_encoding {
            Some(encoding) => RequestDecompressor::decompress(body, encoding),
            None => Ok(body.to_vec()),
        }
    }

    /// Get compression metrics.
    pub fn metrics(&self) -> CompressionMetrics {
        get_compression_metrics()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_middleware_process_response() {
        let config = CompressionConfig::default();
        let middleware = CompressionMiddleware::new(config);
        let body = vec![b'x'; 2048];
        let result = middleware.process_response(&body, "gzip", "application/json").unwrap();
        assert!(result.algorithm.is_some());
    }

    #[test]
    fn test_middleware_process_request_no_encoding() {
        let config = CompressionConfig::default();
        let middleware = CompressionMiddleware::new(config);
        let body = vec![1, 2, 3];
        let result = middleware.process_request(&body, None).unwrap();
        assert_eq!(result, body);
    }

    #[test]
    fn test_middleware_metrics() {
        let config = CompressionConfig::default();
        let middleware = CompressionMiddleware::new(config);
        let metrics = middleware.metrics();
        assert_eq!(metrics.total_requests, 0);
    }
}
