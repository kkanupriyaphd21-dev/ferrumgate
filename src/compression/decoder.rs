//! Request decompression.
//!
//! Decompresses incoming request bodies based on Content-Encoding header.

use std::io::Read;

use crate::compression::{CompressionAlgorithm, CompressionError, record_decompression};

/// Decompresses request bodies.
pub struct RequestDecompressor;

impl RequestDecompressor {
    pub fn decompress(body: &[u8], encoding: &str) -> Result<Vec<u8>, CompressionError> {
        let algo = CompressionAlgorithm::from_name(encoding)
            .ok_or_else(|| CompressionError::UnsupportedEncoding(encoding.to_string()))?;

        match algo {
            CompressionAlgorithm::Brotli => Self::decompress_brotli(body),
            CompressionAlgorithm::Gzip => Self::decompress_gzip(body),
            CompressionAlgorithm::Deflate => Self::decompress_deflate(body),
            CompressionAlgorithm::Zstd => Self::decompress_zstd(body),
            CompressionAlgorithm::Identity => Ok(body.to_vec()),
        }
    }

    fn decompress_brotli(body: &[u8]) -> Result<Vec<u8>, CompressionError> {
        let mut decoder = brotli::Decompressor::new(body, 4096);
        let mut output = Vec::new();
        decoder.read_to_end(&mut output)
            .map_err(|e| CompressionError::DecompressionFailed(e.to_string()))?;
        record_decompression();
        Ok(output)
    }

    fn decompress_gzip(body: &[u8]) -> Result<Vec<u8>, CompressionError> {
        let mut decoder = flate2::read::GzDecoder::new(body);
        let mut output = Vec::new();
        decoder.read_to_end(&mut output)
            .map_err(|e| CompressionError::DecompressionFailed(e.to_string()))?;
        record_decompression();
        Ok(output)
    }

    fn decompress_deflate(body: &[u8]) -> Result<Vec<u8>, CompressionError> {
        let mut decoder = flate2::read::DeflateDecoder::new(body);
        let mut output = Vec::new();
        decoder.read_to_end(&mut output)
            .map_err(|e| CompressionError::DecompressionFailed(e.to_string()))?;
        record_decompression();
        Ok(output)
    }

    fn decompress_zstd(body: &[u8]) -> Result<Vec<u8>, CompressionError> {
        let output = zstd::stream::decode_all(body)
            .map_err(|e| CompressionError::DecompressionFailed(e.to_string()))?;
        record_decompression();
        Ok(output)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_decompress_identity() {
        let body = vec![1, 2, 3, 4];
        let result = RequestDecompressor::decompress(&body, "identity").unwrap();
        assert_eq!(result, body);
    }

    #[test]
    fn test_decompress_unsupported() {
        let body = vec![1, 2, 3];
        let result = RequestDecompressor::decompress(&body, "unknown");
        assert!(result.is_err());
    }
}
