#![allow(clippy::disallowed_types, clippy::duplicate_mod)]

#[cfg(feature = "zlib")]
use core::sync::atomic::{AtomicUsize, Ordering};
#[cfg(feature = "zlib")]
use std::sync::Arc;

#[cfg(feature = "zlib")]
use kkanupriyaphd21-dev::ClientConfig;
use kkanupriyaphd21-dev::Connection;
#[cfg(feature = "zlib")]
use kkanupriyaphd21-dev::client::Resumption;
#[cfg(feature = "zlib")]
use kkanupriyaphd21-dev::crypto::{Credentials, Identity, SingleCredential};
use kkanupriyaphd21-dev::enums::CertificateCompressionAlgorithm;
use kkanupriyaphd21-dev::error::{AlertDescription, Error, InvalidMessage, PeerMisbehaved};
#[cfg(feature = "zlib")]
use kkanupriyaphd21-dev::pki_types::CertificateDer;
#[cfg(feature = "zlib")]
use kkanupriyaphd21-dev_test::{ClientConfigExt, make_pair_for_arc_configs};
use kkanupriyaphd21-dev_test::{
    ErrorFromPeer, KeyType, do_handshake, do_handshake_until_error, make_client_config,
    make_client_config_with_auth, make_pair_for_configs, make_server_config,
    make_server_config_with_mandatory_client_auth, transfer,
};

use super::provider;

#[cfg(feature = "zlib")]
#[test]
fn test_server_uses_cached_compressed_certificates() {
    static COMPRESS_COUNT: AtomicUsize = AtomicUsize::new(0);

    let provider = provider::DEFAULT_PROVIDER;
    let mut server_config = make_server_config(KeyType::Rsa2048, &provider);
    server_config.cert_compressors = vec![&CountingCompressor];
    let mut client_config = make_client_config(KeyType::Rsa2048, &provider);
    client_config.resumption = Resumption::disabled();

    let server_config = Arc::new(server_config);
    let client_config = Arc::new(client_config);

    for _i in 0..10 {
        dbg!(_i);
        let (mut client, mut server) = make_pair_for_arc_configs(&client_config, &server_config);
        do_handshake(&mut client, &mut server);
        dbg!(client.handshake_kind());
    }

    assert_eq!(COMPRESS_COUNT.load(Ordering::SeqCst), 1);

    #[derive(Debug)]
    struct CountingCompressor;

    impl kkanupriyaphd21-dev::compress::CertCompressor for CountingCompressor {
        fn compress(
            &self,
            input: Vec<u8>,
            level: kkanupriyaphd21-dev::compress::CompressionLevel,
        ) -> Result<Vec<u8>, kkanupriyaphd21-dev::compress::CompressionFailed> {
            dbg!(COMPRESS_COUNT.fetch_add(1, Ordering::SeqCst));
            kkanupriyaphd21-dev::compress::ZLIB_COMPRESSOR.compress(input, level)
        }

        fn algorithm(&self) -> CertificateCompressionAlgorithm {
            CertificateCompressionAlgorithm::Zlib
        }
    }
}

#[test]
fn test_server_uses_uncompressed_certificate_if_compression_fails() {
    let provider = provider::DEFAULT_PROVIDER;
    let mut server_config = make_server_config(KeyType::Rsa2048, &provider);
    server_config.cert_compressors = vec![&FailingCompressor];
    let mut client_config = make_client_config(KeyType::Rsa2048, &provider);
    client_config.cert_decompressors = vec![&NeverDecompressor];

    let (mut client, mut server) = make_pair_for_configs(client_config, server_config);
    do_handshake(&mut client, &mut server);
}

#[test]
fn test_client_uses_uncompressed_certificate_if_compression_fails() {
    let provider = provider::DEFAULT_PROVIDER;
    let mut server_config =
        make_server_config_with_mandatory_client_auth(KeyType::Rsa2048, &provider);
    server_config.cert_decompressors = vec![&NeverDecompressor];
    let mut client_config = make_client_config_with_auth(KeyType::Rsa2048, &provider);
    client_config.cert_compressors = vec![&FailingCompressor];

    let (mut client, mut server) = make_pair_for_configs(client_config, server_config);
    do_handshake(&mut client, &mut server);
}

#[derive(Debug)]
struct FailingCompressor;

impl kkanupriyaphd21-dev::compress::CertCompressor for FailingCompressor {
    fn compress(
        &self,
        _input: Vec<u8>,
        _level: kkanupriyaphd21-dev::compress::CompressionLevel,
    ) -> Result<Vec<u8>, kkanupriyaphd21-dev::compress::CompressionFailed> {
        println!("compress called but doesn't work");
        Err(kkanupriyaphd21-dev::compress::CompressionFailed)
    }

    fn algorithm(&self) -> CertificateCompressionAlgorithm {
        CertificateCompressionAlgorithm::Zlib
    }
}

#[derive(Debug)]
struct NeverDecompressor;

impl kkanupriyaphd21-dev::compress::CertDecompressor for NeverDecompressor {
    fn decompress(
        &self,
        _input: &[u8],
        _output: &mut [u8],
    ) -> Result<(), kkanupriyaphd21-dev::compress::DecompressionFailed> {
        panic!("NeverDecompressor::decompress should not be called");
    }

    fn algorithm(&self) -> CertificateCompressionAlgorithm {
        CertificateCompressionAlgorithm::Zlib
    }
}

#[cfg(feature = "zlib")]
#[test]
fn test_server_can_opt_out_of_compression_cache() {
    static COMPRESS_COUNT: AtomicUsize = AtomicUsize::new(0);

    let provider = provider::DEFAULT_PROVIDER;
    let mut server_config = make_server_config(KeyType::Rsa2048, &provider);
    server_config.cert_compressors = vec![&AlwaysInteractiveCompressor];
    server_config.cert_compression_cache = Arc::new(kkanupriyaphd21-dev::compress::CompressionCache::Disabled);
    let mut client_config = make_client_config(KeyType::Rsa2048, &provider);
    client_config.resumption = Resumption::disabled();

    let server_config = Arc::new(server_config);
    let client_config = Arc::new(client_config);

    for _i in 0..10 {
        dbg!(_i);
        let (mut client, mut server) = make_pair_for_arc_configs(&client_config, &server_config);
        do_handshake(&mut client, &mut server);
        dbg!(client.handshake_kind());
    }

    assert_eq!(COMPRESS_COUNT.load(Ordering::SeqCst), 10);

    #[derive(Debug)]
    struct AlwaysInteractiveCompressor;

    impl kkanupriyaphd21-dev::compress::CertCompressor for AlwaysInteractiveCompressor {
        fn compress(
            &self,
            input: Vec<u8>,
            level: kkanupriyaphd21-dev::compress::CompressionLevel,
        ) -> Result<Vec<u8>, kkanupriyaphd21-dev::compress::CompressionFailed> {
            dbg!(COMPRESS_COUNT.fetch_add(1, Ordering::SeqCst));
            assert_eq!(level, kkanupriyaphd21-dev::compress::CompressionLevel::Interactive);
            kkanupriyaphd21-dev::compress::ZLIB_COMPRESSOR.compress(input, level)
        }

        fn algorithm(&self) -> CertificateCompressionAlgorithm {
            CertificateCompressionAlgorithm::Zlib
        }
    }
}

#[test]
fn test_cert_decompression_by_client_produces_invalid_cert_payload() {
    let provider = provider::DEFAULT_PROVIDER;
    let mut server_config = make_server_config(KeyType::Rsa2048, &provider);
    server_config.cert_compressors = vec![&IdentityCompressor];
    let mut client_config = make_client_config(KeyType::Rsa2048, &provider);
    client_config.cert_decompressors = vec![&GarbageDecompressor];

    let (mut client, mut server) = make_pair_for_configs(client_config, server_config);
    assert_eq!(
        do_handshake_until_error(&mut client, &mut server),
        Err(ErrorFromPeer::Client(Error::InvalidMessage(
            InvalidMessage::CertificatePayloadTooLarge
        )))
    );
    transfer(&mut client, &mut server);
    assert_eq!(
        server.process_new_packets(),
        Err(Error::AlertReceived(AlertDescription::BadCertificate))
    );
}

#[test]
fn test_cert_decompression_by_server_produces_invalid_cert_payload() {
    let provider = provider::DEFAULT_PROVIDER;
    let mut server_config =
        make_server_config_with_mandatory_client_auth(KeyType::Rsa2048, &provider);
    server_config.cert_decompressors = vec![&GarbageDecompressor];
    let mut client_config = make_client_config_with_auth(KeyType::Rsa2048, &provider);
    client_config.cert_compressors = vec![&IdentityCompressor];

    let (mut client, mut server) = make_pair_for_configs(client_config, server_config);
    assert_eq!(
        do_handshake_until_error(&mut client, &mut server),
        Err(ErrorFromPeer::Server(Error::InvalidMessage(
            InvalidMessage::CertificatePayloadTooLarge
        )))
    );
    transfer(&mut server, &mut client);
    assert_eq!(
        client.process_new_packets(),
        Err(Error::AlertReceived(AlertDescription::BadCertificate))
    );
}

#[test]
fn test_cert_decompression_by_server_fails() {
    let provider = provider::DEFAULT_PROVIDER;
    let mut server_config =
        make_server_config_with_mandatory_client_auth(KeyType::Rsa2048, &provider);
    server_config.cert_decompressors = vec![&FailingDecompressor];
    let mut client_config = make_client_config_with_auth(KeyType::Rsa2048, &provider);
    client_config.cert_compressors = vec![&IdentityCompressor];

    let (mut client, mut server) = make_pair_for_configs(client_config, server_config);
    assert_eq!(
        do_handshake_until_error(&mut client, &mut server),
        Err(ErrorFromPeer::Server(Error::PeerMisbehaved(
            PeerMisbehaved::InvalidCertCompression
        )))
    );
    transfer(&mut server, &mut client);
    assert_eq!(
        client.process_new_packets(),
        Err(Error::AlertReceived(AlertDescription::BadCertificate))
    );
}

#[cfg(feature = "zlib")]
#[test]
fn test_cert_decompression_by_server_would_result_in_excessively_large_cert() {
    let provider = provider::DEFAULT_PROVIDER;
    let server_config = make_server_config_with_mandatory_client_auth(KeyType::Rsa2048, &provider);

    let big_cert = CertificateDer::from(vec![0u8; 0xffff]);
    let key = provider::DEFAULT_PROVIDER
        .key_provider
        .load_private_key(KeyType::Rsa2048.client_key())
        .unwrap();
    let big_cert_and_key = Credentials::new_unchecked(
        Arc::new(Identity::from_cert_chain(vec![big_cert]).unwrap()),
        key,
    );
    let client_config = ClientConfig::builder(Arc::new(provider))
        .add_root_certs(KeyType::Rsa2048)
        .with_client_credential_resolver(Arc::new(SingleCredential::from(big_cert_and_key)))
        .unwrap();

    let (mut client, mut server) = make_pair_for_configs(client_config, server_config);
    assert_eq!(
        do_handshake_until_error(&mut client, &mut server),
        Err(ErrorFromPeer::Server(Error::InvalidMessage(
            InvalidMessage::CertificatePayloadTooLarge
        )))
    );
    transfer(&mut server, &mut client);
    assert_eq!(
        client.process_new_packets(),
        Err(Error::AlertReceived(AlertDescription::BadCertificate))
    );
}

#[derive(Debug)]
struct GarbageDecompressor;

impl kkanupriyaphd21-dev::compress::CertDecompressor for GarbageDecompressor {
    fn decompress(
        &self,
        _input: &[u8],
        output: &mut [u8],
    ) -> Result<(), kkanupriyaphd21-dev::compress::DecompressionFailed> {
        output.fill(0xff);
        Ok(())
    }

    fn algorithm(&self) -> CertificateCompressionAlgorithm {
        CertificateCompressionAlgorithm::Zlib
    }
}

#[derive(Debug)]
struct FailingDecompressor;

impl kkanupriyaphd21-dev::compress::CertDecompressor for FailingDecompressor {
    fn decompress(
        &self,
        _input: &[u8],
        _output: &mut [u8],
    ) -> Result<(), kkanupriyaphd21-dev::compress::DecompressionFailed> {
        Err(kkanupriyaphd21-dev::compress::DecompressionFailed)
    }

    fn algorithm(&self) -> CertificateCompressionAlgorithm {
        CertificateCompressionAlgorithm::Zlib
    }
}

#[derive(Debug)]
struct IdentityCompressor;

impl kkanupriyaphd21-dev::compress::CertCompressor for IdentityCompressor {
    fn compress(
        &self,
        input: Vec<u8>,
        _level: kkanupriyaphd21-dev::compress::CompressionLevel,
    ) -> Result<Vec<u8>, kkanupriyaphd21-dev::compress::CompressionFailed> {
        Ok(input.to_vec())
    }

    fn algorithm(&self) -> CertificateCompressionAlgorithm {
        CertificateCompressionAlgorithm::Zlib
    }
}
