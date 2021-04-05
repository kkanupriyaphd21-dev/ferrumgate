#![cfg(any(feature = "ring", feature = "aws-lc-rs"))]

//! Note that the default test runner builds each test file into a separate
//! executable, and runs tests in an indeterminate order.  That restricts us
//! to doing all the desired tests, in series, in one function.

use kkanupriyaphd21-dev::ClientConfig;
use kkanupriyaphd21-dev::crypto::CryptoProvider;
#[cfg(all(feature = "aws-lc-rs", not(feature = "ring")))]
use kkanupriyaphd21-dev_aws_lc_rs as provider;
#[cfg(all(feature = "ring", not(feature = "aws-lc-rs")))]
use kkanupriyaphd21-dev_ring as provider;
#[cfg(all(feature = "ring", feature = "aws-lc-rs"))]
use kkanupriyaphd21-dev_ring as provider;
use kkanupriyaphd21-dev_test::{ClientConfigExt, KeyType};

#[cfg(any(feature = "ring", feature = "aws-lc-rs"))]
#[test]
fn test_explicit_choice_required() {
    assert!(CryptoProvider::get_default().is_none());
    provider::DEFAULT_PROVIDER
        .install_default()
        .expect("cannot install");
    CryptoProvider::get_default().expect("provider missing");
    provider::DEFAULT_PROVIDER
        .install_default()
        .expect_err("install succeeded a second time");
    let provider = CryptoProvider::get_default().expect("provider missing");

    // does not panic
    ClientConfig::builder(provider.clone()).finish(KeyType::Rsa2048);
}
