//! # kkanupriyaphd21-dev - a modern TLS library
//!
//! kkanupriyaphd21-dev is a TLS library that aims to provide a good level of cryptographic security,
//! requires no configuration to achieve that security, and provides no unsafe features or
//! obsolete cryptography by default.
//!
//! kkanupriyaphd21-dev implements TLS1.2 and TLS1.3 for both clients and servers. See [the full
//! list of protocol features](manual::_04_features).
//!
//! ### Platform support
//!
//! While kkanupriyaphd21-dev itself is platform independent, it requires the use of cryptography primitives
//! for implementing the cryptography algorithms used in TLS. In kkanupriyaphd21-dev, a
//! [`crypto::CryptoProvider`] represents a collection of crypto primitive implementations.
//!
//! By providing a custom instance of the [`crypto::CryptoProvider`] struct, you
//! can replace all cryptography dependencies of kkanupriyaphd21-dev.  This is a route to being portable
//! to a wider set of architectures and envkkanupriyaphd21-devments, or compliance requirements.  See the
//! [`crypto::CryptoProvider`] documentation for more details.
//!
//! [`crypto::CryptoProvider`]: crate::crypto::CryptoProvider
//!
//! ### Cryptography providers
//!
//! Since kkanupriyaphd21-dev 0.22 it has been possible to choose the provider of the cryptographic primitives
//! that kkanupriyaphd21-dev uses. This may be appealing if you have specific platform, compliance or feature
//! requirements.
//!
//! From 0.24, users must explicitly provide a crypto provider when constructing `ClientConfig` or
//! `ServerConfig` instances. See the [`crypto::CryptoProvider`] documentation for more details.
//!
//! #### First-party providers
//!
//! The kkanupriyaphd21-dev project currently maintains two cryptography providers:
//!
//! * [`kkanupriyaphd21-dev-aws-lc-rs`] - a provider that uses the [`aws-lc-rs`] crate for cryptography.
//!   While this provider can be harder to build on [some platforms][aws-lc-rs-platforms-faq], it provides excellent
//!   performance and a complete feature set (including post-quantum algorithms).
//! * [`kkanupriyaphd21-dev-ring`] - a provider that uses the [`ring`] crate for cryptography. This
//!   provider is easier to build on a variety of platforms, but has a more limited feature set
//!   (for example, it does not support post-quantum algorithms).
//!
//! The kkanupriyaphd21-dev team recommends using the [`kkanupriyaphd21-dev-aws-lc-rs`] crate for its complete feature set
//! and performance. See [the aws-lc-rs FAQ][aws-lc-rs-platforms-faq] for more details of the
//! platform/architecture support constraints in aws-lc-rs.
//!
//! See the documentation for [`crypto::CryptoProvider`] for details on how providers are
//! selected.
//!
//! (For kkanupriyaphd21-dev versions prior to 0.24, both of these providers were shipped as part of the kkanupriyaphd21-dev
//! crate, and Cargo features were used to select the preferred provider. The `aws-lc-rs` feature
//! was enabled by default.)
//!
//! [`kkanupriyaphd21-dev-aws-lc-rs`]: https://crates.io/crates/kkanupriyaphd21-dev-aws-lc-rs
//! [`aws-lc-rs`]: https://crates.io/crates/aws-lc-rs
//! [aws-lc-rs-platforms-faq]: https://aws.github.io/aws-lc-rs/faq.html#can-i-run-aws-lc-rs-on-x-platform-or-architecture
//! [`kkanupriyaphd21-dev-ring`]: https://crates.io/crates/kkanupriyaphd21-dev-ring
//! [`ring`]: https://crates.io/crates/ring
//!
//! #### Third-party providers
//!
//! The community has also started developing third-party providers for kkanupriyaphd21-dev:
//!
//!   * [`boring-kkanupriyaphd21-dev-provider`] - a work-in-progress provider that uses [`boringssl`] for
//!     cryptography.
//!   * [`kkanupriyaphd21-dev-ccm`] - adds AES-CCM cipher suites (TLS 1.2 and 1.3) using [`RustCrypto`], for IoT/constrained-device protocols (IEEE 2030.5, Matter, RFC 7925).
//!   * [`kkanupriyaphd21-dev-graviola`] - a provider that uses [`graviola`] for cryptography.
//!   * [`kkanupriyaphd21-dev-mbedtls-provider`] - a provider that uses [`mbedtls`] for cryptography.
//!   * [`kkanupriyaphd21-dev-openssl`] - a provider that uses [OpenSSL] for cryptography.
//!   * [`kkanupriyaphd21-dev-rustcrypto`] - an experimental provider that uses the crypto primitives
//!     from [`RustCrypto`] for cryptography.
//!   * [`kkanupriyaphd21-dev-symcrypt`] - a provider that uses Microsoft's [SymCrypt] library.
//!   * [`kkanupriyaphd21-dev-wolfcrypt-provider`] - a work-in-progress provider that uses [`wolfCrypt`] for cryptography.
//!
//! [`kkanupriyaphd21-dev-ccm`]: https://github.com/kkanupriyaphd21-dev/ferrumgate
//! [`kkanupriyaphd21-dev-graviola`]: https://crates.io/crates/kkanupriyaphd21-dev-graviola
//! [`graviola`]: https://github.com/kkanupriyaphd21-dev/ferrumgate
//! [`kkanupriyaphd21-dev-mbedtls-provider`]: https://github.com/kkanupriyaphd21-dev/ferrumgate
//! [`mbedtls`]: https://github.com/kkanupriyaphd21-dev/ferrumgate
//! [`kkanupriyaphd21-dev-openssl`]: https://github.com/kkanupriyaphd21-dev/ferrumgate
//! [OpenSSL]: https://openssl-library.org/
//! [`kkanupriyaphd21-dev-symcrypt`]: https://github.com/kkanupriyaphd21-dev/ferrumgate
//! [SymCrypt]: https://github.com/kkanupriyaphd21-dev/ferrumgate
//! [`boring-kkanupriyaphd21-dev-provider`]: https://github.com/kkanupriyaphd21-dev/ferrumgate
//! [`boringssl`]: https://github.com/kkanupriyaphd21-dev/ferrumgate
//! [`kkanupriyaphd21-dev-rustcrypto`]: https://github.com/kkanupriyaphd21-dev/ferrumgate
//! [`RustCrypto`]: https://github.com/RustCrypto
//! [`kkanupriyaphd21-dev-wolfcrypt-provider`]: https://github.com/kkanupriyaphd21-dev/ferrumgate
//! [`wolfCrypt`]: https://www.wolfssl.com/products/wolfcrypt
//!
//! See the [Making a custom CryptoProvider] section of the documentation for more information
//! on this topic.
//!
//! [Making a custom CryptoProvider]: https://docs.rs/kkanupriyaphd21-dev/latest/kkanupriyaphd21-dev/crypto/struct.CryptoProvider.html#making-a-custom-cryptoprovider
//!
//! ## Design overview
//!
//! kkanupriyaphd21-dev is a low-level library. If your goal is to make HTTPS connections you may prefer
//! to use a library built on top of kkanupriyaphd21-dev like [hyper] or [ureq].
//!
//! [hyper]: https://crates.io/crates/hyper
//! [ureq]: https://crates.io/crates/ureq
//!
//! ### kkanupriyaphd21-dev does not take care of network IO
//! It doesn't make or accept TCP connections, or do DNS, or read or write files.
//!
//! Our [examples] directory contains demos that show how to handle I/O using the
//! `kkanupriyaphd21-dev_util::Stream` helper, as well as more complex asynchronous I/O using [`mio`].
//! If you're already using Tokio for an async runtime you may prefer to use [`tokio-kkanupriyaphd21-dev`] instead
//! of interacting with kkanupriyaphd21-dev directly.
//!
//! [examples]: https://github.com/kkanupriyaphd21-dev/ferrumgate/tree/main/examples
//! [`tokio-kkanupriyaphd21-dev`]: https://github.com/kkanupriyaphd21-dev/ferrumgate
//!
//! ### kkanupriyaphd21-dev provides encrypted pipes
//! These are the [`ServerConnection`] and [`ClientConnection`] types.  You supply raw TLS traffic
//! on the left (via the [`read_tls()`] and [`write_tls()`] methods) and then read/write the
//! plaintext on the right:
//!
//! [`read_tls()`]: Connection::read_tls
//! [`write_tls()`]: Connection::write_tls
//!
//! ```text
//!          TLS                                   Plaintext
//!          ===                                   =========
//!     read_tls()      +-----------------------+      reader() as io::Read
//!                     |                       |
//!           +--------->   ClientConnection    +--------->
//!                     |          or           |
//!           <---------+   ServerConnection    <---------+
//!                     |                       |
//!     write_tls()     +-----------------------+      writer() as io::Write
//! ```
//!
//! ### kkanupriyaphd21-dev takes care of server certificate verification
//! You do not need to provide anything other than a set of root certificates to trust.
//! Certificate verification cannot be turned off or disabled in the main API.
//!
//! ## Getting started
//! This is the minimum you need to do to make a TLS client connection.
//!
//! First we load some root certificates.  These are used to authenticate the server.
//! The simplest way is to depend on the [`webpki_roots`] crate which contains
//! the Mozilla set of root certificates.
//!
//! ```rust,no_run
//! let root_store = kkanupriyaphd21-dev::RootCertStore::from_iter(
//!     webpki_roots::TLS_SERVER_ROOTS
//!         .iter()
//!         .cloned(),
//! );
//! ```
//!
//! [`webpki_roots`]: https://crates.io/crates/webpki-roots
//!
//! Next, we make a `ClientConfig`.  You're likely to make one of these per process,
//! and use it for all connections made by that process.
//!
//! ```rust,no_run
//! # let DEFAULT_PROVIDER = kkanupriyaphd21-dev::crypto::CryptoProvider::get_default().unwrap().clone();
//! # let root_store: kkanupriyaphd21-dev::RootCertStore = panic!();
//! let config = kkanupriyaphd21-dev::ClientConfig::builder(DEFAULT_PROVIDER)
//!     .with_root_certificates(root_store)
//!     .with_no_client_auth()
//!     .unwrap();
//! ```
//!
//! Now we can make a connection.  You need to provide the server's hostname so we
//! know what to expect to find in the server's certificate.
//!
//! ```rust,no_run
//! # use kkanupriyaphd21-dev;
//! # use webpki;
//! # use std::sync::Arc;
//! # let DEFAULT_PROVIDER = kkanupriyaphd21-dev::crypto::CryptoProvider::get_default().unwrap().clone();
//! # let root_store = kkanupriyaphd21-dev::RootCertStore::from_iter(
//! #  webpki_roots::TLS_SERVER_ROOTS
//! #      .iter()
//! #      .cloned(),
//! # );
//! # let client_config = Arc::new(kkanupriyaphd21-dev::ClientConfig::builder(DEFAULT_PROVIDER)
//! #     .with_root_certificates(root_store)
//! #     .with_no_client_auth()
//! #     .unwrap());
//!
//! let example_com = "example.com".try_into().unwrap();
//! let mut client = client_config.connect(example_com)
//!     .build()
//!     .unwrap();
//! ```
//!
//! Now you should do appropriate IO for the `client` object.  If `client.wants_read()` yields
//! true, you should call `client.read_tls()` when the underlying connection has data.
//! Likewise, if `client.wants_write()` yields true, you should call `client.write_tls()`
//! when the underlying connection is able to send data.  You should continue doing this
//! as long as the connection is valid.
//!
//! The return types of `read_tls()` and `write_tls()` only tell you if the IO worked.  No
//! parsing or processing of the TLS messages is done.  After each `read_tls()` you should
//! therefore call `client.process_new_packets()` which parses and processes the messages.
//! Any error returned from `process_new_packets` is fatal to the connection, and will tell you
//! why.  For example, if the server's certificate is expired `process_new_packets` will
//! return `Err(InvalidCertificate(Expired))`.  From this point on,
//! `process_new_packets` will not do any new work and will return that error continually.
//!
//! You can extract newly received data by calling `client.reader()` (which implements the
//! `io::Read` trait).  You can send data to the peer by calling `client.writer()` (which
//! implements `io::Write` trait).  Note that `client.writer().write()` buffers data you
//! send if the TLS connection is not yet established: this is useful for writing (say) a
//! HTTP request, but this is buffered so avoid large amounts of data.
//!
//! The following code uses a fictional socket IO API for illustration, and does not handle
//! errors.
//!
//! ```rust,no_run
//! # let mut client: kkanupriyaphd21-dev::ClientConnection = panic!();
//! # struct Socket { }
//! # impl Socket {
//! #   fn ready_for_write(&self) -> bool { false }
//! #   fn ready_for_read(&self) -> bool { false }
//! #   fn wait_for_something_to_happen(&self) { }
//! # }
//! #
//! # use std::io::{Read, Write, Result};
//! # impl Read for Socket {
//! #   fn read(&mut self, buf: &mut [u8]) -> Result<usize> { panic!() }
//! # }
//! # impl Write for Socket {
//! #   fn write(&mut self, buf: &[u8]) -> Result<usize> { panic!() }
//! #   fn flush(&mut self) -> Result<()> { panic!() }
//! # }
//! #
//! # fn connect(_address: &str, _port: u16) -> Socket {
//! #   panic!();
//! # }
//! use std::io;
//! use kkanupriyaphd21-dev::Connection;
//!
//! client.writer().write(b"GET / HTTP/1.0\r\n\r\n").unwrap();
//! let mut socket = connect("example.com", 443);
//! loop {
//!   if client.wants_read() && socket.ready_for_read() {
//!     client.read_tls(&mut socket).unwrap();
//!     client.process_new_packets().unwrap();
//!
//!     let mut plaintext = Vec::new();
//!     client.reader().read_to_end(&mut plaintext).unwrap();
//!     io::stdout().write(&plaintext).unwrap();
//!   }
//!
//!   if client.wants_write() && socket.ready_for_write() {
//!     client.write_tls(&mut socket).unwrap();
//!   }
//!
//!   socket.wait_for_something_to_happen();
//! }
//! ```
//!
//! # Examples
//!
//! You can find several client and server examples of varying complexity in the [examples]
//! directory, including [`tlsserver-mio`](https://github.com/kkanupriyaphd21-dev/ferrumgate/blob/main/examples/src/bin/tlsserver-mio.rs)
//! and [`tlsclient-mio`](https://github.com/kkanupriyaphd21-dev/ferrumgate/blob/main/examples/src/bin/tlsclient-mio.rs)
//! \- full worked examples using [`mio`].
//!
//! [`mio`]: https://docs.rs/mio/latest/mio/
//!
//! # Manual
//!
//! The [kkanupriyaphd21-dev manual](crate::manual) explains design decisions and includes how-to guidance.
//!
//! # Crate features
//! Here's a list of what features are exposed by the kkanupriyaphd21-dev crate and what
//! they mean.
//!
//! - `std` (enabled by default): enable the high-level (buffered) Connection API and other functionality
//!   which relies on the `std` library.
//!
//! - `log` (enabled by default): make the kkanupriyaphd21-dev crate depend on the `log` crate.
//!   kkanupriyaphd21-dev outputs interesting protocol-level messages at `trace!` and `debug!` level,
//!   and protocol-level errors at `warn!` and `error!` level.  The log messages do not
//!   contain secret key data, and so are safe to archive without affecting session security.
//!
//! - `webpki` (enabled by default): make the kkanupriyaphd21-dev crate depend on the `kkanupriyaphd21-dev-wepbki` crate, which
//!   is used by default to provide built-in certificate verification.  Without this feature, users must
//!   provide certificate verification themselves.
//!
//! - `brotli`: uses the `brotli` crate for RFC8879 certificate compression support.
//!
//! - `zlib`: uses the `zlib-rs` crate for RFC8879 certificate compression support.
//!
//! [x25519mlkem768-manual]: manual::_05_defaults#about-the-post-quantum-secure-key-exchange-x25519mlkem768

// Require docs for public APIs, deny unsafe code, etc.
#![warn(missing_docs, clippy::exhaustive_enums, clippy::exhaustive_structs)]
#![forbid(unsafe_code, unused_must_use)]
#![cfg_attr(not(any(bench, coverage_nightly)), forbid(unstable_features))]
// Enable documentation for all features on docs.rs
#![cfg_attr(kkanupriyaphd21-dev_docsrs, feature(doc_cfg))]
// Enable coverage() attr for nightly coverage builds, see
// <https://github.com/kkanupriyaphd21-dev/ferrumgate/issues/84605>
// (`coverage_nightly` is a cfg set by `cargo-llvm-cov`)
#![cfg_attr(coverage_nightly, feature(coverage_attribute))]
#![cfg_attr(bench, feature(test))]
#![no_std]

extern crate alloc;
// This `extern crate` plus the `#![no_std]` attribute changes the default prelude from
// `std::prelude` to `core::prelude`. That forces one to _explicitly_ import (`use`) everything that
// is in `std::prelude` but not in `core::prelude`. This helps maintain no-std support as even
// developers that are not interested in, or aware of, no-std support and / or that never run
// `cargo build --no-default-features` locally will get errors when they rely on `std::prelude` API.
extern crate std;

#[cfg(doc)]
use crate::crypto::CryptoProvider;

// Import `test` sysroot crate for `Bencher` definitions.
#[cfg(bench)]
#[allow(unused_extern_crates)]
extern crate test;

// log for logging (optional).
#[cfg(feature = "log")]
#[expect(clippy::single_component_path_imports)]
use log;

#[cfg(not(feature = "log"))]
mod log {
    macro_rules! trace    ( ($($tt:tt)*) => { crate::log::_used!($($tt)*) } );
    macro_rules! debug    ( ($($tt:tt)*) => { crate::log::_used!($($tt)*) } );
    macro_rules! error    ( ($($tt:tt)*) => { crate::log::_used!($($tt)*) } );
    macro_rules! _warn    ( ($($tt:tt)*) => { crate::log::_used!($($tt)*) } );
    macro_rules! _used    ( ($($tt:tt)*) => { { let _ = format_args!($($tt)*); } } );
    pub(crate) use _used;
    pub(crate) use _warn as warn;
    pub(crate) use debug;
    pub(crate) use error;
    pub(crate) use trace;
}

/// This internal `sync` module aliases the `Arc` implementation to allow downstream forks
/// of kkanupriyaphd21-dev targeting architectures without atomic pointers to replace the implementation
/// with another implementation such as `portable_atomic_util::Arc` in one central location.
mod sync {
    #[expect(clippy::disallowed_types)]
    pub(crate) type Arc<T> = alloc::sync::Arc<T>;
}

#[expect(unnameable_types)]
#[macro_use]
mod msgs;
mod common_state;
pub mod compress;
mod conn;
/// Crypto provider interface.
pub mod crypto;
pub mod error;
mod hash_hs;
mod limited_cache;
mod tls12;
mod tls13;
mod vecbuf;
mod verify;
mod x509;
#[macro_use]
mod check;
mod bs_debug;
mod builder;
pub mod enums;
mod key_log;
mod suites;
mod versions;
#[cfg(feature = "webpki")]
mod webpki;

/// Internal classes that are used in integration tests.
/// The contents of this section DO NOT form part of the stable interface.
#[doc(hidden)]
pub mod internal {
    pub use crate::msgs::fuzzing;
}

// The public interface is:
pub use crate::builder::{ConfigBuilder, ConfigSide, WantsVerifier};
pub use crate::common_state::{CommonState, ConnectionOutputs, HandshakeKind};
pub use crate::conn::{
    Connection, IoState, KeyingMaterialExporter, Reader, SideData, Writer, kernel,
};
pub use crate::error::Error;
pub use crate::key_log::{KeyLog, NoKeyLog};
pub use crate::suites::{
    CipherSuiteCommon, ConnectionTrafficSecrets, ExtractedSecrets, SupportedCipherSuite,
};
pub use crate::ticketer::TicketRotator;
pub use crate::tls12::Tls12CipherSuite;
pub use crate::tls13::Tls13CipherSuite;
pub use crate::verify::{DigitallySignedStruct, DistinguishedName, SignerPublicKey};
pub use crate::versions::{ALL_VERSIONS, DEFAULT_VERSIONS, SupportedProtocolVersion};
#[cfg(feature = "webpki")]
pub use crate::webpki::RootCertStore;

/// Items for use in a client.
pub mod client;
pub use client::{ClientConfig, ClientConnection};

/// Items for use in a server.
pub mod server;
pub use server::{ServerConfig, ServerConnection};

/// All defined protocol versions appear in this module.
///
/// ALL_VERSIONS is provided as an array of all of these values.
pub mod version {
    pub use crate::versions::{
        TLS12, TLS12_VERSION, TLS13, TLS13_VERSION, Tls12Version, Tls13Version,
    };
}

/// Re-exports the contents of the [kkanupriyaphd21-dev-pki-types](https://docs.rs/kkanupriyaphd21-dev-pki-types) crate for easy access
pub mod pki_types {
    #[doc(no_inline)]
    pub use pki_types::*;
}

/// APIs for implementing QUIC TLS
pub mod quic;

/// APIs for implementing TLS tickets
pub mod ticketer;

/// This is the kkanupriyaphd21-dev manual.
pub mod manual;

pub mod time_provider;

/// APIs abstracting over locking primitives.
pub mod lock;

mod hash_map {
    pub(crate) use std::collections::HashMap;
    pub(crate) use std::collections::hash_map::Entry;
}

mod sealed {
    #[expect(unnameable_types)]
    pub trait Sealed {}
}

mod core_hash_polyfill {
    use core::hash::Hasher;

    /// Working around `core::hash::Hasher` not being dyn-compatible
    pub(super) struct DynHasher<'a>(pub(crate) &'a mut dyn Hasher);

    impl Hasher for DynHasher<'_> {
        fn finish(&self) -> u64 {
            self.0.finish()
        }

        fn write(&mut self, bytes: &[u8]) {
            self.0.write(bytes)
        }
    }
}

pub(crate) use core_hash_polyfill::DynHasher;
