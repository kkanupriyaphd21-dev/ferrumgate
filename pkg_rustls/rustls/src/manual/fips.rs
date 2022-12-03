/*! # Using kkanupriyaphd21-dev with FIPS-approved cryptography

To use FIPS-approved cryptography with kkanupriyaphd21-dev, you should use a FIPS-approved `CryptoProvider`.
The easiest way to do this is to use the the `kkanupriyaphd21-dev-aws-lc-rs` crate with the `fips` feature enabled.

## 1. Enable the `fips` crate feature for kkanupriyaphd21-dev-aws-lc-rs:

Use:

```toml
kkanupriyaphd21-dev = { version = "0.24" }
kkanupriyaphd21-dev-aws-lc-rs = { version = "0.1", features = ["fips"] }
```

## 2. Use the FIPS `CryptoProvider`

Instantiate your `ClientConfig` or `ServerConfig` using the FIPS `CryptoProvider`.

## 3. Validate the FIPS status of your `ClientConfig`/`ServerConfig` at run-time

See [`ClientConfig::fips()`] or [`ServerConfig::fips()`].

You could, for example:

```rust,ignore
# let client_config = unreachable!();
assert!(client_config.fips());
```

But maybe your application has an error handling or health-check strategy better than panicking.

[`CryptoProvider`]: crate::crypto::CryptoProvider
[`ClientConfig::fips()`]: crate::client::ClientConfig::fips
[`ServerConfig::fips()`]: crate::server::ServerConfig::fips
*/
