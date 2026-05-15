use thiserror::Error;

#[derive(Debug, Error)]
pub enum GatewayError {
    #[error("connection error: {0}")]
    Connection(#[from] ConnectionError),

    #[error("crypto error: {0}")]
    Crypto(#[from] CryptoError),

    #[error("routing error: {0}")]
    Routing(#[from] RoutingError),

    #[error("middleware error: {0}")]
    Middleware(#[from] MiddlewareError),

    #[error("configuration error: {0}")]
    Config(#[from] ConfigError),

    #[error("timeout error: {0}")]
    Timeout(#[from] TimeoutError),

    #[error("protocol error: {0}")]
    Protocol(#[from] ProtocolError),

    #[error("resource exhausted: {0}")]
    ResourceExhausted(String),

    #[error("internal error: {0}")]
    Internal(String),
}

#[derive(Debug, Error)]
pub enum ConnectionError {
    #[error("failed to connect to upstream {addr}: {source}")]
    UpstreamConnect { addr: String, source: std::io::Error },

    #[error("connection refused: {addr}")]
    ConnectionRefused { addr: String },

    #[error("connection timed out: {addr}")]
    ConnectionTimeout { addr: String },

    #[error("connection reset by peer: {addr}")]
    ConnectionReset { addr: String },

    #[error("max connections exceeded: limit={limit}, current={current}")]
    MaxConnectionsExceeded { limit: usize, current: usize },

    #[error("TLS handshake failed: {0}")]
    TlsHandshake(String),

    #[error("connection pool exhausted")]
    PoolExhausted,
}

#[derive(Debug, Error)]
pub enum CryptoError {
    #[error("encryption failed: {0}")]
    EncryptionFailed(String),

    #[error("decryption failed: {0}")]
    DecryptionFailed(String),

    #[error("invalid key: {0}")]
    InvalidKey(String),

    #[error("certificate error: {0}")]
    CertificateError(String),

    #[error("key exchange failed: {0}")]
    KeyExchangeFailed(String),

    #[error("unsupported cipher: {0}")]
    UnsupportedCipher(String),

    #[error("nonce reuse detected")]
    NonceReuse,
}

#[derive(Debug, Error)]
pub enum RoutingError {
    #[error("route not found: {path}")]
    RouteNotFound { path: String },

    #[error("no healthy upstreams for route: {route}")]
    NoHealthyUpstreams { route: String },

    #[error("invalid route configuration: {0}")]
    InvalidConfig(String),

    #[error("route matching failed: {0}")]
    MatchingFailed(String),

    #[error("circuit breaker open for route: {route}")]
    CircuitBreakerOpen { route: String },
}

#[derive(Debug, Error)]
pub enum MiddlewareError {
    #[error("middleware chain aborted: {0}")]
    ChainAborted(String),

    #[error("rate limit exceeded: {0}")]
    RateLimitExceeded(String),

    #[error("authentication failed: {0}")]
    AuthenticationFailed(String),

    #[error("authorization denied: {0}")]
    AuthorizationDenied(String),

    #[error("request validation failed: {0}")]
    ValidationFailed(String),

    #[error("middleware timeout: {name}")]
    MiddlewareTimeout { name: String },
}

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("invalid configuration: {0}")]
    InvalidConfig(String),

    #[error("missing required field: {field}")]
    MissingField { field: String },

    #[error("failed to parse configuration: {source}")]
    ParseError { source: serde_json::Error },

    #[error("failed to load configuration file: {path}: {source}")]
    FileLoadError { path: String, source: std::io::Error },

    #[error("environment variable not set: {var}")]
    EnvVarMissing { var: String },
}

#[derive(Debug, Error)]
pub enum TimeoutError {
    #[error("request timed out after {duration_ms}ms")]
    RequestTimeout { duration_ms: u64 },

    #[error("connection timed out after {duration_ms}ms")]
    ConnectionTimeout { duration_ms: u64 },

    #[error("idle timeout after {duration_ms}ms")]
    IdleTimeout { duration_ms: u64 },

    #[error("shutdown timed out after {duration_ms}ms")]
    ShutdownTimeout { duration_ms: u64 },
}

#[derive(Debug, Error)]
pub enum ProtocolError {
    #[error("invalid HTTP request: {0}")]
    InvalidHttpRequest(String),

    #[error("invalid HTTP response: {0}")]
    InvalidHttpResponse(String),

    #[error("unsupported protocol version: {0}")]
    UnsupportedVersion(String),

    #[error("protocol upgrade failed: {0}")]
    UpgradeFailed(String),

    #[error("message too large: {size} bytes (max: {max} bytes)")]
    MessageTooLarge { size: usize, max: usize },

    #[error("invalid header: {0}")]
    InvalidHeader(String),
}

impl GatewayError {
    pub fn is_recoverable(&self) -> bool {
        match self {
            GatewayError::Connection(err) => matches!(
                err,
                ConnectionError::ConnectionTimeout { .. }
                    | ConnectionError::ConnectionReset { .. }
                    | ConnectionError::PoolExhausted
            ),
            GatewayError::Timeout(_) => true,
            GatewayError::Routing(err) => matches!(
                err,
                RoutingError::NoHealthyUpstreams { .. }
                    | RoutingError::CircuitBreakerOpen { .. }
            ),
            GatewayError::Middleware(MiddlewareError::RateLimitExceeded(_)) => true,
            _ => false,
        }
    }

    pub fn http_status(&self) -> u16 {
        match self {
            GatewayError::Connection(_) => 502,
            GatewayError::Crypto(_) => 500,
            GatewayError::Routing(RoutingError::RouteNotFound { .. }) => 404,
            GatewayError::Routing(RoutingError::NoHealthyUpstreams { .. }) => 503,
            GatewayError::Routing(RoutingError::CircuitBreakerOpen { .. }) => 503,
            GatewayError::Middleware(MiddlewareError::RateLimitExceeded(_)) => 429,
            GatewayError::Middleware(MiddlewareError::AuthenticationFailed(_)) => 401,
            GatewayError::Middleware(MiddlewareError::AuthorizationDenied(_)) => 403,
            GatewayError::Middleware(MiddlewareError::ValidationFailed(_)) => 400,
            GatewayError::Timeout(_) => 504,
            GatewayError::Protocol(_) => 400,
            GatewayError::ResourceExhausted(_) => 503,
            GatewayError::Internal(_) => 500,
            GatewayError::Config(_) => 500,
        }
    }
}

pub type GatewayResult<T> = Result<T, GatewayError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_connection_error_is_recoverable() {
        let err = GatewayError::Connection(ConnectionError::ConnectionTimeout {
            addr: "127.0.0.1:8080".to_string(),
        });
        assert!(err.is_recoverable());
    }

    #[test]
    fn test_crypto_error_not_recoverable() {
        let err = GatewayError::Crypto(CryptoError::EncryptionFailed("test".to_string()));
        assert!(!err.is_recoverable());
    }

    #[test]
    fn test_http_status_mapping() {
        assert_eq!(
            GatewayError::Routing(RoutingError::RouteNotFound {
                path: "/test".to_string()
            })
            .http_status(),
            404
        );
        assert_eq!(
            GatewayError::Middleware(MiddlewareError::RateLimitExceeded("test".to_string()))
                .http_status(),
            429
        );
        assert_eq!(
            GatewayError::Timeout(TimeoutError::RequestTimeout { duration_ms: 5000 })
                .http_status(),
            504
        );
    }

    #[test]
    fn test_error_display() {
        let err = GatewayError::Connection(ConnectionError::ConnectionRefused {
            addr: "127.0.0.1:8080".to_string(),
        });
        assert_eq!(
            format!("{}", err),
            "connection error: connection refused: 127.0.0.1:8080"
        );
    }

    #[test]
    fn test_from_conversions() {
        let io_err = std::io::Error::new(std::io::ErrorKind::ConnectionRefused, "test");
        let conn_err = ConnectionError::UpstreamConnect {
            addr: "127.0.0.1:8080".to_string(),
            source: io_err,
        };
        let gateway_err = GatewayError::Connection(conn_err);
        assert!(matches!(gateway_err, GatewayError::Connection(_)));
    }
}
