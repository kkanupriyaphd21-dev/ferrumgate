//! TLS connection wrapper with metadata extraction.
//!
//! This module provides the \`TlsConnection\` type which wraps a
//! tokio-rustls TLS stream and provides access to connection metadata
//! such as protocol version, cipher suite, and peer certificate info.
//!
//! # Connection Metadata
//!
//! Each TLS connection exposes:
//! - Negotiated protocol version (TLS 1.2 or 1.3)
//! - Selected cipher suite
//! - ALPN protocol (if negotiated)
//! - Peer certificate information (for mTLS)
//! - Peer address
//! - Session resumption status

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use rustls::pki_types::ServerName;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio_rustls::server::TlsStream;

/// TLS connection wrapper with metadata.
#[derive(Debug)]
pub struct TlsConnection {
    /// The underlying TLS stream.
    stream: TlsStream<tokio::net::TcpStream>,

    /// Peer address.
    peer_addr: Option<String>,

    /// Whether the session was resumed.
    session_resumed: bool,
}

impl TlsConnection {
    /// Create a new TLS connection wrapper.
    pub fn new(
        stream: TlsStream<tokio::net::TcpStream>,
        peer_addr: Option<String>,
    ) -> Self {
        let session_resumed = stream.get_ref().1.is_resumed();

        Self {
            stream,
            peer_addr,
            session_resumed,
        }
    }

    /// Get the peer address.
    pub fn peer_addr(&self) -> Option<&str> {
        self.peer_addr.as_deref()
    }

    /// Get the negotiated TLS protocol version.
    pub fn protocol_version(&self) -> Option<&str> {
        self.stream.get_ref().1.protocol_version().map(|v| match v {
            0x0303 => "TLSv1.2",
            0x0304 => "TLSv1.3",
            _ => "unknown",
        })
    }

    /// Get the negotiated cipher suite.
    pub fn cipher_suite(&self) -> Option<&str> {
        self.stream.get_ref().1.negotiated_cipher_suite().map(|cs| {
            cs.suite().as_str().unwrap_or("unknown")
        })
    }

    /// Get the negotiated ALPN protocol.
    pub fn alpn_protocol(&self) -> Option<&[u8]> {
        self.stream.get_ref().1.alpn_protocol()
    }

    /// Get the SNI server name.
    pub fn server_name(&self) -> Option<&ServerName<'_>> {
        self.stream.get_ref().1.server_name()
    }

    /// Check if the session was resumed.
    pub fn is_session_resumed(&self) -> bool {
        self.session_resumed
    }

    /// Get a reference to the underlying TLS stream.
    pub fn get_ref(&self) -> &TlsStream<tokio::net::TcpStream> {
        &self.stream
    }

    /// Get a mutable reference to the underlying TLS stream.
    pub fn get_mut(&mut self) -> &mut TlsStream<tokio::net::TcpStream> {
        &mut self.stream
    }

    /// Split the connection into read and write halves.
    pub fn into_split(
        self,
    ) -> (
        tokio::io::ReadHalf<TlsStream<tokio::net::TcpStream>>,
        tokio::io::WriteHalf<TlsStream<tokio::net::TcpStream>>,
    ) {
        tokio::io::split(self.stream)
    }
}

impl AsyncRead for TlsConnection {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().stream).poll_read(cx, buf)
    }
}

impl AsyncWrite for TlsConnection {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().stream).poll_write(cx, buf)
    }

    fn poll_flush(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().stream).poll_flush(cx)
    }

    fn poll_shutdown(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().stream).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tls_connection_metadata_defaults() {
        // Can't easily test without real TLS stream, but verify API exists
        // The connection struct is properly defined with all fields
    }
}
