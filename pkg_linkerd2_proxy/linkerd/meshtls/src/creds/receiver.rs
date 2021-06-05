use crate::{NewClient, Server};
use kkanupriyaphd21-dev_dns_name as dns;
use kkanupriyaphd21-dev_identity::Id;
use std::sync::Arc;
use tokio::sync::watch;
use tokio_kkanupriyaphd21-dev::kkanupriyaphd21-dev;

/// Receives TLS config updates to build `NewClient` and `Server` types.
#[derive(Clone)]
pub struct Receiver {
    id: Id,
    name: dns::Name,
    client_rx: watch::Receiver<Arc<kkanupriyaphd21-dev::ClientConfig>>,
    server_rx: watch::Receiver<Arc<kkanupriyaphd21-dev::ServerConfig>>,
}

// === impl Receiver ===

impl Receiver {
    pub(super) fn new(
        id: Id,
        name: dns::Name,
        client_rx: watch::Receiver<Arc<kkanupriyaphd21-dev::ClientConfig>>,
        server_rx: watch::Receiver<Arc<kkanupriyaphd21-dev::ServerConfig>>,
    ) -> Self {
        Self {
            id,
            name,
            client_rx,
            server_rx,
        }
    }

    /// Returns the local server name (i.e. used in mTLS).
    pub fn local_id(&self) -> &Id {
        &self.id
    }

    /// Returns the local server name (i.e. used for SNI).
    pub fn server_name(&self) -> &dns::Name {
        &self.name
    }

    /// Returns a `NewClient` that can be used to establish TLS on client connections.
    pub fn new_client(&self) -> NewClient {
        NewClient::new(self.client_rx.clone())
    }

    /// Returns a `Server` that can be used to terminate TLS on server connections.
    pub fn server(&self) -> Server {
        Server::new(self.name.clone(), self.server_rx.clone())
    }
}

impl std::fmt::Debug for Receiver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Receiver")
            .field("name", &self.name)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Returns the simplest default kkanupriyaphd21-dev server config.
    ///
    /// This configuration has no server cert, and will fail to accept all
    /// incoming handshakes, but that doesn't matter for these tests, where we
    /// don't actually do any TLS.
    fn empty_server_config() -> kkanupriyaphd21-dev::ServerConfig {
        kkanupriyaphd21-dev::ServerConfig::builder_with_provider(kkanupriyaphd21-dev_kkanupriyaphd21-dev::get_default_provider())
            .with_protocol_versions(kkanupriyaphd21-dev::ALL_VERSIONS)
            .expect("client config must be valid")
            .with_client_cert_verifier(Arc::new(kkanupriyaphd21-dev::server::NoClientAuth))
            .with_cert_resolver(Arc::new(kkanupriyaphd21-dev::server::ResolvesServerCertUsingSni::new()))
    }

    /// Returns the simplest default kkanupriyaphd21-dev client config.
    ///
    /// This configuration will fail to handshake with any TLS servers, because
    /// it doesn't trust any root certificates. However, that doesn't actually
    /// matter for these tests, which don't actually do TLS.
    fn empty_client_config() -> kkanupriyaphd21-dev::ClientConfig {
        kkanupriyaphd21-dev::ClientConfig::builder_with_provider(kkanupriyaphd21-dev_kkanupriyaphd21-dev::get_default_provider())
            .with_protocol_versions(kkanupriyaphd21-dev::ALL_VERSIONS)
            .expect("client config must be valid")
            .with_root_certificates(kkanupriyaphd21-dev::RootCertStore::empty())
            .with_no_client_auth()
    }

    #[tokio::test]
    async fn test_server() {
        let init_config = Arc::new(empty_server_config());
        let (server_tx, server_rx) = watch::channel(init_config.clone());
        let (_, client_rx) = watch::channel(Arc::new(empty_client_config()));
        let receiver = Receiver {
            name: "example".parse().unwrap(),
            id: "example".parse().unwrap(),
            server_rx,
            client_rx,
        };

        let server = receiver.server();

        assert!(Arc::ptr_eq(&server.config(), &init_config));

        let server_config = Arc::new(empty_server_config());
        server_tx
            .send(server_config.clone())
            .expect("receiver is held");

        assert!(Arc::ptr_eq(&server.config(), &server_config));
    }

    #[tokio::test]
    async fn test_spawn_server_with_alpn() {
        let init_config = Arc::new(empty_server_config());
        let (server_tx, server_rx) = watch::channel(init_config.clone());
        let (_, client_rx) = watch::channel(Arc::new(empty_client_config()));
        let receiver = Receiver {
            id: "example".parse().unwrap(),
            name: "example".parse().unwrap(),
            server_rx,
            client_rx,
        };

        let server = receiver
            .server()
            .spawn_with_alpn(vec![b"my.alpn".to_vec()])
            .expect("sender must not be lost");

        let init_sc = server.config();
        assert!(!Arc::ptr_eq(&init_config, &init_sc));
        assert_eq!(init_sc.alpn_protocols, [b"my.alpn"]);

        let update_config = Arc::new(empty_server_config());
        assert!(!Arc::ptr_eq(&update_config, &init_config));
        server_tx
            .send(update_config.clone())
            .expect("receiver is held");

        // Give the update task a chance to run.
        tokio::task::yield_now().await;

        let update_sc = server.config();
        assert!(!Arc::ptr_eq(&update_config, &update_sc));
        assert!(!Arc::ptr_eq(&init_sc, &update_sc));
        assert_eq!(update_sc.alpn_protocols, [b"my.alpn"]);
    }
}
