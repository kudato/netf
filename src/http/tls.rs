//! The rustls client config: ring and the webpki roots built into the
//! binary, one config per process.
//!
//! The roots are Mozilla's, compiled in through `webpki-roots`, because
//! routers often have no system certificate store and the result must not
//! depend on the machine. The provider is `ring`, so the build needs no
//! CMake, unlike the default `aws-lc-rs`. rustls checks server names as usual.
//! For an address host such as `https://1.1.1.1/dns-query`, rustls checks
//! the address against the IP addresses of the certificate.

use std::sync::{Arc, OnceLock};

use hyper_rustls::ConfigBuilderExt as _;
use rustls::ClientConfig;

/// Returns the TLS config shared by every connection of the process.
///
/// Building the config parses the roots, so netf builds it once.
pub(crate) fn config() -> Arc<ClientConfig> {
    static CONFIG: OnceLock<Arc<ClientConfig>> = OnceLock::new();
    Arc::clone(CONFIG.get_or_init(|| {
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let config = ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            // ring supports both default versions, TLS 1.2 and 1.3. The
            // call fails only if the build lost one of them.
            .expect("the ring provider supports TLS 1.2 and 1.3")
            .with_webpki_roots()
            .with_no_client_auth();
        let mut config = config;
        // netf builds hyper with HTTP/1.1 only, without HTTP/2.
        config.alpn_protocols = vec![b"http/1.1".to_vec()];
        Arc::new(config)
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn one_config_per_process() {
        let first = config();
        let second = config();
        assert!(Arc::ptr_eq(&first, &second));
        // The provider is ring, with its cipher suites.
        let suites = |provider: &rustls::crypto::CryptoProvider| {
            let suites = provider.cipher_suites.iter();
            suites.map(|suite| suite.suite()).collect::<Vec<_>>()
        };
        let ring = rustls::crypto::ring::default_provider();
        assert_eq!(suites(first.crypto_provider()), suites(&ring));
    }
}
