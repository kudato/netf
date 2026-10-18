//! Resolving `domain:` selectors.
//!
//! The engine sees only the [`Resolver`] trait. Without a proxy, netf uses
//! the resolver of the system through `tokio::net::lookup_host`. With a
//! proxy, DNS goes over HTTPS through the same pool of egresses (`doh`), so
//! no lookup leaves from the real address. [`select`] makes the choice.
//! Without a proxy, it ignores the `doh` setting and prints nothing.
//!
//! The engine resolves each domain once per run. netf never caches the
//! answers on disk.
//!
//! [`punycode::to_ascii`] converts a name before it reaches a resolver. The
//! converted name is lowercase, and each non-ASCII label is in the `xn--`
//! form.

pub(crate) mod doh;
pub(crate) mod punycode;
pub(crate) mod wire;

use std::{
    fmt,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    sync::Arc,
};

pub(crate) use doh::DohResolver;

use crate::{
    addr::Families,
    transport::{BoxFuture, Transport},
};

/// Chooses the resolver of a run.
///
/// Without a proxy, the resolver is the system's. With a proxy, it is DNS
/// over HTTPS to `doh` through `transport`, and so through the proxies.
pub(crate) fn select(
    proxied: bool,
    doh: &str,
    transport: &Arc<dyn Transport>,
) -> Arc<dyn Resolver> {
    if proxied {
        Arc::new(DohResolver::new(Arc::clone(transport), doh))
    } else {
        Arc::new(SystemResolver)
    }
}

/// The resolver of the operating system, through `getaddrinfo` on tokio's
/// blocking pool.
///
/// The resolver asks for both families at once and filters the answer.
/// Every failure is [`DnsError::NotFound`], because `getaddrinfo` has no
/// portable way to tell NXDOMAIN from a dead server.
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct SystemResolver;

impl Resolver for SystemResolver {
    fn resolve<'a>(
        &'a self,
        name: &'a str,
        want: Families,
    ) -> BoxFuture<'a, Result<Resolved, DnsError>> {
        Box::pin(async move {
            let addresses = tokio::net::lookup_host((name, 0))
                .await
                .map_err(|_| DnsError::NotFound)?;
            let mut resolved = Resolved::default();
            for address in addresses {
                match address.ip() {
                    IpAddr::V4(v4) if want.v4() && !resolved.v4.contains(&v4) => {
                        resolved.v4.push(v4);
                    }
                    IpAddr::V6(v6) if want.v6() && !resolved.v6.contains(&v6) => {
                        resolved.v6.push(v6);
                    }
                    _ => {}
                }
            }
            Ok(resolved)
        })
    }
}

/// Resolves domain names to addresses.
///
/// `name` is already in punycode and lowercase. A resolver may leave out
/// the addresses of families that are not in `want`, because the engine
/// filters those addresses anyway.
pub trait Resolver: Send + Sync {
    /// Looks up the addresses of `name`.
    fn resolve<'a>(
        &'a self,
        name: &'a str,
        want: Families,
    ) -> BoxFuture<'a, Result<Resolved, DnsError>>;
}

/// The addresses of a domain.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Resolved {
    /// The addresses from A records.
    pub v4: Vec<Ipv4Addr>,
    /// The addresses from AAAA records.
    pub v6: Vec<Ipv6Addr>,
}

/// A failed lookup.
///
/// Both variants are runtime errors, exit code 1.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DnsError {
    /// The name does not exist: NXDOMAIN. The system resolver reports
    /// every failure this way, because `getaddrinfo` has no portable way to
    /// tell failures apart.
    NotFound,
    /// SERVFAIL, a timeout, or an error of the OS or the DoH server.
    Failed(String),
}

/// The text after `domain <name>: `.
impl fmt::Display for DnsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotFound => f.write_str("not found (NXDOMAIN)"),
            Self::Failed(reason) => write!(f, "DNS failed: {reason}"),
        }
    }
}

impl std::error::Error for DnsError {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transport::{Request, Response, TransportError};

    /// A transport that must not be used.
    struct Unreachable;

    impl Transport for Unreachable {
        fn send(&self, request: Request) -> BoxFuture<'_, Result<Response, TransportError>> {
            panic!("unexpected request to {}", request.url)
        }
    }

    // tokio answers address literals without `getaddrinfo`, so these tests
    // send nothing to any DNS server.
    #[tokio::test(flavor = "current_thread")]
    async fn system_resolver_without_proxy() {
        let transport: Arc<dyn Transport> = Arc::new(Unreachable);
        let resolver = select(false, "https://doh.test/dns-query", &transport);
        let resolved = resolver.resolve("127.0.0.1", Families::BOTH).await.unwrap();
        assert_eq!(resolved.v4, vec![Ipv4Addr::LOCALHOST]);
        let resolved = resolver.resolve("::1", Families::V4).await.unwrap();
        assert_eq!(resolved, Resolved::default());
        let resolved = resolver.resolve("::1", Families::V6).await.unwrap();
        assert_eq!(resolved.v6, vec![Ipv6Addr::LOCALHOST]);
    }

    #[test]
    #[should_panic(expected = "unexpected request to https://doh.test/dns-query")]
    fn doh_with_proxy() {
        let transport: Arc<dyn Transport> = Arc::new(Unreachable);
        let resolver = select(true, "https://doh.test/dns-query", &transport);
        let runtime = tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap();
        let _ = runtime.block_on(resolver.resolve("host.example", Families::V4));
    }

    #[test]
    fn error_texts() {
        assert_eq!(DnsError::NotFound.to_string(), "not found (NXDOMAIN)");
        assert_eq!(
            DnsError::Failed("SERVFAIL".into()).to_string(),
            "DNS failed: SERVFAIL"
        );
    }
}
