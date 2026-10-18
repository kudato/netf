//! DNS over HTTPS, as RFC 8484 defines it: `POST <doh>` with
//! `application/dns-message`.
//!
//! The query goes through the [`Transport`] with [`Class::Doh`], so DoH
//! requests use the proxy pool. The resolver does not follow redirects.
//!
//! With `-4 -6`, the resolver sends the A and AAAA questions at once, as two
//! requests. NXDOMAIN from either question is [`DnsError::NotFound`]. Any
//! other failure is [`DnsError::Failed`] with the reason: a transport error,
//! a status other than 200, an RCODE other than 0 or 3, or a malformed
//! reply.
//!
//! [`Transport`]: crate::transport::Transport
//! [`Class::Doh`]: crate::transport::Class::Doh

use std::sync::Arc;

use super::{
    DnsError, Resolved, Resolver,
    wire::{self, QType, Reply},
};
use crate::{
    addr::Families,
    transport::{BoxFuture, Class, Request, Transport},
};

/// The media type of DNS messages, from RFC 8484, section 6.
const DNS_MESSAGE: &str = "application/dns-message";

/// The largest DNS message. The length field of DNS over TCP is 16 bits.
const MAX_MESSAGE: usize = 65_535;

/// Resolves names with DNS over HTTPS through a [`Transport`].
pub(crate) struct DohResolver {
    transport: Arc<dyn Transport>,
    url: String,
}

impl DohResolver {
    /// Creates a resolver that posts queries to `url`.
    pub(crate) fn new(transport: Arc<dyn Transport>, url: impl Into<String>) -> Self {
        Self {
            transport,
            url: url.into(),
        }
    }

    /// Asks one question and returns the reply.
    async fn ask(&self, name: &str, qtype: QType) -> Result<Reply, DnsError> {
        let id = wire::random_id();
        let message = wire::query(id, name, qtype).map_err(failed)?;
        let request =
            Request::post(&self.url, Class::Doh, message).with_header("Content-Type", DNS_MESSAGE);
        let response = self.transport.send(request).await.map_err(failed)?;
        if response.status != 200 {
            return Err(DnsError::Failed(format!("HTTP {}", response.status)));
        }
        let body = response.body.collect(MAX_MESSAGE).await.map_err(failed)?;
        wire::parse(&body, id, name, qtype).map_err(failed)
    }
}

/// Turns any error into [`DnsError::Failed`] with its text.
fn failed(error: impl std::fmt::Display) -> DnsError {
    DnsError::Failed(error.to_string())
}

/// Reduces the reply to one question to its addresses.
fn addresses(reply: Option<Result<Reply, DnsError>>) -> Result<Resolved, DnsError> {
    match reply {
        None => Ok(Resolved::default()),
        Some(Ok(Reply::Addresses { v4, v6 })) => Ok(Resolved { v4, v6 }),
        Some(Ok(Reply::NxDomain)) => Err(DnsError::NotFound),
        Some(Ok(Reply::Error(rcode))) => Err(DnsError::Failed(wire::rcode_name(rcode))),
        Some(Err(error)) => Err(error),
    }
}

impl Resolver for DohResolver {
    fn resolve<'a>(
        &'a self,
        name: &'a str,
        want: Families,
    ) -> BoxFuture<'a, Result<Resolved, DnsError>> {
        Box::pin(async move {
            let v4 = async {
                if want.v4() {
                    Some(self.ask(name, QType::A).await)
                } else {
                    None
                }
            };
            let v6 = async {
                if want.v6() {
                    Some(self.ask(name, QType::Aaaa).await)
                } else {
                    None
                }
            };
            let (v4, v6) = tokio::join!(v4, v6);
            let (v4, v6) = (addresses(v4), addresses(v6));
            // NXDOMAIN is about the name, so it wins over a failure of the
            // other question.
            match (v4, v6) {
                (Err(DnsError::NotFound), _) | (_, Err(DnsError::NotFound)) => {
                    Err(DnsError::NotFound)
                }
                (Err(error), _) | (_, Err(error)) => Err(error),
                (Ok(v4), Ok(v6)) => Ok(Resolved {
                    v4: v4.v4,
                    v6: v6.v6,
                }),
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use std::{
        net::{Ipv4Addr, Ipv6Addr},
        sync::Mutex,
    };

    use super::*;
    use crate::{
        dns::wire::tests::reply,
        transport::{BodyStream, EgressId, Method, Response, TransportError},
    };

    /// How the fake server answers a query.
    type Answer = fn(&[u8]) -> Result<(u16, Vec<u8>), TransportError>;

    /// A transport that answers DoH queries with a function of the query
    /// and keeps the requests. Nothing leaves the process.
    struct FakeDoh {
        answer: Answer,
        requests: Mutex<Vec<Request>>,
    }

    impl FakeDoh {
        fn new(answer: Answer) -> Arc<Self> {
            Arc::new(Self {
                answer,
                requests: Mutex::new(Vec::new()),
            })
        }

        fn requests(&self) -> Vec<Request> {
            self.requests.lock().unwrap().clone()
        }
    }

    impl Transport for FakeDoh {
        fn send(&self, request: Request) -> BoxFuture<'_, Result<Response, TransportError>> {
            Box::pin(async move {
                let query = request.body.clone().expect("a DoH query has a body");
                self.requests.lock().unwrap().push(request);
                let (status, body) = (self.answer)(&query)?;
                Ok(Response {
                    status,
                    headers: vec![("Content-Type".into(), DNS_MESSAGE.into())],
                    body: BodyStream::from_bytes(body),
                    egress: EgressId::direct(),
                })
            })
        }
    }

    /// The type asked by a query: the two octets before the class.
    fn qtype(query: &[u8]) -> u16 {
        u16::from_be_bytes([query[query.len() - 4], query[query.len() - 3]])
    }

    /// Answers 192.0.2.1 to A and 2001:db8::1 to AAAA.
    fn both(query: &[u8]) -> Result<(u16, Vec<u8>), TransportError> {
        let v6: Ipv6Addr = "2001:db8::1".parse().unwrap();
        let message = match qtype(query) {
            1 => reply(query, 0, &[(None, 1, &[192, 0, 2, 1])]),
            _ => reply(query, 0, &[(None, 28, &v6.octets())]),
        };
        Ok((200, message))
    }

    fn resolver(transport: &Arc<FakeDoh>) -> DohResolver {
        DohResolver::new(
            Arc::clone(transport) as Arc<dyn Transport>,
            "https://doh.test/dns-query",
        )
    }

    #[tokio::test(flavor = "current_thread")]
    async fn posts_a_dns_message() {
        let transport = FakeDoh::new(both);
        let resolved = resolver(&transport)
            .resolve("ex.test", Families::V4)
            .await
            .unwrap();
        assert_eq!(resolved.v4, vec![Ipv4Addr::new(192, 0, 2, 1)]);
        assert!(resolved.v6.is_empty());

        let requests = transport.requests();
        assert_eq!(requests.len(), 1);
        let request = &requests[0];
        assert_eq!(request.method, Method::Post);
        assert_eq!(request.url, "https://doh.test/dns-query");
        assert_eq!(request.class, Class::Doh);
        assert_eq!(request.header("content-type"), Some(DNS_MESSAGE));
        let body = request.body.as_ref().unwrap();
        assert_eq!(qtype(body), 1);
        // RD is set.
        assert_eq!(body[2] & 0x01, 0x01);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn both_families_are_asked() {
        let transport = FakeDoh::new(both);
        let resolved = resolver(&transport)
            .resolve("ex.test", Families::BOTH)
            .await
            .unwrap();
        assert_eq!(resolved.v4, vec![Ipv4Addr::new(192, 0, 2, 1)]);
        assert_eq!(
            resolved.v6,
            vec!["2001:db8::1".parse::<Ipv6Addr>().unwrap()]
        );
        let mut types: Vec<u16> = transport
            .requests()
            .iter()
            .map(|r| qtype(r.body.as_ref().unwrap()))
            .collect();
        types.sort_unstable();
        assert_eq!(types, [1, 28]);

        let resolved = resolver(&transport)
            .resolve("ex.test", Families::V6)
            .await
            .unwrap();
        assert!(resolved.v4.is_empty());
        assert_eq!(resolved.v6.len(), 1);
        assert_eq!(transport.requests().len(), 3);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn nxdomain_is_not_found() {
        let transport = FakeDoh::new(|query| Ok((200, reply(query, 3, &[]))));
        let error = resolver(&transport)
            .resolve("nx.example.test", Families::BOTH)
            .await
            .unwrap_err();
        assert_eq!(error, DnsError::NotFound);
        assert_eq!(error.to_string(), "not found (NXDOMAIN)");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn servfail_fails() {
        let transport = FakeDoh::new(|query| Ok((200, reply(query, 2, &[]))));
        let error = resolver(&transport)
            .resolve("ex.test", Families::V4)
            .await
            .unwrap_err();
        assert_eq!(error.to_string(), "DNS failed: SERVFAIL");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn http_and_transport_errors_fail() {
        let transport = FakeDoh::new(|_| Ok((403, Vec::new())));
        let error = resolver(&transport)
            .resolve("ex.test", Families::V4)
            .await
            .unwrap_err();
        assert_eq!(error.to_string(), "DNS failed: HTTP 403");

        let transport = FakeDoh::new(|_| Err(TransportError::Proxy("connection refused".into())));
        let error = resolver(&transport)
            .resolve("ex.test", Families::V4)
            .await
            .unwrap_err();
        assert_eq!(error.to_string(), "DNS failed: proxy: connection refused");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn foreign_answers_fail() {
        // The server answers with another id.
        let transport = FakeDoh::new(|query| {
            let mut message = reply(query, 0, &[]);
            message[0] ^= 0xFF;
            Ok((200, message))
        });
        let error = resolver(&transport)
            .resolve("ex.test", Families::V4)
            .await
            .unwrap_err();
        assert_eq!(error.to_string(), "DNS failed: answer to another query");

        let transport = FakeDoh::new(|_| Ok((200, vec![0; 5])));
        assert!(matches!(
            resolver(&transport).resolve("ex.test", Families::V4).await,
            Err(DnsError::Failed(_))
        ));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn invalid_names_fail_without_a_request() {
        let transport = FakeDoh::new(both);
        let error = resolver(&transport)
            .resolve("ex..test", Families::V4)
            .await
            .unwrap_err();
        assert_eq!(error.to_string(), "DNS failed: invalid domain name");
        assert!(transport.requests().is_empty());
    }
}
