//! The boundary between netf and the network: the [`Transport`] trait.
//!
//! Every network request goes through one [`Transport::send`] call: dataset
//! downloads, RDAP, the RIPE REST API, and DNS over HTTPS. A request that
//! must leave through a known egress goes through [`Transport::send_via`]
//! instead. The real
//! implementation is `http::HttpTransport`, built on hyper 1 and rustls.
//! Tests replace it with a scripted fake that knows every URL that a test
//! may request and panics on any other, so no test can reach the internet
//! by accident.
//!
//! # What a transport does and does not do
//!
//! A transport sends one request and applies the network policy around it:
//!
//! - the egress pool, with round robin over the proxies
//! - the `concurrency` semaphore per egress and host
//! - the pause after a 429
//! - the retries after a 5xx or a network error
//!
//! A transport does not follow redirects, send conditional headers, or
//! decompress bodies. The `fetch` module, one layer up, does these three
//! things, so the same logic works over any transport.
//!
//! A status other than 2xx is not an error at this level. The transport
//! returns 304, 404, and 3xx as a [`Response`], because their meaning
//! depends on the caller: for RDAP, a 404 means "no record".
//! [`TransportError::Status`] is reserved for a status that the transport
//! gave up on, such as a 5xx after the retries.
//!
//! # Bodies
//!
//! A response body is a [`BodyStream`] of chunks, read as they arrive, so
//! netf never holds a 50 MB dump in memory at once. The semaphore permit of
//! the request lives inside the stream, so a slow download keeps its slot
//! until the reader reads the body to the end or drops it.
//!
//! # Why `Send`
//!
//! netf runs on a current-thread runtime, but the futures and streams are
//! still `Send`. `hyper_util::client::legacy::Client` requires it, and the
//! bound costs nothing. A trait with an `async fn` is not dyn-compatible, so
//! [`Transport::send`] returns a boxed [`BoxFuture`] instead.

use std::{
    fmt,
    future::Future,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
    time::Duration,
};

use bytes::{Bytes, BytesMut};
use futures_util::{Stream, StreamExt as _, stream};

/// A boxed future that is `Send`, as returned by [`Transport::send`] and
/// [`Resolver::resolve`](crate::Resolver::resolve).
///
/// The same type as `futures_util::future::BoxFuture`, written out so that
/// implementers outside the crate need no extra dependency.
pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// Sends requests to the network.
///
/// An implementation sends one request per call and applies the network
/// policy around it: the egress pool, the concurrency limits, the pause
/// after a 429, and the retries. Redirects, conditional headers, and
/// decompression belong to the layer above. An implementation must be
/// shareable between the concurrent requests of one run.
pub trait Transport: Send + Sync {
    /// Sends one request and returns the response once its headers arrive.
    ///
    /// The network policy applies: the pool, the semaphores, the pauses after
    /// a 429, and the retries after a 5xx. The transport does not follow
    /// redirects.
    ///
    /// # Errors
    ///
    /// Returns a [`TransportError`] if the connection or the proxy fails, a
    /// timeout expires, the retries after a 5xx run out, or the server asks
    /// for too long a pause.
    fn send(&self, request: Request) -> BoxFuture<'_, Result<Response, TransportError>>;

    /// Returns the egresses that requests go out through, in pool order.
    ///
    /// The list is either `direct` or one egress per proxy. The default
    /// implementation returns only the direct egress.
    fn egresses(&self) -> Vec<EgressId> {
        vec![EgressId::direct()]
    }

    /// Sends one request through `egress` only.
    ///
    /// RIPE counts its limit on personal data per IP address, so a
    /// request that spends the limit must use a known egress. The transport
    /// retries a 5xx or a network error on the same egress. It returns a 429
    /// as a [`Response`] at once instead of waiting: from RIPE, a 429 means
    /// that the limit of this egress is spent for the day.
    ///
    /// The default implementation, which calls [`send`](Self::send), suits a
    /// transport with one egress and no pauses of its own.
    ///
    /// # Errors
    ///
    /// Returns the same errors as [`send`](Self::send).
    fn send_via(
        &self,
        request: Request,
        egress: EgressId,
    ) -> BoxFuture<'_, Result<Response, TransportError>> {
        let _ = egress;
        self.send(request)
    }
}

/// The HTTP method of a [`Request`].
///
/// netf only reads. Only DNS over HTTPS sends a request body.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum Method {
    /// `GET`: datasets, RDAP, the RIPE REST API.
    Get,
    /// `POST`: DNS over HTTPS (RFC 8484).
    Post,
}

impl fmt::Display for Method {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Get => "GET",
            Self::Post => "POST",
        })
    }
}

/// What a request is for.
///
/// The class names the request in messages, such as `netf: rdap: lacnic:
/// rate limited, waiting 60s`. It also selects the `Accept` header.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub enum Class {
    /// A dataset download, named by its cache file: `ris-v4`, `asn`,
    /// `stats-arin`, `whois-apnic-inetnum`, `bootstrap-asn`.
    Dataset(&'static str),
    /// An RDAP request, named by the registry of the server: `ripencc`,
    /// `arin`, `apnic`, `lacnic`, or `afrinic`. A server that is not one of
    /// these five is named by its host.
    Rdap(Arc<str>),
    /// The RIPE database REST API.
    RipeRest,
    /// DNS over HTTPS.
    Doh,
}

impl Class {
    /// Returns the `Accept` header for requests of this class.
    pub fn accept(&self) -> &'static str {
        match self {
            Self::Dataset(_) => "*/*",
            Self::Rdap(_) => "application/rdap+json",
            Self::RipeRest => "application/json",
            Self::Doh => "application/dns-message",
        }
    }
}

/// Prints the name used in messages: `ris-v4`, `rdap: lacnic`, `ripe`,
/// `doh`.
impl fmt::Display for Class {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Dataset(name) => f.write_str(name),
            Self::Rdap(rir) => write!(f, "rdap: {rir}"),
            Self::RipeRest => f.write_str("ripe"),
            Self::Doh => f.write_str("doh"),
        }
    }
}

/// One HTTP request.
///
/// The transport adds the `User-Agent` header and the `Accept` header from
/// [`Class::accept`].
/// `headers` holds only the headers that the caller chooses, such as
/// `If-None-Match` or `Content-Type`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Request {
    /// The HTTP method.
    pub method: Method,
    /// The absolute URL, `http` or `https`.
    pub url: String,
    /// Extra headers, in order.
    pub headers: Vec<(&'static str, String)>,
    /// The body, for [`Method::Post`].
    pub body: Option<Bytes>,
    /// What the request is for.
    pub class: Class,
}

impl Request {
    /// Creates a `GET` request without extra headers.
    pub fn get(url: impl Into<String>, class: Class) -> Self {
        Self {
            method: Method::Get,
            url: url.into(),
            headers: Vec::new(),
            body: None,
            class,
        }
    }

    /// Creates a `POST` request with a body.
    pub fn post(url: impl Into<String>, class: Class, body: impl Into<Bytes>) -> Self {
        Self {
            method: Method::Post,
            url: url.into(),
            headers: Vec::new(),
            body: Some(body.into()),
            class,
        }
    }

    /// Adds a header and returns the request.
    #[must_use]
    pub fn with_header(mut self, name: &'static str, value: impl Into<String>) -> Self {
        self.headers.push((name, value.into()));
        self
    }

    /// Returns the first value of a header. The name comparison ignores
    /// ASCII case.
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(key, _)| key.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_str())
    }
}

/// The response to a [`Request`]: status and headers, with the body still to
/// be read.
#[derive(Debug)]
pub struct Response {
    /// The HTTP status. 304, 404, and 3xx are responses, not errors, because
    /// their meaning depends on the caller.
    pub status: u16,
    /// The headers, in the order and with the names that the server sent.
    pub headers: Vec<(String, String)>,
    /// The body, streamed.
    pub body: BodyStream,
    /// The egress that the request went through. netf counts the RIPE limit
    /// per egress.
    pub egress: EgressId,
}

impl Response {
    /// Returns the first value of a header. The name comparison ignores
    /// ASCII case.
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(key, _)| key.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_str())
    }
}

/// The body of a [`Response`]: a stream of chunks of any size.
///
/// Chunk boundaries carry no meaning. A reader must accept a line or a gzip
/// member that is split at any byte. Dropping the stream abandons the rest
/// of the body and closes the connection.
pub struct BodyStream(Pin<Box<dyn Stream<Item = Result<Bytes, TransportError>> + Send>>);

impl BodyStream {
    /// Wraps a stream of chunks.
    pub fn new<S>(stream: S) -> Self
    where
        S: Stream<Item = Result<Bytes, TransportError>> + Send + 'static,
    {
        Self(Box::pin(stream))
    }

    /// Returns an empty body.
    pub fn empty() -> Self {
        Self::new(stream::empty())
    }

    /// Returns a body of one chunk.
    pub fn from_bytes(bytes: impl Into<Bytes>) -> Self {
        Self::from_chunks(vec![bytes.into()])
    }

    /// Returns a body of the given chunks, in order.
    pub fn from_chunks(chunks: Vec<Bytes>) -> Self {
        Self::new(stream::iter(chunks.into_iter().map(Ok)))
    }

    /// Returns the next chunk, or `None` at the end of the body.
    ///
    /// # Errors
    ///
    /// Returns `Some` of a [`TransportError`] if reading the body fails or
    /// times out.
    pub async fn next_chunk(&mut self) -> Option<Result<Bytes, TransportError>> {
        self.0.next().await
    }

    /// Reads the whole body into memory.
    ///
    /// netf uses it only for small responses: RDAP and REST JSON, and DNS
    /// messages. Datasets are read line by line instead.
    ///
    /// # Errors
    ///
    /// Returns [`TransportError::TooLarge`] as soon as the body exceeds
    /// `limit` bytes, or the error of the stream if a chunk fails.
    pub async fn collect(mut self, limit: usize) -> Result<Bytes, TransportError> {
        let mut buffer = BytesMut::new();
        while let Some(chunk) = self.next_chunk().await {
            let chunk = chunk?;
            if buffer.len() + chunk.len() > limit {
                return Err(TransportError::TooLarge);
            }
            buffer.extend_from_slice(&chunk);
        }
        Ok(buffer.freeze())
    }
}

impl Stream for BodyStream {
    type Item = Result<Bytes, TransportError>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        self.0.as_mut().poll_next(cx)
    }
}

impl fmt::Debug for BodyStream {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("BodyStream { .. }")
    }
}

/// The egress that a request went out through: `direct`, or the URL of a
/// proxy from `--proxy`.
///
/// For the registries, each proxy is a separate IP address, so netf keeps
/// the pauses after a 429 and the RIPE limit per egress.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct EgressId(pub Arc<str>);

impl EgressId {
    /// Returns the egress without a proxy, which uses the machine's own
    /// address.
    pub fn direct() -> Self {
        Self(Arc::from("direct"))
    }
}

impl fmt::Display for EgressId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// A failure of the transport after its own retries.
///
/// [`Display`](fmt::Display) prints the cause without context, such as
/// `connection refused` or `HTTP 503`. The caller adds what it was
/// fetching.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TransportError {
    /// The transport could not connect. The text is the cause, such as
    /// `connection refused`.
    Connect(String),
    /// A timeout. The text names what the transport waited for: `connect`,
    /// `response headers`, or `response body`.
    Timeout(&'static str),
    /// Reading from or writing to the connection failed. This error also
    /// covers a body that ends too early.
    Io(String),
    /// The server kept responding with this status, a 5xx, after the
    /// retries.
    Status(u16),
    /// The server asked for a pause longer than an hour, or sent the sixth
    /// 429 in a row. The duration is the last pause that it asked for.
    RateLimited(Duration),
    /// The proxy refused or failed the `CONNECT`. The text is the cause.
    Proxy(String),
    /// The body is larger than the caller's limit.
    TooLarge,
}

impl fmt::Display for TransportError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Connect(cause) | Self::Io(cause) => f.write_str(cause),
            Self::Timeout(what) => write!(f, "timed out waiting for {what}"),
            Self::Status(status) => write!(f, "HTTP {status}"),
            Self::RateLimited(wait) => write!(
                f,
                "rate limited for {}, giving up",
                crate::report::duration(*wait)
            ),
            Self::Proxy(cause) => write!(f, "proxy: {cause}"),
            Self::TooLarge => f.write_str("response too large"),
        }
    }
}

impl std::error::Error for TransportError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn class_names() {
        assert_eq!(Class::Dataset("ris-v4").to_string(), "ris-v4");
        assert_eq!(Class::Rdap(Arc::from("lacnic")).to_string(), "rdap: lacnic");
        assert_eq!(Class::RipeRest.to_string(), "ripe");
        assert_eq!(Class::Doh.accept(), "application/dns-message");
    }

    #[test]
    fn error_texts() {
        assert_eq!(TransportError::Status(503).to_string(), "HTTP 503");
        assert_eq!(
            TransportError::RateLimited(Duration::from_secs(7200)).to_string(),
            "rate limited for 2h, giving up"
        );
        assert_eq!(
            TransportError::Connect("connection refused".into()).to_string(),
            "connection refused"
        );
    }

    #[test]
    fn headers_ignore_case() {
        let request = Request::get("https://example.test/", Class::RipeRest)
            .with_header("If-None-Match", "\"abc\"");
        assert_eq!(request.header("if-none-match"), Some("\"abc\""));
        assert_eq!(request.header("etag"), None);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn collect_respects_the_limit() {
        let body = BodyStream::from_chunks(vec![Bytes::from("ab"), Bytes::from("cd")]);
        assert_eq!(body.collect(4).await.unwrap(), Bytes::from("abcd"));
        let body = BodyStream::from_chunks(vec![Bytes::from("ab"), Bytes::from("cd")]);
        assert_eq!(body.collect(3).await, Err(TransportError::TooLarge));
    }
}
