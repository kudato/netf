//! The real network: `HttpTransport` on hyper 1.
//!
//! `HttpTransport` is the only implementation of [`Transport`] in the
//! binary. Only `lib.rs` names it, so the rest of the crate can be tested
//! without it. `HttpTransport` owns the pool of egresses (direct or
//! proxies), the concurrency limits per server and egress, TLS, and the
//! retry policy for a 429, a 5xx, and a network error.
//!
//! # One request
//!
//! 1. [`egress::Pool::pick`] picks an egress in round robin and skips the
//!    egresses on which the host is paused after a 429.
//! 2. The request takes a slot of the `(egress, host)` semaphore and holds
//!    the slot until the reader reads the body to the end or drops it.
//! 3. The request goes out with `User-Agent: netf/<version>` and the
//!    `Accept` of its class. The headers must arrive within 30 s.
//! 4. A 429 pauses the pair, and the request goes out again on the same
//!    egress after the pause. A 5xx is retried on the same egress, and a
//!    network error is retried on the next egress, after 1 s and then 4 s
//!    ([`retry`]).
//!    Any other status is the response, including 3xx, 4xx, and 501. A 501
//!    says that the server never handles this request, so a retry cannot
//!    help.
//!
//! # Bodies
//!
//! The body is streamed, and more than 60 s without a chunk is a timeout. A
//! body cut short by a reset or a timeout is a network error too. If the
//! response to a `GET` was a `200` with a validator (`ETag` or
//! `Last-Modified`), the transport sends the request again, up to the same
//! two times. If the new response has the same validators and the same
//! `Content-Length`, the file did not change in between, and the transport
//! skips the bytes that it already delivered. Otherwise, or without
//! validators, the error reaches the reader. netf does not send `Range`,
//! because not all the sources support it and a resend costs only time.
//!
//! [`Transport`]: crate::transport::Transport

pub(crate) mod connect;
pub(crate) mod egress;
pub(crate) mod retry;
pub(crate) mod tls;

use std::{
    error::Error as StdError,
    sync::Arc,
    time::{Duration, SystemTime},
};

use bytes::{Buf as _, Bytes};
use futures_util::stream;
use http::{
    HeaderMap, Uri,
    header::{ACCEPT, CONTENT_LENGTH, ETAG, LAST_MODIFIED, RETRY_AFTER, USER_AGENT},
};
use http_body_util::{BodyExt as _, Full};
use hyper::body::Incoming;
use tokio::sync::OwnedSemaphorePermit;

pub use self::connect::ProxyError;
use self::{
    egress::Pool,
    retry::{Attempts, RETRY_PAUSES},
};
use crate::{
    report::{Notice, Reporter},
    transport::{
        BodyStream, BoxFuture, EgressId, Method, Request, Response, Transport, TransportError,
    },
};

/// The `User-Agent` of every request.
const USER_AGENT_VALUE: &str = concat!("netf/", env!("CARGO_PKG_VERSION"));

/// The settings of [`HttpTransport`].
///
/// [`Default`] gives the values that netf runs with. Tests shorten the
/// timeouts and pauses instead of waiting for them.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HttpOptions {
    /// The `--proxy` URLs, `http://[user:pass@]host:port`. Empty means
    /// direct.
    pub proxies: Vec<String>,
    /// The concurrent requests per server and egress: `--concurrency`, 8 by
    /// default.
    pub concurrency: usize,
    /// The time to establish the TCP connection: 10 s.
    pub connect_timeout: Duration,
    /// The time from sending the request to the response headers: 30 s. It
    /// includes the connection, the `CONNECT`, and TLS.
    pub response_timeout: Duration,
    /// The longest silence between chunks of a body: 60 s.
    pub body_timeout: Duration,
    /// The pause before each retry after a 5xx or a network error: 1 s and
    /// 4 s. The number of pauses is the number of retries.
    pub retry_pauses: Vec<Duration>,
}

impl Default for HttpOptions {
    fn default() -> Self {
        Self {
            proxies: Vec::new(),
            concurrency: 8,
            connect_timeout: Duration::from_secs(10),
            response_timeout: Duration::from_secs(30),
            body_timeout: Duration::from_secs(60),
            retry_pauses: RETRY_PAUSES.to_vec(),
        }
    }
}

/// The [`Transport`] of the binary: hyper 1 with rustls, the egress pool,
/// and the retry policy.
///
/// The transport runs inside a tokio runtime with time and I/O enabled.
/// Notices about pauses after a 429 go to the reporter passed to
/// [`HttpTransport::new`].
pub struct HttpTransport {
    inner: Arc<Inner>,
}

impl HttpTransport {
    /// Creates the transport.
    ///
    /// # Errors
    ///
    /// Returns a [`ProxyError`] if netf cannot use a proxy URL. The error
    /// converts to a usage error, with exit code 2.
    pub fn new(options: HttpOptions, reporter: Arc<dyn Reporter>) -> Result<Self, ProxyError> {
        let proxies = options
            .proxies
            .iter()
            .map(|url| connect::parse_proxy(url))
            .collect::<Result<Vec<_>, _>>()?;
        let pool = Pool::new(&proxies, options.concurrency, options.connect_timeout);
        Ok(Self {
            inner: Arc::new(Inner {
                pool,
                reporter,
                response_timeout: options.response_timeout,
                body_timeout: options.body_timeout,
                retry_pauses: options.retry_pauses,
            }),
        })
    }

    /// Returns the egresses in pool order: `direct`, or each proxy as
    /// `http://host:port` without credentials.
    pub fn egresses(&self) -> Vec<EgressId> {
        self.inner.pool.ids()
    }
}

impl Transport for HttpTransport {
    fn send(&self, request: Request) -> BoxFuture<'_, Result<Response, TransportError>> {
        Box::pin(Arc::clone(&self.inner).send(request, None))
    }

    fn egresses(&self) -> Vec<EgressId> {
        self.inner.pool.ids()
    }

    fn send_via(
        &self,
        request: Request,
        egress: EgressId,
    ) -> BoxFuture<'_, Result<Response, TransportError>> {
        let inner = Arc::clone(&self.inner);
        Box::pin(async move {
            let index = inner
                .pool
                .ids()
                .iter()
                .position(|id| *id == egress)
                .ok_or_else(|| TransportError::Connect(format!("no egress {}", egress.0)))?;
            inner.send(request, Some(index)).await
        })
    }
}

impl From<ProxyError> for crate::error::Error {
    fn from(error: ProxyError) -> Self {
        Self::usage(error.to_string())
    }
}

/// What the transport and its body streams share.
struct Inner {
    pool: Pool,
    reporter: Arc<dyn Reporter>,
    response_timeout: Duration,
    body_timeout: Duration,
    retry_pauses: Vec<Duration>,
}

/// A response whose headers have arrived, with the slot it holds.
struct Exchange {
    response: http::Response<Incoming>,
    permit: OwnedSemaphorePermit,
    egress: usize,
}

/// The validators of a response. A resumed download must get the same
/// validators.
#[derive(Clone, Debug, Eq, PartialEq)]
struct Validators {
    etag: Option<String>,
    last_modified: Option<String>,
    length: Option<String>,
}

impl Validators {
    fn of(headers: &HeaderMap) -> Self {
        let get = |name| {
            headers.get(name).map(|value: &http::HeaderValue| {
                String::from_utf8_lossy(value.as_bytes()).into_owned()
            })
        };
        Self {
            etag: get(ETAG),
            last_modified: get(LAST_MODIFIED),
            length: get(CONTENT_LENGTH),
        }
    }

    /// Returns whether a resent response can be recognized as the same file.
    fn identify(&self) -> bool {
        self.etag.is_some() || self.last_modified.is_some()
    }
}

impl Inner {
    /// Sends `request` with the whole policy and wraps the response.
    ///
    /// With `pin`, the request goes only through that egress, and a 429 is
    /// returned as the response.
    async fn send(
        self: Arc<Self>,
        request: Request,
        pin: Option<usize>,
    ) -> Result<Response, TransportError> {
        let exchange = self.exchange(&request, pin).await?;
        let (parts, body) = exchange.response.into_parts();
        let headers = parts
            .headers
            .iter()
            .map(|(name, value)| {
                (
                    name.as_str().to_owned(),
                    String::from_utf8_lossy(value.as_bytes()).into_owned(),
                )
            })
            .collect();
        let validators = Validators::of(&parts.headers);
        let resume = (request.method == Method::Get
            && parts.status == http::StatusCode::OK
            && validators.identify())
        .then(|| Resume {
            request,
            pin,
            validators,
            used: 0,
        });
        let egress = self.pool.get(exchange.egress).id().clone();
        let state = BodyState {
            inner: self,
            resume,
            body: Some(body),
            permit: Some(exchange.permit),
            delivered: 0,
            skip: 0,
        };
        let body = BodyStream::new(stream::unfold(state, |mut state| async move {
            let item = state.next().await?;
            Some((item, state))
        }));
        Ok(Response {
            status: parts.status.as_u16(),
            headers,
            body,
            egress,
        })
    }

    /// Sends `request` until it gets a response to return or gives up.
    ///
    /// With `pin`, every attempt goes through that egress, and a 429 is
    /// returned as the response. The caller decides what the 429 means.
    async fn exchange(
        &self,
        request: &Request,
        pin: Option<usize>,
    ) -> Result<Exchange, TransportError> {
        let (uri, host) = target(&request.url)?;
        let mut attempts = Attempts::new(&self.retry_pauses);
        // After a 429 or a 5xx the next attempt stays on the same egress.
        let mut sticky: Option<usize> = None;
        loop {
            let (index, state) = match sticky.take().or(pin) {
                Some(index) => (index, self.pool.get(index).host(&host)),
                None => self.pool.pick(&host).await,
            };
            let egress = self.pool.get(index);
            let permit = state.slot().await;
            // A pause may have started while this request was queued.
            state.wait_pause().await;
            let sent =
                tokio::time::timeout(self.response_timeout, egress.request(build(request, &uri)?))
                    .await;
            let outcome = match sent {
                Err(_) => Err(TransportError::Timeout("response headers")),
                Ok(Err(error)) => Err(connect::classify(&error, egress.proxy_id())),
                Ok(Ok(response)) => Ok(response),
            };
            match outcome {
                Ok(response)
                    if pin.is_none()
                        && response.status() == http::StatusCode::TOO_MANY_REQUESTS =>
                {
                    let value = response
                        .headers()
                        .get(RETRY_AFTER)
                        .and_then(|value| value.to_str().ok());
                    let wait = retry::retry_after(value, SystemTime::now());
                    drop((response, permit));
                    if !attempts.rate_limited(wait) {
                        return Err(TransportError::RateLimited(wait));
                    }
                    if state.pause(wait) {
                        self.reporter.notice(&Notice::RateLimited {
                            class: request.class.clone(),
                            wait,
                        });
                    }
                    sticky = Some(index);
                }
                Ok(response)
                    if response.status().is_server_error()
                        && response.status() != http::StatusCode::NOT_IMPLEMENTED =>
                {
                    let status = response.status().as_u16();
                    drop((response, permit));
                    let Some(pause) = attempts.failed() else {
                        return Err(TransportError::Status(status));
                    };
                    tokio::time::sleep(pause).await;
                    sticky = Some(index);
                }
                Ok(response) => {
                    return Ok(Exchange {
                        response,
                        permit,
                        egress: index,
                    });
                }
                Err(error) => {
                    drop(permit);
                    let Some(pause) = attempts.failed() else {
                        return Err(error);
                    };
                    // The retry takes the next egress in round robin,
                    // because this egress or its proxy may be what failed.
                    tokio::time::sleep(pause).await;
                }
            }
        }
    }
}

/// Parses the URL of a request.
///
/// Returns the URL and the `host:port` that keys the semaphores.
fn target(url: &str) -> Result<(Uri, String), TransportError> {
    let invalid = || TransportError::Connect(format!("invalid URL {url}"));
    let uri: Uri = url.parse().map_err(|_| invalid())?;
    let host = uri.host().ok_or_else(invalid)?.to_ascii_lowercase();
    let port = match (uri.port_u16(), uri.scheme_str()) {
        (Some(port), _) => port,
        (None, Some("http")) => 80,
        (None, Some("https")) => 443,
        _ => return Err(invalid()),
    };
    Ok((uri, format!("{host}:{port}")))
}

/// Builds the hyper request for one attempt.
fn build(request: &Request, uri: &Uri) -> Result<http::Request<Full<Bytes>>, TransportError> {
    let method = match request.method {
        Method::Get => http::Method::GET,
        Method::Post => http::Method::POST,
    };
    let mut builder = http::Request::builder()
        .method(method)
        .uri(uri.clone())
        .header(USER_AGENT, USER_AGENT_VALUE)
        .header(ACCEPT, request.class.accept());
    for (name, value) in &request.headers {
        builder = builder.header(*name, value.as_str());
    }
    builder
        .body(Full::new(request.body.clone().unwrap_or_default()))
        .map_err(|error| TransportError::Connect(format!("invalid request: {error}")))
}

/// What a body stream needs to send its request again.
struct Resume {
    request: Request,
    /// The egress the request is pinned to, if any.
    pin: Option<usize>,
    validators: Validators,
    /// Resends so far.
    used: usize,
}

/// The state behind a [`BodyStream`]: the hyper body and the slot that it
/// holds.
struct BodyState {
    inner: Arc<Inner>,
    /// Set if the download can be resumed after a cut.
    resume: Option<Resume>,
    /// `None` once the body has ended, with or without an error.
    body: Option<Incoming>,
    permit: Option<OwnedSemaphorePermit>,
    /// Bytes given to the reader.
    delivered: u64,
    /// Bytes of a resent response still to skip.
    skip: u64,
}

impl BodyState {
    /// Returns the next chunk, or `None` at the end.
    async fn next(&mut self) -> Option<Result<Bytes, TransportError>> {
        loop {
            let body = self.body.as_mut()?;
            let frame = tokio::time::timeout(self.inner.body_timeout, body.frame()).await;
            let error = match frame {
                Ok(Some(Ok(frame))) => {
                    // Trailers carry nothing netf reads.
                    let Ok(mut data) = frame.into_data() else {
                        continue;
                    };
                    if self.skip > 0 {
                        let skipped = data
                            .len()
                            .min(usize::try_from(self.skip).unwrap_or(usize::MAX));
                        data.advance(skipped);
                        self.skip -= skipped as u64;
                    }
                    if data.is_empty() {
                        continue;
                    }
                    self.delivered += data.len() as u64;
                    return Some(Ok(data));
                }
                Ok(None) => {
                    // The slot is free as soon as the body is read, even if
                    // the reader keeps the stream.
                    self.body = None;
                    self.permit = None;
                    return None;
                }
                Ok(Some(Err(error))) => TransportError::Io(innermost(&error)),
                Err(_) => TransportError::Timeout("response body"),
            };
            self.body = None;
            self.permit = None;
            if self.resend().await {
                continue;
            }
            return Some(Err(error));
        }
    }

    /// Sends the request again after a cut.
    ///
    /// Returns `true` if the same file is coming again and the stream can go
    /// on.
    async fn resend(&mut self) -> bool {
        let Some(resume) = self.resume.as_mut() else {
            return false;
        };
        let Some(&pause) = self.inner.retry_pauses.get(resume.used) else {
            return false;
        };
        resume.used += 1;
        tokio::time::sleep(pause).await;
        let Ok(exchange) = self.inner.exchange(&resume.request, resume.pin).await else {
            return false;
        };
        let (parts, body) = exchange.response.into_parts();
        if parts.status != http::StatusCode::OK
            || Validators::of(&parts.headers) != resume.validators
        {
            return false;
        }
        self.body = Some(body);
        self.permit = Some(exchange.permit);
        self.skip = self.delivered;
        true
    }
}

/// The text of the innermost cause of an error, cleaned for messages.
fn innermost(error: &(dyn StdError + 'static)) -> String {
    let mut current = error;
    while let Some(source) = current.source() {
        current = source;
    }
    match current.downcast_ref::<std::io::Error>() {
        Some(io) => connect::describe_io(io),
        None => connect::describe(&current.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn targets() {
        let (_, host) = target("https://RDAP.Example.test/ip/192.0.2.4").unwrap();
        assert_eq!(host, "rdap.example.test:443");
        let (_, host) = target("http://127.0.0.1:8080/x").unwrap();
        assert_eq!(host, "127.0.0.1:8080");
        let (_, host) = target("http://[2001:db8::1]/").unwrap();
        assert_eq!(host, "[2001:db8::1]:80");
        assert!(target("ftp://example.test/").is_err());
        assert!(target("not a url").is_err());
    }

    #[test]
    fn requests_carry_user_agent_and_accept() {
        let request = Request::get("https://rdap.test/x", crate::transport::Class::Doh)
            .with_header("If-None-Match", "\"v1\"");
        let (uri, _) = target(&request.url).unwrap();
        let built = build(&request, &uri).unwrap();
        assert_eq!(built.headers()[USER_AGENT], USER_AGENT_VALUE);
        assert_eq!(built.headers()[ACCEPT], "application/dns-message");
        assert_eq!(built.headers()["if-none-match"], "\"v1\"");
        assert!(USER_AGENT_VALUE.starts_with("netf/"));
    }

    #[test]
    fn proxy_errors_are_usage_errors() {
        let options = HttpOptions {
            proxies: vec!["socks5://127.0.0.1:1080".into()],
            ..HttpOptions::default()
        };
        let reporter: Arc<dyn Reporter> = Arc::new(crate::report::StderrReporter::new(false));
        let Err(error) = HttpTransport::new(options, reporter) else {
            panic!("socks5 accepted");
        };
        let error = crate::error::Error::from(error);
        assert_eq!(error.kind(), crate::error::Kind::Usage);
    }
}
