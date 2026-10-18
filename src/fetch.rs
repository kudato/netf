//! Downloads over a [`Transport`].
//!
//! The module sends conditional `GET` requests with the validators of the
//! cache and follows redirects. It detects gzip from the first bytes and
//! streams the body line by line into the dataset parser, but reads small
//! JSON responses whole.
//!
//! The transport sends one request and applies the network policy. This
//! module adds the steps that do not depend on the network:
//!
//! - **Redirects.** For `GET`, the module follows 301, 302, 303, 307, and
//!   308, at most [`MAX_REDIRECTS`] times. `Location` can be absolute or
//!   relative to the URL that responded. LACNIC responds to RDAP requests
//!   with a 307 to another host, and the module follows it with a new
//!   request through the pool. Redirects from HTTPS to HTTP fail before
//!   the next request.
//! - **Conditional requests.** With [`Validators`] from a cache file, the
//!   module sends `If-None-Match` and `If-Modified-Since`, and a 304
//!   becomes [`Fetched::NotModified`].
//! - **Decompression by content.** A body is gzip if its first two bytes
//!   are `1f 8b`, whatever the URL or `Content-Encoding` say. The sources
//!   differ, and hyper decompresses nothing: RIS dumps are `.gz` files,
//!   `asn.txt` comes with `Content-Encoding: gzip`, and the delegated stats
//!   are plain.
//! - **Lines.** [`Body::lines`] feeds the body to a [`LineSink`] chunk by
//!   chunk, through [`gzip::GzipLines`] or straight to a [`LineSplitter`].
//!   The memory is the inflate window and the current line. If the sink
//!   returns [`Control::Stop`], the download ends: the rest of the body is
//!   dropped, and the connection closes.
//! - **JSON.** [`json`] reads small responses, from RDAP and the RIPE REST
//!   API, whole and up to [`JSON_LIMIT`].
//!
//! Errors name the source. A dataset error also names the URL, as in
//! `ris-v4: https://…/riswhoisdump.IPv4.gz: HTTP 503`, and other errors
//! look like `rdap: arin: connection refused`.

pub(crate) mod gzip;
pub(crate) mod lines;

use std::io::Read as _;

use self::{
    gzip::GzipLines,
    lines::{Control, LineSink, LineSplitter},
};
use crate::{
    error::{Error, Result},
    transport::{BodyStream, Class, Request, Transport, TransportError},
};

/// The maximum number of redirects for one request.
pub(crate) const MAX_REDIRECTS: usize = 5;

/// The maximum size of a JSON response, as received and after
/// decompression: 8 MB.
pub(crate) const JSON_LIMIT: usize = 8 << 20;

/// The validators of a cached copy, which make a request conditional.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub(crate) struct Validators {
    /// The `ETag` of the copy, sent as `If-None-Match`.
    pub(crate) etag: Option<String>,
    /// The `Last-Modified` of the copy, sent as `If-Modified-Since`.
    pub(crate) last_modified: Option<String>,
}

impl Validators {
    /// Returns `true` if there is nothing to send.
    pub(crate) fn is_empty(&self) -> bool {
        self.etag.is_none() && self.last_modified.is_none()
    }
}

/// The response to [`get`].
#[derive(Debug)]
pub(crate) enum Fetched {
    /// A 304: the cached copy is still current.
    NotModified,
    /// Any other final response, with its body not read yet.
    Body(Body),
}

/// A response body that is not read yet, with the context that errors
/// about it need.
#[derive(Debug)]
pub(crate) struct Body {
    /// The HTTP status of the final response, after redirects.
    pub(crate) status: u16,
    /// The validators of the response, for the cache.
    pub(crate) validators: Validators,
    class: Class,
    /// The requested URL, for messages.
    requested: String,
    stream: BodyStream,
}

impl Body {
    /// Returns `true` for a 2xx status.
    pub(crate) fn is_success(&self) -> bool {
        (200..300).contains(&self.status)
    }

    /// Returns the error for an unexpected status of this response:
    /// `ris-v4: https://…: HTTP 404`.
    pub(crate) fn status_error(&self) -> Error {
        context(
            &self.class,
            &self.requested,
            format!("HTTP {}", self.status),
        )
    }

    /// Reads the body line by line into `sink`, and decompresses gzip.
    ///
    /// Returns [`Control::Stop`] if the sink stopped the reading, and drops
    /// the rest of the body unread.
    ///
    /// # Errors
    ///
    /// Returns an error if the transport fails, the gzip data is damaged,
    /// or the sink fails.
    pub(crate) async fn lines(mut self, sink: &mut dyn LineSink) -> Result<Control> {
        let prefix = (self.class.clone(), self.requested.clone());
        let fail = move |error: Error| error.with_prefix(display_context(&prefix.0, &prefix.1));
        // Wait for two bytes before choosing the decoder. A body of one byte
        // is not gzip.
        let mut head = Vec::new();
        let mut first = None;
        while head.len() < 2 {
            match self.stream.next_chunk().await {
                Some(chunk) => {
                    let chunk =
                        chunk.map_err(|e| transport_error(&self.class, &self.requested, e))?;
                    if head.is_empty() && chunk.len() >= 2 {
                        first = Some(chunk);
                        break;
                    }
                    head.extend_from_slice(&chunk);
                }
                None => break,
            }
        }
        let start: &[u8] = first.as_deref().unwrap_or(&head);
        let mut reader = if start.starts_with(&gzip::MAGIC) {
            Decode::Gzip(Box::new(GzipLines::new()))
        } else {
            Decode::Plain(LineSplitter::new())
        };
        if reader.push(start, sink).map_err(&fail)? == Control::Stop {
            return Ok(Control::Stop);
        }
        drop(first);
        while let Some(chunk) = self.stream.next_chunk().await {
            let chunk = chunk.map_err(|e| transport_error(&self.class, &self.requested, e))?;
            if reader.push(&chunk, sink).map_err(&fail)? == Control::Stop {
                return Ok(Control::Stop);
            }
        }
        reader.finish(sink).map_err(&fail)
    }

    /// Reads the whole body, at most `limit` bytes.
    ///
    /// The limit applies twice: to the body as received and to the body
    /// after decompression.
    ///
    /// # Errors
    ///
    /// Returns an error if the transport fails, the gzip data is damaged,
    /// or the body is larger than `limit`.
    pub(crate) async fn bytes(self, limit: usize) -> Result<Vec<u8>> {
        let raw = self
            .stream
            .collect(limit)
            .await
            .map_err(|e| transport_error(&self.class, &self.requested, e))?;
        if !raw.starts_with(&gzip::MAGIC) {
            return Ok(raw.to_vec());
        }
        let mut out = Vec::new();
        let decoder = flate2::read::MultiGzDecoder::new(&raw[..]);
        decoder
            .take(limit as u64 + 1)
            .read_to_end(&mut out)
            .map_err(|_| {
                context(
                    &self.class,
                    &self.requested,
                    "gzip: corrupt or truncated data",
                )
            })?;
        if out.len() > limit {
            return Err(transport_error(
                &self.class,
                &self.requested,
                TransportError::TooLarge,
            ));
        }
        Ok(out)
    }
}

/// The decoder that the first bytes of a body select.
enum Decode {
    Gzip(Box<GzipLines>),
    Plain(LineSplitter),
}

impl Decode {
    fn push(&mut self, chunk: &[u8], sink: &mut dyn LineSink) -> Result<Control> {
        match self {
            Self::Gzip(decoder) => decoder.push(chunk, sink),
            Self::Plain(splitter) => splitter.push(chunk, sink),
        }
    }

    fn finish(&mut self, sink: &mut dyn LineSink) -> Result<Control> {
        match self {
            Self::Gzip(decoder) => decoder.finish(sink),
            Self::Plain(splitter) => splitter.finish(sink),
        }
    }
}

/// Sends a `GET` and follows redirects.
///
/// The request is conditional if `validators` are given. Every final
/// status other than 304 comes back as a [`Body`], because the meaning of
/// a 404 depends on the caller. A 304 to a request that was not
/// conditional also comes back as a [`Body`], and its status is not a
/// success, so the caller treats it as an error.
///
/// # Errors
///
/// Returns an error if the transport fails or a redirect has no valid
/// `Location`. Redirects from HTTPS to HTTP and chains longer than
/// [`MAX_REDIRECTS`] also return errors.
pub(crate) async fn get(
    transport: &dyn Transport,
    url: &str,
    class: Class,
    validators: Option<&Validators>,
) -> Result<Fetched> {
    let mut current = url.to_owned();
    for _ in 0..=MAX_REDIRECTS {
        let mut request = Request::get(current.clone(), class.clone());
        if let Some(validators) = validators {
            if let Some(etag) = &validators.etag {
                request = request.with_header("If-None-Match", etag.clone());
            }
            if let Some(date) = &validators.last_modified {
                request = request.with_header("If-Modified-Since", date.clone());
            }
        }
        let response = transport
            .send(request)
            .await
            .map_err(|e| transport_error(&class, url, e))?;
        match response.status {
            301 | 302 | 303 | 307 | 308 => {
                current = redirect(&current, response.header("Location"))
                    .map_err(|cause| context(&class, url, cause))?;
            }
            304 if validators.is_some_and(|v| !v.is_empty()) => return Ok(Fetched::NotModified),
            status => {
                let validators = Validators {
                    etag: response.header("ETag").map(str::to_owned),
                    last_modified: response.header("Last-Modified").map(str::to_owned),
                };
                return Ok(Fetched::Body(Body {
                    status,
                    validators,
                    class,
                    requested: url.to_owned(),
                    stream: response.body,
                }));
            }
        }
    }
    Err(context(&class, url, "too many redirects"))
}

/// Fetches a JSON response and returns the status and the parsed body.
///
/// A 2xx body must be JSON. The body of another status is parsed if it is
/// JSON and is `null` otherwise. The RIPE REST API, for example, explains a
/// 404 in JSON.
///
/// # Errors
///
/// Returns an error if [`get`] fails, the body cannot be read, or a 2xx
/// body is not valid JSON.
pub(crate) async fn json(
    transport: &dyn Transport,
    url: &str,
    class: Class,
) -> Result<(u16, serde_json::Value)> {
    let Fetched::Body(body) = get(transport, url, class.clone(), None).await? else {
        // Unreachable: `get` returns `NotModified` only with validators.
        return Err(context(&class, url, "HTTP 304"));
    };
    let status = body.status;
    let success = body.is_success();
    let bytes = body.bytes(JSON_LIMIT).await?;
    match serde_json::from_slice(&bytes) {
        Ok(value) => Ok((status, value)),
        Err(_) if !success => Ok((status, serde_json::Value::Null)),
        Err(error) => Err(context(&class, url, format!("invalid JSON: {error}"))),
    }
}

/// Resolves `Location` and rejects redirects from HTTPS to HTTP.
///
/// # Errors
///
/// Returns an error if `Location` is missing or cannot be resolved, or if
/// the redirect changes HTTPS to HTTP.
pub(crate) fn redirect(base: &str, location: Option<&str>) -> Result<String, &'static str> {
    let next = location
        .and_then(|location| resolve(base, location))
        .ok_or("redirect without a valid Location")?;
    if base
        .split_once(':')
        .is_some_and(|(scheme, _)| scheme.eq_ignore_ascii_case("https"))
        && next
            .split_once(':')
            .is_some_and(|(scheme, _)| scheme.eq_ignore_ascii_case("http"))
    {
        return Err("redirect from HTTPS to HTTP is not allowed");
    }
    Ok(next)
}

/// Resolves a `Location` against the URL that sent it.
///
/// Handles absolute URLs, `//host/path`, `/path`, and paths relative to the
/// directory of `base`. The query of `base` is never kept.
fn resolve(base: &str, location: &str) -> Option<String> {
    let location = location.trim();
    if location.is_empty() {
        return None;
    }
    if has_scheme(location) {
        return Some(location.to_owned());
    }
    let (scheme, rest) = base.split_once("://")?;
    if let Some(net_path) = location.strip_prefix("//") {
        return Some(format!("{scheme}://{net_path}"));
    }
    let authority_end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let (authority, path) = rest.split_at(authority_end);
    if location.starts_with('/') {
        return Some(format!("{scheme}://{authority}{}", remove_dots(location)));
    }
    let path = path.split(['?', '#']).next().unwrap_or("");
    let dir = match path.rfind('/') {
        Some(slash) => &path[..=slash],
        None => "/",
    };
    if location.starts_with('?') {
        let file = path.strip_prefix(dir).unwrap_or("");
        return Some(format!("{scheme}://{authority}{dir}{file}{location}"));
    }
    Some(format!(
        "{scheme}://{authority}{}",
        remove_dots(&format!("{dir}{location}"))
    ))
}

/// Removes `.` and `..` segments from an absolute path, as RFC 3986
/// section 5.2.4 describes.
///
/// The query and the fragment stay as they are.
fn remove_dots(path: &str) -> String {
    let split = path.find(['?', '#']).unwrap_or(path.len());
    let (path, tail) = path.split_at(split);
    let mut out: Vec<&str> = Vec::new();
    let segments: Vec<&str> = path.split('/').skip(1).collect();
    for (i, segment) in segments.iter().enumerate() {
        let last = i + 1 == segments.len();
        match *segment {
            "." | ".." => {
                if *segment == ".." {
                    out.pop();
                }
                if last {
                    out.push("");
                }
            }
            other => out.push(other),
        }
    }
    format!("/{}{tail}", out.join("/"))
}

/// Returns `true` if `url` starts with `scheme:`.
///
/// A scheme starts with a letter and has only letters, digits, `+`, `-`,
/// and `.`.
fn has_scheme(url: &str) -> bool {
    match url.split_once(':') {
        Some((scheme, _)) => {
            !scheme.is_empty()
                && scheme.starts_with(|c: char| c.is_ascii_alphabetic())
                && scheme
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '-' | '.'))
        }
        None => false,
    }
}

/// Returns the prefix of messages about `url` fetched as `class`.
fn display_context(class: &Class, url: &str) -> String {
    match class {
        Class::Dataset(_) => format!("{class}: {url}"),
        _ => class.to_string(),
    }
}

/// Returns an error about `url`, such as `ris-v4: <url>: <cause>` or
/// `rdap: arin: <cause>`.
fn context(class: &Class, url: &str, cause: impl Into<String>) -> Error {
    Error::runtime(cause).with_prefix(display_context(class, url))
}

/// Returns a transport error about `url`.
fn transport_error(class: &Class, url: &str, error: TransportError) -> Error {
    context(class, url, error.to_string())
}

/// Test helpers for this layer and the layers above it.
///
/// The module has a transport with scripted replies per URL and a log of
/// requests, a fake clock, a reporter that keeps notices, and temporary
/// directories.
#[cfg(test)]
pub(crate) mod testing {
    use std::{
        collections::{HashMap, VecDeque},
        path::{Path, PathBuf},
        sync::{
            Mutex,
            atomic::{AtomicUsize, Ordering},
        },
        time::{Duration, SystemTime},
    };

    use bytes::Bytes;

    use crate::{
        Clock, Notice, Reporter,
        transport::{
            BodyStream, BoxFuture, EgressId, Request, Response, Transport, TransportError,
        },
    };

    /// One scripted reply.
    #[derive(Clone, Debug)]
    pub(crate) struct Reply {
        pub(crate) status: u16,
        pub(crate) headers: Vec<(String, String)>,
        pub(crate) chunks: Vec<Bytes>,
        /// Ends the body with this error after the chunks.
        pub(crate) cut: Option<TransportError>,
    }

    impl Reply {
        pub(crate) fn status(status: u16) -> Self {
            Self {
                status,
                headers: Vec::new(),
                chunks: Vec::new(),
                cut: None,
            }
        }

        pub(crate) fn ok(body: impl Into<Bytes>) -> Self {
            Self::status(200).body(body)
        }

        pub(crate) fn body(mut self, body: impl Into<Bytes>) -> Self {
            self.chunks = vec![body.into()];
            self
        }

        pub(crate) fn chunked(mut self, body: &[u8], size: usize) -> Self {
            self.chunks = body
                .chunks(size.max(1))
                .map(Bytes::copy_from_slice)
                .collect();
            self
        }

        pub(crate) fn header(mut self, name: &str, value: &str) -> Self {
            self.headers.push((name.to_owned(), value.to_owned()));
            self
        }

        pub(crate) fn cut(mut self, error: TransportError) -> Self {
            self.cut = Some(error);
            self
        }
    }

    /// A transport that responds with the scripted replies for each URL, in
    /// order.
    ///
    /// A request without a queued reply panics.
    #[derive(Default)]
    pub(crate) struct Stub {
        replies: Mutex<HashMap<String, VecDeque<Reply>>>,
        log: Mutex<Vec<Request>>,
    }

    impl Stub {
        pub(crate) fn new() -> Self {
            Self::default()
        }

        /// Queues a reply for `url`.
        pub(crate) fn on(&self, url: &str, reply: Reply) -> &Self {
            self.replies
                .lock()
                .unwrap()
                .entry(url.to_owned())
                .or_default()
                .push_back(reply);
            self
        }

        /// Returns the requests sent so far.
        pub(crate) fn log(&self) -> Vec<Request> {
            self.log.lock().unwrap().clone()
        }

        /// Returns the number of requests sent so far.
        pub(crate) fn count(&self) -> usize {
            self.log.lock().unwrap().len()
        }
    }

    impl Transport for Stub {
        fn send(&self, request: Request) -> BoxFuture<'_, Result<Response, TransportError>> {
            let reply = self
                .replies
                .lock()
                .unwrap()
                .get_mut(&request.url)
                .and_then(VecDeque::pop_front)
                .unwrap_or_else(|| panic!("unexpected request: {}", request.url));
            self.log.lock().unwrap().push(request);
            Box::pin(async move {
                let mut items: Vec<Result<Bytes, TransportError>> =
                    reply.chunks.into_iter().map(Ok).collect();
                if let Some(error) = reply.cut {
                    items.push(Err(error));
                }
                Ok(Response {
                    status: reply.status,
                    headers: reply.headers,
                    body: BodyStream::new(futures_util::stream::iter(items)),
                    egress: EgressId::direct(),
                })
            })
        }
    }

    /// A clock moved by hand.
    pub(crate) struct FakeClock(Mutex<SystemTime>);

    impl FakeClock {
        pub(crate) fn new() -> Self {
            // A whole second, because file systems keep at least that
            // precision.
            Self(Mutex::new(
                SystemTime::UNIX_EPOCH + Duration::from_secs(1_800_000_000),
            ))
        }

        pub(crate) fn advance(&self, by: Duration) {
            *self.0.lock().unwrap() += by;
        }
    }

    impl Clock for FakeClock {
        fn now(&self) -> SystemTime {
            *self.0.lock().unwrap()
        }
    }

    /// A reporter that keeps the notices and errors.
    #[derive(Default)]
    pub(crate) struct Collect(Mutex<Vec<String>>);

    impl Collect {
        pub(crate) fn lines(&self) -> Vec<String> {
            self.0.lock().unwrap().clone()
        }
    }

    impl Reporter for Collect {
        fn notice(&self, notice: &Notice) {
            self.0.lock().unwrap().push(notice.to_string());
        }

        fn error(&self, message: &str) {
            self.0.lock().unwrap().push(message.to_owned());
        }

        fn progress(&self, _: u32, _: u32, _: &'static str) {}

        fn clear_progress(&self) {}
    }

    /// A new directory under `target/unit-tmp`, removed on drop.
    pub(crate) struct TempDir(PathBuf);

    impl TempDir {
        pub(crate) fn new(name: &str) -> Self {
            static NEXT: AtomicUsize = AtomicUsize::new(0);
            let path = Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("target")
                .join("unit-tmp")
                .join(format!(
                    "{name}-{}-{}",
                    std::process::id(),
                    NEXT.fetch_add(1, Ordering::Relaxed)
                ));
            let _ = std::fs::remove_dir_all(&path);
            std::fs::create_dir_all(&path).unwrap();
            Self(path)
        }

        pub(crate) fn path(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    /// Compresses `data` with gzip.
    pub(crate) fn gzip(data: &[u8]) -> Vec<u8> {
        use std::io::Write as _;
        let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        encoder.write_all(data).unwrap();
        encoder.finish().unwrap()
    }
}

#[cfg(test)]
mod tests {
    use super::{
        testing::{Reply, Stub, gzip},
        *,
    };

    const URL: &str = "https://ris.ripe.test/dumps/riswhoisdump.IPv4.gz";

    #[derive(Default)]
    struct Collect {
        lines: Vec<String>,
        stop_after: Option<usize>,
    }

    impl LineSink for Collect {
        fn line(&mut self, line: &[u8]) -> Result<Control> {
            self.lines.push(String::from_utf8(line.to_vec()).unwrap());
            Ok(match self.stop_after {
                Some(n) if self.lines.len() >= n => Control::Stop,
                _ => Control::Continue,
            })
        }
    }

    fn body(fetched: Fetched) -> Body {
        match fetched {
            Fetched::Body(body) => body,
            Fetched::NotModified => panic!("304"),
        }
    }

    async fn lines_of(stub: &Stub) -> Vec<String> {
        let fetched = get(stub, URL, Class::Dataset("ris-v4"), None)
            .await
            .unwrap();
        let mut sink = Collect::default();
        body(fetched).lines(&mut sink).await.unwrap();
        sink.lines
    }

    #[tokio::test(flavor = "current_thread")]
    async fn one_byte_bodies() {
        assert_eq!(lines_of(Stub::new().on(URL, Reply::ok("x"))).await, ["x"]);
        assert!(
            lines_of(Stub::new().on(URL, Reply::ok("")))
                .await
                .is_empty()
        );
        // The gzip magic split over two chunks is still sniffed.
        let packed = gzip(b"a\nb\n");
        let stub = Stub::new();
        stub.on(URL, Reply::status(200).chunked(&packed, 1));
        assert_eq!(lines_of(&stub).await, ["a", "b"]);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn conditional_headers_and_304() {
        let stub = Stub::new();
        stub.on(URL, Reply::status(304));
        let validators = Validators {
            etag: Some("\"abc\"".into()),
            last_modified: Some("Sat, 17 Oct 2026 00:00:00 GMT".into()),
        };
        let fetched = get(&stub, URL, Class::Dataset("ris-v4"), Some(&validators))
            .await
            .unwrap();
        assert!(matches!(fetched, Fetched::NotModified));
        let request = &stub.log()[0];
        assert_eq!(request.header("If-None-Match"), Some("\"abc\""));
        assert_eq!(
            request.header("If-Modified-Since"),
            Some("Sat, 17 Oct 2026 00:00:00 GMT")
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn validators_of_the_answer() {
        let stub = Stub::new();
        stub.on(
            URL,
            Reply::ok("a")
                .header("etag", "\"v1\"")
                .header("Last-Modified", "Sat, 17 Oct 2026 00:00:00 GMT"),
        );
        let fetched = body(
            get(&stub, URL, Class::Dataset("ris-v4"), None)
                .await
                .unwrap(),
        );
        assert_eq!(fetched.validators.etag.as_deref(), Some("\"v1\""));
        assert!(fetched.validators.last_modified.is_some());
        assert!(stub.log()[0].header("If-None-Match").is_none());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn redirects_are_followed() {
        let stub = Stub::new();
        stub.on(
            "https://rdap.lacnic.test/rdap/ip/192.0.2.1",
            Reply::status(307).header("Location", "https://rdap.registro.test/ip/192.0.2.1"),
        );
        stub.on(
            "https://rdap.registro.test/ip/192.0.2.1",
            Reply::status(302).header("location", "../v2/ip?x=1"),
        );
        stub.on(
            "https://rdap.registro.test/v2/ip?x=1",
            Reply::ok("{\"a\":1}"),
        );
        let (status, value) = json(
            &stub,
            "https://rdap.lacnic.test/rdap/ip/192.0.2.1",
            Class::Rdap("lacnic".into()),
        )
        .await
        .unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(status, 200);
        assert_eq!(value["a"], 1);
        assert_eq!(stub.count(), 3);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn https_to_http_redirects_are_rejected() {
        for status in [301, 302, 303, 307, 308] {
            for (url, next) in [
                (URL, "http://downloads.test/data"),
                ("hTtPs://ris.ripe.test/data", "HtTp://downloads.test/data"),
            ] {
                let stub = Stub::new();
                stub.on(
                    url,
                    Reply::status(status).header("Location", &format!(" {next} ")),
                );
                stub.on(next, Reply::ok("data"));
                let error = get(&stub, url, Class::Dataset("ris-v4"), None)
                    .await
                    .unwrap_err();
                assert_eq!(
                    error.message(),
                    format!("ris-v4: {url}: redirect from HTTPS to HTTP is not allowed")
                );
                assert_eq!(stub.count(), 1);
                assert_eq!(stub.log()[0].url, url);
            }
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn http_redirects_and_https_upgrades_are_followed() {
        let stub = Stub::new();
        let first = "http://127.0.0.1:9/first";
        let second = "http://127.0.0.1:9/second";
        let third = "https://downloads.test/data";
        stub.on(first, Reply::status(301).header("Location", "/second"));
        stub.on(second, Reply::status(308).header("Location", third));
        stub.on(third, Reply::ok("data"));
        let fetched = get(&stub, first, Class::Dataset("ris-v4"), None)
            .await
            .unwrap();
        assert_eq!(body(fetched).bytes(4).await.unwrap(), b"data"[..]);
        assert_eq!(
            stub.log()
                .iter()
                .map(|request| request.url.as_str())
                .collect::<Vec<_>>(),
            [first, second, third]
        );
    }

    #[test]
    fn redirects_require_a_location() {
        for location in [None, Some(""), Some(" \t ")] {
            assert_eq!(
                redirect(URL, location),
                Err("redirect without a valid Location")
            );
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn too_many_redirects() {
        let stub = Stub::new();
        for _ in 0..=MAX_REDIRECTS {
            stub.on(URL, Reply::status(301).header("Location", URL));
        }
        let error = get(&stub, URL, Class::Dataset("ris-v4"), None)
            .await
            .unwrap_err();
        assert_eq!(
            error.message(),
            format!("ris-v4: {URL}: too many redirects")
        );
        assert_eq!(stub.count(), MAX_REDIRECTS + 1);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn errors_name_the_source() {
        let stub = Stub::new();
        stub.on(URL, Reply::status(404));
        let fetched = body(
            get(&stub, URL, Class::Dataset("ris-v4"), None)
                .await
                .unwrap(),
        );
        assert_eq!(
            fetched.status_error().to_string(),
            format!("netf: ris-v4: {URL}: HTTP 404")
        );

        let stub = Stub::new();
        stub.on(
            URL,
            Reply::ok("a\nb").cut(TransportError::Io("connection reset".into())),
        );
        let fetched = body(
            get(&stub, URL, Class::Dataset("ris-v4"), None)
                .await
                .unwrap(),
        );
        let error = fetched.lines(&mut Collect::default()).await.unwrap_err();
        assert_eq!(error.message(), format!("ris-v4: {URL}: connection reset"));

        let stub = Stub::new();
        let packed = gzip(b"a\nb\n");
        stub.on(URL, Reply::ok(packed[..packed.len() - 3].to_vec()));
        let fetched = body(
            get(&stub, URL, Class::Dataset("ris-v4"), None)
                .await
                .unwrap(),
        );
        let error = fetched.lines(&mut Collect::default()).await.unwrap_err();
        assert_eq!(
            error.message(),
            format!("ris-v4: {URL}: gzip: corrupt or truncated data")
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn stop_drops_the_rest() {
        let stub = Stub::new();
        stub.on(
            URL,
            Reply::status(200)
                .chunked(b"a\nb\nc\nd\n", 2)
                .cut(TransportError::Io("never read".into())),
        );
        let fetched = body(
            get(&stub, URL, Class::Dataset("ris-v4"), None)
                .await
                .unwrap(),
        );
        let mut sink = Collect {
            stop_after: Some(2),
            ..Collect::default()
        };
        assert_eq!(fetched.lines(&mut sink).await.unwrap(), Control::Stop);
        assert_eq!(sink.lines, ["a", "b"]);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn json_limits_and_errors() {
        let url = "https://rest.ripe.test/search.json?query-string=X";
        let stub = Stub::new();
        stub.on(url, Reply::status(404).body("{\"errormessages\":{}}"));
        let (status, value) = json(&stub, url, Class::RipeRest).await.unwrap();
        assert_eq!(status, 404);
        assert!(value["errormessages"].is_object());

        let stub = Stub::new();
        stub.on(url, Reply::status(404).body("not json"));
        assert_eq!(
            json(&stub, url, Class::RipeRest).await.unwrap(),
            (404, serde_json::Value::Null)
        );

        let stub = Stub::new();
        stub.on(url, Reply::ok("{"));
        let error = json(&stub, url, Class::RipeRest).await.unwrap_err();
        assert!(error.message().starts_with("ripe: invalid JSON"), "{error}");

        let stub = Stub::new();
        stub.on(url, Reply::ok(gzip(b"{\"gz\":true}")));
        assert_eq!(
            json(&stub, url, Class::RipeRest).await.unwrap().1["gz"],
            true
        );

        // A small compressed body that inflates past the limit.
        let stub = Stub::new();
        stub.on(url, Reply::ok(gzip(&vec![b' '; JSON_LIMIT + 1])));
        let error = json(&stub, url, Class::RipeRest).await.unwrap_err();
        assert_eq!(error.message(), "ripe: response too large");

        let stub = Stub::new();
        stub.on(url, Reply::ok(vec![b' '; JSON_LIMIT + 1]));
        let error = json(&stub, url, Class::RipeRest).await.unwrap_err();
        assert_eq!(error.message(), "ripe: response too large");
    }

    #[test]
    fn locations() {
        let base = "https://h.test/a/b/c?q=1";
        assert_eq!(
            resolve(base, "https://x.test/y").unwrap(),
            "https://x.test/y"
        );
        assert_eq!(resolve(base, "//x.test/y").unwrap(), "https://x.test/y");
        assert_eq!(resolve(base, "/y").unwrap(), "https://h.test/y");
        assert_eq!(resolve(base, "d").unwrap(), "https://h.test/a/b/d");
        assert_eq!(resolve(base, "?z").unwrap(), "https://h.test/a/b/c?z");
        assert_eq!(resolve("https://h.test", "d").unwrap(), "https://h.test/d");
        assert_eq!(resolve(base, "../x/./y").unwrap(), "https://h.test/a/x/y");
        assert_eq!(resolve(base, "/../../y/..").unwrap(), "https://h.test/");
        assert_eq!(resolve(base, " "), None);
    }
}
