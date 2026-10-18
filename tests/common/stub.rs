//! A stub HTTP server and a stub HTTP CONNECT proxy for the tests of the
//! real transport.
//!
//! The server listens on `127.0.0.1:0` and serves fixtures by
//! `<host>/<path>`. With `NETF_SOURCE_BASE` set to the stub, netf requests
//! `https://ris.ripe.test/dumps/x` as `<base>/ris.ripe.test/dumps/x`.
//! The server replaces `${BASE}` in text fixtures with its own base URL, so
//! the bootstrap fixtures point back at the stub. Tests script 304, 429
//! with `Retry-After`, 5xx, redirects, slow bodies, and cut bodies. The
//! server counts concurrent requests.
//!
//! The proxy listens on a second port, checks `Proxy-Authorization`, and
//! counts tunnels. Nothing listens on other addresses, so tests never leave
//! the machine.
//!
//! Each stub runs on its own thread with its own single-threaded runtime.
//! The stub answers while the test blocks on a run of netf, and it stops
//! when it is dropped.
//!
//! The stubs follow these rules:
//!
//! - Scripted replies ([`StubServer::on`]) are served once each, in order,
//!   per path and query string. [`StubServer::always`] answers when the queue
//!   is empty.
//! - A path without a scripted reply is a fixture: `/<name>` serves
//!   `tests/fixtures/<name>` with an `ETag`. A request with that tag in
//!   `If-None-Match` gets 304. A path without a fixture gets 404.
//! - A request counts as in flight from its arrival until its body is sent
//!   or dropped. [`StubServer::peak`] is the most requests in flight at
//!   once.
//! - The proxy opens tunnels only to `127.0.0.1`. A `CONNECT` to any other
//!   address gets 403.

use std::{
    collections::{HashMap, VecDeque},
    convert::Infallible,
    io,
    net::{SocketAddr, TcpListener as StdListener},
    sync::{
        Arc, Mutex, PoisonError,
        atomic::{AtomicUsize, Ordering},
    },
    thread,
    time::Duration,
};

use bytes::Bytes;
use futures_util::stream;
use http_body_util::{BodyExt as _, StreamBody, combinators::BoxBody};
use hyper::{
    body::{Frame, Incoming},
    server::conn::http1,
    service::service_fn,
};
use hyper_util::rt::TokioIo;
use tokio::{
    io::{AsyncReadExt as _, AsyncWriteExt as _},
    net::{TcpListener, TcpStream},
    sync::oneshot,
};

/// Locks `mutex` and ignores poisoning.
///
/// A mutex is poisoned only after a panic, and a panic has already failed
/// the test.
fn lock<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

/// Runs `serve` on a new thread with a single-threaded runtime.
///
/// `serve` stops when the caller drops the returned sender.
fn spawn<F, Fut>(listener: StdListener, serve: F) -> oneshot::Sender<()>
where
    F: FnOnce(TcpListener) -> Fut + Send + 'static,
    Fut: Future<Output = ()> + 'static,
{
    let (stop, stopped) = oneshot::channel::<()>();
    listener
        .set_nonblocking(true)
        .expect("a non-blocking listener");
    thread::spawn(move || {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("a Tokio runtime");
        let local = tokio::task::LocalSet::new();
        local.block_on(&runtime, async move {
            let listener = TcpListener::from_std(listener).expect("a Tokio listener");
            tokio::select! {
                () = serve(listener) => {}
                _ = stopped => {}
            }
        });
        // Dropping the runtime cancels the connections still open.
    });
    stop
}

/// A scripted reply of [`StubServer`].
#[derive(Clone, Debug)]
pub(crate) struct Reply {
    status: u16,
    headers: Vec<(String, String)>,
    chunks: Vec<Bytes>,
    /// Waits this long before the headers.
    delay: Duration,
    /// Waits this long before each chunk.
    chunk_delay: Duration,
    /// After the chunks, sends nothing more for an hour before it ends the
    /// body.
    stall: bool,
    /// After the chunks, breaks the connection.
    cut: bool,
}

impl Reply {
    /// Returns a reply with `status` and an empty body.
    pub(crate) fn status(status: u16) -> Self {
        Self {
            status,
            headers: Vec::new(),
            chunks: Vec::new(),
            delay: Duration::ZERO,
            chunk_delay: Duration::ZERO,
            stall: false,
            cut: false,
        }
    }

    /// Returns a 200 reply with `body` in one chunk.
    pub(crate) fn ok(body: impl Into<Bytes>) -> Self {
        Self::status(200).chunks(vec![body.into()])
    }

    /// Adds the header `name` with `value`.
    pub(crate) fn header(mut self, name: &str, value: &str) -> Self {
        self.headers.push((name.to_owned(), value.to_owned()));
        self
    }

    /// Replaces the body with `chunks`, each sent as one frame.
    pub(crate) fn chunks(mut self, chunks: Vec<Bytes>) -> Self {
        self.chunks = chunks;
        self
    }

    /// Waits `delay` before sending the headers.
    pub(crate) fn delay(mut self, delay: Duration) -> Self {
        self.delay = delay;
        self
    }

    /// Waits `delay` before each chunk of the body.
    pub(crate) fn chunk_delay(mut self, delay: Duration) -> Self {
        self.chunk_delay = delay;
        self
    }

    /// Sends nothing after the chunks and keeps the connection open.
    pub(crate) fn stall(mut self) -> Self {
        self.stall = true;
        self
    }

    /// Breaks the connection after the chunks.
    pub(crate) fn cut(mut self) -> Self {
        self.cut = true;
        self
    }
}

/// A request the stub received.
#[derive(Clone, Debug)]
pub(crate) struct Received {
    /// The method, such as `GET` or `POST`.
    pub(crate) method: String,
    /// The path and query string.
    pub(crate) path: String,
    /// The headers, names in lowercase.
    pub(crate) headers: Vec<(String, String)>,
    /// The body.
    pub(crate) body: Bytes,
}

impl Received {
    /// Returns the value of the header `name`, given in lowercase.
    pub(crate) fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(n, _)| n == name)
            .map(|(_, v)| v.as_str())
    }
}

#[derive(Default)]
struct Script {
    once: HashMap<String, VecDeque<Reply>>,
    always: HashMap<String, Reply>,
}

#[derive(Default)]
struct Shared {
    base: String,
    script: Mutex<Script>,
    received: Mutex<Vec<Received>>,
    inflight: AtomicUsize,
    peak: AtomicUsize,
}

/// Counts a request in flight until dropped.
struct InFlight(Arc<Shared>);

impl InFlight {
    fn new(shared: &Arc<Shared>) -> Self {
        let now = shared.inflight.fetch_add(1, Ordering::SeqCst) + 1;
        shared.peak.fetch_max(now, Ordering::SeqCst);
        Self(Arc::clone(shared))
    }
}

impl Drop for InFlight {
    fn drop(&mut self) {
        self.0.inflight.fetch_sub(1, Ordering::SeqCst);
    }
}

type Body = BoxBody<Bytes, io::Error>;

/// The stub HTTP server.
///
/// The server stops when dropped.
pub(crate) struct StubServer {
    shared: Arc<Shared>,
    addr: SocketAddr,
    _stop: oneshot::Sender<()>,
}

impl StubServer {
    /// Starts a server on a free port of `127.0.0.1`.
    pub(crate) fn start() -> Self {
        let listener = StdListener::bind("127.0.0.1:0").expect("a free port on 127.0.0.1");
        let addr = listener.local_addr().expect("the address of the stub");
        let shared = Arc::new(Shared {
            base: format!("http://{addr}"),
            ..Shared::default()
        });
        let serving = Arc::clone(&shared);
        let stop = spawn(listener, move |listener| async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    continue;
                };
                let shared = Arc::clone(&serving);
                tokio::task::spawn_local(async move {
                    let service = service_fn(move |request| {
                        let shared = Arc::clone(&shared);
                        async move { Ok::<_, Infallible>(answer(shared, request).await) }
                    });
                    // Errors are the cuts and timeouts the tests make.
                    let _ = http1::Builder::new()
                        .serve_connection(TokioIo::new(stream), service)
                        .await;
                });
            }
        });
        Self {
            shared,
            addr,
            _stop: stop,
        }
    }

    /// Returns the base URL, `http://127.0.0.1:<port>`.
    pub(crate) fn base(&self) -> &str {
        &self.shared.base
    }

    /// Returns the address the server listens on.
    pub(crate) fn addr(&self) -> SocketAddr {
        self.addr
    }

    /// Returns the URL of `path`, which starts with `/`.
    pub(crate) fn url(&self, path: &str) -> String {
        format!("{}{path}", self.shared.base)
    }

    /// Queues `reply` for the next request to `path`.
    pub(crate) fn on(&self, path: &str, reply: Reply) -> &Self {
        lock(&self.shared.script)
            .once
            .entry(path.to_owned())
            .or_default()
            .push_back(reply);
        self
    }

    /// Answers `path` with `reply` whenever its queue is empty.
    pub(crate) fn always(&self, path: &str, reply: Reply) -> &Self {
        lock(&self.shared.script)
            .always
            .insert(path.to_owned(), reply);
        self
    }

    /// Returns the requests received so far, in order of arrival.
    pub(crate) fn received(&self) -> Vec<Received> {
        lock(&self.shared.received).clone()
    }

    /// Returns the number of requests to `path` so far.
    pub(crate) fn count(&self, path: &str) -> usize {
        lock(&self.shared.received)
            .iter()
            .filter(|r| r.path == path)
            .count()
    }

    /// Returns the most requests in flight at once.
    pub(crate) fn peak(&self) -> usize {
        self.shared.peak.load(Ordering::SeqCst)
    }

    /// Returns the number of requests in flight now.
    pub(crate) fn inflight(&self) -> usize {
        self.shared.inflight.load(Ordering::SeqCst)
    }
}

/// Answers one request.
async fn answer(shared: Arc<Shared>, request: hyper::Request<Incoming>) -> hyper::Response<Body> {
    let guard = InFlight::new(&shared);
    let (parts, body) = request.into_parts();
    let path = parts
        .uri
        .path_and_query()
        .map_or("/", |p| p.as_str())
        .to_owned();
    let body = body
        .collect()
        .await
        .map(|b| b.to_bytes())
        .unwrap_or_default();
    let received = Received {
        method: parts.method.to_string(),
        path: path.clone(),
        headers: parts
            .headers
            .iter()
            .map(|(n, v)| {
                (
                    n.as_str().to_owned(),
                    String::from_utf8_lossy(v.as_bytes()).into_owned(),
                )
            })
            .collect(),
        body,
    };
    let reply = {
        let mut script = lock(&shared.script);
        script
            .once
            .get_mut(&path)
            .and_then(VecDeque::pop_front)
            .or_else(|| script.always.get(&path).cloned())
    };
    let reply = reply.unwrap_or_else(|| serve_fixture(&shared.base, &path, &received));
    lock(&shared.received).push(received);
    respond(reply, guard).await
}

/// Returns the reply for the fixture at `path`.
///
/// The reply is 200 with an `ETag`. It is 304 if `If-None-Match` has that
/// tag, and 404 if the text fixture does not exist, even for a `.gz` path.
/// Text fixtures get `${BASE}` replaced with `base`.
fn serve_fixture(base: &str, path: &str, request: &Received) -> Reply {
    let name = path.trim_start_matches('/');
    let plain = name.strip_suffix(".gz").unwrap_or(name);
    if name.is_empty() || name.contains("..") || !super::fixture_path(plain).is_file() {
        return Reply::status(404);
    }
    let mut data = super::fixture(name);
    if !name.ends_with(".gz") {
        let text = String::from_utf8_lossy(&data).replace("${BASE}", base);
        data = Bytes::from(text);
    }
    // The tag must not change between requests or runs.
    let etag = format!("\"{:016x}\"", stable_hash(&data));
    if request.header("if-none-match") == Some(etag.as_str()) {
        return Reply::status(304).header("ETag", &etag);
    }
    Reply::ok(data).header("ETag", &etag)
}

/// Returns the FNV-1a hash of `data`.
///
/// FNV-1a gives the same hash in every process and every run.
fn stable_hash(data: &[u8]) -> u64 {
    data.iter().fold(0xcbf2_9ce4_8422_2325, |hash, &byte| {
        (hash ^ u64::from(byte)).wrapping_mul(0x0100_0000_01b3)
    })
}

/// Sends `reply`.
///
/// `guard` lives until the body is sent or dropped.
async fn respond(reply: Reply, guard: InFlight) -> hyper::Response<Body> {
    if !reply.delay.is_zero() {
        tokio::time::sleep(reply.delay).await;
    }
    let mut builder = hyper::Response::builder().status(reply.status);
    for (name, value) in &reply.headers {
        builder = builder.header(name, value);
    }
    let state = (reply.clone(), VecDeque::from(reply.chunks), guard, false);
    let frames = stream::unfold(state, |(reply, mut chunks, guard, done)| async move {
        if done {
            return None;
        }
        if let Some(chunk) = chunks.pop_front() {
            if !reply.chunk_delay.is_zero() {
                tokio::time::sleep(reply.chunk_delay).await;
            }
            return Some((Ok(Frame::data(chunk)), (reply, chunks, guard, false)));
        }
        if reply.stall {
            tokio::time::sleep(Duration::from_secs(3600)).await;
        }
        if reply.cut {
            // hyper writes buffered data only while the body is pending. An
            // immediate error would discard the headers and the chunks.
            tokio::time::sleep(Duration::from_millis(50)).await;
            let error = io::Error::new(io::ErrorKind::ConnectionReset, "cut by the test");
            return Some((Err(error), (reply, chunks, guard, true)));
        }
        None
    });
    builder
        .body(StreamBody::new(frames).boxed())
        .expect("a valid scripted response")
}

/// What the proxy saw.
#[derive(Default)]
struct ProxyLog {
    /// The target of every `CONNECT`.
    connects: Mutex<Vec<String>>,
    /// The `Proxy-Authorization` of every `CONNECT`.
    authorizations: Mutex<Vec<Option<String>>>,
    /// The number of tunnels opened.
    tunnels: AtomicUsize,
}

/// A stub HTTP CONNECT proxy.
///
/// The proxy stops when dropped.
pub(crate) struct StubProxy {
    log: Arc<ProxyLog>,
    addr: SocketAddr,
    _stop: oneshot::Sender<()>,
}

impl StubProxy {
    /// Starts a proxy on a free port of `127.0.0.1`.
    ///
    /// If `authorization` is given, the proxy requires it as the exact
    /// `Proxy-Authorization` value and answers 407 to anything else.
    pub(crate) fn start(authorization: Option<&str>) -> Self {
        let listener = StdListener::bind("127.0.0.1:0").expect("a free port on 127.0.0.1");
        let addr = listener.local_addr().expect("the address of the proxy");
        let log = Arc::new(ProxyLog::default());
        let serving = Arc::clone(&log);
        let required: Option<Arc<str>> = authorization.map(Arc::from);
        let stop = spawn(listener, move |listener| async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    continue;
                };
                let log = Arc::clone(&serving);
                let required = required.clone();
                tokio::task::spawn_local(async move {
                    let _ = tunnel(stream, &log, required.as_deref()).await;
                });
            }
        });
        Self {
            log,
            addr,
            _stop: stop,
        }
    }

    /// Returns the URL of the proxy, `http://127.0.0.1:<port>`.
    pub(crate) fn url(&self) -> String {
        format!("http://{}", self.addr)
    }

    /// Returns the URL of the proxy with `userinfo`,
    /// `http://<userinfo>@127.0.0.1:<port>`.
    pub(crate) fn url_with(&self, userinfo: &str) -> String {
        format!("http://{userinfo}@{}", self.addr)
    }

    /// Returns the targets of the `CONNECT` requests so far.
    pub(crate) fn connects(&self) -> Vec<String> {
        lock(&self.log.connects).clone()
    }

    /// Returns the `Proxy-Authorization` values of the `CONNECT` requests
    /// so far.
    pub(crate) fn authorizations(&self) -> Vec<Option<String>> {
        lock(&self.log.authorizations).clone()
    }

    /// Returns the number of tunnels opened.
    pub(crate) fn tunnels(&self) -> usize {
        self.log.tunnels.load(Ordering::SeqCst)
    }
}

/// Serves one client connection of the proxy.
async fn tunnel(mut client: TcpStream, log: &ProxyLog, required: Option<&str>) -> io::Result<()> {
    // Reads the head of the request. If the head exceeds 16 KiB, the proxy
    // closes the connection.
    let mut head = Vec::new();
    let mut buffer = [0_u8; 1024];
    let end = loop {
        let read = client.read(&mut buffer).await?;
        if read == 0 {
            return Ok(());
        }
        head.extend_from_slice(&buffer[..read]);
        if let Some(at) = head.windows(4).position(|w| w == b"\r\n\r\n") {
            break at + 4;
        }
        if head.len() > 16 * 1024 {
            return Ok(());
        }
    };
    let text = String::from_utf8_lossy(&head[..end]).into_owned();
    let mut lines = text.split("\r\n");
    let request_line = lines.next().unwrap_or_default();
    let mut words = request_line.split(' ');
    let (method, target) = (words.next().unwrap_or(""), words.next().unwrap_or(""));
    let authorization = lines
        .filter_map(|line| line.split_once(':'))
        .find(|(name, _)| name.trim().eq_ignore_ascii_case("proxy-authorization"))
        .map(|(_, value)| value.trim().to_owned());
    lock(&log.connects).push(target.to_owned());
    lock(&log.authorizations).push(authorization.clone());

    if method != "CONNECT" {
        client
            .write_all(b"HTTP/1.1 405 Method Not Allowed\r\nContent-Length: 0\r\n\r\n")
            .await?;
        return Ok(());
    }
    if required.is_some() && authorization.as_deref() != required {
        client
            .write_all(
                b"HTTP/1.1 407 Proxy Authentication Required\r\n\
                  Proxy-Authenticate: Basic realm=\"stub\"\r\nContent-Length: 0\r\n\r\n",
            )
            .await?;
        return Ok(());
    }
    // Tunnels never leave the machine.
    if !target.starts_with("127.0.0.1:") {
        client
            .write_all(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n")
            .await?;
        return Ok(());
    }
    let Ok(mut upstream) = TcpStream::connect(target).await else {
        client
            .write_all(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n")
            .await?;
        return Ok(());
    };
    client
        .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        .await?;
    log.tunnels.fetch_add(1, Ordering::SeqCst);
    upstream.write_all(&head[end..]).await?;
    tokio::io::copy_bidirectional(&mut client, &mut upstream).await?;
    Ok(())
}
