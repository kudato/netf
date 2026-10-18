//! Fakes shared by the integration tests.
//!
//! The whole pipeline runs in process through [`netf::run`], with fakes in
//! place of the network, DNS, the clock, and stderr:
//!
//! - [`FakeTransport`] answers scripted responses per `(method, URL)`. It
//!   **panics on any other request**, so no test can reach a real host.
//!   Several responses for one URL are served in order, such as 200 then
//!   304, or 500, 500, then 200.
//! - [`FakeResolver`] answers DNS from a table and panics on unknown names.
//! - [`FakeClock`] moves only when a test advances it, for TTLs and the UTC
//!   day.
//! - [`CollectReporter`] keeps the stderr lines instead of printing them.
//! - [`fixture`] reads `tests/fixtures/<name>`. For a `.gz` name without a
//!   file, it compresses the text file when it reads it, so the repository
//!   keeps no compressed copies.
//! - [`TempHome`] is a new home directory under Cargo's temporary directory
//!   for tests. It is removed on drop.
//! - [`World`] puts the fakes together, and [`World::run`] runs netf.
//!
//! The worlds differ in what they serve:
//!
//! - [`World::standard`] serves the fixtures and the names of
//!   [`standard_resolver`]. The fixtures are consistent: every source has
//!   the same AS and networks. They live under
//!   `tests/fixtures/<host>/<path>`, the layout that the stub server serves
//!   for `NETF_SOURCE_BASE`. The world serves the RIS dumps, asn.txt, the
//!   delegated stats, the IANA bootstrap, and [`FakeRdap`], a fake RDAP
//!   service of the five registries.
//! - [`World::owners`] is the same world. Tests of holders use this name.
//! - [`World::search`] adds the dumps of APNIC and AFRINIC and
//!   [`FakeSearch`], the fake search services.
//!
//! [`table`] and [`full_table`] read the rows of the output back. [`Span`]
//! and [`spans`] read the addresses of rows and lists.

// Each test file uses only some of the helpers.
#![allow(dead_code)]
// `tests/common/mod.rs` is how Cargo shares code between test files without
// making it a test file of its own.
#![allow(clippy::mod_module_files)]

pub(crate) mod stub;

use std::{
    collections::{HashMap, VecDeque},
    fs,
    io::Write as _,
    path::{Path, PathBuf},
    sync::{
        Arc, Mutex, OnceLock, PoisonError,
        atomic::{AtomicUsize, Ordering},
    },
    time::{Duration, SystemTime},
};

use bytes::Bytes;
use futures_util::StreamExt as _;
use netf::{
    BodyStream, BoxFuture, Clock, DnsError, EgressId, Environment, Families, Invocation, Method,
    Notice, Outcome, Reporter, Request, Resolved, Resolver, Response, Transport, TransportError,
};

/// The value of `NETF_SOURCE_BASE` for runs without a stub server.
///
/// The port is closed. A request that gets past the fakes fails at once and
/// never reaches the internet.
pub(crate) const CLOSED_BASE: &str = "http://127.0.0.1:9";

/// Locks `mutex` and ignores poisoning.
///
/// A mutex is poisoned only after a panic, and a panic has already failed
/// the test.
fn lock<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

/// A scripted response of [`FakeTransport`].
#[derive(Clone, Debug)]
pub(crate) struct Scripted {
    /// The status code.
    pub(crate) status: u16,
    /// The response headers.
    pub(crate) headers: Vec<(String, String)>,
    /// The body, chunk by chunk. Tests split lines and gzip members at
    /// chosen places.
    pub(crate) body: Vec<Bytes>,
    /// Waits this long before answering. Tests of concurrency and
    /// interruption use the delay.
    pub(crate) delay: Option<Duration>,
    /// Ends the body with this error after the chunks, like a connection
    /// cut in the middle of a download.
    pub(crate) cut: Option<TransportError>,
    /// Fails the request itself with this error instead of answering.
    pub(crate) fail: Option<TransportError>,
    /// After the chunks, the body neither ends nor sends more, like a
    /// download that hangs. Tests of interruption use it.
    pub(crate) stall: bool,
}

impl Scripted {
    /// Returns a response with `status` and an empty body.
    pub(crate) fn status(status: u16) -> Self {
        Self {
            status,
            headers: Vec::new(),
            body: Vec::new(),
            delay: None,
            cut: None,
            fail: None,
            stall: false,
        }
    }

    /// Returns a 200 response with `body` in one chunk.
    pub(crate) fn ok(body: impl Into<Bytes>) -> Self {
        Self::status(200).chunks(vec![body.into()])
    }

    /// Returns a response that fails the request with `error`, such as a
    /// refused connection or a timeout.
    pub(crate) fn error(error: TransportError) -> Self {
        Self {
            fail: Some(error),
            ..Self::status(0)
        }
    }

    /// Adds the header `name` with `value`.
    pub(crate) fn header(mut self, name: &str, value: &str) -> Self {
        self.headers.push((name.to_owned(), value.to_owned()));
        self
    }

    /// Replaces the body with `chunks`.
    pub(crate) fn chunks(mut self, chunks: Vec<Bytes>) -> Self {
        self.body = chunks;
        self
    }

    /// Splits the body into chunks of `size` bytes.
    pub(crate) fn chunked(mut self, size: usize) -> Self {
        let whole: Vec<u8> = self.body.iter().flat_map(|c| c.iter().copied()).collect();
        self.body = whole
            .chunks(size.max(1))
            .map(Bytes::copy_from_slice)
            .collect();
        self
    }

    /// Waits `delay` before answering.
    pub(crate) fn delay(mut self, delay: Duration) -> Self {
        self.delay = Some(delay);
        self
    }

    /// Ends the body after its chunks with an I/O error.
    pub(crate) fn cut(mut self) -> Self {
        self.cut = Some(TransportError::Io("connection reset by peer".into()));
        self
    }

    /// Hangs after the chunks, so the body never ends.
    pub(crate) fn stall(mut self) -> Self {
        self.stall = true;
        self
    }
}

/// Decrements the count of requests in flight when dropped.
///
/// The guard drops when the request ends or when its future is dropped.
struct Inflight<'a>(&'a AtomicUsize);

impl Drop for Inflight<'_> {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}

/// A [`Transport`] that answers from a script and panics on anything else.
#[derive(Debug, Default)]
pub(crate) struct FakeTransport {
    routes: Mutex<HashMap<(Method, String), VecDeque<Scripted>>>,
    always: Mutex<HashMap<(Method, String), Scripted>>,
    log: Mutex<Vec<Request>>,
    inflight: AtomicUsize,
    peak: AtomicUsize,
    handlers: Mutex<Vec<Handler>>,
}

/// The signature of a handler of [`FakeTransport::handle`].
type HandlerFn = dyn Fn(&Request) -> Option<Scripted> + Send + Sync;

/// A response computed from the request, tried after the scripted ones.
struct Handler(Box<HandlerFn>);

impl std::fmt::Debug for Handler {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Handler")
    }
}

impl FakeTransport {
    /// Creates a transport with no responses.
    pub(crate) fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    /// Adds `answer` to the queue of `method url`.
    pub(crate) fn on(&self, method: Method, url: &str, answer: Scripted) -> &Self {
        lock(&self.routes)
            .entry((method, url.to_owned()))
            .or_default()
            .push_back(answer);
        self
    }

    /// Adds `answer` to the queue of `GET url`.
    pub(crate) fn get(&self, url: &str, answer: Scripted) -> &Self {
        self.on(Method::Get, url, answer)
    }

    /// Answers `GET url` with `answer` whenever its queue is empty.
    ///
    /// The source can then be downloaded any number of times.
    pub(crate) fn always(&self, url: &str, answer: Scripted) -> &Self {
        lock(&self.always).insert((Method::Get, url.to_owned()), answer);
        self
    }

    /// Adds `handler`, a fake server such as [`FakeRdap`].
    ///
    /// A handler answers a request when nothing is scripted for its URL and
    /// the handler returns `Some`. Handlers are tried in the order they were
    /// added.
    pub(crate) fn handle(
        &self,
        handler: impl Fn(&Request) -> Option<Scripted> + Send + Sync + 'static,
    ) -> &Self {
        lock(&self.handlers).push(Handler(Box::new(handler)));
        self
    }

    /// Returns the requests made to `url`, in order.
    pub(crate) fn requests_to(&self, url: &str) -> Vec<Request> {
        lock(&self.log)
            .iter()
            .filter(|r| r.url == url)
            .cloned()
            .collect()
    }

    /// Returns every request made, in order.
    pub(crate) fn requests(&self) -> Vec<Request> {
        lock(&self.log).clone()
    }

    /// Returns how many requests went to `url`, with any method.
    pub(crate) fn count(&self, url: &str) -> usize {
        lock(&self.log).iter().filter(|r| r.url == url).count()
    }

    /// Returns the largest number of requests that were in flight at once.
    pub(crate) fn peak(&self) -> usize {
        self.peak.load(Ordering::SeqCst)
    }

    /// Returns the responses that were scripted but never requested.
    pub(crate) fn unused(&self) -> Vec<(Method, String)> {
        lock(&self.routes)
            .iter()
            .filter(|(_, answers)| !answers.is_empty())
            .map(|(key, _)| key.clone())
            .collect()
    }
}

impl Transport for FakeTransport {
    fn send(&self, request: Request) -> BoxFuture<'_, Result<Response, TransportError>> {
        Box::pin(async move {
            let key = (request.method, request.url.clone());
            let scripted = lock(&self.routes)
                .get_mut(&key)
                .and_then(VecDeque::pop_front);
            let answer = scripted
                .or_else(|| lock(&self.always).get(&key).cloned())
                .or_else(|| lock(&self.handlers).iter().find_map(|h| (h.0)(&request)));
            let Some(answer) = answer else {
                panic!(
                    "FakeTransport: unexpected request {} {} (unknown URL or no answers left)",
                    request.method, request.url
                );
            };
            lock(&self.log).push(request);
            let now = self.inflight.fetch_add(1, Ordering::SeqCst) + 1;
            self.peak.fetch_max(now, Ordering::SeqCst);
            let _inflight = Inflight(&self.inflight);
            if let Some(delay) = answer.delay {
                tokio::time::sleep(delay).await;
            }
            if let Some(error) = answer.fail {
                return Err(error);
            }
            let mut items: Vec<Result<Bytes, TransportError>> =
                answer.body.into_iter().map(Ok).collect();
            if let Some(error) = answer.cut {
                items.push(Err(error));
            }
            let body = if answer.stall {
                BodyStream::new(
                    futures_util::stream::iter(items).chain(futures_util::stream::pending()),
                )
            } else {
                BodyStream::new(futures_util::stream::iter(items))
            };
            Ok(Response {
                status: answer.status,
                headers: answer.headers,
                body,
                egress: EgressId::direct(),
            })
        })
    }
}

/// A [`Resolver`] that answers from a table and panics on unknown names.
#[derive(Debug, Default)]
pub(crate) struct FakeResolver {
    answers: HashMap<String, Result<Resolved, DnsError>>,
    log: Mutex<Vec<String>>,
}

impl FakeResolver {
    /// Creates a resolver that knows no names.
    pub(crate) fn new() -> Self {
        Self::default()
    }

    /// Makes `name` resolve to the addresses `v4` and `v6`.
    pub(crate) fn with(mut self, name: &str, v4: &[&str], v6: &[&str]) -> Self {
        let resolved = Resolved {
            v4: v4
                .iter()
                .map(|a| a.parse().expect("IPv4 address"))
                .collect(),
            v6: v6
                .iter()
                .map(|a| a.parse().expect("IPv6 address"))
                .collect(),
        };
        self.answers.insert(name.to_owned(), Ok(resolved));
        self
    }

    /// Makes `name` fail with `error`.
    pub(crate) fn failing(mut self, name: &str, error: DnsError) -> Self {
        self.answers.insert(name.to_owned(), Err(error));
        self
    }

    /// Returns the names looked up, in order.
    pub(crate) fn lookups(&self) -> Vec<String> {
        lock(&self.log).clone()
    }
}

impl Resolver for FakeResolver {
    /// Returns only the families in `want`, as the real resolvers do.
    fn resolve<'a>(
        &'a self,
        name: &'a str,
        want: Families,
    ) -> BoxFuture<'a, Result<Resolved, DnsError>> {
        Box::pin(async move {
            lock(&self.log).push(name.to_owned());
            match self.answers.get(name) {
                Some(Ok(resolved)) => Ok(Resolved {
                    v4: if want.v4() {
                        resolved.v4.clone()
                    } else {
                        Vec::new()
                    },
                    v6: if want.v6() {
                        resolved.v6.clone()
                    } else {
                        Vec::new()
                    },
                }),
                Some(Err(error)) => Err(error.clone()),
                None => panic!("FakeResolver: unexpected name {name}"),
            }
        })
    }
}

/// A [`Clock`] that moves only when a test advances it.
#[derive(Debug)]
pub(crate) struct FakeClock(Mutex<SystemTime>);

impl FakeClock {
    /// Returns a clock at 2026-01-01 00:00:00 UTC.
    pub(crate) fn new() -> Self {
        Self::at(SystemTime::UNIX_EPOCH + Duration::from_secs(1_767_225_600))
    }

    /// Returns a clock at `time`.
    pub(crate) fn at(time: SystemTime) -> Self {
        Self(Mutex::new(time))
    }

    /// Moves the clock forward by `by`.
    pub(crate) fn advance(&self, by: Duration) {
        *lock(&self.0) += by;
    }
}

impl Default for FakeClock {
    fn default() -> Self {
        Self::new()
    }
}

impl Clock for FakeClock {
    fn now(&self) -> SystemTime {
        *lock(&self.0)
    }
}

/// A [`Reporter`] that keeps the lines of stderr.
#[derive(Debug, Default)]
pub(crate) struct CollectReporter {
    lines: Mutex<Vec<String>>,
    progress: Mutex<Vec<(u32, u32, &'static str)>>,
}

impl CollectReporter {
    /// Creates an empty reporter.
    pub(crate) fn new() -> Self {
        Self::default()
    }

    /// Returns the notices and the error, as they would be printed.
    pub(crate) fn lines(&self) -> Vec<String> {
        lock(&self.lines).clone()
    }

    /// Returns every progress report as `(done, total, what)`.
    pub(crate) fn progress(&self) -> Vec<(u32, u32, &'static str)> {
        lock(&self.progress).clone()
    }
}

impl Reporter for CollectReporter {
    fn notice(&self, notice: &Notice) {
        lock(&self.lines).push(notice.to_string());
    }

    fn error(&self, message: &str) {
        lock(&self.lines).push(message.to_owned());
    }

    fn progress(&self, done: u32, total: u32, what: &'static str) {
        lock(&self.progress).push((done, total, what));
    }

    fn clear_progress(&self) {}
}

/// Returns the path of `tests/fixtures/<name>`.
pub(crate) fn fixture_path(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(name)
}

/// Reads the fixture `name`.
///
/// If `name` ends with `.gz` and only the text file exists, returns the
/// text file compressed with gzip.
///
/// # Panics
///
/// Panics if the fixture does not exist.
pub(crate) fn fixture(name: &str) -> Bytes {
    let path = fixture_path(name);
    if let Ok(data) = fs::read(&path) {
        return data.into();
    }
    let Some(plain) = name.strip_suffix(".gz") else {
        panic!("no fixture {}", path.display());
    };
    let data = fs::read(fixture_path(plain))
        .unwrap_or_else(|e| panic!("no fixture {name} or {plain}: {e}"));
    gzip(&data)
}

/// Compresses `data` with gzip, for responses made up by a test.
pub(crate) fn gzip(data: &[u8]) -> Bytes {
    let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
    encoder.write_all(data).expect("gzip in memory");
    encoder.finish().expect("gzip in memory").into()
}

/// A new home directory, removed on drop.
///
/// The directory is under Cargo's temporary directory for integration
/// tests, inside `target/`, and not under the system's. Tests write nothing
/// outside the build tree.
#[derive(Debug)]
pub(crate) struct TempHome {
    path: PathBuf,
}

impl TempHome {
    /// Creates a home whose base config holds only [`SOURCES_CONFIG`].
    pub(crate) fn new() -> Self {
        let home = Self::bare();
        home.base_config("");
        home
    }

    /// Creates an empty home, as before the first run of netf.
    ///
    /// The name of the directory holds the process ID and a counter, so no
    /// two homes share a directory. Without a config, the sources are the real
    /// defaults, so a run in this home must not download anything.
    pub(crate) fn bare() -> Self {
        static NEXT: AtomicUsize = AtomicUsize::new(0);
        let id = NEXT.fetch_add(1, Ordering::SeqCst);
        let path = Path::new(env!("CARGO_TARGET_TMPDIR"))
            .join(format!("home-{}-{id}", std::process::id()));
        // Removes a directory left by a crashed run with the same pid.
        let _ = fs::remove_dir_all(&path);
        fs::create_dir_all(&path).expect("create the test home");
        Self { path }
    }

    /// Returns the path of the home.
    pub(crate) fn path(&self) -> &Path {
        &self.path
    }

    /// Writes `text` followed by [`SOURCES_CONFIG`] to the base config,
    /// `~/.netf/config.toml`.
    ///
    /// Creates `~/.netf` with mode 0700, because netf refuses a `~/.netf`
    /// that other users can access.
    pub(crate) fn base_config(&self, text: &str) {
        let dir = self.path.join(".netf");
        fs::create_dir_all(&dir).expect("create ~/.netf");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).expect("chmod ~/.netf");
        }
        let mut text = text.to_owned();
        if !text.is_empty() && !text.ends_with('\n') {
            text.push('\n');
        }
        text.push_str(SOURCES_CONFIG);
        fs::write(dir.join("config.toml"), text).expect("write the config");
    }
}

/// The `[sources]` table of every test home.
///
/// The hosts are synthetic, and the paths are those of the default sources.
/// Under `NETF_SOURCE_BASE`, each URL maps to
/// `tests/fixtures/<host>/<path>`.
pub(crate) const SOURCES_CONFIG: &str = "\
[sources]
ris-v4 = \"https://ris.ripe.test/dumps/riswhoisdump.IPv4.gz\"
ris-v6 = \"https://ris.ripe.test/dumps/riswhoisdump.IPv6.gz\"
asn = \"https://ftp.ripe.test/ripe/asnames/asn.txt\"
stats-ripencc = \"https://ftp.ripe.test/pub/stats/ripencc/delegated-ripencc-extended-latest\"
stats-arin = \"https://ftp.arin.test/pub/stats/arin/delegated-arin-extended-latest\"
stats-apnic = \"https://ftp.apnic.test/stats/apnic/delegated-apnic-extended-latest\"
stats-lacnic = \"https://ftp.lacnic.test/pub/stats/lacnic/delegated-lacnic-extended-latest\"
stats-afrinic = \"https://ftp.afrinic.test/stats/afrinic/delegated-afrinic-extended-latest\"
whois-apnic-inetnum = \"https://ftp.apnic.test/apnic/whois/apnic.db.inetnum.gz\"
whois-apnic-inet6num = \"https://ftp.apnic.test/apnic/whois/apnic.db.inet6num.gz\"
whois-apnic-aut-num = \"https://ftp.apnic.test/apnic/whois/apnic.db.aut-num.gz\"
whois-apnic-organisation = \"https://ftp.apnic.test/apnic/whois/apnic.db.organisation.gz\"
whois-afrinic-db = \"https://ftp.afrinic.test/dbase/afrinic.db.gz\"
bootstrap-asn = \"https://data.iana.test/rdap/asn.json\"
bootstrap-ipv4 = \"https://data.iana.test/rdap/ipv4.json\"
bootstrap-ipv6 = \"https://data.iana.test/rdap/ipv6.json\"
ripe-rest = \"https://rest.ripe.test\"
";

impl Default for TempHome {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for TempHome {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

/// Returns the environment of a test run.
///
/// `home` is both the home and the current directory, and `HOME` points at
/// it. `NETF_SOURCE_BASE` is [`CLOSED_BASE`].
pub(crate) fn environment(home: &Path) -> Environment {
    let vars = [
        ("HOME", home.to_string_lossy().into_owned()),
        ("NETF_SOURCE_BASE", CLOSED_BASE.to_owned()),
    ];
    Environment {
        home: Some(home.to_path_buf()),
        cwd: home.to_path_buf(),
        vars: vars.into_iter().map(|(k, v)| (k.to_owned(), v)).collect(),
        ..Environment::default()
    }
}

/// Everything a run sees: fakes for the network, DNS, the clock, and
/// stderr, and a home directory.
#[derive(Debug)]
pub(crate) struct World {
    /// The network.
    pub(crate) transport: Arc<FakeTransport>,
    /// DNS.
    pub(crate) resolver: Arc<FakeResolver>,
    /// The clock.
    pub(crate) clock: Arc<FakeClock>,
    /// The home directory.
    pub(crate) home: TempHome,
    /// The fake RDAP service, after [`World::serve_registries`] runs.
    rdap: OnceLock<Arc<FakeRdap>>,
}

impl World {
    /// Returns a world with no responses and no names.
    ///
    /// The home holds only [`SOURCES_CONFIG`].
    pub(crate) fn new() -> Self {
        Self::with_resolver(FakeResolver::new())
    }

    /// Returns a world with an empty home, as before the first run.
    ///
    /// See [`TempHome::bare`].
    pub(crate) fn bare() -> Self {
        Self {
            home: TempHome::bare(),
            ..Self::new()
        }
    }

    /// Returns a world that resolves names with `resolver`.
    pub(crate) fn with_resolver(resolver: FakeResolver) -> Self {
        Self {
            transport: FakeTransport::new(),
            resolver: Arc::new(resolver),
            clock: Arc::new(FakeClock::new()),
            home: TempHome::new(),
            rdap: OnceLock::new(),
        }
    }

    /// Builds the invocation of `args` and the reporter it writes to.
    pub(crate) fn invocation(&self, args: &[&str]) -> (Invocation, Arc<CollectReporter>) {
        let reporter = Arc::new(CollectReporter::new());
        let invocation = Invocation {
            args: args.iter().map(Into::into).collect(),
            env: environment(self.home.path()),
            transport: Some(self.transport.clone()),
            resolver: Some(self.resolver.clone()),
            clock: self.clock.clone(),
            reporter: reporter.clone(),
        };
        (invocation, reporter)
    }

    /// Runs netf with `args` and returns the outcome and the stderr lines.
    pub(crate) fn run(&self, args: &[&str]) -> (Outcome, Vec<String>) {
        let (invocation, reporter) = self.invocation(args);
        let outcome = runtime().block_on(netf::run(invocation));
        (outcome, reporter.lines())
    }
}

impl Default for World {
    fn default() -> Self {
        Self::new()
    }
}

/// Runs `args` in `world` and returns the outcome.
pub(crate) fn run_query(args: &[&str], world: &World) -> Outcome {
    world.run(args).0
}

/// Returns a runtime like the binary's: one thread, with I/O and timers.
pub(crate) fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("a Tokio runtime")
}

// The world of the fixtures.
//
// One set of synthetic data, consistent between the sources. It uses
// AS 64496–64511 (RFC 5398), the networks 192.0.2.0/24, 198.51.100.0/24,
// and 203.0.113.0/24 (RFC 5737), 2001:db8::/32 (RFC 3849), and invented
// names. The files live where the stub server looks for them,
// `tests/fixtures/<host>/<path>`, so the in-process tests and the tests of
// the binary read the same data.
//
// RIS IPv4 (`riswhoisdump.IPv4`):
//
// | route              | origins        |
// |--------------------|----------------|
// | 192.0.2.0/24       | 64496, 64497   |
// | 192.0.2.0/26       | 64496          |
// | 192.0.2.64/27      | 64498          |
// | 192.0.2.128/27     | {64499,64500}  |
// | 198.51.100.0/24    | 64501          |
// | 198.51.100.128/25  | 64502          |
// | 203.0.113.0/28 … 203.0.113.112/28 (8 routes) | 64503 |
// | 203.0.113.128/27   | 64507 (not in asn.txt) |
// | 203.0.113.160/27   | 64504          |
//
// 203.0.113.192/26 is not announced. RIS IPv6: 2001:db8::/32 (64496,
// 64497), 2001:db8:100::/40 (64506), 2001:db8:200::/48 ({64499,64500}).
//
// asn.txt: 64496 EXAMPLE-NET (XA), 64497 TELE-EDGE (XB, organization with
// a comma), 64498 DOCNET (XE), 64499 SETONE (XC), 64500 SETTWO (XC),
// 64501 HOMENET (XD), 64502 ROGUE (XB), 64503 EXAMPLE-CDN (XF, while the
// APNIC stats say XG),
// 64504 NOCOUNTRY-AS (no country), 64505 QUIET-AS (`- ` form, XE, no
// routes), 64506 SIXNET (XD, IPv6 only). 64507 has routes but no line.
// 64511 has neither.

/// The URL of the RIS IPv4 dump, rewritten to [`CLOSED_BASE`].
pub(crate) const RIS_V4: &str = "http://127.0.0.1:9/ris.ripe.test/dumps/riswhoisdump.IPv4.gz";
/// The URL of the RIS IPv6 dump, rewritten to [`CLOSED_BASE`].
pub(crate) const RIS_V6: &str = "http://127.0.0.1:9/ris.ripe.test/dumps/riswhoisdump.IPv6.gz";
/// The URL of asn.txt, rewritten to [`CLOSED_BASE`].
pub(crate) const ASN_TXT: &str = "http://127.0.0.1:9/ftp.ripe.test/ripe/asnames/asn.txt";

/// The fixture of the RIS IPv4 dump, compressed by [`fixture`] when read.
pub(crate) const RIS_V4_FIXTURE: &str = "ris.ripe.test/dumps/riswhoisdump.IPv4.gz";
/// The fixture of the RIS IPv6 dump, compressed by [`fixture`] when read.
pub(crate) const RIS_V6_FIXTURE: &str = "ris.ripe.test/dumps/riswhoisdump.IPv6.gz";
/// The fixture of asn.txt.
pub(crate) const ASN_FIXTURE: &str = "ftp.ripe.test/ripe/asnames/asn.txt";

/// The validators the fixtures are served with.
pub(crate) const ETAG: &str = "\"fixture-1\"";
/// See [`ETAG`].
pub(crate) const LAST_MODIFIED: &str = "Thu, 01 Jan 2026 00:00:00 GMT";

/// Returns a 200 response with the fixture `name` and both validators.
pub(crate) fn dataset(name: &str) -> Scripted {
    Scripted::ok(fixture(name))
        .header("ETag", ETAG)
        .header("Last-Modified", LAST_MODIFIED)
}

/// Returns a resolver that knows the names of the world.
///
/// - `www.example.test` resolves to 192.0.2.10 (in 192.0.2.0/26),
///   198.51.100.130 (in 198.51.100.128/25), and 2001:db8::10 (in
///   2001:db8::/32).
/// - `v4only.example.test` resolves to 203.0.113.200, which is not
///   announced. It has no AAAA record.
/// - `xn--hxajbheg2az3al.xn--jxalpdlp` resolves to 192.0.2.70. The name is
///   the punycode form of `παράδειγμα.δοκιμή`. The table holds that form
///   because netf sends names to DNS in punycode.
/// - `nx.example.test` fails with NXDOMAIN.
/// - `broken.example.test` fails with SERVFAIL.
pub(crate) fn standard_resolver() -> FakeResolver {
    FakeResolver::new()
        .with(
            "www.example.test",
            &["192.0.2.10", "198.51.100.130"],
            &["2001:db8::10"],
        )
        .with("v4only.example.test", &["203.0.113.200"], &[])
        .with("xn--hxajbheg2az3al.xn--jxalpdlp", &["192.0.2.70"], &[])
        .failing("nx.example.test", DnsError::NotFound)
        .failing("broken.example.test", DnsError::Failed("SERVFAIL".into()))
}

/// Returns the sorted names of the files in `dir`.
///
/// Returns an empty list if `dir` does not exist.
pub(crate) fn files_in(dir: &Path) -> Vec<String> {
    let mut names: Vec<String> = fs::read_dir(dir)
        .map(|entries| {
            entries
                .filter_map(Result::ok)
                .map(|e| e.file_name().to_string_lossy().into_owned())
                .collect()
        })
        .unwrap_or_default();
    names.sort();
    names
}

/// Returns every file under `dir`, recursively, as sorted paths relative to
/// `dir`.
pub(crate) fn files_under(dir: &Path) -> Vec<String> {
    fn walk(root: &Path, dir: &Path, out: &mut Vec<String>) {
        let Ok(entries) = fs::read_dir(dir) else {
            return;
        };
        for entry in entries.filter_map(Result::ok) {
            let path = entry.path();
            if path.is_dir() {
                walk(root, &path, out);
            } else {
                let relative = path.strip_prefix(root).unwrap_or(&path);
                out.push(relative.to_string_lossy().into_owned());
            }
        }
    }
    let mut out = Vec::new();
    walk(dir, dir, &mut out);
    out.sort();
    out
}

impl World {
    /// Returns a world with the fixtures.
    ///
    /// Every dataset can be downloaded any number of times, and DNS knows
    /// the names of [`standard_resolver`]. Rows need asn.txt and the
    /// registries besides the routes, so the world serves the registries
    /// too.
    pub(crate) fn standard() -> Self {
        let world = Self::with_resolver(standard_resolver());
        world.serve_datasets();
        world.serve_registries();
        world
    }

    /// Serves the RIS dumps and asn.txt whenever nothing else is queued.
    pub(crate) fn serve_datasets(&self) {
        self.transport.always(RIS_V4, dataset(RIS_V4_FIXTURE));
        self.transport.always(RIS_V6, dataset(RIS_V6_FIXTURE));
        self.transport.always(ASN_TXT, dataset(ASN_FIXTURE));
    }

    /// Returns the path of `~/.netf`.
    pub(crate) fn netf_dir(&self) -> PathBuf {
        self.home.path().join(".netf")
    }

    /// Returns the path of the default cache directory, `~/.netf/cache`.
    pub(crate) fn cache_dir(&self) -> PathBuf {
        self.netf_dir().join("cache")
    }

    /// Writes `text` to `name` in the home and returns the path.
    ///
    /// The home is also the current directory of the runs.
    pub(crate) fn write(&self, name: &str, text: &str) -> PathBuf {
        let path = self.home.path().join(name);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).expect("create the directory");
        }
        fs::write(&path, text).expect("write the file");
        path
    }

    /// Writes `text` and the sources of the tests to the base config.
    ///
    /// See [`TempHome::base_config`].
    pub(crate) fn base_config(&self, text: &str) {
        self.home.base_config(text);
    }

    /// Runs `args` and returns stdout and the stderr lines.
    ///
    /// # Panics
    ///
    /// Panics if the exit code is not 0 or stdout is not UTF-8.
    pub(crate) fn ok(&self, args: &[&str]) -> (String, Vec<String>) {
        let (outcome, stderr) = self.run(args);
        assert_eq!(outcome.code, 0, "netf {args:?} failed: {stderr:?}");
        let stdout = String::from_utf8(outcome.stdout).expect("UTF-8 stdout");
        (stdout, stderr)
    }

    /// Runs `args` and returns the exit code and the stderr lines.
    ///
    /// A failed run of netf prints nothing on stdout.
    ///
    /// # Panics
    ///
    /// Panics if the run succeeds or prints anything on stdout.
    pub(crate) fn fail(&self, args: &[&str]) -> (u8, Vec<String>) {
        let (outcome, stderr) = self.run(args);
        assert_ne!(outcome.code, 0, "netf {args:?} succeeded: {stderr:?}");
        assert!(
            outcome.stdout.is_empty(),
            "netf {args:?} failed but printed {:?}",
            String::from_utf8_lossy(&outcome.stdout)
        );
        (outcome.code, stderr)
    }
}

/// One row of the output, cut to the columns part, route, and AS.
///
/// The other columns are network, holder, and abuse. [`full_table`] reads
/// them.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct Row {
    /// The part, `None` if the table has no such column, or `Some("-")` if
    /// the row took its route whole.
    pub(crate) part: Option<String>,
    /// The route, or `no route`.
    pub(crate) route: String,
    /// The AS of the route, such as `AS64496 EXAMPLE-NET, AS64497 TELE-EDGE`.
    pub(crate) ases: String,
}

impl Row {
    /// Returns the addresses of the row.
    ///
    /// These are the addresses of the part if there is one, else those of
    /// the route. Returns `None` for a row without either.
    pub(crate) fn addresses(&self) -> Option<Span> {
        match self.part.as_deref() {
            Some(part) if part != "-" => Some(Span::parse(part)),
            _ if self.route != "no route" => Some(Span::parse(&self.route)),
            _ => None,
        }
    }
}

/// The rows of a run.
#[derive(Clone, Debug)]
pub(crate) struct Table {
    /// Whether the table has the column part.
    ///
    /// netf prints the column only when some row has a part. A row has a
    /// part when the query takes less than its whole route.
    pub(crate) has_part: bool,
    /// The rows, in the order printed.
    pub(crate) rows: Vec<Row>,
}

impl Table {
    /// Returns the routes in the order printed.
    pub(crate) fn routes(&self) -> Vec<&str> {
        self.rows.iter().map(|r| r.route.as_str()).collect()
    }

    /// Returns the routes, sorted and without repeats.
    pub(crate) fn route_set(&self) -> Vec<&str> {
        let mut routes = self.routes();
        routes.sort_unstable();
        routes.dedup();
        routes
    }

    /// Returns the rows of `route`.
    pub(crate) fn of(&self, route: &str) -> Vec<&Row> {
        self.rows.iter().filter(|r| r.route == route).collect()
    }

    /// Returns the only row of `route`.
    ///
    /// # Panics
    ///
    /// Panics if `route` has no row or more than one.
    pub(crate) fn one(&self, route: &str) -> &Row {
        let rows = self.of(route);
        assert_eq!(rows.len(), 1, "rows of {route}: {:?}", self.rows);
        rows[0]
    }

    /// Returns the union of the addresses of all rows.
    pub(crate) fn addresses(&self) -> Vec<Span> {
        merge(self.rows.iter().filter_map(Row::addresses).collect())
    }

    /// Checks that the rows are in the order of addresses, IPv4 first.
    ///
    /// A row sorts by the first address of its part or its route.
    pub(crate) fn assert_in_address_order(&self) {
        let firsts: Vec<(bool, u128)> = self
            .rows
            .iter()
            .filter_map(Row::addresses)
            .map(|s| (s.v6, s.first))
            .collect();
        let mut sorted = firsts.clone();
        sorted.sort_unstable();
        assert_eq!(firsts, sorted, "rows out of order: {:?}", self.rows);
    }

    /// Checks the order of a table with pieces.
    ///
    /// The routes must be in the order of addresses. The pieces of each
    /// route must stay together and in order, because netf orders and
    /// limits whole routes.
    pub(crate) fn assert_grouped_by_route(&self) {
        // Runs of rows of one route, in order.
        let mut groups: Vec<(&str, Vec<Span>)> = Vec::new();
        for row in self.rows.iter().filter(|r| r.route != "no route") {
            let part = row.addresses().expect("a route");
            match groups.last_mut() {
                Some((route, parts)) if *route == row.route => parts.push(part),
                _ => groups.push((&row.route, vec![part])),
            }
        }
        let routes: Vec<&str> = groups.iter().map(|(r, _)| *r).collect();
        let mut unique = routes.clone();
        unique.sort_unstable();
        unique.dedup();
        assert_eq!(
            routes.len(),
            unique.len(),
            "pieces torn apart: {:?}",
            self.rows
        );
        let firsts: Vec<(bool, u128)> = routes
            .iter()
            .map(|r| Span::parse(r))
            .map(|s| (s.v6, s.first))
            .collect();
        assert!(firsts.is_sorted(), "routes out of order: {:?}", self.rows);
        for (route, parts) in &groups {
            assert!(
                parts.is_sorted(),
                "pieces of {route} out of order: {:?}",
                self.rows
            );
        }
    }
}

/// Splits a line of the table into its columns.
///
/// Two spaces or more separate the values, and no value contains two
/// spaces in a row.
pub(crate) fn columns(line: &str) -> Vec<&str> {
    line.split("  ")
        .map(str::trim)
        .filter(|c| !c.is_empty())
        .collect()
}

/// Reads the rows of `stdout`, keeping the columns part, route, and AS.
///
/// Without the column part, the second column is the AS. It starts with
/// `AS`, or it is `-` for a row without a route. With the column part, the
/// second column is the route.
///
/// # Panics
///
/// Panics if a line has too few columns.
pub(crate) fn table(stdout: &str) -> Table {
    let lines: Vec<Vec<&str>> = stdout.lines().map(columns).collect();
    let has_part = lines
        .first()
        .is_some_and(|c| c.len() > 1 && !c[1].starts_with("AS") && c[1] != "-");
    let rows = lines
        .iter()
        .map(|c| {
            let need = if has_part { 3 } else { 2 };
            assert!(c.len() >= need, "too few columns in {c:?} of\n{stdout}");
            if has_part {
                Row {
                    part: Some(c[0].to_owned()),
                    route: c[1].to_owned(),
                    ases: c[2].to_owned(),
                }
            } else {
                Row {
                    part: None,
                    route: c[0].to_owned(),
                    ases: c[1].to_owned(),
                }
            }
        })
        .collect();
    Table { has_part, rows }
}

/// A range of addresses of one family.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub(crate) struct Span {
    /// IPv6, not IPv4.
    pub(crate) v6: bool,
    /// The first address.
    pub(crate) first: u128,
    /// The last address.
    pub(crate) last: u128,
}

impl Span {
    /// Parses an address, a prefix `a/len`, or a range `a-b`.
    ///
    /// # Panics
    ///
    /// Panics if `text` is none of these, or if a prefix has host bits set.
    pub(crate) fn parse(text: &str) -> Self {
        fn addr(text: &str) -> (bool, u128) {
            match text
                .parse::<std::net::IpAddr>()
                .unwrap_or_else(|e| panic!("not an address: {text:?}: {e}"))
            {
                std::net::IpAddr::V4(a) => (false, u128::from(u32::from(a))),
                std::net::IpAddr::V6(a) => (true, u128::from(a)),
            }
        }
        if let Some((a, b)) = text.split_once('-') {
            let (v6, first) = addr(a);
            let (v6b, last) = addr(b);
            assert_eq!(v6, v6b, "a range across families: {text}");
            return Self { v6, first, last };
        }
        let (a, len) = text.split_once('/').unwrap_or((text, ""));
        let (v6, value) = addr(a);
        let bits = if v6 { 128 } else { 32 };
        let len: u32 = if len.is_empty() {
            bits
        } else {
            len.parse().expect("a prefix length")
        };
        assert!(len <= bits, "prefix too long: {text}");
        let host = if len == bits {
            0
        } else {
            (1u128 << (bits - len)) - 1
        };
        assert_eq!(value & host, 0, "host bits set in {text}");
        Self {
            v6,
            first: value,
            last: value | host,
        }
    }

    /// Formats an address of this family.
    fn format(&self, value: u128) -> String {
        if self.v6 {
            std::net::Ipv6Addr::from(value).to_string()
        } else {
            std::net::Ipv4Addr::from(u32::try_from(value).expect("an IPv4 address")).to_string()
        }
    }

    /// Returns the minimal list of prefixes that cover exactly this range.
    pub(crate) fn prefixes(&self) -> Vec<String> {
        let bits: u32 = if self.v6 { 128 } else { 32 };
        let mut out = Vec::new();
        let mut first = self.first;
        loop {
            // The largest block aligned at `first` that ends by `last`.
            let mut size = first.trailing_zeros().min(bits);
            while size > 0 && first + ((1u128 << size) - 1) > self.last {
                size -= 1;
            }
            out.push(format!("{}/{}", self.format(first), bits - size));
            let end = first + ((1u128 << size) - 1);
            if end >= self.last {
                return out;
            }
            first = end + 1;
        }
    }
}

/// Returns the union of `spans`, sorted and without overlaps or neighbors.
pub(crate) fn merge(mut spans: Vec<Span>) -> Vec<Span> {
    spans.sort_unstable();
    let mut out: Vec<Span> = Vec::new();
    for span in spans {
        match out.last_mut() {
            Some(last) if last.v6 == span.v6 && span.first <= last.last.saturating_add(1) => {
                last.last = last.last.max(span.last);
            }
            _ => out.push(span),
        }
    }
    out
}

/// Parses every text with [`Span::parse`] and merges them.
pub(crate) fn spans<'a>(texts: impl IntoIterator<Item = &'a str>) -> Vec<Span> {
    merge(texts.into_iter().map(Span::parse).collect())
}

/// Returns the collapsed list of `spans` as `--ipset` prints it.
///
/// The list holds the minimal prefixes, one per line, IPv4 first.
pub(crate) fn ipset_of(spans: &[Span]) -> String {
    merge(spans.to_vec())
        .iter()
        .flat_map(Span::prefixes)
        .map(|p| p + "\n")
        .collect()
}

// The registries.
//
// The delegated stats of the five registries, the IANA bootstrap, and the
// RDAP answers are consistent with the routes above. The stats are in
// `tests/fixtures/ftp.<rir>…/delegated-<rir>-extended-latest`:
//
// | registry | block                                   | AS                    |
// |----------|-----------------------------------------|-----------------------|
// | ripencc  | XA 192.0.2.0/24, XA 2001:db8::/32       | 64496 XA, 64497 XB, 64499–64500 XC, 64501 XD, 64502 XB, 64506 XD |
// | arin     | XE 198.51.100.0/24, 233.252.0.0/24 available | 64498 XE, 64505 XE |
// | apnic    | XG 203.0.113.0 + 96 (not a CIDR block), 203.0.113.96/27 reserved | 64503 XG |
// | lacnic   | XH 203.0.113.128 + 96, opaque-id L3C0FFEE | 64504, 64507 XH, L3C0FFEE |
// | afrinic  | XI 203.0.113.224/27, opaque-id FEXAMPLE1 | 64508–64510 XI, 64511 available |
//
// So 203.0.113.192/27 (lacnic) and 203.0.113.224/27 (afrinic) are blocks
// without a route, and 203.0.113.96/28 and 203.0.113.112/28 are routes
// without a block.
//
// The RDAP answers (RFC 9083) are in
// `tests/fixtures/<server>/…/{ip,autnum,entity}/…`, and `FakeRdap` serves
// them. The networks of each registry, most specific last:
//
// - RIPE: 192.0.2.0/24 ORG-EN1-RIPE "Example Networks LLC" XA, with abuse
//   abuse@example.net, administrative JD1-RIPE without e-mail in the
//   network answer, and
//   technical NOC1-RIPE with its own JS1-RIPE. 192.0.2.0/26 ORG-CH1-RIPE
//   "Client Hosting Ltd" XB (abuse@client-hosting.example, MR1-RIPE without
//   e-mail in the network answer). 192.0.2.128/25 "Lease Broker LLC" XE, and inside it
//   192.0.2.128/27 "Tenant One GmbH" XC (`links rel=up`: /27 → /25 → /24).
//   2001:db8::/32 EN1, XA. The entities include ORG-EN1-RIPE, ORG-CH1-RIPE
//   (no AS), and the persons JD1-RIPE and MR1-RIPE, whose own answers have
//   an e-mail.
//   ORG-EN1-RIPE has the networks /24 and 2001:db8::/32, AS64496, and
//   AS64502, which ORG-RT1-RIPE holds with EN1 only as sponsor.
//   ORG-EN1-RIPE also has the notice `limited search results to 100
//   maximum`. Every RIPE AS has an abuse role.
// - ARIN: 198.51.100.0/24 DNI-1 "Documentation Net Inc" XE, with contacts
//   nested in the organization: ABUSE1-ARIN abuse@docnet.example,
//   ADMIN1-ARIN, and the technical NOC1-ARIN and NOC2-ARIN.
//   198.51.100.128/26 "Small Customer LLC" XE, with no contacts. AS64498
//   (DNI-1) and AS64505 (QN-1 "Quiet Networks, Inc.", no networks). The
//   entity DNI-1 has the notice `result set truncated due to
//   authorization`.
// - APNIC: 203.0.113.0–203.0.113.95 ORG-ECL1-AP "Example CDN Ltd" XG (IRT
//   irt@cdn.example). 203.0.113.16/28 "CDN Customer Pty Ltd" XG. AS64503
//   with abuse@cdn.example.
// - LACNIC answers 307 to rdap.registro.test for 203.0.113.128/25. There,
//   203.0.113.128/26 "Rede Exemplo Ltda", inside it 203.0.113.160/27
//   "Provedor Exemplo Ltda", and 203.0.113.192/27 "Ilha Exemplo Ltda" are
//   all XH, with one contact in all three roles. AS64504 and AS64507.
// - AFRINIC: 203.0.113.224/27 ORG-SN1-AFRINIC "Savanna Net Ltd" XI, with
//   no abuse. AS64508–64510, with no abuse.

/// The delegated stats of each registry: the registry, the URL rewritten
/// to [`CLOSED_BASE`], and the fixture.
pub(crate) const STATS: [(&str, &str, &str); 5] = [
    (
        "ripencc",
        "http://127.0.0.1:9/ftp.ripe.test/pub/stats/ripencc/delegated-ripencc-extended-latest",
        "ftp.ripe.test/pub/stats/ripencc/delegated-ripencc-extended-latest",
    ),
    (
        "arin",
        "http://127.0.0.1:9/ftp.arin.test/pub/stats/arin/delegated-arin-extended-latest",
        "ftp.arin.test/pub/stats/arin/delegated-arin-extended-latest",
    ),
    (
        "apnic",
        "http://127.0.0.1:9/ftp.apnic.test/stats/apnic/delegated-apnic-extended-latest",
        "ftp.apnic.test/stats/apnic/delegated-apnic-extended-latest",
    ),
    (
        "lacnic",
        "http://127.0.0.1:9/ftp.lacnic.test/pub/stats/lacnic/delegated-lacnic-extended-latest",
        "ftp.lacnic.test/pub/stats/lacnic/delegated-lacnic-extended-latest",
    ),
    (
        "afrinic",
        "http://127.0.0.1:9/ftp.afrinic.test/stats/afrinic/delegated-afrinic-extended-latest",
        "ftp.afrinic.test/stats/afrinic/delegated-afrinic-extended-latest",
    ),
];

/// The IANA bootstrap files: the URL rewritten to [`CLOSED_BASE`], and the
/// fixture.
///
/// The fixtures name the RDAP servers of [`RDAP_HOSTS`], and
/// `NETF_SOURCE_BASE` rewrites those URLs like every source.
pub(crate) const BOOTSTRAP: [(&str, &str); 3] = [
    (
        "http://127.0.0.1:9/data.iana.test/rdap/asn.json",
        "data.iana.test/rdap/asn.json",
    ),
    (
        "http://127.0.0.1:9/data.iana.test/rdap/ipv4.json",
        "data.iana.test/rdap/ipv4.json",
    ),
    (
        "http://127.0.0.1:9/data.iana.test/rdap/ipv6.json",
        "data.iana.test/rdap/ipv6.json",
    ),
];

/// The RDAP servers of the fixtures, each a directory of `tests/fixtures`.
pub(crate) const RDAP_HOSTS: [&str; 6] = [
    "rdap.db.ripe.test",
    "rdap.arin.test",
    "rdap.apnic.test",
    "rdap.lacnic.test",
    "rdap.afrinic.test",
    "rdap.registro.test",
];

/// An RDAP request, read back from its URL.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub(crate) struct RdapCall {
    /// The server, one of [`RDAP_HOSTS`].
    pub(crate) host: String,
    /// `ip`, `autnum`, `entity`, or `entities`.
    pub(crate) kind: String,
    /// What was asked, percent-decoded, such as `192.0.2.0/24`, `64496`, or
    /// a handle. For `entities`, the query string.
    pub(crate) value: String,
}

/// Decodes `%XX` escapes.
fn percent_decode(text: &str) -> String {
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%'
            && let Some(hex) = text.get(i + 1..i + 3)
            && let Ok(byte) = u8::from_str_radix(hex, 16)
        {
            out.push(byte);
            i += 3;
            continue;
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Reads an RDAP request from `url`.
///
/// The URL is rewritten to [`CLOSED_BASE`], or it is as is for a redirect
/// or a link that the client did not rewrite. Returns `None` if the URL is
/// not of an RDAP server of the fixtures.
pub(crate) fn rdap_call(url: &str) -> Option<RdapCall> {
    let rest = url
        .strip_prefix(CLOSED_BASE)
        .and_then(|r| r.strip_prefix('/'))
        .or_else(|| url.split_once("://").map(|(_, r)| r))?;
    let (host, path) = rest.split_once('/')?;
    if !RDAP_HOSTS.contains(&host) {
        return None;
    }
    let (path, query) = path.split_once('?').unwrap_or((path, ""));
    let segments: Vec<&str> = path.split('/').collect();
    let at = segments
        .iter()
        .rposition(|s| matches!(*s, "ip" | "autnum" | "entity" | "entities"))?;
    let kind = segments[at].to_owned();
    let value = if kind == "entities" {
        percent_decode(query)
    } else {
        percent_decode(&segments[at + 1..].join("/"))
    };
    Some(RdapCall {
        host: host.to_owned(),
        kind,
        value,
    })
}

/// What a record of [`FakeRdap`] answers for.
#[derive(Clone, Debug)]
enum RdapKey {
    /// An `ip network`, by its range.
    Net(Span),
    /// An `autnum`, by its range of numbers.
    As(u32, u32),
    /// An `entity`, by its handle in uppercase.
    Entity(String),
}

/// One record of [`FakeRdap`].
#[derive(Clone, Debug)]
struct RdapRecord {
    host: String,
    key: RdapKey,
    body: Bytes,
}

/// A fake RDAP service of the five registries and rdap.registro.test over
/// the JSON fixtures.
///
/// The service answers like a real server, not by URL:
///
/// - `ip/<address or prefix>` returns the most specific network of that
///   server that covers the whole address or prefix, else 404.
/// - `autnum/<n>` returns the record whose range has `n`, else 404.
/// - `entity/<handle>` returns the entity with that handle, ignoring case,
///   else 404.
/// - `entities?…` returns an empty search result. [`FakeSearch`] answers
///   real searches.
/// - rdap.lacnic.test answers 307 to `https://rdap.registro.test/ip/<query>`
///   for requests inside 203.0.113.128/25, as LACNIC does for Brazil.
///
/// Responses carry `Content-Type: application/rdap+json`. A 404 has an RFC
/// 9083 error body. Records added by [`FakeRdap::insert`] win over the
/// fixtures with the same range or handle.
#[derive(Debug, Default)]
pub(crate) struct FakeRdap {
    records: Mutex<Vec<RdapRecord>>,
}

/// The type of RDAP responses.
const RDAP_JSON: &str = "application/rdap+json";

/// Parses an address of either family into `(v6, value)`.
fn ip_value(text: &str) -> Option<(bool, u128)> {
    match text.parse::<std::net::IpAddr>().ok()? {
        std::net::IpAddr::V4(a) => Some((false, u128::from(u32::from(a)))),
        std::net::IpAddr::V6(a) => Some((true, u128::from(a))),
    }
}

/// Returns the range of an RDAP `ip` request, an address or a prefix.
///
/// Host bits are ignored, as servers do.
fn query_span(value: &str) -> Option<Span> {
    let (addr, len) = value.split_once('/').unwrap_or((value, ""));
    let (v6, value) = ip_value(addr)?;
    let bits: u32 = if v6 { 128 } else { 32 };
    let len: u32 = if len.is_empty() {
        bits
    } else {
        len.parse().ok()?
    };
    if len > bits {
        return None;
    }
    let host = if len == bits {
        0
    } else if len == 0 {
        if v6 { u128::MAX } else { u128::from(u32::MAX) }
    } else {
        (1u128 << (bits - len)) - 1
    };
    Some(Span {
        v6,
        first: value & !host,
        last: (value & !host) | host,
    })
}

/// Adds every file under `dir`, recursively, to `out`.
fn walk(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            walk(&path, out);
        } else {
            out.push(path);
        }
    }
}

impl FakeRdap {
    /// Loads every RDAP fixture of [`RDAP_HOSTS`].
    pub(crate) fn load() -> Self {
        let rdap = Self::default();
        for host in RDAP_HOSTS {
            let mut files = Vec::new();
            walk(&fixture_path(host), &mut files);
            files.sort();
            for file in files {
                let text = fs::read(&file).expect("read an RDAP fixture");
                let json: serde_json::Value = serde_json::from_slice(&text)
                    .unwrap_or_else(|e| panic!("{}: not JSON: {e}", file.display()));
                let record = Self::record(host, &json)
                    .unwrap_or_else(|| panic!("{}: not an RDAP record", file.display()));
                lock(&rdap.records).push(record);
            }
        }
        rdap
    }

    /// Returns the record of `json` on `host`, keyed by its
    /// `objectClassName`.
    fn record(host: &str, json: &serde_json::Value) -> Option<RdapRecord> {
        let key = match json["objectClassName"].as_str()? {
            "ip network" => {
                let (v6, first) = ip_value(json["startAddress"].as_str()?)?;
                let (_, last) = ip_value(json["endAddress"].as_str()?)?;
                RdapKey::Net(Span { v6, first, last })
            }
            "autnum" => RdapKey::As(
                u32::try_from(json["startAutnum"].as_u64()?).ok()?,
                u32::try_from(json["endAutnum"].as_u64()?).ok()?,
            ),
            "entity" => RdapKey::Entity(json["handle"].as_str()?.to_uppercase()),
            _ => return None,
        };
        Some(RdapRecord {
            host: host.to_owned(),
            key,
            body: Bytes::from(serde_json::to_vec_pretty(json).expect("serialize JSON")),
        })
    }

    /// Adds `record` to `host`, ahead of the fixtures.
    pub(crate) fn insert(&self, host: &str, record: &serde_json::Value) {
        let record = Self::record(host, record).expect("an RDAP record");
        lock(&self.records).insert(0, record);
    }

    /// Returns a 404 with an RFC 9083 error body.
    fn not_found(what: &str) -> Scripted {
        let body = serde_json::json!({
            "rdapConformance": ["rdap_level_0"],
            "errorCode": 404,
            "title": "Not Found",
            "description": [format!("{what}: no such object")],
        });
        Scripted::status(404)
            .header("Content-Type", RDAP_JSON)
            .chunks(vec![Bytes::from(body.to_string())])
    }

    /// Answers `request`.
    ///
    /// Returns `None` if `request` is not an RDAP request of the fixtures.
    /// [`FakeTransport`] then panics unless another handler answers.
    pub(crate) fn answer(&self, request: &Request) -> Option<Scripted> {
        let call = rdap_call(&request.url)?;
        let ok = |body: &Bytes| {
            Some(
                Scripted::ok(body.clone())
                    .header("Content-Type", RDAP_JSON)
                    .header("Access-Control-Allow-Origin", "*"),
            )
        };
        let records = lock(&self.records);
        let of_host = records.iter().filter(|r| r.host == call.host);
        match call.kind.as_str() {
            "ip" => {
                let Some(query) = query_span(&call.value) else {
                    return Some(Scripted::status(400).header("Content-Type", RDAP_JSON));
                };
                let brazil = query_span("203.0.113.128/25").expect("a prefix");
                if call.host == "rdap.lacnic.test"
                    && query.v6 == brazil.v6
                    && query.first >= brazil.first
                    && query.last <= brazil.last
                {
                    return Some(Scripted::status(307).header(
                        "Location",
                        &format!("https://rdap.registro.test/ip/{}", call.value),
                    ));
                }
                let best = of_host
                    .filter_map(|r| match &r.key {
                        RdapKey::Net(s)
                            if s.v6 == query.v6
                                && s.first <= query.first
                                && query.last <= s.last =>
                        {
                            Some((s.last - s.first, r))
                        }
                        _ => None,
                    })
                    // Takes the first of the smallest, so inserted records
                    // win.
                    .reduce(|a, b| if b.0 < a.0 { b } else { a });
                match best {
                    Some((_, record)) => ok(&record.body),
                    None => Some(Self::not_found(&call.value)),
                }
            }
            "autnum" => {
                let number: u32 = call
                    .value
                    .trim_start_matches(['A', 'S', 'a', 's'])
                    .parse()
                    .ok()?;
                let found = of_host
                    .into_iter()
                    .find(|r| matches!(r.key, RdapKey::As(a, b) if a <= number && number <= b));
                match found {
                    Some(record) => ok(&record.body),
                    None => Some(Self::not_found(&call.value)),
                }
            }
            "entity" => {
                let handle = call.value.to_uppercase();
                let found = of_host
                    .into_iter()
                    .find(|r| matches!(&r.key, RdapKey::Entity(h) if *h == handle));
                match found {
                    Some(record) => ok(&record.body),
                    None => Some(Self::not_found(&call.value)),
                }
            }
            "entities" => ok(&Bytes::from(
                serde_json::json!({
                    "rdapConformance": ["rdap_level_0"],
                    "entitySearchResults": [],
                })
                .to_string(),
            )),
            _ => None,
        }
    }
}

impl World {
    /// Returns a world with the fixtures of the registries.
    ///
    /// The world is the same as [`World::standard`], which also serves the
    /// registries.
    pub(crate) fn owners() -> Self {
        Self::standard()
    }

    /// Serves the registries and returns the fake RDAP service.
    ///
    /// The delegated stats and the IANA bootstrap are served whenever
    /// nothing else is queued, and [`FakeRdap`] answers for the RDAP servers.
    /// Tests add records to the returned service with [`FakeRdap::insert`].
    /// The registries are served once per world, and a second call returns
    /// the same service.
    pub(crate) fn serve_registries(&self) -> Arc<FakeRdap> {
        let rdap = self.rdap.get_or_init(|| {
            for (_, url, name) in STATS {
                self.transport.always(url, dataset(name));
            }
            for (url, name) in BOOTSTRAP {
                self.transport.always(url, dataset(name));
            }
            let rdap = Arc::new(FakeRdap::load());
            let server = Arc::clone(&rdap);
            self.transport.handle(move |request| server.answer(request));
            rdap
        });
        Arc::clone(rdap)
    }

    /// Returns the RDAP requests made so far, in order.
    pub(crate) fn rdap_calls(&self) -> Vec<RdapCall> {
        self.transport
            .requests()
            .iter()
            .filter_map(|r| rdap_call(&r.url))
            .collect()
    }

    /// Returns the values of the RDAP requests of `kind` to `host` made so
    /// far, in order.
    pub(crate) fn rdap_values(&self, host: &str, kind: &str) -> Vec<String> {
        self.rdap_calls()
            .into_iter()
            .filter(|c| c.host == host && c.kind == kind)
            .map(|c| c.value)
            .collect()
    }
}

/// A row of the output with all its columns.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct FullRow {
    /// The column part, if the table has it.
    pub(crate) part: Option<String>,
    /// The route, or `no route`.
    pub(crate) route: String,
    /// The AS of the route.
    pub(crate) ases: String,
    /// The network, the CIDR of the most specific registry record that
    /// covers the part or the route.
    pub(crate) net: String,
    /// The holder of the network and its country.
    pub(crate) owner: String,
    /// The abuse mailboxes of the network, then ` / ` and those of the AS.
    pub(crate) abuse: String,
    /// The columns added by `--fields`, in order.
    pub(crate) extra: Vec<String>,
}

/// Reads the rows of `stdout` with all their columns.
///
/// The column part is recognized as in [`table`].
///
/// # Panics
///
/// Panics if a line has too few columns.
pub(crate) fn full_table(stdout: &str) -> Vec<FullRow> {
    let lines: Vec<Vec<&str>> = stdout.lines().map(columns).collect();
    let has_part = lines
        .first()
        .is_some_and(|c| c.len() > 1 && !c[1].starts_with("AS") && c[1] != "-");
    lines
        .iter()
        .map(|c| {
            let skip = usize::from(has_part);
            assert!(c.len() >= skip + 5, "too few columns in {c:?} of\n{stdout}");
            FullRow {
                part: has_part.then(|| c[0].to_owned()),
                route: c[skip].to_owned(),
                ases: c[skip + 1].to_owned(),
                net: c[skip + 2].to_owned(),
                owner: c[skip + 3].to_owned(),
                abuse: c[skip + 4].to_owned(),
                extra: c[skip + 5..].iter().map(|s| (*s).to_owned()).collect(),
            }
        })
        .collect()
}

/// Returns the only row of `route` in `rows`.
///
/// # Panics
///
/// Panics if `route` has no row or more than one.
pub(crate) fn full_row<'a>(rows: &'a [FullRow], route: &str) -> &'a FullRow {
    let found: Vec<&FullRow> = rows.iter().filter(|r| r.route == route).collect();
    assert_eq!(found.len(), 1, "rows of {route}: {rows:#?}");
    found[0]
}

// The search: the dumps of APNIC and AFRINIC, the RIPE REST API, and the
// RDAP searches by name.
//
// The APNIC dumps hold these objects:
//
// - 203.0.113.0 - 203.0.113.95 (EXAMPLE-CDN-XG, mnt-by MAINT-XG-EXAMPLECDN,
//   contacts ECA1-AP). It has no abuse-c. Its abuse contact
//   IRT-EXAMPLECDN-XG is on ORG-ECL1-AP.
// - 203.0.113.16 - 203.0.113.31 (ORG-CC1-AP, MAINT-XG-CDNCUSTOMER, abuse-c
//   IRT-CDNCUSTOMER-XG).
// - 2001:db8:f000::/36 (MAINT-XG-EXAMPLECDN).
// - AS64503 (MAINT-XG-EXAMPLECDN, abuse-c IRT-EXAMPLECDN-AS).
//
// The AFRINIC dump holds 203.0.113.224 - 203.0.113.255 and AS64508. The
// network has mnt-by EXAMPLE-AF-HM-MNT, mnt-lower and mnt-routes
// SAVANNA-MNT, and the contact SN1-AFRINIC. SN1-AFRINIC is a role whose
// own contact SNA1-AFRINIC is not a contact of the network.
//
// The REST objects of RIPE mirror the RDAP fixtures:
//
// - 192.0.2.0/24 (EXAMPLE-HM-MNT and EXNET-MNT, admin JD1-RIPE, tech
//   NOC1-RIPE, abuse AR-EN1-RIPE).
// - 192.0.2.0/26 (CH-MNT, MR1-RIPE, AR-CH1-RIPE).
// - 192.0.2.128/25 and 192.0.2.128/27 (LB-MNT, AR-LB1-RIPE, AR-TO1-RIPE).
// - 2001:db8::/32 (EXNET-MNT).
// - The aut-nums with `<AS-NAME>-MNT` and `AR-<asn>-RIPE`. AS64496 also has
//   admin JD1-RIPE.
// - The `organisation` objects EN1, CH1, LB1, and TO1 with their abuse-c.
// - 101 inetnums of one address each, 192.0.2.0 to 192.0.2.100, of
//   BULK-MNT. The API cuts them at 100.

/// The APNIC dumps: the URL rewritten to [`CLOSED_BASE`], and the fixture.
pub(crate) const APNIC_DUMPS: [(&str, &str); 4] = [
    (
        "http://127.0.0.1:9/ftp.apnic.test/apnic/whois/apnic.db.inetnum.gz",
        "ftp.apnic.test/apnic/whois/apnic.db.inetnum.gz",
    ),
    (
        "http://127.0.0.1:9/ftp.apnic.test/apnic/whois/apnic.db.inet6num.gz",
        "ftp.apnic.test/apnic/whois/apnic.db.inet6num.gz",
    ),
    (
        "http://127.0.0.1:9/ftp.apnic.test/apnic/whois/apnic.db.aut-num.gz",
        "ftp.apnic.test/apnic/whois/apnic.db.aut-num.gz",
    ),
    (
        "http://127.0.0.1:9/ftp.apnic.test/apnic/whois/apnic.db.organisation.gz",
        "ftp.apnic.test/apnic/whois/apnic.db.organisation.gz",
    ),
];

/// See [`APNIC_DUMPS`].
pub(crate) const APNIC_INETNUM: &str = APNIC_DUMPS[0].0;
/// See [`APNIC_DUMPS`].
pub(crate) const APNIC_INET6NUM: &str = APNIC_DUMPS[1].0;
/// See [`APNIC_DUMPS`].
pub(crate) const APNIC_AUT_NUM: &str = APNIC_DUMPS[2].0;
/// See [`APNIC_DUMPS`].
pub(crate) const APNIC_ORGANISATION: &str = APNIC_DUMPS[3].0;

/// The AFRINIC dump, every class in one file.
pub(crate) const AFRINIC_DB: &str = "http://127.0.0.1:9/ftp.afrinic.test/dbase/afrinic.db.gz";
/// The fixture of [`AFRINIC_DB`].
pub(crate) const AFRINIC_DB_FIXTURE: &str = "ftp.afrinic.test/dbase/afrinic.db.gz";

/// The search of the RIPE REST API, rewritten to [`CLOSED_BASE`].
pub(crate) const REST_SEARCH: &str = "http://127.0.0.1:9/rest.ripe.test/search.json";

/// The text RIPE adds to an answer cut at 100 objects.
///
/// netf prints this text to stderr.
pub(crate) const REST_LIMITED: &str = "limited search results to 100 maximum";

/// A search of the RIPE REST API, read back from its URL.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub(crate) struct RestCall {
    /// `query-string`, decoded.
    pub(crate) query: String,
    /// Every `inverse-attribute`.
    pub(crate) inverse: Vec<String>,
    /// Every `type-filter`.
    pub(crate) types: Vec<String>,
    /// Every `flags`.
    pub(crate) flags: Vec<String>,
}

/// Decodes a value of a query string, with `%XX` escapes and `+` for a space.
fn query_decode(text: &str) -> String {
    percent_decode(&text.replace('+', " "))
}

/// Returns the decoded `(name, value)` pairs of a query string.
fn query_pairs(query: &str) -> Vec<(String, String)> {
    query
        .split('&')
        .filter(|p| !p.is_empty())
        .map(|p| {
            let (name, value) = p.split_once('=').unwrap_or((p, ""));
            (query_decode(name), query_decode(value))
        })
        .collect()
}

/// Reads a REST search from `url`, rewritten or not.
///
/// Returns `None` for other URLs.
pub(crate) fn rest_call(url: &str) -> Option<RestCall> {
    let query = url
        .strip_prefix(REST_SEARCH)
        .or_else(|| url.strip_prefix("https://rest.ripe.test/search.json"))?
        .strip_prefix('?')?;
    let mut call = RestCall::default();
    for (name, value) in query_pairs(query) {
        match name.as_str() {
            "query-string" => call.query = value,
            "inverse-attribute" => call.inverse.push(value),
            "type-filter" => call.types.push(value),
            "flags" => call.flags.push(value),
            _ => {}
        }
    }
    Some(call)
}

/// Returns whether `text` matches a glob of `*` and `?`, ignoring case.
///
/// RDAP searches entities by name with such globs (RFC 9082, section
/// 3.2.3).
fn glob_match(pattern: &str, text: &str) -> bool {
    let p: Vec<char> = pattern.to_lowercase().chars().collect();
    let t: Vec<char> = text.to_lowercase().chars().collect();
    let (mut i, mut j) = (0, 0);
    let mut back: Option<(usize, usize)> = None;
    while j < t.len() {
        if i < p.len() && (p[i] == '?' || p[i] == t[j]) {
            i += 1;
            j += 1;
        } else if i < p.len() && p[i] == '*' {
            back = Some((i, j));
            i += 1;
        } else if let Some((bi, bj)) = back {
            i = bi + 1;
            j = bj + 1;
            back = Some((bi, bj + 1));
        } else {
            return false;
        }
    }
    p[i..].iter().all(|c| *c == '*')
}

/// Returns the `fn` of the vCard of `entity`.
fn vcard_fn(entity: &serde_json::Value) -> Option<&str> {
    entity["vcardArray"][1]
        .as_array()?
        .iter()
        .find(|p| p[0] == "fn")?[3]
        .as_str()
}

/// The fake search services over the fixtures.
///
/// - `rest.ripe.test/search.json?query-string=X&inverse-attribute=A&
///   type-filter=T…` returns the objects of `rest.ripe.test/objects.json`
///   in the order of the file. An object matches if its type is `T`, or
///   any type without a filter, and its attribute `A` equals `X`, ignoring
///   case. Without `inverse-attribute`, the primary key must equal `X`,
///   and an `organisation` also matches if every word of `X` is a word of
///   its `org-name`. More than 100 objects are cut to 100 with the warning
///   of RIPE. If no object matches, the response is a 404 with the "no
///   entries" body of RIPE.
/// - `entities?fn=<glob>` of an RDAP server returns, as
///   `entitySearchResults`, the entities of that server whose `fn` matches
///   the glob, ignoring case. Organizations, persons, and roles match
///   alike. The results lack their resources and notices. rdap.lacnic.test
///   answers 307 to `https://rdap.registro.test/entities?…`, which has no
///   entities. A server passed to [`FakeSearch::refuse`] answers with the
///   given status.
///
/// Install the service before [`World::serve_registries`], because
/// [`FakeRdap`] answers `entities` with an empty result.
#[derive(Debug, Default)]
pub(crate) struct FakeSearch {
    objects: Vec<serde_json::Value>,
    entities: Vec<(String, serde_json::Value)>,
    refused: Mutex<HashMap<String, u16>>,
}

impl FakeSearch {
    /// Loads the REST objects and the entities of [`RDAP_HOSTS`].
    pub(crate) fn load() -> Self {
        let read = |name: &str| -> serde_json::Value {
            let text = fs::read(fixture_path(name)).expect("read a search fixture");
            serde_json::from_slice(&text).unwrap_or_else(|e| panic!("{name}: not JSON: {e}"))
        };
        let objects = read("rest.ripe.test/objects.json")["objects"]["object"]
            .as_array()
            .expect("objects.object")
            .clone();
        let mut entities = Vec::new();
        for host in RDAP_HOSTS {
            let mut files = Vec::new();
            walk(&fixture_path(host), &mut files);
            files.sort();
            for file in files {
                let text = fs::read(&file).expect("read an RDAP fixture");
                let json: serde_json::Value =
                    serde_json::from_slice(&text).expect("an RDAP fixture is JSON");
                if json["objectClassName"] == "entity" {
                    entities.push((host.to_owned(), json));
                }
            }
        }
        Self {
            objects,
            entities,
            refused: Mutex::default(),
        }
    }

    /// Makes `host`, one of [`RDAP_HOSTS`], answer its searches with
    /// `status`.
    ///
    /// A registry that does not search answers 400 or 501.
    pub(crate) fn refuse(&self, host: &str, status: u16) {
        lock(&self.refused).insert(host.to_owned(), status);
    }

    /// Answers `request`, or returns `None` if it is not a search.
    pub(crate) fn answer(&self, request: &Request) -> Option<Scripted> {
        if let Some(call) = rest_call(&request.url) {
            return Some(self.rest(&call));
        }
        let call = rdap_call(&request.url)?;
        if call.kind != "entities" {
            return None;
        }
        let query = request.url.split_once('?').map_or("", |(_, q)| q);
        Some(self.entities(&call.host, query))
    }

    /// Returns the response of the REST API to `call`.
    fn rest(&self, call: &RestCall) -> Scripted {
        let error = |name: &str| -> serde_json::Value {
            let text = fs::read(fixture_path(name)).expect("read a REST error");
            serde_json::from_slice(&text).expect("a REST error is JSON")
        };
        let found: Vec<&serde_json::Value> = self
            .objects
            .iter()
            .filter(|o| {
                call.types.is_empty() || call.types.iter().any(|t| o["type"].as_str() == Some(t))
            })
            .filter(|o| {
                let attributes = o["attributes"]["attribute"].as_array();
                let attributes = attributes.map(Vec::as_slice).unwrap_or_default();
                let equal = |a: &serde_json::Value| {
                    a["value"]
                        .as_str()
                        .is_some_and(|v| v.eq_ignore_ascii_case(&call.query))
                };
                if call.inverse.is_empty() {
                    // Matches the primary key. An `organisation` also
                    // matches if every word of `call.query` is a word of its
                    // name, as RIPE searches `organisation` objects by name.
                    let named = o["type"] == "organisation"
                        && attributes
                            .iter()
                            .find(|a| a["name"] == "org-name")
                            .and_then(|a| a["value"].as_str())
                            .is_some_and(|name| {
                                let words: Vec<String> =
                                    name.split_whitespace().map(str::to_lowercase).collect();
                                let mut query = call.query.split_whitespace().peekable();
                                query.peek().is_some()
                                    && query.all(|word| words.contains(&word.to_lowercase()))
                            });
                    named || attributes.first().is_some_and(equal)
                } else {
                    attributes.iter().any(|a| {
                        call.inverse.iter().any(|i| a["name"].as_str() == Some(i)) && equal(a)
                    })
                }
            })
            .collect();
        let json = |status: u16, body: serde_json::Value| {
            Scripted::status(status)
                .header("Content-Type", "application/json")
                .chunks(vec![Bytes::from(body.to_string())])
        };
        if found.is_empty() {
            return json(404, error("rest.ripe.test/errors/no-entries.json"));
        }
        let mut body = serde_json::json!({
            "service": {"name": "search"},
            "objects": {"object": found.iter().take(100).collect::<Vec<_>>()},
            "terms-and-conditions": {
                "type": "locator",
                "href": "https://docs.db.ripe.test/terms-conditions.html",
            },
        });
        if found.len() > 100 {
            body["errormessages"] =
                error("rest.ripe.test/errors/limited.json")["errormessages"].clone();
        }
        json(200, body)
    }

    /// Returns the response of `host` to `entities?<query>`.
    fn entities(&self, host: &str, query: &str) -> Scripted {
        if let Some(status) = lock(&self.refused).get(host).copied() {
            let body = serde_json::json!({
                "rdapConformance": ["rdap_level_0"],
                "errorCode": status,
                "title": "Search not supported",
                "description": ["entity search is not available"],
            });
            return Scripted::status(status)
                .header("Content-Type", RDAP_JSON)
                .chunks(vec![Bytes::from(body.to_string())]);
        }
        if host == "rdap.lacnic.test" {
            return Scripted::status(307).header(
                "Location",
                &format!("https://rdap.registro.test/entities?{query}"),
            );
        }
        let pattern = query_pairs(query)
            .into_iter()
            .find(|(name, _)| name == "fn")
            .map(|(_, value)| value);
        let Some(pattern) = pattern else {
            return Scripted::status(400).header("Content-Type", RDAP_JSON);
        };
        let results: Vec<serde_json::Value> = self
            .entities
            .iter()
            .filter(|(h, e)| h == host && vcard_fn(e).is_some_and(|f| glob_match(&pattern, f)))
            .map(|(_, e)| {
                let mut e = e.clone();
                if let Some(map) = e.as_object_mut() {
                    for key in ["networks", "autnums", "notices", "rdapConformance"] {
                        map.remove(key);
                    }
                }
                e
            })
            .collect();
        Scripted::ok(Bytes::from(
            serde_json::json!({
                "rdapConformance": ["rdap_level_0"],
                "entitySearchResults": results,
            })
            .to_string(),
        ))
        .header("Content-Type", RDAP_JSON)
    }
}

impl World {
    /// Returns a world for searches.
    ///
    /// The world is [`World::standard`] with the dumps and the search
    /// services of [`World::serve_search`].
    pub(crate) fn search() -> Self {
        Self::search_server().0
    }

    /// Returns [`World::search`] and its search services.
    ///
    /// Tests use the services to call [`FakeSearch::refuse`].
    pub(crate) fn search_server() -> (Self, Arc<FakeSearch>) {
        let world = Self::with_resolver(standard_resolver());
        world.serve_datasets();
        let search = world.serve_search();
        world.serve_registries();
        (world, search)
    }

    /// Serves the APNIC and AFRINIC dumps and the searches.
    ///
    /// The dumps are served whenever nothing else is queued, and
    /// [`FakeSearch`] answers the searches. Call `serve_search` before
    /// [`World::serve_registries`], whose handler answers `entities` too.
    pub(crate) fn serve_search(&self) -> Arc<FakeSearch> {
        for (url, name) in APNIC_DUMPS {
            self.transport.always(url, dataset(name));
        }
        self.transport
            .always(AFRINIC_DB, dataset(AFRINIC_DB_FIXTURE));
        let search = Arc::new(FakeSearch::load());
        let server = Arc::clone(&search);
        self.transport.handle(move |request| server.answer(request));
        search
    }

    /// Returns the searches of the RIPE REST API made so far, in order.
    pub(crate) fn rest_calls(&self) -> Vec<RestCall> {
        self.transport
            .requests()
            .iter()
            .filter_map(|r| rest_call(&r.url))
            .collect()
    }

    /// Returns how many times the dumps of `urls` were requested, in total.
    pub(crate) fn dump_requests(&self, urls: &[&str]) -> usize {
        urls.iter().map(|url| self.transport.count(url)).sum()
    }
}
