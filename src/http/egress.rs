//! The pool of egresses: `direct`, or the `--proxy` list used in round
//! robin. The pool keeps a pause after a 429 and a semaphore for each pair
//! of egress and host.
//!
//! # Invariants
//!
//! - An empty proxy list creates one `direct` egress.
//! - With proxies, the pool creates one egress per normalized address and
//!   authorization pair. The first occurrence of each pair sets the order.
//!   All HTTP requests use these proxies, including DNS over HTTPS.
//! - Each `(egress, host)` pair has a semaphore of `concurrency` slots. A
//!   request takes its slot before it is sent and holds the slot until the
//!   reader reads the body to the end or drops it, so a long download keeps
//!   its place. The host is the `host:port` of the URL. A redirect to
//!   another host is a new request with its own semaphore.
//! - A 429 pauses one `(egress, host)` pair. The requests that go out
//!   through the pair wait, and the round robin skips the pair, so the other
//!   egresses go on.

use std::{
    collections::{HashMap, HashSet},
    sync::{
        Arc, Mutex, PoisonError,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

use bytes::Bytes;
use http_body_util::Full;
use hyper_util::{
    client::legacy::{Client as Legacy, ResponseFuture},
    rt::{TokioExecutor, TokioTimer},
};
use tokio::{
    sync::{OwnedSemaphorePermit, Semaphore},
    time::Instant,
};

use super::connect::{self, DirectConnector, ProxyConnector, ProxyUrl};
use crate::transport::EgressId;

/// How long an idle connection is kept for reuse.
const IDLE_TIMEOUT: Duration = Duration::from_secs(90);

/// Locks a mutex and ignores poisoning.
///
/// The guarded data stays consistent, because every critical section is a
/// single assignment or lookup.
fn lock<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

/// The hyper client of an egress.
///
/// The two connectors have different types. One `match` here is simpler
/// than a connector enum with streams that delegate to each kind.
enum Client {
    Direct(Legacy<DirectConnector, Full<Bytes>>),
    Proxy(Legacy<ProxyConnector, Full<Bytes>>),
}

/// One way out: the machine's own address or one proxy.
pub(crate) struct Egress {
    id: EgressId,
    /// Set for a proxy. A connection failure is then a failure of the
    /// proxy.
    proxied: bool,
    client: Client,
    concurrency: usize,
    hosts: Mutex<HashMap<String, Arc<HostState>>>,
}

/// The state of one `(egress, host)` pair.
pub(crate) struct HostState {
    slots: Arc<Semaphore>,
    paused_until: Mutex<Option<Instant>>,
}

impl HostState {
    /// Waits for a free slot.
    ///
    /// Dropping the permit releases the slot.
    pub(crate) async fn slot(&self) -> OwnedSemaphorePermit {
        Arc::clone(&self.slots)
            .acquire_owned()
            .await
            .expect("the semaphore of an egress is never closed")
    }

    /// Returns the end of the current pause, if a pause is in force.
    pub(crate) fn paused_until(&self) -> Option<Instant> {
        lock(&self.paused_until).filter(|&until| until > Instant::now())
    }

    /// Pauses the pair for `wait` from now.
    ///
    /// Returns `true` if the call starts or extends a pause. Returns `false`
    /// if a pause that ends no earlier was already in force. In that case
    /// the user already got a notice.
    pub(crate) fn pause(&self, wait: Duration) -> bool {
        let until = Instant::now() + wait;
        let mut paused = lock(&self.paused_until);
        match *paused {
            Some(current) if current >= until => false,
            _ => {
                *paused = Some(until);
                true
            }
        }
    }

    /// Waits until no pause is in force.
    pub(crate) async fn wait_pause(&self) {
        while let Some(until) = self.paused_until() {
            tokio::time::sleep_until(until).await;
        }
    }
}

impl Egress {
    /// Creates the egress without a proxy.
    fn direct(concurrency: usize, connect_timeout: Duration) -> Self {
        let client = Client::Direct(builder(concurrency).build(connect::direct(connect_timeout)));
        Self::new(EgressId::direct(), false, client, concurrency)
    }

    /// Creates the egress through `proxy`.
    fn proxy(proxy: &ProxyUrl, concurrency: usize, connect_timeout: Duration) -> Self {
        let connector = connect::proxy(proxy, connect_timeout);
        let client = Client::Proxy(builder(concurrency).build(connector));
        Self::new(proxy.id.clone(), true, client, concurrency)
    }

    fn new(id: EgressId, proxied: bool, client: Client, concurrency: usize) -> Self {
        Self {
            id,
            proxied,
            client,
            concurrency,
            hosts: Mutex::new(HashMap::new()),
        }
    }

    /// Returns the name of the egress.
    pub(crate) fn id(&self) -> &EgressId {
        &self.id
    }

    /// Returns the name of the egress if it is a proxy, for error messages.
    ///
    /// Returns `None` for `direct`.
    pub(crate) fn proxy_id(&self) -> Option<&EgressId> {
        self.proxied.then_some(&self.id)
    }

    /// Returns the state of `host` on this egress, creating it on first use.
    pub(crate) fn host(&self, host: &str) -> Arc<HostState> {
        let mut hosts = lock(&self.hosts);
        Arc::clone(hosts.entry(host.to_owned()).or_insert_with(|| {
            Arc::new(HostState {
                slots: Arc::new(Semaphore::new(self.concurrency)),
                paused_until: Mutex::new(None),
            })
        }))
    }

    /// Sends a request through this egress.
    pub(crate) fn request(&self, request: http::Request<Full<Bytes>>) -> ResponseFuture {
        match &self.client {
            Client::Direct(client) => client.request(request),
            Client::Proxy(client) => client.request(request),
        }
    }
}

/// Returns the hyper client settings that both kinds of egress share.
///
/// The client speaks HTTP/1.1 and keeps up to `concurrency` idle
/// connections per host.
fn builder(concurrency: usize) -> hyper_util::client::legacy::Builder {
    let mut builder = Legacy::builder(TokioExecutor::new());
    builder
        .pool_timer(TokioTimer::new())
        .pool_idle_timeout(IDLE_TIMEOUT)
        .pool_max_idle_per_host(concurrency);
    builder
}

/// All the egresses of a run, and the round robin over them.
pub(crate) struct Pool {
    egresses: Vec<Egress>,
    next: AtomicUsize,
}

impl Pool {
    /// Creates a `direct` egress if `proxies` is empty.
    ///
    /// Otherwise, creates one egress per normalized address and authorization
    /// pair. The first occurrence of each pair sets the order.
    ///
    /// A `concurrency` of 0 counts as 1.
    pub(crate) fn new(proxies: &[ProxyUrl], concurrency: usize, connect_timeout: Duration) -> Self {
        let concurrency = concurrency.max(1);
        let egresses = if proxies.is_empty() {
            vec![Egress::direct(concurrency, connect_timeout)]
        } else {
            let mut seen = HashSet::new();
            proxies
                .iter()
                .filter(|proxy| seen.insert((&proxy.id, &proxy.authorization)))
                .map(|proxy| Egress::proxy(proxy, concurrency, connect_timeout))
                .collect()
        };
        Self {
            egresses,
            next: AtomicUsize::new(0),
        }
    }

    /// Returns the egress at `index`.
    pub(crate) fn get(&self, index: usize) -> &Egress {
        &self.egresses[index]
    }

    /// Returns the names of all the egresses, in order.
    pub(crate) fn ids(&self) -> Vec<EgressId> {
        self.egresses.iter().map(|e| e.id.clone()).collect()
    }

    /// Picks the next egress for `host` in round robin.
    ///
    /// Skips the egresses on which `host` is paused. If all of them are
    /// paused, waits for the pause that ends first. Returns the index of the
    /// egress and its state for `host`.
    pub(crate) async fn pick(&self, host: &str) -> (usize, Arc<HostState>) {
        loop {
            let count = self.egresses.len();
            let start = self.next.fetch_add(1, Ordering::Relaxed) % count;
            let mut earliest: Option<Instant> = None;
            for offset in 0..count {
                let index = (start + offset) % count;
                let state = self.egresses[index].host(host);
                match state.paused_until() {
                    None => return (index, state),
                    Some(until) => {
                        earliest = Some(earliest.map_or(until, |e| e.min(until)));
                    }
                }
            }
            if let Some(until) = earliest {
                tokio::time::sleep_until(until).await;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn proxies(count: usize) -> Vec<ProxyUrl> {
        (0..count)
            .map(|i| connect::parse_proxy(&format!("http://127.0.0.1:{}", 9000 + i)).unwrap())
            .collect()
    }

    #[tokio::test(flavor = "current_thread")]
    async fn direct_without_proxies() {
        let pool = Pool::new(&[], 8, Duration::from_secs(10));
        assert_eq!(pool.ids(), vec![EgressId::direct()]);
        assert!(pool.get(0).proxy_id().is_none());
    }

    #[test]
    fn duplicate_proxies_keep_first_occurrence_order() {
        let proxies: Vec<_> = [
            "http://first.example:8080",
            "http://user:p%40ss@auth.example:3128",
            "http://last.example:8080",
            "HTTP://FIRST.Example:8080/",
            "http://%75ser%3Ap%40ss@AUTH.example:3128/",
            "http://last.example:8080",
        ]
        .into_iter()
        .map(|url| connect::parse_proxy(url).unwrap())
        .collect();
        let pool = Pool::new(&proxies, 2, Duration::from_secs(10));
        assert_eq!(
            pool.ids(),
            vec![
                EgressId("http://first.example:8080".into()),
                EgressId("http://auth.example:3128".into()),
                EgressId("http://last.example:8080".into()),
            ]
        );
    }

    #[test]
    fn proxies_with_different_credentials_stay_separate() {
        let proxies: Vec<_> = [
            "http://user@proxy.example:8080",
            "http://user:@proxy.example:8080/",
            "http://user:one@proxy.example:8080",
            "http://user:two@proxy.example:8080",
            "http://User:one@proxy.example:8080",
            "http://proxy.example:8080",
        ]
        .into_iter()
        .map(|url| connect::parse_proxy(url).unwrap())
        .collect();
        let pool = Pool::new(&proxies, 2, Duration::from_secs(10));
        assert_eq!(
            pool.ids(),
            vec![EgressId("http://proxy.example:8080".into()); 5]
        );
    }

    #[test]
    fn a_shorter_pause_does_not_shorten_a_longer_one() {
        let pool = Pool::new(&[], 1, Duration::from_secs(10));
        let state = pool.get(0).host("a.test:443");
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .build()
            .unwrap();
        runtime.block_on(async {
            assert!(state.pause(Duration::from_secs(60)));
            assert!(!state.pause(Duration::from_secs(1)));
            assert!(state.pause(Duration::from_secs(120)));
            assert!(state.paused_until().is_some());
        });
    }

    #[tokio::test(flavor = "current_thread")]
    async fn all_paused_waits_for_the_first_to_end() {
        let pool = Pool::new(&proxies(2), 1, Duration::from_secs(10));
        assert!(
            pool.get(0)
                .host("a.test:443")
                .pause(Duration::from_millis(300))
        );
        assert!(
            pool.get(1)
                .host("a.test:443")
                .pause(Duration::from_millis(50))
        );
        let started = Instant::now();
        let (index, _) = pool.pick("a.test:443").await;
        assert_eq!(index, 1);
        let waited = started.elapsed();
        assert!(waited >= Duration::from_millis(50) && waited < Duration::from_millis(300));
    }
}
