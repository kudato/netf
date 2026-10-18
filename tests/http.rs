//! Tests of the real transport against stubs on `127.0.0.1`.
//!
//! The tests cover limits, proxies, retries, timeouts, and cut bodies.
//! Nothing leaves the machine. Every URL is a stub's, and the stub proxy
//! tunnels only to `127.0.0.1`.

mod common;

use std::{
    sync::Arc,
    time::{Duration, Instant},
};

use bytes::Bytes;
use futures_util::future::join_all;
use netf::{
    Class, EgressId, HttpOptions, HttpTransport, Request, Response, Transport, TransportError,
};

use common::{
    CollectReporter,
    stub::{Reply, StubProxy, StubServer},
};

/// Returns the default options with short retry pauses, so the retries cost
/// milliseconds.
fn options() -> HttpOptions {
    HttpOptions {
        retry_pauses: vec![Duration::from_millis(10), Duration::from_millis(20)],
        ..HttpOptions::default()
    }
}

fn start(options: HttpOptions) -> (HttpTransport, Arc<CollectReporter>) {
    let reporter = Arc::new(CollectReporter::new());
    let transport = HttpTransport::new(options, reporter.clone()).expect("valid options");
    (transport, reporter)
}

fn dataset() -> Class {
    Class::Dataset("ris-v4")
}

async fn get(transport: &HttpTransport, url: &str) -> Result<Response, TransportError> {
    transport.send(Request::get(url, dataset())).await
}

async fn body(response: Response) -> Result<Bytes, TransportError> {
    response.body.collect(1 << 20).await
}

#[tokio::test]
async fn get_and_post() {
    let server = StubServer::start();
    server.on("/a", Reply::ok("hello").header("ETag", "\"1\""));
    server.on("/dns", Reply::ok("answer"));
    let (transport, _) = start(options());

    let response = get(&transport, &server.url("/a")).await.unwrap();
    assert_eq!(response.status, 200);
    assert_eq!(response.egress, EgressId::direct());
    assert_eq!(response.header("etag"), Some("\"1\""));
    assert_eq!(body(response).await.unwrap(), "hello");

    let request = Request::post(server.url("/dns"), Class::Doh, "query")
        .with_header("Content-Type", "application/dns-message");
    let response = transport.send(request).await.unwrap();
    assert_eq!(body(response).await.unwrap(), "answer");

    let received = server.received();
    assert_eq!(received[0].method, "GET");
    let agent = concat!("netf/", env!("CARGO_PKG_VERSION"));
    assert_eq!(received[0].header("user-agent"), Some(agent));
    assert_eq!(received[0].header("accept"), Some("*/*"));
    assert_eq!(received[1].method, "POST");
    assert_eq!(
        received[1].header("accept"),
        Some("application/dns-message")
    );
    assert_eq!(
        received[1].header("content-type"),
        Some("application/dns-message")
    );
    assert_eq!(received[1].body, "query");
    assert_eq!(transport.egresses(), vec![EgressId::direct()]);
}

/// Requests every URL of `urls` at once and returns the egresses.
///
/// Each body is read to the end and must be `ab`.
///
/// # Panics
///
/// Panics if a request fails or a body is not `ab`.
async fn many(transport: &HttpTransport, urls: Vec<String>) -> Vec<EgressId> {
    join_all(urls.iter().map(|url| async move {
        let response = get(transport, url).await.unwrap();
        let egress = response.egress.clone();
        assert_eq!(body(response).await.unwrap(), "ab");
        egress
    }))
    .await
}

fn slow() -> Reply {
    Reply::status(200)
        .chunks(vec![Bytes::from("a"), Bytes::from("b")])
        .chunk_delay(Duration::from_millis(60))
}

#[tokio::test]
async fn concurrency_per_host() {
    let server = StubServer::start();
    server.always("/slow", slow());
    let (transport, _) = start(HttpOptions {
        concurrency: 3,
        ..options()
    });
    many(&transport, vec![server.url("/slow"); 12]).await;
    assert_eq!(server.count("/slow"), 12);
    assert_eq!(server.peak(), 3);
}

#[tokio::test]
async fn an_unread_body_keeps_its_slot() {
    let server = StubServer::start();
    let other = StubServer::start();
    server.always("/x", Reply::ok("x"));
    other.always("/x", Reply::ok("y"));
    let (transport, _) = start(HttpOptions {
        concurrency: 1,
        ..options()
    });

    let held = get(&transport, &server.url("/x")).await.unwrap();
    // The same host waits for the slot...
    let url = server.url("/x");
    let waiting = tokio::time::timeout(Duration::from_millis(300), get(&transport, &url));
    assert!(waiting.await.is_err());
    // ...another host does not.
    let response = get(&transport, &other.url("/x")).await.unwrap();
    assert_eq!(body(response).await.unwrap(), "y");

    drop(held);
    let response = get(&transport, &server.url("/x")).await.unwrap();
    assert_eq!(body(response).await.unwrap(), "x");
}

#[tokio::test]
async fn proxies_multiply_the_limit_and_take_turns() {
    let server = StubServer::start();
    server.always("/slow", slow());
    let first = StubProxy::start(None);
    let second = StubProxy::start(None);
    let (transport, _) = start(HttpOptions {
        proxies: vec![first.url(), second.url()],
        concurrency: 2,
        ..options()
    });
    assert_eq!(
        transport.egresses(),
        vec![EgressId(first.url().into()), EgressId(second.url().into())]
    );

    let egresses = many(&transport, vec![server.url("/slow"); 12]).await;
    assert_eq!(server.peak(), 4);
    let through_first = egresses
        .iter()
        .filter(|e| e.0.as_ref() == first.url())
        .count();
    assert_eq!(through_first, 6);
    // Every tunnel went to the stub, never elsewhere.
    let target = server.addr().to_string();
    assert!(first.connects().iter().all(|c| *c == target));
    assert!(second.tunnels() >= 2);

    // When the requests go one at a time, the egresses alternate.
    server.always("/one", Reply::ok("ab"));
    let mut seen = Vec::new();
    for _ in 0..4 {
        seen.push(get(&transport, &server.url("/one")).await.unwrap().egress);
    }
    assert_ne!(seen[0], seen[1]);
    assert_eq!(seen[0], seen[2]);
    assert_eq!(seen[1], seen[3]);
}

#[tokio::test]
async fn duplicate_proxies_share_the_limit() {
    let server = StubServer::start();
    server.always("/slow", slow());
    let proxy = StubProxy::start(None);
    let (transport, _) = start(HttpOptions {
        proxies: vec![proxy.url(), format!("{}/", proxy.url()), proxy.url()],
        concurrency: 2,
        ..options()
    });

    let egresses = many(&transport, vec![server.url("/slow"); 12]).await;

    assert_eq!(server.count("/slow"), 12);
    assert_eq!(server.peak(), 2);
    assert_eq!(egresses, vec![EgressId(proxy.url().into()); 12]);
    assert_eq!(transport.egresses(), vec![EgressId(proxy.url().into())]);
}

#[tokio::test]
async fn connect_with_credentials() {
    let server = StubServer::start();
    server.always("/a", Reply::ok("ok"));
    // The credentials are `user:p@ss`, with the `@` percent-encoded in the
    // URL.
    let proxy = StubProxy::start(Some("Basic dXNlcjpwQHNz"));

    let (transport, _) = start(HttpOptions {
        proxies: vec![
            proxy.url_with("user:p%40ss"),
            format!("{}/", proxy.url_with("%75ser%3Ap%40ss")),
        ],
        ..options()
    });
    // The name of the egress has no credentials.
    assert_eq!(transport.egresses(), vec![EgressId(proxy.url().into())]);
    let response = get(&transport, &server.url("/a")).await.unwrap();
    assert_eq!(response.egress, EgressId(proxy.url().into()));
    assert_eq!(body(response).await.unwrap(), "ok");
    assert_eq!(
        proxy.authorizations(),
        vec![Some("Basic dXNlcjpwQHNz".to_owned())]
    );

    // With wrong credentials, the proxy answers 407. The transport counts it
    // as a failure of the proxy and returns a proxy error.
    let (transport, _) = start(HttpOptions {
        proxies: vec![proxy.url_with("user:wrong")],
        ..options()
    });
    let error = get(&transport, &server.url("/a")).await.unwrap_err();
    let TransportError::Proxy(cause) = &error else {
        panic!("{error:?}");
    };
    assert!(cause.starts_with(&proxy.url()), "{cause}");
    assert_eq!(server.count("/a"), 1);
}

#[tokio::test]
async fn a_dead_proxy_is_a_proxy_error() {
    let closed = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://{}", closed.local_addr().unwrap());
    drop(closed);
    let (transport, _) = start(HttpOptions {
        proxies: vec![url.clone()],
        ..options()
    });
    let error = get(&transport, "http://127.0.0.1:9/x").await.unwrap_err();
    assert_eq!(
        error,
        TransportError::Proxy(format!("{url}: connection refused"))
    );
}

#[test]
fn unusable_proxy_urls() {
    let reporter = Arc::new(CollectReporter::new());
    for (url, message) in [
        (
            "socks5://10.0.0.2:1080",
            "--proxy socks5://10.0.0.2:1080: unsupported proxy scheme, only http:// is supported",
        ),
        (
            "https://u:secret@10.0.0.2:3128",
            "--proxy https://***@10.0.0.2:3128: unsupported proxy scheme, only http:// is supported",
        ),
        ("http://10.0.0.2", "--proxy http://10.0.0.2: missing port"),
        (
            "http://alice:demo/password@127.0.0.1:8080",
            "--proxy http://***@127.0.0.1:8080: a proxy URL has no path",
        ),
        (
            "http://alice%3Ademo-password@127.0.0.1:bad",
            "--proxy http://***@127.0.0.1:bad: invalid port",
        ),
        (
            "alice:demo-password@127.0.0.1:8080",
            "--proxy: not a URL, expected http://host:port",
        ),
    ] {
        let options = HttpOptions {
            proxies: vec![url.to_owned()],
            ..options()
        };
        let Err(error) = HttpTransport::new(options, reporter.clone()) else {
            panic!("{url} accepted");
        };
        assert_eq!(error.to_string(), message);
    }
}

#[tokio::test]
async fn retry_after_pauses_and_notifies() {
    let server = StubServer::start();
    server.on("/ip", Reply::status(429).header("Retry-After", "1"));
    server.always("/ip", Reply::ok("{}"));
    let (transport, reporter) = start(options());

    let started = Instant::now();
    let request = Request::get(server.url("/ip"), Class::Rdap("lacnic".into()));
    let response = transport.send(request).await.unwrap();
    assert_eq!(response.status, 200);
    assert!(started.elapsed() >= Duration::from_millis(950));
    assert_eq!(server.count("/ip"), 2);
    assert_eq!(
        reporter.lines(),
        vec!["netf: rdap: lacnic: rate limited, waiting 1s".to_owned()]
    );
}

#[tokio::test]
async fn a_paused_egress_is_skipped() {
    let server = StubServer::start();
    server.on("/ip", Reply::status(429).header("Retry-After", "1"));
    server.always("/ip", Reply::ok("{}"));
    let first = StubProxy::start(None);
    let second = StubProxy::start(None);
    let (transport, reporter) = start(HttpOptions {
        proxies: vec![first.url(), second.url()],
        ..options()
    });
    let transport = Arc::new(transport);

    // The first request gets the 429 through the first proxy and waits.
    let paused = tokio::spawn({
        let transport = Arc::clone(&transport);
        let url = server.url("/ip");
        async move { get(&transport, &url).await.map(|r| r.egress) }
    });
    while reporter.lines().is_empty() {
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    // Meanwhile, the other requests go through the second proxy.
    for _ in 0..2 {
        let response = get(&transport, &server.url("/ip")).await.unwrap();
        assert_eq!(response.egress, EgressId(second.url().into()));
    }
    // The first request retries on its own egress after the pause.
    let egress = paused.await.unwrap().unwrap();
    assert_eq!(egress, EgressId(first.url().into()));
    assert_eq!(reporter.lines().len(), 1);
}

#[tokio::test]
async fn duplicate_proxies_observe_the_same_pause() {
    let server = StubServer::start();
    server.on("/ip", Reply::status(429).header("Retry-After", "1"));
    server.always("/ip", Reply::ok("{}"));
    let proxy = StubProxy::start(None);
    let (transport, reporter) = start(HttpOptions {
        proxies: vec![proxy.url(), format!("{}/", proxy.url())],
        ..options()
    });
    let transport = Arc::new(transport);
    let started = Instant::now();
    let paused = tokio::spawn({
        let transport = Arc::clone(&transport);
        let url = server.url("/ip");
        async move { body(get(&transport, &url).await.unwrap()).await.unwrap() }
    });
    // The HTTP 429 notice confirms that the proxy pause has started.
    tokio::time::timeout(Duration::from_secs(5), async {
        while reporter.lines().is_empty() {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("a rate-limit notice");

    // The second request waits for the pause, even with a duplicate proxy URL.
    let response = get(&transport, &server.url("/ip")).await.unwrap();
    assert!(started.elapsed() >= Duration::from_secs(1));
    assert_eq!(response.egress, EgressId(proxy.url().into()));
    assert_eq!(body(response).await.unwrap(), "{}");
    assert_eq!(paused.await.unwrap(), "{}");
    assert_eq!(server.count("/ip"), 3);
    assert_eq!(reporter.lines().len(), 1);
}

#[tokio::test]
async fn too_long_a_pause_gives_up() {
    let server = StubServer::start();
    server.always("/ip", Reply::status(429).header("Retry-After", "7200"));
    let (transport, reporter) = start(options());
    let error = get(&transport, &server.url("/ip")).await.unwrap_err();
    assert_eq!(
        error,
        TransportError::RateLimited(Duration::from_secs(7200))
    );
    assert_eq!(error.to_string(), "rate limited for 2h, giving up");
    assert_eq!(server.count("/ip"), 1);
    assert!(reporter.lines().is_empty());
}

#[tokio::test]
async fn the_sixth_429_in_a_row_gives_up() {
    let server = StubServer::start();
    server.always("/ip", Reply::status(429).header("Retry-After", "0"));
    let (transport, _) = start(options());
    let error = get(&transport, &server.url("/ip")).await.unwrap_err();
    assert_eq!(error, TransportError::RateLimited(Duration::ZERO));
    assert_eq!(server.count("/ip"), 6);
}

#[tokio::test]
async fn server_errors_are_retried_twice() {
    let server = StubServer::start();
    server.on("/a", Reply::status(500));
    server.on("/a", Reply::status(503));
    server.always("/a", Reply::ok("ok"));
    server.always("/b", Reply::status(500));
    let (transport, _) = start(options());

    let response = get(&transport, &server.url("/a")).await.unwrap();
    assert_eq!(body(response).await.unwrap(), "ok");
    assert_eq!(server.count("/a"), 3);

    let error = get(&transport, &server.url("/b")).await.unwrap_err();
    assert_eq!(error, TransportError::Status(500));
    assert_eq!(server.count("/b"), 3);
}

#[tokio::test]
async fn connection_refused() {
    let closed = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://{}/x", closed.local_addr().unwrap());
    drop(closed);
    let (transport, _) = start(options());
    let error = get(&transport, &url).await.unwrap_err();
    assert_eq!(error, TransportError::Connect("connection refused".into()));
}

#[tokio::test]
async fn headers_timeout() {
    let server = StubServer::start();
    server.always("/late", Reply::ok("late").delay(Duration::from_secs(5)));
    let (transport, _) = start(HttpOptions {
        response_timeout: Duration::from_millis(150),
        ..options()
    });
    let started = Instant::now();
    let error = get(&transport, &server.url("/late")).await.unwrap_err();
    assert_eq!(error, TransportError::Timeout("response headers"));
    assert_eq!(server.count("/late"), 3);
    assert!(started.elapsed() < Duration::from_secs(2));
}

#[tokio::test]
async fn body_idle_timeout() {
    let server = StubServer::start();
    server.always("/stall", Reply::ok("first").stall());
    let (transport, _) = start(HttpOptions {
        body_timeout: Duration::from_millis(150),
        ..options()
    });
    let mut response = get(&transport, &server.url("/stall")).await.unwrap();
    let chunk = response.body.next_chunk().await.unwrap().unwrap();
    assert_eq!(chunk, "first");
    let error = response.body.next_chunk().await.unwrap().unwrap_err();
    assert_eq!(error, TransportError::Timeout("response body"));
    assert!(response.body.next_chunk().await.is_none());
    // Without validators, there is nothing to resume.
    assert_eq!(server.count("/stall"), 1);
}

#[tokio::test]
async fn a_cut_body_with_validators_resumes() {
    let server = StubServer::start();
    let cut = Reply::status(200)
        .header("ETag", "\"v1\"")
        .chunks(vec![Bytes::from("hello "), Bytes::from("wo")])
        .cut();
    server.on("/file", cut.clone());
    server.always("/file", Reply::ok("hello world").header("ETag", "\"v1\""));
    let (transport, _) = start(options());
    let response = get(&transport, &server.url("/file")).await.unwrap();
    assert_eq!(body(response).await.unwrap(), "hello world");
    assert_eq!(server.count("/file"), 2);

    // The second response is a different file, so the cut stands.
    server.on("/changed", cut);
    server.always(
        "/changed",
        Reply::ok("other text!").header("ETag", "\"v2\""),
    );
    let response = get(&transport, &server.url("/changed")).await.unwrap();
    let error = body(response).await.unwrap_err();
    assert!(matches!(error, TransportError::Io(_)), "{error:?}");
    assert_eq!(server.count("/changed"), 2);
}
