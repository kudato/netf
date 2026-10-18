//! Tests of what RDAP needs from the real transport.
//!
//! `--ripe-emails` pins its requests to one egress, because RIPE limits
//! personal data per IP and day. A pinned request takes that egress on
//! every attempt, and a 429 comes back as a response at once. The search of
//! organizations by name needs its request to reach the registry as written.
//!
//! Nothing leaves the machine. Every URL is a stub's on `127.0.0.1`, and
//! the stub proxies tunnel only there.

mod common;

use std::{sync::Arc, time::Duration};

use netf::{Class, EgressId, HttpOptions, HttpTransport, Request, Transport};

use common::{
    CollectReporter,
    stub::{Reply, StubProxy, StubServer},
};

fn start(proxies: Vec<String>) -> (HttpTransport, Arc<CollectReporter>) {
    let reporter = Arc::new(CollectReporter::new());
    let options = HttpOptions {
        proxies,
        retry_pauses: vec![Duration::from_millis(10), Duration::from_millis(20)],
        ..HttpOptions::default()
    };
    let transport = HttpTransport::new(options, reporter.clone()).expect("valid options");
    (transport, reporter)
}

fn rdap() -> Class {
    Class::Rdap(Arc::from("ripencc"))
}

fn egress(proxy: &StubProxy) -> EgressId {
    EgressId(proxy.url().into())
}

#[tokio::test]
async fn the_trait_lists_the_egresses_of_the_pool() {
    let first = StubProxy::start(None);
    let second = StubProxy::start(None);
    let (transport, _) = start(vec![first.url(), second.url()]);
    let transport: &dyn Transport = &transport;
    assert_eq!(transport.egresses(), [egress(&first), egress(&second)]);
    let (direct, _) = start(Vec::new());
    assert_eq!(Transport::egresses(&direct), [EgressId::direct()]);
}

#[tokio::test]
async fn every_request_goes_through_the_pinned_egress() {
    let server = StubServer::start();
    server.always("/entity/JD1-TEST", Reply::ok("{}"));
    let first = StubProxy::start(None);
    let second = StubProxy::start(None);
    let (transport, _) = start(vec![first.url(), second.url()]);
    for _ in 0..3 {
        let request = Request::get(server.url("/entity/JD1-TEST"), rdap());
        let response = transport.send_via(request, egress(&second)).await.unwrap();
        assert_eq!(response.status, 200);
        assert_eq!(response.egress, egress(&second));
        assert_eq!(response.body.collect(1 << 10).await.unwrap(), "{}");
    }
    assert_eq!(first.tunnels(), 0);
    assert!(second.tunnels() >= 1);
    let received = server.received();
    assert_eq!(received.len(), 3);
    assert_eq!(received[0].header("accept"), Some("application/rdap+json"));
}

#[tokio::test]
async fn a_429_is_returned_at_once_without_a_pause() {
    let server = StubServer::start();
    server.on(
        "/entity/JD1-TEST",
        Reply::status(429).header("Retry-After", "3600"),
    );
    server.always("/entity/JD1-TEST", Reply::ok("{}"));
    let (transport, reporter) = start(Vec::new());
    let request = Request::get(server.url("/entity/JD1-TEST"), rdap());
    let response = transport
        .send_via(request, EgressId::direct())
        .await
        .unwrap();
    assert_eq!(response.status, 429);
    assert_eq!(server.count("/entity/JD1-TEST"), 1);
    assert!(reporter.lines().is_empty());
    // The host is not paused for the other requests either.
    let request = Request::get(server.url("/entity/JD1-TEST"), rdap());
    let response = tokio::time::timeout(Duration::from_secs(5), transport.send(request))
        .await
        .expect("no pause")
        .unwrap();
    assert_eq!(response.status, 200);
}

#[tokio::test]
async fn server_errors_are_retried_on_the_same_egress() {
    let server = StubServer::start();
    server.on("/entity/JD1-TEST", Reply::status(503));
    server.on("/entity/JD1-TEST", Reply::status(502));
    server.always("/entity/JD1-TEST", Reply::ok("{}"));
    let first = StubProxy::start(None);
    let second = StubProxy::start(None);
    let (transport, _) = start(vec![first.url(), second.url()]);
    let request = Request::get(server.url("/entity/JD1-TEST"), rdap());
    let response = transport.send_via(request, egress(&first)).await.unwrap();
    assert_eq!(response.status, 200);
    assert_eq!(response.egress, egress(&first));
    assert_eq!(server.count("/entity/JD1-TEST"), 3);
    assert_eq!(second.tunnels(), 0);
}

const SEARCH: &str = "/entities?fn=Example%20Holdings*";

#[tokio::test]
async fn a_search_reaches_the_registry_as_written() {
    let server = StubServer::start();
    server.always(SEARCH, Reply::ok(r#"{"entitySearchResults": []}"#));
    let proxy = StubProxy::start(None);
    for proxies in [Vec::new(), vec![proxy.url()]] {
        let (transport, _) = start(proxies);
        let request = Request::get(server.url(SEARCH), rdap());
        let response = transport.send(request).await.unwrap();
        assert_eq!(response.status, 200);
    }
    let received = server.received();
    assert_eq!(received.len(), 2);
    for request in received {
        assert_eq!(
            (request.method.as_str(), request.path.as_str()),
            ("GET", SEARCH)
        );
    }
    assert!(proxy.tunnels() >= 1);
}
