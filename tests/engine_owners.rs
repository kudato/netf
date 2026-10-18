//! End-to-end tests of the registry data, run in process. They cover the
//! registry columns of the rows, the fields of the delegated stats,
//! `net.org` and `as.org`, the limit with expensive filters, the cache of
//! RDAP responses, and 429 from a registry.
//!
//! The data is the world of `tests/common/mod.rs`: the routes, plus the
//! stats, bootstrap, and RDAP fixtures of the five registries.

mod common;

use std::{collections::BTreeSet, sync::Arc};

use common::{
    BOOTSTRAP, CLOSED_BASE, FullRow, World, full_row, full_table,
    stub::{Reply, StubServer},
};
use netf::Invocation;

/// The eight routes of AS64503, in the order of addresses.
const CDN_ROUTES: [&str; 8] = [
    "203.0.113.0/28",
    "203.0.113.16/28",
    "203.0.113.32/28",
    "203.0.113.48/28",
    "203.0.113.64/28",
    "203.0.113.80/28",
    "203.0.113.96/28",
    "203.0.113.112/28",
];

/// Runs `args` and returns the rows with every column.
///
/// # Panics
///
/// Panics if the exit code is not 0 or stderr is not empty.
fn quiet_rows(world: &World, args: &[&str]) -> Vec<FullRow> {
    let (stdout, stderr) = world.ok(args);
    assert!(stderr.is_empty(), "netf {args:?}: stderr {stderr:?}");
    full_table(&stdout)
}

/// Runs `args` with `--ipset` and returns stdout.
///
/// # Panics
///
/// Panics if the exit code is not 0 or stderr is not empty.
fn ipset(world: &World, args: &[&str]) -> String {
    let mut all = vec!["--ipset"];
    all.extend_from_slice(args);
    let (stdout, stderr) = world.ok(&all);
    assert!(stderr.is_empty(), "netf {all:?}: stderr {stderr:?}");
    stdout
}

/// Returns the routes of `rows`, in order.
fn routes_of(rows: &[FullRow]) -> Vec<&str> {
    rows.iter().map(|r| r.route.as_str()).collect()
}

/// Returns the values of the `ip` requests to `host` that are in `routes`,
/// without repeats.
fn asked_routes(world: &World, host: &str, routes: &[&str]) -> BTreeSet<String> {
    world
        .rdap_values(host, "ip")
        .into_iter()
        .filter(|v| routes.contains(&v.as_str()))
        .collect()
}

/// Checks that netf made no request to RDAP or to the bootstrap.
fn assert_no_rdap(world: &World) {
    assert_eq!(world.rdap_calls(), Vec::new(), "RDAP requests");
    for (url, _) in BOOTSTRAP {
        assert_eq!(world.transport.count(url), 0, "{url} requested");
    }
}

// The network, holder, and abuse columns

#[test]
fn leased_network_shows_the_tenant() {
    // The most specific record of 192.0.2.128/27 is the record of the
    // tenant: block /24, then lease /25, then tenant /27.
    let world = World::owners();
    let rows = quiet_rows(&world, &["route: 192.0.2.128/27"]);
    assert_eq!(rows.len(), 1, "{rows:?}");
    let row = &rows[0];
    assert_eq!(row.ases, "AS64499 SETONE, AS64500 SETTWO");
    assert_eq!(row.net, "192.0.2.128/27");
    assert_eq!(row.owner, "Tenant One GmbH, XC");
    assert_eq!(
        row.abuse,
        "abuse@tenant-one.example / abuse@set-one.example, abuse@set-two.example"
    );
}

#[test]
fn address_of_a_client_gives_the_client() {
    // `ip: <address of a client>` gives the client, because the record must
    // cover the address, not the route. The record of the client has no
    // abuse contact, so the column shows `-`. netf does not take the
    // mailbox from the parent record.
    let world = World::owners();
    let rows = quiet_rows(&world, &["ip: 198.51.100.130"]);
    assert_eq!(
        rows,
        vec![FullRow {
            part: Some("198.51.100.130".into()),
            route: "198.51.100.128/25".into(),
            ases: "AS64502 ROGUE".into(),
            net: "198.51.100.128/26".into(),
            owner: "Small Customer LLC, XE".into(),
            abuse: "- / abuse@rogue.example".into(),
            extra: vec![],
        }]
    );
}

#[test]
fn apnic_range_that_is_not_a_prefix() {
    // A record that is not a CIDR block prints as `first-last`. The
    // reserved quarter has no record, so its rows show `-`.
    let world = World::owners();
    let rows = quiet_rows(&world, &["as.asn: 64503"]);
    assert_eq!(routes_of(&rows), CDN_ROUTES);
    for route in ["203.0.113.0/28", "203.0.113.32/28", "203.0.113.80/28"] {
        let row = full_row(&rows, route);
        assert_eq!(row.ases, "AS64503 EXAMPLE-CDN");
        assert_eq!(row.net, "203.0.113.0-203.0.113.95", "{route}");
        assert_eq!(row.owner, "Example CDN Ltd, XG", "{route}");
        assert_eq!(row.abuse, "irt@cdn.example / abuse@cdn.example", "{route}");
    }
    let customer = full_row(&rows, "203.0.113.16/28");
    assert_eq!(customer.net, "203.0.113.16/28");
    assert_eq!(customer.owner, "CDN Customer Pty Ltd, XG");
    assert_eq!(
        customer.abuse,
        "abuse@cdn-customer.example / abuse@cdn.example"
    );
    for route in ["203.0.113.96/28", "203.0.113.112/28"] {
        let row = full_row(&rows, route);
        assert_eq!(row.net, "-", "{route}");
        assert_eq!(row.owner, "-", "{route}");
        assert_eq!(row.abuse, "- / abuse@cdn.example", "{route}");
    }
}

#[test]
fn lacnic_redirects_to_registro_br() {
    // netf follows redirects, and LACNIC answers 307 to
    // `rdap.registro.test`. One LACNIC handle holds all three roles.
    let world = World::owners();
    let rows = quiet_rows(&world, &["as.asn: 64504 or as.asn: 64507"]);
    assert_eq!(routes_of(&rows), ["203.0.113.128/27", "203.0.113.160/27"]);
    let first = full_row(&rows, "203.0.113.128/27");
    assert_eq!(first.ases, "AS64507");
    assert_eq!(first.net, "203.0.113.128/26");
    assert_eq!(first.owner, "Rede Exemplo Ltda, XH");
    assert_eq!(
        first.abuse,
        "abuse@rede-exemplo.example / noc@rede-exemplo.example"
    );
    let second = full_row(&rows, "203.0.113.160/27");
    assert_eq!(second.ases, "AS64504 NOCOUNTRY-AS");
    assert_eq!(second.net, "203.0.113.160/27");
    assert_eq!(second.owner, "Provedor Exemplo Ltda, XH");
    assert_eq!(
        second.abuse,
        "abuse@provedor.example / noc@nocountry.example"
    );
    assert!(
        !world.rdap_values("rdap.lacnic.test", "ip").is_empty(),
        "LACNIC first: {:?}",
        world.rdap_calls()
    );
    assert!(
        !world.rdap_values("rdap.registro.test", "ip").is_empty(),
        "the redirect was not followed: {:?}",
        world.rdap_calls()
    );
}

#[test]
fn ipset_asks_no_registry() {
    // `--ipset` asks RDAP only if a condition needs it. `net.country` comes
    // from the stats, without RDAP.
    let world = World::owners();
    assert_eq!(
        ipset(&world, &["as.asn: 64503"]),
        "203.0.113.0/25\n",
        "AS64503"
    );
    assert_eq!(ipset(&world, &["net.country: XI"]), "203.0.113.224/27\n");
    assert_no_rdap(&world);
}

// `net.country`, `net.rir`, and `as.rir`: the delegated stats

#[test]
fn no_route_row_for_the_unannounced_rest() {
    // The addresses of the XH block that no route covers are a `no route` row.
    // Its network is the record that covers them.
    let world = World::owners();
    let rows = quiet_rows(&world, &["net.country: XH"]);
    assert_eq!(
        routes_of(&rows),
        ["203.0.113.128/27", "203.0.113.160/27", "no route"]
    );
    let rest = full_row(&rows, "no route");
    assert_eq!(rest.ases, "-");
    assert_eq!(rest.net, "203.0.113.192/27");
    assert_eq!(rest.owner, "Ilha Exemplo Ltda, XH");
    assert_eq!(rest.abuse, "abuse@ilha.example");
    let rows = quiet_rows(&world, &["net.country: XH and route: *"]);
    assert_eq!(routes_of(&rows), ["203.0.113.128/27", "203.0.113.160/27"]);
}

#[test]
fn every_route_includes_the_unannounced_blocks() {
    // A query with nothing to look up runs over every route and every
    // block of the stats that no route covers.
    let world = World::owners();
    let rows = quiet_rows(&world, &["not route: *"]);
    let nets: Vec<&str> = rows.iter().map(|r| r.net.as_str()).collect();
    assert_eq!(routes_of(&rows), ["no route", "no route"]);
    assert_eq!(nets, ["203.0.113.192/27", "203.0.113.224/27"]);
    assert_eq!(ipset(&world, &["not route: *"]), "203.0.113.192/26\n");
    assert_eq!(
        ipset(&world, &["not as.asn: 64496"]),
        "192.0.2.0/24\n198.51.100.0/24\n203.0.113.0/24\n"
    );
}

#[test]
fn conditions_on_routes_and_as_skip_the_stats() {
    // A row without a route has no AS, so these queries never need the
    // blocks without a route.
    let stats = |world: &World| {
        let requests = world.transport.requests();
        requests
            .iter()
            .filter(|r| r.url.contains("/delegated-"))
            .count()
    };
    for query in ["route: *", "as.name: *", "not as.asn: 64496 and as.asn: *"] {
        let world = World::owners();
        assert!(!ipset(&world, &[query]).is_empty(), "{query}");
        assert_eq!(stats(&world), 0, "{query}");
    }
}

#[test]
fn available_and_reserved_are_not_networks() {
    // The registry did not give out the available and reserved blocks, so
    // they are not `net` records.
    let world = World::owners();
    assert_eq!(
        ipset(&world, &["net.rir: *"]),
        "192.0.2.0/24\n198.51.100.0/24\n203.0.113.0/26\n203.0.113.64/27\n203.0.113.128/25\n"
    );
    assert_eq!(ipset(&world, &["net.rir: arin"]), "198.51.100.0/24\n");
    assert_eq!(
        ipset(&world, &["net.rir: apnic"]),
        "203.0.113.0/26\n203.0.113.64/27\n"
    );
    // `route: * and not net.rir: *` finds the routes that no block covers.
    assert_eq!(
        ipset(&world, &["route: * and not net.rir: *"]),
        "203.0.113.96/27\n"
    );
    let rows = quiet_rows(&world, &["route: * and not net.rir: *"]);
    assert_eq!(routes_of(&rows), ["203.0.113.96/28", "203.0.113.112/28"]);
    assert_eq!(
        ipset(&world, &["-6", "net.rir: ripencc"]),
        "2001:db8::/32\n"
    );
}

// `net.org` and `as.org`

#[test]
fn net_org_by_handle() {
    // `net.org` gives the routes in the networks of the organization and
    // the routes that cover these networks. The `--ipset` list has only the
    // addresses of the record inside the route.
    let world = World::owners();
    let rows = quiet_rows(&world, &["net.org: ORG-CH1-RIPE"]);
    assert_eq!(routes_of(&rows), ["192.0.2.0/24", "192.0.2.0/26"]);
    for row in &rows {
        assert_eq!(row.owner, "Client Hosting Ltd, XB", "{row:?}");
        assert_eq!(row.net, "192.0.2.0/26", "{row:?}");
    }
    assert_eq!(ipset(&world, &["net.org: ORG-CH1-RIPE"]), "192.0.2.0/26\n");
    // netf ignores the case of organization handles.
    assert_eq!(ipset(&world, &["net.org: org-ch1-ripe"]), "192.0.2.0/26\n");
}

#[test]
fn net_org_of_the_hoster_reports_truncation() {
    // `net.org` of a hoster gives every route in its network, of any AS.
    // The truncation message of the registry goes to stderr as one line.
    let world = World::owners();
    // When the RDAP list is empty or truncated, the RIPE REST API
    // completes it.
    world.serve_search();
    let (stdout, stderr) = world.ok(&["net.org: ORG-EN1-RIPE"]);
    let rows = full_table(&stdout);
    assert_eq!(
        routes_of(&rows),
        [
            "192.0.2.0/24",
            "192.0.2.0/26",
            "192.0.2.64/27",
            "192.0.2.128/27"
        ]
    );
    assert_eq!(
        full_row(&rows, "192.0.2.0/24").owner,
        "Example Networks LLC, XA"
    );
    assert_eq!(
        stderr,
        ["netf: ripencc: limited search results to 100 maximum"]
    );
    let (stdout, _) = world.ok(&["--ipset", "net.org: ORG-EN1-RIPE"]);
    assert_eq!(stdout, "192.0.2.0/24\n");
}

#[test]
fn as_org_keeps_only_own_resources() {
    // `as.org` gives the routes of the AS of the organization. AS64502
    // names Example Networks only as a sponsor, so netf drops AS64502.
    let world = World::owners();
    // When the RDAP list is empty or truncated, the RIPE REST API
    // completes it.
    world.serve_search();
    // stderr may also have the truncation notice of the entity.
    let (stdout, _) = world.ok(&["as.org: ORG-EN1-RIPE"]);
    let rows = full_table(&stdout);
    assert_eq!(routes_of(&rows), ["192.0.2.0/24", "192.0.2.0/26"]);
    let (stdout, _) = world.ok(&["--ipset", "as.org: ORG-EN1-RIPE"]);
    assert_eq!(stdout, "192.0.2.0/24\n");
}

#[test]
fn as_org_with_a_block_of_as() {
    // An organization may list its AS as one block, `startAutnum` to
    // `endAutnum`: every AS of the block counts, as with a list of single AS.
    let world = World::search();
    let rdap = world.serve_registries();
    let autnum = |first: u32, last: u32| {
        serde_json::json!({
            "objectClassName": "autnum",
            "handle": format!("AS{first}"),
            "startAutnum": first,
            "endAutnum": last,
            "entities": [{"objectClassName": "entity", "handle": "BLK-1-ARIN",
                          "roles": ["registrant"]}],
        })
    };
    let org = |autnums: Vec<serde_json::Value>| {
        serde_json::json!({
            "objectClassName": "entity",
            "handle": "BLK-1-ARIN",
            "vcardArray": ["vcard", [
                ["version", {}, "text", "4.0"],
                ["fn", {}, "text", "Block Holder Inc"],
                ["kind", {}, "text", "org"],
            ]],
            "autnums": autnums,
        })
    };
    rdap.insert("rdap.arin.test", &org(vec![autnum(64499, 64502)]));
    let rows = quiet_rows(&world, &["as.org: BLK-1-ARIN"]);
    let block = routes_of(&rows);
    assert_eq!(
        block,
        ["192.0.2.128/27", "198.51.100.0/24", "198.51.100.128/25"]
    );
    let world = World::search();
    world.serve_registries().insert(
        "rdap.arin.test",
        &org((64499..=64502).map(|n| autnum(n, n)).collect()),
    );
    let rows = quiet_rows(&world, &["as.org: BLK-1-ARIN"]);
    assert_eq!(routes_of(&rows), block);
}

#[test]
fn org_by_opaque_id_of_the_stats() {
    // `net.org` and `as.org` match the opaque-id of the stats. The block
    // without a route is in the list.
    let world = World::owners();
    assert_eq!(
        ipset(&world, &["net.org: L3C0FFEE"]),
        "203.0.113.128/26\n203.0.113.192/27\n"
    );
    assert_eq!(ipset(&world, &["as.org: L3C0FFEE"]), "203.0.113.128/26\n");
    let rows = quiet_rows(&world, &["net.org: FEXAMPLE1"]);
    assert_eq!(
        rows,
        vec![FullRow {
            part: None,
            route: "no route".into(),
            ases: "-".into(),
            net: "203.0.113.224/27".into(),
            owner: "Savanna Net Ltd, XI".into(),
            abuse: "-".into(),
            extra: vec![],
        }]
    );
}

#[test]
fn empty_organizations_are_reported() {
    // An organization with nothing to show gives code 0 and a notice on
    // stderr: `not found`, `no networks`, or `no AS` for `as.org`.
    let world = World::owners();
    // When the RDAP list is empty or truncated, the RIPE REST API
    // completes it.
    world.serve_search();
    for (query, notice) in [
        (
            "net.org: NOSUCH-ORG",
            "netf: net.org: NOSUCH-ORG: not found",
        ),
        ("net.org: QN-1", "netf: net.org: QN-1: no networks"),
        ("as.org: ORG-CH1-RIPE", "netf: as.org: ORG-CH1-RIPE: no AS"),
    ] {
        let (stdout, stderr) = world.ok(&[query]);
        assert_eq!(stdout, "", "{query}");
        assert_eq!(stderr, [notice], "{query}");
        let (stdout, stderr) = world.ok(&["--ipset", query]);
        assert_eq!(stdout, "", "--ipset {query}");
        assert_eq!(stderr, [notice], "--ipset {query}");
    }
}

#[test]
fn net_org_as_a_filter() {
    // A condition on `net.*` must hold for one network of the route. The
    // customer record of 203.0.113.16/28 lies inside the range of
    // ORG-ECL1-AP. The reserved quarter has no record at all.
    let world = World::owners();
    let (stdout, _) = world.ok(&["as.asn: 64503 and net.org: ORG-ECL1-AP"]);
    assert_eq!(routes_of(&full_table(&stdout)), CDN_ROUTES[..6]);
    let (stdout, _) = world.ok(&["--ipset", "as.asn: 64503 and net.org: ORG-ECL1-AP"]);
    assert_eq!(stdout, "203.0.113.0/26\n203.0.113.64/27\n");
}

// The limit

#[test]
fn holders_only_for_the_rows_shown() {
    // netf asks RDAP for holders only for the rows that it shows.
    let world = World::owners();
    let (stdout, stderr) = world.ok(&["--limit", "2", "as.asn: 64503"]);
    assert_eq!(
        routes_of(&full_table(&stdout)),
        ["203.0.113.0/28", "203.0.113.16/28"]
    );
    assert_eq!(
        stderr,
        ["netf: showing 2 of 8 matches; refine the query or use --limit 0"]
    );
    assert_eq!(
        asked_routes(&world, "rdap.apnic.test", &CDN_ROUTES),
        BTreeSet::from(["203.0.113.0/28".to_owned(), "203.0.113.16/28".to_owned()])
    );
}

/// Runs an expensive filter with `--limit 2 --concurrency <window>`.
///
/// Checks the limit message and the requests beyond the limit.
fn check_window(window: usize) {
    let world = World::owners();
    let concurrency = window.to_string();
    let (stdout, stderr) = world.ok(&[
        "--limit",
        "2",
        "--concurrency",
        &concurrency,
        "as.asn: 64503 and net.org: ORG-ECL1-AP",
    ]);
    assert_eq!(
        routes_of(&full_table(&stdout)),
        ["203.0.113.0/28", "203.0.113.16/28"]
    );
    // netf checks the routes in the order of addresses, with a window of
    // `concurrency` × egresses requests. Without a proxy, there is one
    // egress.
    let asked = asked_routes(&world, "rdap.apnic.test", &CDN_ROUTES);
    assert!(
        (2..=2 + window).contains(&asked.len()),
        "window {window}: asked {asked:?}"
    );
    let line = stderr
        .iter()
        .find(|l| l.starts_with("netf: showing first 2 matches; "))
        .unwrap_or_else(|| panic!("no limit message: {stderr:?}"));
    let rest = line
        .strip_prefix("netf: showing first 2 matches; ")
        .and_then(|r| r.strip_suffix(" candidates not checked; use --limit 0"))
        .unwrap_or_else(|| {
            panic!("expected `<N> candidates not checked; use --limit 0`: {line:?}")
        });
    let unchecked: usize = rest.parse().expect("a number of routes");
    assert!(
        (8 - asked.len()..=6).contains(&unchecked),
        "{unchecked} not checked with {} asked",
        asked.len()
    );
    assert!(
        stderr.iter().all(|l| !l.starts_with("netf: showing 2 of")),
        "the total is unknown with an expensive filter: {stderr:?}"
    );
}

#[test]
fn expensive_filter_stops_at_the_limit() {
    check_window(1);
    check_window(2);
}

// The cache of RDAP responses

#[test]
fn second_run_asks_nothing() {
    // Within the TTL, a response comes from the cache. The cache keeps 404
    // responses too, and the reserved routes get 404 from APNIC.
    let world = World::owners();
    let (first, _) = world.ok(&["as.asn: 64503"]);
    let asked = world.transport.requests().len();
    assert!(
        world
            .rdap_values("rdap.apnic.test", "ip")
            .contains(&"203.0.113.96/28".to_owned()),
        "{:?}",
        world.rdap_calls()
    );
    let (second, _) = world.ok(&["as.asn: 64503"]);
    assert_eq!(first, second);
    assert_eq!(
        world.transport.requests().len(),
        asked,
        "second run: {:?}",
        &world.transport.requests()[asked..]
    );
    assert!(
        !common::files_in(&world.cache_dir().join("responses")).is_empty(),
        "the first run writes its responses to the cache"
    );
}

#[test]
fn no_cache_asks_again_and_writes_nothing() {
    // `--no-cache` neither reads nor writes the cache.
    let world = World::owners();
    world.ok(&["--no-cache", "as.asn: 64501"]);
    let asked = world.rdap_calls().len();
    assert!(asked >= 2, "{:?}", world.rdap_calls());
    world.ok(&["--no-cache", "as.asn: 64501"]);
    assert_eq!(world.rdap_calls().len(), 2 * asked);
    assert!(
        !world.cache_dir().join("responses").exists(),
        "{:?}",
        common::files_under(&world.netf_dir())
    );
}

// 429 from a registry

#[test]
fn rate_limited_registry_is_waited_for() {
    // On 429, netf waits as long as the registry says and prints
    // `netf: rdap: <rir>: rate limited, waiting Ns`. The real transport makes
    // the pause, so this test runs over HTTP against the stub server.
    // Tests cannot shorten `Retry-After`, so the test waits one real second.
    //
    // First, check that netf rewrites the RDAP servers of the bootstrap to
    // `NETF_SOURCE_BASE`. Otherwise the real transport would go to the
    // internet, and tests never do that.
    let fake = World::owners();
    fake.ok(&["as.asn: 64501"]);
    for request in fake.transport.requests() {
        assert!(
            request.url.starts_with(CLOSED_BASE),
            "not rewritten: {}; refusing to run over the network",
            request.url
        );
    }

    let world = World::standard();
    let stub = StubServer::start();
    stub.on(
        "/rdap.arin.test/registry/ip/198.51.100.0/24",
        Reply::status(429).header("Retry-After", "1"),
    );
    let (mut invocation, reporter): (Invocation, _) = world.invocation(&["as.asn: 64501"]);
    invocation.transport = None;
    invocation
        .env
        .vars
        .insert("NETF_SOURCE_BASE".into(), stub.base().to_owned());
    let reporter = Arc::clone(&reporter);
    let outcome = common::runtime().block_on(netf::run(invocation));
    let stderr = reporter.lines();
    assert_eq!(outcome.code, 0, "{stderr:?}");
    assert!(
        stderr.contains(&"netf: rdap: arin: rate limited, waiting 1s".to_owned()),
        "{stderr:?}"
    );
    let stdout = String::from_utf8(outcome.stdout).expect("UTF-8");
    assert_eq!(
        full_table(&stdout),
        vec![FullRow {
            part: None,
            route: "198.51.100.0/24".into(),
            ases: "AS64501 HOMENET".into(),
            net: "198.51.100.0/24".into(),
            owner: "Documentation Net Inc, XE".into(),
            abuse: "abuse@docnet.example / abuse@homenet.example".into(),
            extra: vec![],
        }]
    );
    assert_eq!(
        stub.count("/rdap.arin.test/registry/ip/198.51.100.0/24"),
        2,
        "429, then the answer"
    );
}
