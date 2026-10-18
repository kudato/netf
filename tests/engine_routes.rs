//! End-to-end tests of queries on routes, AS, and domains, run in process
//! over the fixtures of [`World::standard`].
//!
//! The data is the synthetic world of `tests/common/mod.rs`. These tests
//! check only the part, route, and AS columns. `tests/engine_owners.rs`
//! tests the network, holder, and abuse columns.

mod common;

use common::{
    ASN_FIXTURE, ASN_TXT, RIS_V4, RIS_V6, Scripted, Span, Table, World, fixture, gzip, ipset_of,
    spans, table,
};

/// The AS column of 192.0.2.0/24 and 2001:db8::/32: two origins, in the
/// order of the dump.
const TWO_AS: &str = "AS64496 EXAMPLE-NET, AS64497 TELE-EDGE";
/// The AS column of the AS set routes.
const AS_SET: &str = "AS64499 SETONE, AS64500 SETTWO";

/// Runs `args` and returns the rows.
///
/// # Panics
///
/// Panics if the exit code is not 0 or stderr is not empty.
fn quiet(world: &World, args: &[&str]) -> Table {
    let (stdout, stderr) = world.ok(args);
    assert!(stderr.is_empty(), "netf {args:?}: stderr {stderr:?}");
    table(&stdout)
}

/// Runs `args` like [`quiet`] and returns the routes in the order printed.
///
/// # Panics
///
/// Panics like [`quiet`], or if the rows are not in the order of addresses.
fn routes(world: &World, args: &[&str]) -> Vec<String> {
    let table = quiet(world, args);
    table.assert_in_address_order();
    table.routes().into_iter().map(str::to_owned).collect()
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

/// Returns the URLs requested, without repeats, in order.
fn urls(world: &World) -> Vec<String> {
    let mut seen = Vec::new();
    for request in world.transport.requests() {
        if !seen.contains(&request.url) {
            seen.push(request.url);
        }
    }
    seen
}

// `ip:`

#[test]
fn ip_address_takes_the_most_specific_route() {
    let world = World::standard();
    // `route: <ip>` and `ip: <ip>` take the most specific route that covers
    // the address. 192.0.2.10 is in 192.0.2.0/24 and in 192.0.2.0/26.
    let t = quiet(&world, &["ip:", "192.0.2.10"]);
    assert!(t.has_part, "ip: takes part of the route: {t:?}");
    assert_eq!(t.rows.len(), 1, "{t:?}");
    let row = &t.rows[0];
    assert_eq!(row.part.as_deref(), Some("192.0.2.10"));
    assert_eq!(row.route, "192.0.2.0/26");
    assert_eq!(row.ases, "AS64496 EXAMPLE-NET");

    // A prefix with two origins shows every AS of the route, with names.
    let t = quiet(&world, &["ip: 192.0.2.200"]);
    assert_eq!(t.rows.len(), 1, "{t:?}");
    assert_eq!(t.rows[0].route, "192.0.2.0/24");
    assert_eq!(t.rows[0].ases, TWO_AS);

    // Every member of an AS set in the RIS dump is an origin.
    let t = quiet(&world, &["ip: 192.0.2.140"]);
    assert_eq!(t.one("192.0.2.128/27").ases, AS_SET);
}

#[test]
fn ip_network_gives_the_covering_route_and_the_routes_inside() {
    // `ip: <network>` gives the covering route with a part, plus the routes
    // inside the network. Only inside a scope does it give the covering
    // route alone.
    let world = World::standard();
    let t = quiet(&world, &["ip: 192.0.2.0/25"]);
    t.assert_in_address_order();
    assert!(t.has_part, "{t:?}");
    assert_eq!(
        t.route_set(),
        ["192.0.2.0/24", "192.0.2.0/26", "192.0.2.64/27"]
    );
    // The /24 covers the network, so the part is the network.
    assert_eq!(t.one("192.0.2.0/24").part.as_deref(), Some("192.0.2.0/25"));
    assert_eq!(t.one("192.0.2.64/27").ases, "AS64498 DOCNET");
    // The rows and `--ipset` give the same addresses.
    assert_eq!(t.addresses(), spans(["192.0.2.0/25"]));
}

#[test]
fn ip_without_a_route_is_no_route() {
    // An address without a covering route still makes a row. Its route is
    // `no route`, and the missing AS is `-`.
    let world = World::standard();
    let t = quiet(&world, &["ip: 203.0.113.200"]);
    assert_eq!(t.rows.len(), 1, "{t:?}");
    let row = &t.rows[0];
    assert_eq!(row.part.as_deref(), Some("203.0.113.200"));
    assert_eq!(row.route, "no route");
    assert_eq!(row.ases, "-");
}

#[test]
fn ip_network_without_a_covering_route() {
    // 203.0.113.128/25 has two routes inside, and no AS announces
    // 203.0.113.192/26. The rows and `--ipset` give the same addresses, so
    // the rest of the network is a `no route` row, one per unannounced
    // piece.
    let world = World::standard();
    let t = quiet(&world, &["ip: 203.0.113.128/25"]);
    t.assert_in_address_order();
    assert_eq!(
        t.route_set(),
        ["203.0.113.128/27", "203.0.113.160/27", "no route"]
    );
    // An AS missing from `asn.txt` shows its number without a name.
    assert_eq!(t.one("203.0.113.128/27").ases, "AS64507");
    assert_eq!(t.one("203.0.113.160/27").ases, "AS64504 NOCOUNTRY-AS");
    assert_eq!(t.addresses(), spans(["203.0.113.128/25"]));
    assert_eq!(
        ipset(&world, &["ip: 203.0.113.128/25"]),
        "203.0.113.128/25\n"
    );
}

#[test]
fn ipset_of_ip_downloads_nothing() {
    // `ip:` downloads nothing. In the list, an address is a /32, and
    // adjacent networks are joined.
    let world = World::standard();
    assert_eq!(
        ipset(
            &world,
            &["ip: (192.0.2.10 or 192.0.2.11 or 198.51.100.0/25 or 198.51.100.128/25)"]
        ),
        "192.0.2.10/31\n198.51.100.0/24\n"
    );
    assert_eq!(urls(&world), Vec::<String>::new());
}

// `domain:`

#[test]
fn domain_in_both_families() {
    // With `-4 -6`, the IPv4 rows come first, then the IPv6 rows.
    let world = World::standard();
    let t = quiet(&world, &["-4", "-6", "domain: www.example.test"]);
    t.assert_in_address_order();
    assert_eq!(
        t.routes(),
        ["192.0.2.0/26", "198.51.100.128/25", "2001:db8::/32"]
    );
    let v6 = t.one("2001:db8::/32");
    assert_eq!(v6.part.as_deref(), Some("2001:db8::10"));
    assert_eq!(v6.ases, TWO_AS);
    assert_eq!(
        ipset(&world, &["-4", "-6", "domain: www.example.test"]),
        "192.0.2.10/32\n198.51.100.130/32\n2001:db8::10/128\n"
    );
}

#[test]
fn international_domain_is_looked_up_in_punycode() {
    // netf looks up παράδειγμα.δοκιμή as xn--hxajbheg2az3al.xn--jxalpdlp.
    let world = World::standard();
    assert_eq!(
        ipset(&world, &["domain: παράδειγμα.δοκιμή"]),
        "192.0.2.70/32\n"
    );
    assert_eq!(
        world.resolver.lookups(),
        ["xn--hxajbheg2az3al.xn--jxalpdlp"]
    );
}

#[test]
fn nxdomain_is_code_1() {
    // NXDOMAIN is an error with code 1, in a query and in a scope.
    let world = World::standard();
    for args in [
        &["domain: nx.example.test"][..],
        &["--ipset", "as.asn: {domain: nx.example.test}"][..],
    ] {
        let (code, stderr) = world.fail(args);
        assert_eq!(code, 1, "{args:?}");
        assert_eq!(
            stderr,
            ["netf: domain nx.example.test: not found (NXDOMAIN)"],
            "{args:?}"
        );
    }
}

#[test]
fn domain_without_an_address_of_the_family() {
    // A domain that exists but has no AAAA record gives a notice and code 0.
    let world = World::standard();
    let (stdout, stderr) = world.ok(&["-6", "domain: v4only.example.test"]);
    assert_eq!(stdout, "");
    assert_eq!(
        stderr,
        ["netf: domain v4only.example.test: no IPv6 address"]
    );
}

// `route:`

#[test]
fn route_exact_and_covering() {
    let world = World::standard();
    let t = quiet(&world, &["route: 192.0.2.0/26"]);
    assert!(!t.has_part, "route: takes whole routes: {t:?}");
    assert_eq!(t.routes(), ["192.0.2.0/26"]);
    assert_eq!(t.rows[0].ases, "AS64496 EXAMPLE-NET");
    // `route: <ip>` gives the most specific route that covers the address.
    assert_eq!(routes(&world, &["route: 192.0.2.70"]), ["192.0.2.64/27"]);
    // `route: <network>` gives the route with this prefix. There is none.
    assert_eq!(
        routes(&world, &["route: 192.0.2.0/25"]),
        Vec::<String>::new()
    );
}

/// Every IPv4 route of the fixtures, in the order of addresses.
const ALL_V4: [&str; 16] = [
    "192.0.2.0/24",
    "192.0.2.0/26",
    "192.0.2.64/27",
    "192.0.2.128/27",
    "198.51.100.0/24",
    "198.51.100.128/25",
    "203.0.113.0/28",
    "203.0.113.16/28",
    "203.0.113.32/28",
    "203.0.113.48/28",
    "203.0.113.64/28",
    "203.0.113.80/28",
    "203.0.113.96/28",
    "203.0.113.112/28",
    "203.0.113.128/27",
    "203.0.113.160/27",
];

/// The collapsed list of every IPv4 route.
const ALL_V4_IPSET: &str = "192.0.2.0/24\n198.51.100.0/24\n203.0.113.0/25\n203.0.113.128/26\n";

#[test]
fn route_of_a_domain() {
    // `route: {domain: www.example.test}` gives the whole routes of the
    // addresses of the domain.
    let world = World::standard();
    let t = quiet(&world, &["route: {domain: www.example.test}"]);
    assert!(!t.has_part, "{t:?}");
    assert_eq!(t.route_set(), ["192.0.2.0/26", "198.51.100.128/25"]);
}

// `as.asn:`

#[test]
fn as_asn_rows_have_every_route_of_the_as() {
    let world = World::standard();
    let t = quiet(&world, &["as.asn: 64496"]);
    assert!(!t.has_part, "{t:?}");
    // A network inside a network of the same AS gives both rows.
    assert_eq!(t.routes(), ["192.0.2.0/24", "192.0.2.0/26"]);
    // The AS column lists every AS of the route, not only the one asked.
    assert_eq!(t.one("192.0.2.0/24").ases, TWO_AS);
    assert_eq!(t.one("192.0.2.0/26").ases, "AS64496 EXAMPLE-NET");
    // The number works with or without `AS`, and as a bare operand.
    let (plain, _) = world.ok(&["as.asn: 64496"]);
    for args in [
        &["as.asn: AS64496"][..],
        &["AS64496"][..],
        &["as.asn:", "64496"][..],
    ] {
        assert_eq!(world.ok(args).0, plain, "{args:?}");
    }
}

#[test]
fn as_asn_ranges() {
    // Ranges take `>`, `>=`, `<`, and `<=`. netf gives no notice for a
    // number of a range that has no networks: 64505, 64506 in IPv4, and the
    // numbers from 64508 up.
    let world = World::standard();
    assert_eq!(
        ipset(&world, &["as.asn >= 64503 and as.asn <= 64510"]),
        "203.0.113.0/25\n203.0.113.128/26\n"
    );
    assert_eq!(ipset(&world, &["as.asn < 64497"]), "192.0.2.0/24\n");
    assert_eq!(ipset(&world, &["as.asn > 64507"]), "");
    let t = quiet(&world, &["as.asn >= 64504 and as.asn <= 64504"]);
    assert_eq!(t.routes(), ["203.0.113.160/27"]);
}

#[test]
fn ipset_reports_only_the_number() {
    // A number without networks gives a notice. `--ipset` does not
    // download the AS names.
    let world = World::standard();
    let (stdout, stderr) = world.ok(&["--ipset", "as.asn: (64496 or 64505)"]);
    assert_eq!(stdout, "192.0.2.0/24\n");
    assert_eq!(stderr, ["netf: AS64505: no networks"]);
    let (stdout, stderr) = world.ok(&["--ipset", "as.asn: 64511"]);
    assert_eq!(stdout, "");
    assert_eq!(stderr, ["netf: AS64511: no networks"]);
    assert_eq!(world.transport.count(ASN_TXT), 0);
}

// `as.name:`

#[test]
fn as_name_with_a_pattern() {
    let world = World::standard();
    let mut want = vec!["192.0.2.0/24", "192.0.2.0/26"];
    want.extend(ALL_V4.iter().filter(|r| r.ends_with("/28")));
    assert_eq!(routes(&world, &["as.name: example*"]), want);
    assert_eq!(
        ipset(&world, &["as.name: example*"]),
        "192.0.2.0/24\n203.0.113.0/25\n"
    );
    // `as.name` downloads `asn.txt` as well. The registry answers for the
    // rows shown are not datasets.
    let mut got: Vec<_> = urls(&world)
        .into_iter()
        .filter(|url| !url.contains("/data.iana.test/") && !url.contains("/rdap."))
        .collect();
    got.sort();
    assert_eq!(got, [ASN_TXT, RIS_V4]);
}

#[test]
fn as_name_is_the_first_word_only() {
    // The organization is not in `as.name`. netf reports a value that
    // finds no AS.
    let world = World::standard();
    let (stdout, stderr) = world.ok(&["as.name: networks"]);
    assert_eq!(stdout, "");
    assert_eq!(stderr, ["netf: as.name: networks: no AS"]);
    let (stdout, stderr) = world.ok(&["as.name: nosuch*"]);
    assert_eq!(stdout, "");
    assert_eq!(stderr, ["netf: as.name: nosuch*: no AS"]);
}

#[test]
fn bare_word_searches_as_name() {
    // A bare word searches `as.name`, `as.org`, and `net.org`. This test
    // checks only `as.name`.
    let world = World::standard();
    assert_eq!(
        world.ok(&["example-net"]).0,
        world.ok(&["as.name: example-net"]).0
    );
    let (stdout, stderr) = world.ok(&["nosuchword"]);
    assert_eq!(stdout, "");
    assert_eq!(stderr, ["netf: nosuchword: nothing found"]);
}

// `as.country:`

#[test]
fn field_star_is_presence() {
    // `field: *` means that the record has the field. 64504 has no country,
    // and 64507 is not in `asn.txt` at all.
    let world = World::standard();
    assert_eq!(
        routes(&world, &["route: * and not as.country: *"]),
        ["203.0.113.128/27", "203.0.113.160/27"]
    );
    assert_eq!(
        routes(&world, &["route: * and not as.name: *"]),
        ["203.0.113.128/27"]
    );
}

// `and`, `or`, `not`, and parentheses

#[test]
fn one_as_holds_every_condition_on_as() {
    // One AS must hold every condition on `as.*`. The origins of
    // 192.0.2.0/24 are EXAMPLE-NET of XA and TELE-EDGE of XB.
    let world = World::standard();
    let none: Vec<String> = Vec::new();
    assert_eq!(
        routes(&world, &["as.name: example-net and as.country: XB"]),
        none
    );
    assert_eq!(
        routes(&world, &["as.name: tele-edge and as.country: XB"]),
        ["192.0.2.0/24"]
    );
    assert_eq!(
        routes(&world, &["as.name: example-net and not as.country: XA"]),
        none
    );
    assert_eq!(
        routes(&world, &["as.name: tele-edge and not as.country: XA"]),
        ["192.0.2.0/24"]
    );
    // A route with an AS of EXAMPLE-NET and any AS from XB.
    assert_eq!(
        routes(
            &world,
            &["as.name: example-net and route: {as.country: XB}"]
        ),
        ["192.0.2.0/24"]
    );
}

#[test]
fn operators_and_precedence() {
    // `not` binds first, then `and`, then `or`. netf ignores the case of
    // operators.
    let world = World::standard();
    assert_eq!(
        routes(
            &world,
            &["(as.asn: 64498 or as.asn: 64501) and not as.country: XD"]
        ),
        ["192.0.2.64/27"]
    );
    assert_eq!(
        routes(
            &world,
            &["as.asn: 64498 OR as.asn: 64501 AND as.country: XB"]
        ),
        ["192.0.2.64/27"]
    );
    assert_eq!(
        routes(
            &world,
            &["as.asn: 64498 or as.asn: 64501 and as.country: XD"]
        ),
        ["192.0.2.64/27", "198.51.100.0/24"]
    );
    let cdn: Vec<&str> = ALL_V4
        .iter()
        .copied()
        .filter(|r| r.ends_with("/28"))
        .collect();
    assert_eq!(
        routes(&world, &["NOT as.asn: 64496 And as.name: example*"]),
        cdn
    );
}

// `not ip:`

/// The addresses of AS64496 without 192.0.2.16/28.
const CUT_IPSET: &str = "192.0.2.0/28\n192.0.2.32/27\n192.0.2.64/26\n192.0.2.128/25\n";

#[test]
fn not_ip_cuts_routes_into_parts() {
    let world = World::standard();
    let query = "as.asn: 64496 and not ip: 192.0.2.16/28";
    let list = ipset(&world, &[query]);
    assert_eq!(list, CUT_IPSET);

    // Each remaining piece is a row with its route.
    let t = quiet(&world, &[query]);
    t.assert_grouped_by_route();
    assert!(t.has_part, "{t:?}");
    assert_eq!(t.route_set(), ["192.0.2.0/24", "192.0.2.0/26"]);
    let cut = Span::parse("192.0.2.16/28");
    for row in &t.rows {
        let part = Span::parse(row.part.as_deref().expect("a part"));
        let route = Span::parse(&row.route);
        assert!(
            route.first <= part.first && part.last <= route.last,
            "{row:?}"
        );
        assert!(part.last < cut.first || part.first > cut.last, "{row:?}");
    }
    let parts_of = |route: &str| {
        spans(
            t.of(route)
                .iter()
                .map(|r| r.part.as_deref().expect("a part")),
        )
    };
    assert_eq!(
        parts_of("192.0.2.0/24"),
        spans([
            "192.0.2.0/28",
            "192.0.2.32/27",
            "192.0.2.64/26",
            "192.0.2.128/25"
        ])
    );
    assert_eq!(
        parts_of("192.0.2.0/26"),
        spans(["192.0.2.0/28", "192.0.2.32/27"])
    );
    // The rows and `--ipset` give the same addresses.
    assert_eq!(ipset_of(&t.addresses()), list);
}

#[test]
fn not_domain_cuts_addresses() {
    // `not domain:` cuts out the addresses of the domain. 192.0.2.10 is the
    // only one inside AS64496.
    let world = World::standard();
    assert_eq!(
        ipset(&world, &["as.asn: 64496 and not domain: www.example.test"]),
        "192.0.2.0/29\n192.0.2.8/31\n192.0.2.11/32\n192.0.2.12/30\n\
         192.0.2.16/28\n192.0.2.32/27\n192.0.2.64/26\n192.0.2.128/25\n"
    );
}

#[test]
fn ip_minus_ip_downloads_nothing() {
    // `--ipset` has no address arithmetic of its own. It lists the addresses
    // of the rows, so a query made only of `ip:` selectors needs no download.
    let world = World::standard();
    assert_eq!(
        ipset(&world, &["ip: 192.0.2.0/24 and not ip: 192.0.2.0/25"]),
        "192.0.2.128/25\n"
    );
    assert_eq!(urls(&world), Vec::<String>::new());
}

#[test]
fn not_ip_alone_is_an_error() {
    // `not ip:` without a positive condition is code 2.
    let world = World::standard();
    let (code, stderr) = world.fail(&["not ip: 192.0.2.0/24"]);
    assert_eq!(code, 2, "{stderr:?}");
    assert!(world.transport.requests().is_empty());
}

#[test]
fn hijack_monitor() {
    // The route of the own AS goes, and the foreign route inside the own
    // network stays, in the rows and in `--ipset`. A scope gives the same
    // result when it takes the own AS from the covering route.
    let world = World::standard();
    for query in [
        "ip: 198.51.100.0/24 and not as.asn: 64501",
        "ip: 198.51.100.0/24 and not as.asn: {ip: 198.51.100.0/24}",
    ] {
        let t = quiet(&world, &[query]);
        assert_eq!(t.routes(), ["198.51.100.128/25"], "{query}");
        assert_eq!(t.rows[0].ases, "AS64502 ROGUE", "{query}");
        assert_eq!(ipset(&world, &[query]), "198.51.100.128/25\n", "{query}");
    }
}

// Scopes

#[test]
fn scope_takes_the_as_of_a_domain() {
    // `as.asn: {domain: …}` takes the AS of the addresses, then every route
    // of each AS.
    let world = World::standard();
    let query = "as.asn: {domain: www.example.test}";
    assert_eq!(ipset(&world, &[query]), "192.0.2.0/24\n198.51.100.128/25\n");
    let t = quiet(&world, &[query]);
    assert!(!t.has_part, "{t:?}");
    assert_eq!(
        t.route_set(),
        ["192.0.2.0/24", "192.0.2.0/26", "198.51.100.128/25"]
    );
}

#[test]
fn scope_over_other_fields() {
    // Any field takes a scope, any query goes inside, and scopes nest.
    let world = World::standard();
    assert_eq!(
        routes(&world, &["as.country: {as.asn: 64502}"]),
        ["192.0.2.0/24", "198.51.100.128/25"]
    );
    assert_eq!(
        routes(&world, &["as.name: {ip: 192.0.2.70}"]),
        ["192.0.2.64/27"]
    );
    assert_eq!(
        routes(&world, &["as.asn: {route: {ip: 192.0.2.140}}"]),
        ["192.0.2.128/27"]
    );
    // `ip: {query}` gives the addresses of the query.
    assert_eq!(ipset(&world, &["ip: {as.asn: 64498}"]), "192.0.2.64/27\n");
}

// Sets

const BASE_SETS: &str = "\
[set.docs]
query = \"as.asn: 64498\"

[set.hijack]
query = \"ip: 198.51.100.0/24 and not as.asn: 64501\"
";

const EXTRA_SETS: &str = "\
[set.both]
query = \"set: docs or set: hijack\"

[set.six]
query = \"as.asn: 64496\"
ipv6 = true
";

#[test]
fn sets_from_two_configs() {
    let world = World::standard();
    world.base_config(BASE_SETS);
    world.write("extra.toml", EXTRA_SETS);
    // `-s NAME` is short for `--ipset 'set: NAME'`.
    assert_eq!(
        world.ok(&["-s", "docs"]),
        ("192.0.2.64/27\n".into(), vec![])
    );
    assert_eq!(
        world.ok(&["-c", "extra.toml", "-s", "both"]),
        ("192.0.2.64/27\n198.51.100.128/25\n".into(), vec![])
    );
    // The family of the named set wins over the default.
    assert_eq!(
        world.ok(&["-c", "extra.toml", "-s", "six"]),
        ("2001:db8::/32\n".into(), vec![])
    );
    // A named set of the `-c` file exists only with it.
    let (code, _) = world.fail(&["-s", "both"]);
    assert_eq!(code, 2);
    // `set:` in a query.
    assert_eq!(
        routes(&world, &["set: docs and as.country: XE"]),
        ["192.0.2.64/27"]
    );
    assert_eq!(
        routes(&world, &["set: docs and as.country: XB"]),
        Vec::<String>::new()
    );
    assert_eq!(
        routes(&world, &["-c", "extra.toml", "set: both"]),
        ["192.0.2.64/27", "198.51.100.128/25"]
    );
}

// `@path`

const BANNED: &str = "\
# banned addresses
192.0.2.70
# the second one
198.51.100.130

2001:db8::1
";

#[test]
fn values_from_a_file() {
    let world = World::standard();
    let path = world.write("banned.txt", BANNED);
    let (stdout, stderr) = world.ok(&["--ipset", "ip: @banned.txt"]);
    assert_eq!(stdout, "192.0.2.70/32\n198.51.100.130/32\n");
    // netf drops the addresses of the other family and says so in one
    // line.
    assert_eq!(stderr, ["netf: 1 IPv6 address skipped, use -6"]);
    let absolute = format!("ip: @{}", path.display());
    assert_eq!(world.ok(&["--ipset", &absolute]).0, stdout);

    // The same with `-6`, with the plural in the notice.
    let (stdout, stderr) = world.ok(&["-6", "--ipset", "ip: @banned.txt"]);
    assert_eq!(stdout, "2001:db8::1/128\n");
    assert_eq!(stderr, ["netf: 2 IPv4 addresses skipped, use -4"]);

    world.write("asns.txt", "64498\n# a comment\n64501\n");
    assert_eq!(
        routes(&world, &["as.asn: @asns.txt"]),
        ["192.0.2.64/27", "198.51.100.0/24"]
    );
}

#[test]
fn path_in_a_config_set() {
    // `@path` works in the config too.
    let world = World::standard();
    let path = world.write("lists/banned.txt", BANNED);
    world.base_config(&format!(
        "[set.banned]\nquery = \"ip: @{}\"\n",
        path.display()
    ));
    let (stdout, stderr) = world.ok(&["-s", "banned"]);
    assert_eq!(stdout, "192.0.2.70/32\n198.51.100.130/32\n");
    assert_eq!(stderr, ["netf: 1 IPv6 address skipped, use -6"]);
}

#[test]
fn unreadable_path_is_code_2() {
    // A file that cannot be read is code 2.
    let world = World::standard();
    let (code, _) = world.fail(&["ip: @missing.txt"]);
    assert_eq!(code, 2);
}

// Families

#[test]
fn ipset_in_both_families() {
    // The list has IPv4 first, then IPv6, in any order of the flags.
    let world = World::standard();
    assert_eq!(
        ipset(&world, &["-4", "-6", "as.asn: 64496"]),
        "192.0.2.0/24\n2001:db8::/32\n"
    );
    assert_eq!(
        ipset(&world, &["as.asn: 64496", "-6", "-4"]),
        "192.0.2.0/24\n2001:db8::/32\n"
    );
    assert_eq!(
        ipset(&world, &["-4", "-6", "route: *"]),
        format!("{ALL_V4_IPSET}2001:db8::/32\n")
    );
    assert_eq!(ipset(&world, &["-6", "route: *"]), "2001:db8::/32\n");
}

#[test]
fn addresses_of_the_other_family_are_skipped() {
    // The skipped addresses give one line on stderr and code 0.
    let world = World::standard();
    let (stdout, stderr) = world.ok(&["ip: 2001:db8::1"]);
    assert_eq!(stdout, "");
    assert_eq!(stderr, ["netf: 1 IPv6 address skipped, use -6"]);
    let (stdout, stderr) = world.ok(&["ip: (192.0.2.70 or 2001:db8::1 or 2001:db8::2)"]);
    assert_eq!(table(&stdout).routes(), ["192.0.2.64/27"]);
    assert_eq!(stderr, ["netf: 2 IPv6 addresses skipped, use -6"]);
}

// The limit

#[test]
fn limit_shows_the_first_routes() {
    let world = World::standard();
    let (stdout, stderr) = world.ok(&["--limit", "5", "route: *"]);
    let t = table(&stdout);
    t.assert_in_address_order();
    let mut got = t.routes();
    got.sort_unstable();
    let mut want = ALL_V4[..5].to_vec();
    want.sort_unstable();
    assert_eq!(got, want);
    assert_eq!(
        stderr,
        ["netf: showing 5 of 16 routes; refine the query or use --limit 0"]
    );
    // `--limit 0` shows every route, without the notice.
    let t = quiet(&world, &["--limit", "0", "route: *"]);
    assert_eq!(t.rows.len(), ALL_V4.len());
}

#[test]
fn default_limit_is_100() {
    // The dump has 150 routes of one AS.
    let world = World::with_resolver(common::standard_resolver());
    // netf also asks the registry, but only for the rows it shows.
    world.serve_registries();
    let dump: String = (0..150)
        .map(|i| format!("64510\t203.0.113.{i}/32\t1\n"))
        .collect();
    world
        .transport
        .always(RIS_V4, Scripted::ok(gzip(dump.as_bytes())));
    world
        .transport
        .always(ASN_TXT, Scripted::ok(fixture(ASN_FIXTURE)));
    let (stdout, stderr) = world.ok(&["as.asn: 64510"]);
    let t = table(&stdout);
    assert_eq!(t.rows.len(), 100);
    assert_eq!(t.rows[0].route, "203.0.113.0/32");
    assert_eq!(t.rows[99].route, "203.0.113.99/32");
    // AS64510 is not in `asn.txt`, so the AS column has the number alone.
    assert_eq!(t.rows[0].ases, "AS64510");
    assert_eq!(
        stderr,
        ["netf: showing 100 of 150 routes; refine the query or use --limit 0"]
    );
    // `--ipset` is never limited.
    assert_eq!(
        world.ok(&["--ipset", "as.asn: 64510"]),
        (
            "203.0.113.0/25\n203.0.113.128/28\n203.0.113.144/30\n203.0.113.148/31\n".into(),
            vec![]
        )
    );
}

// `-f`

/// Checks that the home has `out.txt` with `old` and no temporary files.
fn assert_untouched(world: &World) {
    let out = world.home.path().join("out.txt");
    assert_eq!(std::fs::read_to_string(out).unwrap(), "old\n");
    let names = common::files_in(world.home.path());
    assert!(
        names.iter().all(|n| !n.contains(".tmp")),
        "temporary files left: {names:?}"
    );
}

#[test]
fn file_is_kept_on_errors() {
    // netf leaves the file of `-f` untouched when a source fails, a domain
    // is not found, or the query is wrong.
    let world = World::standard();
    world.write("out.txt", "old\n");
    world.transport.get(RIS_V4, Scripted::status(404));
    let (code, _) = world.fail(&["-f", "out.txt", "--ipset", "as.asn: 64498"]);
    assert_eq!(code, 1);
    assert_untouched(&world);
    let (code, _) = world.fail(&[
        "-f",
        "out.txt",
        "--ipset",
        "as.asn: {domain: nx.example.test}",
    ]);
    assert_eq!(code, 1);
    assert_untouched(&world);
    let (code, _) = world.fail(&["-f", "out.txt", "bogus: 1"]);
    assert_eq!(code, 2);
    assert_untouched(&world);
}

// Errors

#[test]
fn a_source_that_fails_is_code_1() {
    let world = World::standard();
    // The test uses 404 rather than 5xx, so there are no retries to wait for.
    world.transport.get(RIS_V4, Scripted::status(404));
    let (code, stderr) = world.fail(&["as.asn: 64496"]);
    assert_eq!(code, 1);
    assert_eq!(stderr.len(), 1, "{stderr:?}");
    // The error of a failed dataset has the form `<dataset>: <url>: <reason>`.
    assert!(
        stderr[0].starts_with(&format!("netf: ris-v4: {RIS_V4}: ")) && stderr[0].contains("404"),
        "{stderr:?}"
    );
    // All or nothing: the IPv4 addresses are not printed when IPv6 fails.
    world.transport.get(RIS_V6, Scripted::status(404));
    let (code, _) = world.fail(&["--no-cache", "-4", "-6", "--ipset", "as.asn: 64496"]);
    assert_eq!(code, 1);
}

#[test]
fn errors_in_the_query_are_code_2() {
    let world = World::standard();
    // An unknown field suggests similar ones.
    let (code, stderr) = world.fail(&["holder: x"]);
    assert_eq!(code, 2);
    let last = stderr.last().expect("an error");
    assert!(
        last.contains("net.org") && last.contains("as.org"),
        "{stderr:?}"
    );
    // netf does not support nested KQL groups.
    let (code, stderr) = world.fail(&["as:{name: x and country: XB}"]);
    assert_eq!(code, 2);
    assert!(
        stderr
            .last()
            .is_some_and(|l| l.contains("is not supported")),
        "{stderr:?}"
    );
    // An option inside the query is code 2.
    let (code, _) = world.fail(&["as.asn:", "-4", "64496"]);
    assert_eq!(code, 2);
    // `--fields` does not go with `--ipset`.
    let (code, _) = world.fail(&["--fields", "net.org", "--ipset", "as.asn: 64496"]);
    assert_eq!(code, 2);
    // Nothing was downloaded for a query that cannot run.
    assert!(world.transport.requests().is_empty());
}
