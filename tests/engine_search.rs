//! End-to-end tests of searches, run in process. They cover searches by
//! maintainer and contact through the RIPE REST API and the dumps of APNIC
//! and AFRINIC. They cover searches of organizations by name through the
//! RIPE REST API and `entities?fn=` of the other registries. They also cover
//! the bare word, `*` in field names, the expensive filters `*.mnt: *`,
//! `*.contact: *`, and `*.org: *`, the notices of the engine, and the memory
//! of a streamed dump.
//!
//! The data is the world of `tests/common/mod.rs` with the search fixtures
//! of [`World::search`]: the dumps, the REST objects, and the RDAP searches.

mod common;

use std::{
    alloc::{GlobalAlloc, Layout, System},
    cell::Cell,
    fmt::Write as _,
};

use common::{
    AFRINIC_DB, APNIC_AUT_NUM, APNIC_INET6NUM, APNIC_INETNUM, APNIC_ORGANISATION, FullRow,
    REST_LIMITED, Scripted, World, fixture, full_row, full_table, gzip,
};

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

/// The routes of 192.0.2.0/24.
const RIPE_ROUTES: [&str; 4] = [
    "192.0.2.0/24",
    "192.0.2.0/26",
    "192.0.2.64/27",
    "192.0.2.128/27",
];

/// The addresses of APNIC 203.0.113.0 - 203.0.113.95.
const CDN_NET: &str = "203.0.113.0/26\n203.0.113.64/27\n";

/// The notices that netf prints when a registry truncates an answer.
///
/// They are the only lines that a search by name may add, because the
/// entities of the fixtures have them.
const TRUNCATIONS: [&str; 3] = [
    "netf: ripencc: limited search results to 100 maximum",
    "netf: arin: result set truncated due to authorization",
    "netf: apnic: result set truncated due to unexplainable reasons",
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

/// Runs `args` and returns the rows with every column.
///
/// # Panics
///
/// Panics if the exit code is not 0 or stderr has a line that is not a
/// truncation notice.
fn rows(world: &World, args: &[&str]) -> Vec<FullRow> {
    let (stdout, stderr) = world.ok(args);
    assert_truncations_only(args, &stderr);
    full_table(&stdout)
}

/// Checks that `stderr` has only truncation notices.
fn assert_truncations_only(args: &[&str], stderr: &[String]) {
    assert!(
        stderr.iter().all(|l| TRUNCATIONS.contains(&l.as_str())),
        "netf {args:?}: stderr {stderr:?}"
    );
}

/// Runs `args` like [`quiet_rows`] and returns the routes, in order.
///
/// # Panics
///
/// Panics like [`quiet_rows`].
fn routes(world: &World, args: &[&str]) -> Vec<String> {
    quiet_rows(world, args)
        .into_iter()
        .map(|r| r.route)
        .collect()
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

/// Runs `args` like [`ipset`], but allows truncation notices on stderr.
///
/// # Panics
///
/// Panics if the exit code is not 0 or stderr has a line that is not a
/// truncation notice.
fn ipset_cut(world: &World, args: &[&str]) -> String {
    let mut all = vec!["--ipset"];
    all.extend_from_slice(args);
    let (stdout, stderr) = world.ok(&all);
    assert_truncations_only(&all, &stderr);
    stdout
}

/// Returns the routes of `rows`, in order.
fn routes_of(rows: &[FullRow]) -> Vec<&str> {
    rows.iter().map(|r| r.route.as_str()).collect()
}

/// Expects code 0, an empty stdout, and an empty stderr, in rows and in
/// `--ipset`.
///
/// A search by maintainer or contact that finds nothing prints no notice.
fn assert_empty(world: &World, query: &str) {
    let (stdout, stderr) = world.ok(&[query]);
    assert_eq!(stdout, "", "{query}");
    assert!(stderr.is_empty(), "{query}: {stderr:?}");
    assert_eq!(ipset(world, &[query]), "", "--ipset {query}");
}

// `net.mnt`

#[test]
fn net_mnt_from_the_ripe_rest_api() {
    // `net.mnt: X` gives the records that this maintainer keeps. The list
    // has the addresses of the record inside the route, not the whole
    // route.
    let world = World::search();
    let rows = quiet_rows(&world, &["net.mnt: CH-MNT"]);
    assert_eq!(routes_of(&rows), ["192.0.2.0/24", "192.0.2.0/26"]);
    assert_eq!(full_row(&rows, "192.0.2.0/26").net, "192.0.2.0/26");
    assert_eq!(ipset(&world, &["net.mnt: CH-MNT"]), "192.0.2.0/26\n");
    // netf ignores the case of maintainer handles.
    assert_eq!(ipset(&world, &["net.mnt: ch-mnt"]), "192.0.2.0/26\n");
}

#[test]
fn net_mnt_from_the_apnic_dump() {
    // netf searches APNIC in its database dump.
    let world = World::search();
    assert_eq!(
        routes(&world, &["net.mnt: MAINT-XG-EXAMPLECDN"]),
        CDN_ROUTES[..6]
    );
    assert_eq!(ipset(&world, &["net.mnt: MAINT-XG-EXAMPLECDN"]), CDN_NET);
    assert_eq!(
        ipset(&world, &["net.mnt: MAINT-XG-CDNCUSTOMER"]),
        "203.0.113.16/28\n"
    );
    assert_eq!(
        ipset(&world, &["-6", "net.mnt: MAINT-XG-EXAMPLECDN"]),
        "2001:db8:f000::/36\n"
    );
}

#[test]
fn net_mnt_list_of_values() {
    // One field takes a list of values.
    let world = World::search();
    assert_eq!(
        ipset(&world, &["net.mnt: (CH-MNT or SAVANNA-MNT)"]),
        "192.0.2.0/26\n203.0.113.224/27\n"
    );
}

// `*.contact`

#[test]
fn net_contact_in_any_role_and_by_role() {
    // Without a role, the handle matches in any role. With a role, it
    // matches only in that role.
    let world = World::search();
    assert_eq!(ipset(&world, &["net.contact: MR1-RIPE"]), "192.0.2.0/26\n");
    assert_eq!(ipset(&world, &["net.contact: NOC1-RIPE"]), "192.0.2.0/24\n");
    assert_eq!(
        ipset(&world, &["net.contact.administrative: JD1-RIPE"]),
        "192.0.2.0/24\n"
    );
    assert_empty(&world, "net.contact.technical: JD1-RIPE");
    assert_eq!(
        ipset(&world, &["net.contact.abuse: AR-CH1-RIPE"]),
        "192.0.2.0/26\n"
    );
    assert_eq!(
        routes(&world, &["as.contact: JD1-RIPE"]),
        ["192.0.2.0/24", "192.0.2.0/26"]
    );
}

#[test]
fn net_contact_abuse_through_the_apnic_organisation() {
    // A contact matches on the record and on its holder. netf finds the
    // abuse contact of 203.0.113.0 - 203.0.113.95 only on ORG-ECL1-AP, in
    // `apnic.db.organisation`. The `mnt-irt` of the record does not count.
    let world = World::search();
    assert_eq!(
        routes(&world, &["net.contact.abuse: IRT-EXAMPLECDN-XG"]),
        CDN_ROUTES[..6]
    );
    assert_eq!(
        ipset(&world, &["net.contact.abuse: IRT-EXAMPLECDN-XG"]),
        CDN_NET
    );
    assert_eq!(
        ipset(&world, &["net.contact.abuse: IRT-CDNCUSTOMER-XG"]),
        "203.0.113.16/28\n"
    );
    assert_eq!(
        ipset(&world, &["as.contact.abuse: IRT-EXAMPLECDN-AS"]),
        "203.0.113.0/25\n"
    );
    assert_eq!(routes(&world, &["net.contact: ECA1-AP"]), CDN_ROUTES[..6]);
}

#[test]
fn arin_contacts_are_not_searched() {
    // netf searches ARIN only by organization, so a contact of ARIN finds
    // nothing, and netf prints no notice …
    let world = World::search();
    assert_empty(&world, "net.contact.abuse: ABUSE1-ARIN");
    // … but as a filter on the rows of `ip:`, netf reads the contact from
    // the RDAP record. ARIN nests the contacts in the organization.
    assert_eq!(
        routes(
            &world,
            &["ip: 198.51.100.0/24 and net.contact.abuse: ABUSE1-ARIN"]
        ),
        ["198.51.100.0/24", "198.51.100.128/25"]
    );
    assert_empty(
        &world,
        "ip: 198.51.100.0/24 and net.contact.abuse: QNA-ARIN",
    );
}

// The RIPE REST API: requests and responses

#[test]
fn ripe_rest_answer_cut_at_100() {
    // The message of RIPE goes to stderr as one line. netf uses the first
    // 100 records, 192.0.2.0 to 192.0.2.99.
    let world = World::search();
    let (stdout, stderr) = world.ok(&["--ipset", "net.mnt: BULK-MNT"]);
    assert_eq!(stdout, "192.0.2.0/26\n192.0.2.64/27\n192.0.2.96/30\n");
    assert_eq!(stderr, [format!("netf: ripencc: {REST_LIMITED}")]);
}

#[test]
fn ripe_rest_requests_use_flags_and_one_type_per_field() {
    // The requests use `query-string`, `inverse-attribute`, `type-filter`,
    // `flags=r`, and `flags=no-referenced`. netf asks for aut-num only for
    // `as.*`, for inetnum for `net.*`, and for inet6num only with `-6`.
    let world = World::search();
    ipset(&world, &["net.mnt: CH-MNT"]);
    let calls = world.rest_calls();
    assert!(
        !calls.is_empty(),
        "no REST request: {:?}",
        world.transport.requests()
    );
    for call in &calls {
        assert!(call.flags.iter().any(|f| f == "r"), "{call:?}");
        assert!(call.flags.iter().any(|f| f == "no-referenced"), "{call:?}");
        assert_eq!(call.types.len(), 1, "{call:?}");
    }
    assert!(
        calls.iter().any(|c| c.query.eq_ignore_ascii_case("CH-MNT")
            && c.inverse == ["mnt-by"]
            && c.types == ["inetnum"]),
        "{calls:?}"
    );
    assert!(
        calls
            .iter()
            .all(|c| c.types != ["inet6num"] && c.types != ["aut-num"]),
        "{calls:?}"
    );

    let world = World::search();
    ipset(&world, &["-4", "-6", "net.mnt: CH-MNT"]);
    assert!(
        world.rest_calls().iter().any(|c| c.types == ["inet6num"]),
        "{:?}",
        world.rest_calls()
    );

    let world = World::search();
    ipset(&world, &["as.mnt: EXAMPLE-NET-MNT"]);
    let calls = world.rest_calls();
    assert!(calls.iter().any(|c| c.types == ["aut-num"]), "{calls:?}");
    assert!(
        calls
            .iter()
            .all(|c| c.types != ["inetnum"] && c.types != ["inet6num"]),
        "{calls:?}"
    );
}

#[test]
fn dumps_are_fetched_only_for_mnt_and_contact() {
    // netf downloads the dumps of APNIC and AFRINIC only when the query has
    // `*.mnt` or `*.contact`. It downloads aut-num for `as.*` and inetnum for
    // `net.*`, plus inet6num with `-6`.
    let world = World::search();
    ipset(&world, &["net.mnt: CH-MNT"]);
    assert!(world.dump_requests(&[APNIC_INETNUM]) >= 1);
    assert!(world.dump_requests(&[AFRINIC_DB]) >= 1);
    assert_eq!(world.dump_requests(&[APNIC_AUT_NUM, APNIC_INET6NUM]), 0);

    let world = World::search();
    ipset(&world, &["-6", "net.mnt: CH-MNT"]);
    assert!(world.dump_requests(&[APNIC_INET6NUM]) >= 1);

    let world = World::search();
    ipset(&world, &["as.mnt: EXAMPLE-NET-MNT"]);
    assert!(world.dump_requests(&[APNIC_AUT_NUM]) >= 1);
    assert_eq!(world.dump_requests(&[APNIC_INETNUM, APNIC_INET6NUM]), 0);

    // APNIC keeps the abuse contact on the `organisation`, so netf downloads
    // the `organisation` dump.
    let world = World::search();
    ipset(&world, &["net.contact.abuse: IRT-EXAMPLECDN-XG"]);
    assert!(world.dump_requests(&[APNIC_ORGANISATION]) >= 1);
}

// Expensive filters: `*.mnt: *`, `*.contact: *`, and `*.org: *`

#[test]
fn net_mnt_star_is_checked_on_the_rdap_record() {
    // netf checks `*.mnt: *` on the RDAP answer of every route.
    // 203.0.113.16/28 has a record without a maintainer, but its parent
    // (`rel=up`) has one. 96/28 and 112/28 have no record.
    let world = World::search();
    assert_eq!(
        routes(&world, &["as.asn: 64503 and net.mnt: *"]),
        CDN_ROUTES[..6]
    );
    // ARIN has no maintainers.
    assert_eq!(
        routes(&world, &["as.asn: (64498 or 64501) and as.mnt: *"]),
        ["198.51.100.0/24"]
    );
}

#[test]
fn contact_star_is_checked_on_the_rdap_record() {
    // ARIN keeps the contacts in the organization. AFRINIC has no abuse
    // role in RDAP.
    let world = World::search();
    assert_eq!(
        routes(&world, &["ip: 198.51.100.0/24 and net.contact.abuse: *"]),
        ["198.51.100.0/24", "198.51.100.128/25"]
    );
    assert_empty(&world, "ip: 203.0.113.224/27 and net.contact.abuse: *");
    let rows = quiet_rows(&world, &["ip: 203.0.113.224/27 and net.contact: *"]);
    assert_eq!(routes_of(&rows), ["no route"]);
}

#[test]
fn org_star_is_a_filter() {
    // `field: *` works in any field. `route: * and not net.org: *` gives
    // the routes outside every network of a holder. 203.0.113.96/27 is
    // reserved and has no record.
    let world = World::search();
    assert_eq!(
        routes(&world, &["route: * and not net.org: *"]),
        ["203.0.113.96/28", "203.0.113.112/28"]
    );
    assert_eq!(
        routes(&world, &["as.asn: 64498 and as.org: *"]),
        ["192.0.2.64/27"]
    );
}

#[test]
fn expensive_filter_stops_at_the_limit() {
    // With a condition on the RDAP record, netf asks in the order of
    // addresses until it reaches the limit, so the total is unknown.
    let world = World::search();
    let (stdout, stderr) = world.ok(&[
        "--limit",
        "2",
        "--concurrency",
        "1",
        "as.asn: 64503 and net.mnt: *",
    ]);
    assert_eq!(
        routes_of(&full_table(&stdout)),
        ["203.0.113.0/28", "203.0.113.16/28"]
    );
    let line = stderr
        .iter()
        .find(|l| l.starts_with("netf: showing first 2 matches; "))
        .unwrap_or_else(|| panic!("no limit message: {stderr:?}"));
    let unchecked: usize = line
        .strip_prefix("netf: showing first 2 matches; ")
        .and_then(|r| r.strip_suffix(" candidates not checked; use --limit 0"))
        .unwrap_or_else(|| panic!("expected `<N> candidates not checked; use --limit 0`: {line:?}"))
        .parse()
        .expect("a number of routes");
    assert!((1..=6).contains(&unchecked), "{line}");
}

// Organizations by name

#[test]
fn net_org_by_name() {
    // A value with spaces goes in quotes, and `*` is a pattern inside quotes
    // too. netf ignores the case of names.
    let world = World::search();
    let found = rows(&world, &["net.org: \"Client Hosting*\""]);
    assert_eq!(routes_of(&found), ["192.0.2.0/24", "192.0.2.0/26"]);
    assert_eq!(
        ipset_cut(&world, &["net.org: \"client hosting ltd\""]),
        "192.0.2.0/26\n"
    );
    assert_eq!(
        ipset_cut(&world, &["net.org: \"Lease Broker*\""]),
        "192.0.2.128/25\n"
    );
    assert_eq!(
        routes_of(&rows(&world, &["net.org: \"Example CDN*\""])),
        CDN_ROUTES[..6]
    );
}

#[test]
fn name_pattern_in_several_registries() {
    // "Example*" matches Example Networks LLC of RIPE and Example CDN Ltd
    // of APNIC. The searches of ARIN, AFRINIC, and LACNIC find nothing.
    // netf searches RIPE by name through its REST API
    // (`type-filter=organisation`) and the other four through RDAP `fn=`.
    let world = World::search();
    assert_eq!(
        ipset_cut(&world, &["net.org: \"Example*\""]),
        "192.0.2.0/24\n203.0.113.0/26\n203.0.113.64/27\n"
    );
    assert!(
        world
            .rest_calls()
            .iter()
            .any(|call| call.types == ["organisation"]
                && call.inverse.is_empty()
                && call.query.contains("Example")),
        "RIPE not searched: {:?}",
        world.rest_calls()
    );
    for host in [
        "rdap.arin.test",
        "rdap.apnic.test",
        "rdap.lacnic.test",
        "rdap.afrinic.test",
    ] {
        assert!(
            !world.rdap_values(host, "entities").is_empty(),
            "{host} not searched: {:?}",
            world.rdap_calls()
        );
    }
}

#[test]
fn empty_name_searches_are_reported() {
    // A search by name that finds nothing prints `not found`, `no networks`,
    // or, for `as.org`, `no AS`.
    let world = World::search();
    for (query, notice) in [
        (
            "net.org: \"No Such Org*\"",
            "netf: net.org: No Such Org*: not found",
        ),
        (
            "as.org: \"Client Hosting Ltd\"",
            "netf: as.org: Client Hosting Ltd: no AS",
        ),
        (
            "net.org: \"Quiet Networks*\"",
            "netf: net.org: Quiet Networks*: no networks",
        ),
    ] {
        let (stdout, stderr) = world.ok(&[query]);
        assert_eq!(stdout, "", "{query}");
        assert_eq!(stderr, [notice], "{query}");
    }
}

#[test]
fn registry_without_search_is_reported_once() {
    // A registry that answers 501 or 400 does not stop the search in the
    // others. netf prints `netf: rdap: <rir>: search not supported` once
    // per registry per run.
    let (world, search) = World::search_server();
    search.refuse("rdap.afrinic.test", 501);
    let (stdout, stderr) = world.ok(&["net.org: (\"Client*\" or \"Lease*\")"]);
    // The /24 gives two pieces, 192.0.2.0/26 and 192.0.2.128/25, one row
    // each.
    assert_eq!(
        routes_of(&full_table(&stdout)),
        [
            "192.0.2.0/24",
            "192.0.2.0/24",
            "192.0.2.0/26",
            "192.0.2.128/27"
        ]
    );
    let notice = "netf: rdap: afrinic: search not supported";
    assert_eq!(
        stderr.iter().filter(|l| *l == notice).count(),
        1,
        "{stderr:?}"
    );

    let (world, search) = World::search_server();
    search.refuse("rdap.arin.test", 400);
    let (stdout, stderr) = world.ok(&["--ipset", "net.org: \"Client Hosting*\""]);
    assert_eq!(stdout, "192.0.2.0/26\n");
    assert!(
        stderr.contains(&"netf: rdap: arin: search not supported".to_owned()),
        "{stderr:?}"
    );
}

// The bare word

#[test]
fn bare_word_searches_organizations_by_name() {
    // A value without a field is an ordinary operand. The bare word `w`
    // means `as.name: w or as.org: w or net.org: w`. Its searches of
    // organizations print no `not found` or `no networks` notices.
    let world = World::search();
    for word in ["\"Tenant One GmbH\"", "tenant*"] {
        assert_eq!(
            routes_of(&rows(&world, &[word])),
            ["192.0.2.0/24", "192.0.2.128/27"],
            "{word}"
        );
        assert_eq!(ipset_cut(&world, &[word]), "192.0.2.128/27\n", "{word}");
    }
    assert_eq!(routes_of(&rows(&world, &["savanna*"])), ["no route"]);
    assert_eq!(
        routes_of(&rows(&world, &["\"Example CDN*\""])),
        CDN_ROUTES,
        "net.org and as.org together"
    );
}

#[test]
fn bare_word_without_results() {
    // A bare word that finds nothing prints `nothing found`, with code 0.
    let world = World::search();
    let (stdout, stderr) = world.ok(&["nosuchword"]);
    assert_eq!(stdout, "");
    assert_eq!(stderr, ["netf: nosuchword: nothing found"]);
}

// `*` in field names

#[test]
fn field_name_patterns_match_mnt_and_contact_fields() {
    // `*` in a field name matches any characters, and the pattern must
    // match the whole name. `*.mnt` means `net.mnt or as.mnt`, and so does
    // `*mnt`.
    let world = World::search();
    assert_eq!(
        routes(&world, &["*.mnt: EXAMPLE-NET-MNT"]),
        ["192.0.2.0/24", "192.0.2.0/26"]
    );
    assert_eq!(ipset(&world, &["*mnt: CH-MNT"]), "192.0.2.0/26\n");
    assert_eq!(
        ipset(&world, &["*.contact.abuse: IRT-EXAMPLECDN-AS"]),
        "203.0.113.0/25\n"
    );
}

#[test]
fn field_name_patterns_match_country_and_org_fields() {
    // `*country: XA` means `net.country: XA or as.country: XA`, and
    // `*.org` means `net.org or as.org`.
    let world = World::search();
    assert_eq!(routes(&world, &["*country: XA"]), RIPE_ROUTES);
    assert_eq!(ipset(&world, &["*country: XA"]), "192.0.2.0/24\n");
    let (stdout, _) = world.ok(&["*.org: ORG-CH1-RIPE"]);
    assert_eq!(
        routes_of(&full_table(&stdout)),
        ["192.0.2.0/24", "192.0.2.0/26"]
    );
}

// Examples of the query syntax on the fixtures

#[test]
fn example_queries_of_lists_ranges_routes_and_operators() {
    // The test runs one example query of each kind. `tests/engine_routes.rs`
    // tests the other kinds: named sets, `@path`, `not ip:`, and the hijack
    // monitor.
    let world = World::search();
    assert_eq!(
        routes(&world, &["as.asn: (64498 or 64501)"]),
        ["192.0.2.64/27", "198.51.100.0/24"]
    );
    assert_eq!(
        routes(&world, &["as.asn >= 64503 and as.asn <= 64504"]),
        [&CDN_ROUTES[..], &["203.0.113.160/27"]].concat()
    );
    assert_eq!(
        routes(&world, &["route: * and not net.rir: *"]),
        ["203.0.113.96/28", "203.0.113.112/28"]
    );
    assert_eq!(
        ipset(&world, &["as.asn: 64501 and not ip: 198.51.100.64/26"]),
        "198.51.100.0/26\n198.51.100.128/25\n"
    );
    // One AS must have both properties. EXAMPLE-NET is XA, not XB.
    let (stdout, _) = world.ok(&["as.name: example-net and as.country: XB"]);
    assert_eq!(stdout, "");
    // netf ignores the case of operators.
    assert_eq!(
        routes(&world, &["as.asn: 64501 OR as.asn: 64498 AND NOT route: *"]),
        ["198.51.100.0/24"]
    );
}

#[test]
fn nested_group_and_unknown_field_fail_with_code_2() {
    // A nested KQL group is code 2 with a hint. An unknown field is code 2
    // with a suggestion.
    let world = World::search();
    let (code, stderr) = world.fail(&["as:{as.name: example-net}"]);
    assert_eq!(code, 2);
    assert!(
        stderr
            .first()
            .is_some_and(|l| l.starts_with("netf: as:{…} is not supported")),
        "{stderr:?}"
    );
    let (code, stderr) = world.fail(&["holder: x"]);
    assert_eq!(code, 2);
    assert!(
        stderr.iter().any(|l| l.contains("net.org")),
        "no suggestion: {stderr:?}"
    );
}

#[test]
fn quoted_org_name_finds_the_holder() {
    // `net.org: "EXAMPLE LLC"` finds the holder by a name in quotes.
    let world = World::search();
    let found = rows(&world, &["net.org: \"EXAMPLE NETWORKS LLC\""]);
    assert_eq!(routes_of(&found), RIPE_ROUTES);
}

// Memory

thread_local! {
    /// Bytes allocated and not freed by this thread.
    static LIVE: Cell<i64> = const { Cell::new(0) };
    /// The largest [`LIVE`] since the last [`reset_peak`].
    static PEAK: Cell<i64> = const { Cell::new(0) };
}

/// Adds `delta` to the bytes of this thread.
fn note(delta: i64) {
    let _ = LIVE.try_with(|live| {
        let now = live.get() + delta;
        live.set(now);
        let _ = PEAK.try_with(|peak| peak.set(peak.get().max(now)));
    });
}

/// Starts a measurement and returns the bytes held now.
fn reset_peak() -> i64 {
    let now = LIVE.with(Cell::get);
    PEAK.with(|peak| peak.set(now));
    now
}

/// The system allocator, counting the bytes of each thread.
///
/// The runtime of the tests, [`common::runtime`], has one thread.
struct Counting;

/// Returns `size` as a signed count of bytes.
fn bytes(size: usize) -> i64 {
    i64::try_from(size).unwrap_or(i64::MAX)
}

// SAFETY: every call goes to `System` with the same arguments. The counting
// touches only `const` thread-locals without destructors, which neither
// allocate nor unwind.
#[allow(unsafe_code)]
unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        // SAFETY: the caller's contract is passed on.
        let ptr = unsafe { System.alloc(layout) };
        if !ptr.is_null() {
            note(bytes(layout.size()));
        }
        ptr
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        // SAFETY: the caller's contract is passed on.
        let ptr = unsafe { System.alloc_zeroed(layout) };
        if !ptr.is_null() {
            note(bytes(layout.size()));
        }
        ptr
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        // SAFETY: the caller's contract is passed on.
        unsafe { System.dealloc(ptr, layout) };
        note(-bytes(layout.size()));
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        // SAFETY: the caller's contract is passed on.
        let new = unsafe { System.realloc(ptr, layout, new_size) };
        if !new.is_null() {
            note(bytes(new_size) - bytes(layout.size()));
        }
        new
    }
}

#[global_allocator]
static ALLOCATOR: Counting = Counting;

/// The size of the made-up APNIC inetnum dump, uncompressed.
const BIG_DUMP: usize = 16 << 20;

/// The most a streamed pass may hold above what it started with.
///
/// The budget covers the window of the decompressor, a line, the records
/// found, and the small datasets of the run. Memory does not depend on the
/// size of the sources.
const STREAM_BUDGET: i64 = 4 << 20;

/// Returns an APNIC inetnum dump of [`BIG_DUMP`] bytes.
///
/// The dump has filler records of another maintainer inside
/// 203.0.113.96/27, then the objects of the fixture.
fn big_inetnum_dump() -> Vec<u8> {
    let mut text = String::with_capacity(BIG_DUMP + 4096);
    let mut n = 0u32;
    while text.len() < BIG_DUMP {
        let host = 96 + n % 32;
        let _ = write!(
            text,
            "inetnum:        203.0.113.{host} - 203.0.113.{host}\n\
             netname:        FILLER-{n}\n\
             descr:          Filler assignment {n} of the memory test\n\
             country:        XG\n\
             admin-c:        FIL1-AP\n\
             tech-c:         FIL1-AP\n\
             status:         ASSIGNED NON-PORTABLE\n\
             mnt-by:         MAINT-XG-FILLER\n\
             source:         APNIC\n\n"
        );
        n += 1;
    }
    let mut data = text.into_bytes();
    data.extend_from_slice(&fixture("ftp.apnic.test/apnic/whois/apnic.db.inetnum"));
    data
}

#[test]
fn streamed_dump_is_not_held_in_memory() {
    // Without the cache, netf downloads, decompresses, and parses a source
    // line by line, so memory does not depend on its size. The dump is far
    // larger than the budget, and the test measures the peak of the
    // allocations of the run.
    let world = World::search();
    let compressed = gzip(&big_inetnum_dump());
    world
        .transport
        .always(APNIC_INETNUM, Scripted::ok(compressed).chunked(64 * 1024));
    let (invocation, reporter) =
        world.invocation(&["--no-cache", "--ipset", "net.mnt: MAINT-XG-EXAMPLECDN"]);
    let runtime = common::runtime();
    let start = reset_peak();
    let outcome = runtime.block_on(netf::run(invocation));
    let peak = PEAK.with(Cell::get) - start;
    assert_eq!(outcome.code, 0, "{:?}", reporter.lines());
    assert_eq!(String::from_utf8_lossy(&outcome.stdout), CDN_NET);
    assert!(
        peak < STREAM_BUDGET,
        "the run held {peak} bytes over a dump of {BIG_DUMP} bytes"
    );
    assert!(world.transport.count(APNIC_INETNUM) >= 1);
}
