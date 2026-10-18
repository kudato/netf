//! End-to-end tests of scopes, `field: {query}`, run in process. They cover
//! every field outside the braces, nesting, the operators around a scope,
//! `ip: {…}`, and the covering route of `{ip: <network>}`.
//!
//! The data is the world of `tests/common/mod.rs` with the search fixtures
//! of [`World::search`]. A scope takes these values from the inner rows:
//!
//! - `as.org` and `net.org`: the handle and the name of the holder, and the
//!   opaque-id of the block.
//! - `*.mnt` and `*.contact`: the handles of the RDAP record. For `net`, the
//!   record is the most specific one. For `as`, it is the autnum.
//!
//! `tests/engine_routes.rs` also tests scopes over `as.asn`, `route`, and
//! the `as.*` fields of `asn.txt`.

mod common;

use common::{FullRow, World, full_table};

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

/// The notices that netf prints when a registry truncates an answer.
///
/// An organization in the fixtures may have one, and a scope over `*.org`
/// asks for that organization.
const TRUNCATIONS: [&str; 3] = [
    "netf: ripencc: limited search results to 100 maximum",
    "netf: arin: result set truncated due to authorization",
    "netf: apnic: result set truncated due to unexplainable reasons",
];

/// Runs `args` and returns the rows with every column.
///
/// # Panics
///
/// Panics if the exit code is not 0 or stderr has a line that is not a
/// truncation notice.
fn rows(world: &World, args: &[&str]) -> Vec<FullRow> {
    let (stdout, stderr) = world.ok(args);
    assert!(
        stderr.iter().all(|l| TRUNCATIONS.contains(&l.as_str())),
        "netf {args:?}: stderr {stderr:?}"
    );
    full_table(&stdout)
}

/// Runs `args` like [`rows`] and returns the routes of the rows, in order.
///
/// # Panics
///
/// Panics like [`rows`].
fn routes(world: &World, args: &[&str]) -> Vec<String> {
    rows(world, args).into_iter().map(|r| r.route).collect()
}

/// Runs `args` with `--ipset` and returns stdout.
///
/// # Panics
///
/// Panics if the exit code is not 0 or stderr has a line that is not a
/// truncation notice.
fn ipset(world: &World, args: &[&str]) -> String {
    let mut all = vec!["--ipset"];
    all.extend_from_slice(args);
    let (stdout, stderr) = world.ok(&all);
    assert!(
        stderr.iter().all(|l| TRUNCATIONS.contains(&l.as_str())),
        "netf {all:?}: stderr {stderr:?}"
    );
    stdout
}

// Scopes over the fields of the local datasets

#[test]
fn net_country_and_rir_scopes() {
    // `net.country` and `net.rir` take the values of the blocks of the
    // inner rows.
    let world = World::search();
    assert_eq!(
        routes(&world, &["net.country: {ip: 203.0.113.20}"]),
        CDN_ROUTES[..6]
    );
    // 192.0.2.64/27 (AS64498 of ARIN) lies in a block of RIPE.
    assert_eq!(routes(&world, &["net.rir: {as.asn: 64498}"]), RIPE_ROUTES);
}

#[test]
fn as_rir_and_as_name_scopes() {
    // `as.name`, `as.country`, and `as.rir` take the values of the AS of
    // the inner rows.
    let world = World::search();
    // 198.51.100.0/24 is announced by AS64501 of RIPE.
    let ripe_as = routes(&world, &["as.rir: ripencc"]);
    assert_eq!(routes(&world, &["as.rir: {ip: 198.51.100.10}"]), ripe_as);
    assert_eq!(routes(&world, &["as.name: {ip: 203.0.113.20}"]), CDN_ROUTES);
    assert_eq!(
        routes(&world, &["as.country: {as.asn: 64503}"]),
        CDN_ROUTES,
        "EXAMPLE-CDN is the only AS of XF"
    );
}

#[test]
fn ip_scope_of_a_set() {
    // `ip: {set: banned}` gives the same addresses as `set: banned`.
    let world = World::search();
    world.base_config("[set.banned]\nquery = \"as.asn: 64498 or ip: 203.0.113.200\"\n");
    let direct = ipset(&world, &["set: banned"]);
    assert_eq!(direct, "192.0.2.64/27\n203.0.113.200/32\n");
    assert_eq!(ipset(&world, &["ip: {set: banned}"]), direct);
}

#[test]
fn domain_scope_is_code_2() {
    // `domain: {…}` is a usage error, code 2.
    let world = World::search();
    let (code, _) = world.fail(&["domain: {net.org: ORG-CH1-RIPE}"]);
    assert_eq!(code, 2);
}

// Scopes over `*.org`

#[test]
fn net_org_scope_of_an_address() {
    // `net.org: {ip: <address>}` finds every network of the holder whose
    // network covers the address.
    let world = World::search();
    assert_eq!(
        routes(&world, &["net.org: {ip: 198.51.100.10}"]),
        ["198.51.100.0/24", "198.51.100.128/25"]
    );
    assert_eq!(
        ipset(&world, &["net.org: {ip: 198.51.100.10}"]),
        "198.51.100.0/24\n"
    );
}

#[test]
fn net_org_scope_of_an_as() {
    // The routes of AS64496 lie in the networks of Example Networks and
    // of its client. These two holders hold the whole 192.0.2.0/24.
    let world = World::search();
    assert_eq!(routes(&world, &["net.org: {as.asn: 64496}"]), RIPE_ROUTES);
    assert_eq!(
        ipset(&world, &["net.org: {as.asn: 64496}"]),
        "192.0.2.0/24\n"
    );
}

// Nesting and operators

#[test]
fn scope_inside_a_scope() {
    // The organizations of `www.example.test` hold AS64496 and AS64502.
    // No other AS has the contacts of these two.
    let world = World::search();
    assert_eq!(
        routes(
            &world,
            &["as.contact: {as.org: {domain: www.example.test}}"]
        ),
        ["192.0.2.0/24", "192.0.2.0/26", "198.51.100.128/25"]
    );
    assert_eq!(
        routes(&world, &["as.asn: {as.org: {ip: 203.0.113.20}}"]),
        CDN_ROUTES
    );
}

#[test]
fn hijack_check_takes_only_the_covering_route() {
    // In `ip: N and not as.org: {ip: N}`, the braces take only the route
    // that covers the whole network N. Here that route is 192.0.2.0/24 of
    // AS64496 and AS64497. The routes of other organizations inside N stay.
    let world = World::search();
    assert_eq!(
        routes(
            &world,
            &["ip: 192.0.2.0/24 and not as.org: {ip: 192.0.2.0/24}"]
        ),
        ["192.0.2.64/27", "192.0.2.128/27"]
    );
}

#[test]
fn scopes_on_org_mnt_and_contact_fields_exit_with_code_0() {
    // Every field takes a scope, and each of these queries exits with code 0.
    let world = World::search();
    for query in [
        "net.org: {as.asn: 64496}",
        "as.org: {ip: 203.0.113.20}",
        "as.mnt: {ip: 192.0.2.10}",
        "net.mnt: {ip: 192.0.2.10}",
        "as.contact: {ip: 192.0.2.10}",
        "net.contact.abuse: {ip: 203.0.113.20}",
    ] {
        let (outcome, stderr) = world.run(&["--ipset", query]);
        assert_eq!(outcome.code, 0, "{query}: {stderr:?}");
    }
}
