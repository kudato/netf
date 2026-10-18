//! `--fields` end to end, in process, over the world of
//! `tests/common/mod.rs`.
//!
//! `net.*` shows every record from the block of the registry down to the
//! record of the column network, joined with ` > `. `as.*` shows every AS
//! of the route, joined with `, `. A contact is shown whole as
//! `HANDLE name email tel`, and several contacts are joined with `; `.
//!
//! When the block of the stats and the top RDAP record have the same range,
//! they count as one record. So the chain of 192.0.2.128/27 starts with
//! `Example Networks LLC`, the holder of the block. Only RDAP knows that
//! name.

mod common;

use common::{FullRow, World, full_table};

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

/// Runs `args` and returns the added columns of its only row.
///
/// # Panics
///
/// Panics like [`quiet_rows`], or if the run does not give exactly one row.
fn extra(world: &World, args: &[&str]) -> Vec<String> {
    let rows = quiet_rows(world, args);
    assert_eq!(rows.len(), 1, "netf {args:?}: {rows:#?}");
    rows.into_iter().next().map(|r| r.extra).unwrap_or_default()
}

#[test]
fn net_fields_show_the_chain_of_records() {
    // `--fields net.org,net.country` shows a lease: the /24 block of
    // Example Networks (XA), the /25 lease (XE), and the /27 tenant (XC).
    // netf follows `links rel=up` to find each record above.
    let world = World::owners();
    assert_eq!(
        extra(
            &world,
            &["--fields", "net.org,net.country", "route: 192.0.2.128/27"]
        ),
        [
            "Example Networks LLC > Lease Broker LLC > Tenant One GmbH",
            "XA > XE > XC"
        ]
    );
}

#[test]
fn as_fields_list_every_as_of_the_route() {
    // `as.*` shows every AS of the route, joined with commas, in the order
    // of the AS column.
    let world = World::owners();
    assert_eq!(
        extra(
            &world,
            &[
                "--fields",
                "as.name,as.country,as.rir",
                "route: 192.0.2.0/24"
            ]
        ),
        ["EXAMPLE-NET, TELE-EDGE", "XA, XB", "ripencc, ripencc"]
    );
}

#[test]
fn output_fields_export_exact_matches_chains_and_origin_mailboxes() {
    let world = World::owners();
    assert_eq!(
        extra(
            &world,
            &[
                "--fields",
                "match,net.holder,net.range,net.abuse,as.abuse",
                "ip: 192.0.2.140",
            ]
        ),
        [
            "192.0.2.140",
            "Tenant One GmbH",
            "192.0.2.0/24 > 192.0.2.128/25 > 192.0.2.128/27",
            "abuse@tenant-one.example",
            "AS64499: abuse@set-one.example, AS64500: abuse@set-two.example",
        ]
    );
    assert_eq!(
        extra(&world, &["--fields", "as.abuse", "ip: 203.0.113.200"]),
        ["-"]
    );
}

#[test]
fn arin_contacts_come_from_the_organization() {
    // ARIN keeps the contacts at the holder. Several contacts of one role
    // are joined with `; `.
    let world = World::owners();
    let shown = extra(
        &world,
        &[
            "--fields",
            "net.contact.abuse,net.contact.technical",
            "as.asn: 64501",
        ],
    );
    assert_eq!(
        shown[0],
        "ABUSE1-ARIN Abuse Desk abuse@docnet.example +1 555 0101"
    );
    let mut technical: Vec<&str> = shown[1].split("; ").collect();
    technical.sort_unstable();
    assert_eq!(
        technical,
        [
            "NOC1-ARIN Network Operations noc1@docnet.example +1 555 0105",
            "NOC2-ARIN Backup Operations noc2@docnet.example +1 555 0106",
        ]
    );
}

#[test]
fn lacnic_contact_in_all_roles() {
    // LACNIC gives one handle for all three roles.
    let world = World::owners();
    let contact = "XH-REEX-LACNIC-C Rede Exemplo Ltda noc@rede-exemplo.example +1 555 0131";
    assert_eq!(
        extra(
            &world,
            &[
                "--fields",
                "as.contact.abuse,as.contact.administrative,as.contact.technical",
                "as.asn: 64507",
            ]
        ),
        [contact, contact, contact]
    );
}

#[test]
fn fields_errors_are_usage_errors() {
    // `--fields` accepts only `as.*` and `net.*`, and it cannot be combined
    // with `--ipset`. Each mistake is a usage error with code 2.
    let world = World::owners();
    for (args, text) in [
        (
            &["--fields", "holder", "as.asn: 64496"][..],
            "netf: --fields: holder: unknown field; see netf --help=fields\n\n  --fields holder\n           ^^^^^^\n",
        ),
        (
            &["--fields", "route", "as.asn: 64496"][..],
            "netf: --fields: route: already a column\n\n  --fields route\n           ^^^^^\n",
        ),
        (
            &["--ipset", "--fields", "as.name", "as.asn: 64496"][..],
            "netf: --fields cannot be combined with --ipset: the list has no columns",
        ),
    ] {
        let (code, stderr) = world.fail(args);
        assert_eq!(code, 2, "{args:?}");
        assert_eq!(stderr, [text], "{args:?}");
    }
    assert!(world.transport.requests().is_empty());
}
