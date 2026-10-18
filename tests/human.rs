//! Human output through the application boundary, with isolated fixtures.

mod common;

use common::{World, runtime};
use unicode_width::UnicodeWidthStr as _;

fn human(world: &World, args: &[&str], width: Option<usize>) -> String {
    let (mut invocation, reporter) = world.invocation(args);
    invocation.env.stdout_is_terminal = true;
    invocation.env.stdout_columns = width;
    let outcome = runtime().block_on(netf::run(invocation));
    assert_eq!(outcome.code, 0, "{:?}", reporter.lines());
    String::from_utf8(outcome.stdout).unwrap()
}

#[test]
fn defaults_show_organizations_and_registry_context() {
    let world = World::standard();
    let out = human(&world, &["as.asn: 64498"], Some(80));
    assert!(out.starts_with("BGP route"), "{out}");
    for value in [
        "AS organization",
        "Network holder",
        "Documentation Net Inc",
        "Example Networks LLC",
        "Registry network: 192.0.2.0/24",
    ] {
        assert!(out.contains(value), "{out}");
    }
    for hidden in ["DOCNET", "abuse@", "XA", "Match:"] {
        assert!(!out.contains(hidden), "{out}");
    }
    assert_eq!(out, human(&world, &["as.asn: 64498"], None));
    assert_eq!(out.matches("Field reference:").count(), 1);
}

#[test]
fn moas_values_stay_with_their_origins_at_every_width() {
    let world = World::standard();
    for width in [45, 80, 120, 160] {
        let out = human(
            &world,
            &["--fields", "as.abuse,net.abuse", "ip: 192.0.2.140"],
            Some(width),
        );
        assert!(
            out.lines().all(|line| line.width() <= width),
            "{width}: {out}"
        );
        for value in [
            "192.0.2.140",
            "192.0.2.128/27",
            "Set One GmbH",
            "Set Two GmbH",
            "Tenant One GmbH",
        ] {
            assert!(out.contains(value), "{out}");
        }
        assert_eq!(out.matches("AS64499").count(), 1, "{out}");
        assert_eq!(out.matches("AS64500").count(), 1, "{out}");
        let one = out.find("AS64499").unwrap();
        let two = out.find("AS64500").unwrap();
        let org_one = out.find("Set One GmbH").unwrap();
        let org_two = out.find("Set Two GmbH").unwrap();
        assert!(one < org_one && org_one < two && two < org_two, "{out}");
        let email_one = out.find("abuse@set-one.example").unwrap();
        let email_two = out.find("abuse@set-two.example").unwrap();
        assert!(
            one < email_one && email_one < two && two < email_two,
            "{out}"
        );
    }
}

#[test]
fn config_accepts_output_fields_and_saved_sets_still_export_all_cidrs() {
    let world = World::standard();
    world.base_config("fields = [\"match\", \"net.range\", \"net.abuse\", \"as.abuse\"]\nlimit = 1\n[set.office]\nquery = \"as.asn: 64496 or as.asn: 64501\"\n");
    let out = human(&world, &["as.asn: 64498"], Some(80));
    assert!(out.contains("Match: 192.0.2.64/27"), "{out}");
    assert!(out.contains("net.range:"), "{out}");
    let (expected, _) = world.ok(&["--ipset", "as.asn: 64496 or as.asn: 64501"]);
    assert_eq!(human(&world, &["--set", "office"], Some(45)), expected);
    assert!(expected.lines().count() > 1, "{expected}");
}

#[test]
fn fields_keep_chain_and_full_contacts_without_duplicate_defaults() {
    let world = World::standard();
    let out = human(
        &world,
        &[
            "--fields",
            "as.asn,as.org,net.holder,net.org,net.range,net.contact.abuse,net.country",
            "route: 192.0.2.128/27",
        ],
        Some(80),
    );
    assert!(
        out.contains("Example Networks LLC > Lease Broker LLC > Tenant One GmbH"),
        "{out}"
    );
    assert!(
        out.contains("net.range: 192.0.2.0/24 > 192.0.2.128/25 > 192.0.2.128/27"),
        "{out}"
    );
    assert!(
        out.contains("net.country (registration): XA > XE > XC"),
        "{out}"
    );
    assert!(out.contains("net.contact.abuse:"), "{out}");
    assert_eq!(out.matches("Set One GmbH").count(), 1, "{out}");
    assert!(!out.contains("net.holder:"), "{out}");
    assert!(!out.contains("Registry network:"), "{out}");
}

#[test]
fn pipe_file_and_ipset_keep_their_formats() {
    let world = World::standard();
    let args = ["--fields", "net.org,as.country", "ip: 192.0.2.140"];
    let (pipe, _) = world.ok(&args);
    assert!(!pipe.contains("BGP route"));
    assert!(!pipe.contains("Field reference"));
    let mut file_args = args.to_vec();
    file_args.extend(["-f", "answer.txt"]);
    assert!(human(&world, &file_args, Some(45)).is_empty());
    assert_eq!(
        std::fs::read_to_string(world.home.path().join("answer.txt")).unwrap(),
        pipe
    );
    assert_eq!(
        human(
            &world,
            &["--ipset", "--limit", "1", "ip: 192.0.2.140"],
            Some(45)
        ),
        "192.0.2.140/32\n"
    );
}

#[test]
fn output_only_names_are_not_query_predicates() {
    let world = World::standard();
    for field in ["match", "net.holder", "net.range", "net.abuse", "as.abuse"] {
        let (outcome, _) = world.run(&[&format!("{field}: *")]);
        assert_eq!(outcome.code, 2, "{field}");
        let out = human(&world, &["--fields", field, "as.asn: 64498"], Some(80));
        assert!(out.contains("AS64498"));
    }
}

#[test]
fn no_route_and_ipv6_keep_exact_matches() {
    let world = World::standard();
    let out = human(&world, &["ip: 203.0.113.200"], Some(45));
    assert!(out.contains("Match: 203.0.113.200"), "{out}");
    assert!(out.contains("BGP route: not seen in RIPE RIS"), "{out}");
    assert!(out.contains("Origin AS: not available"), "{out}");
    let out = human(&world, &["-6", "ip: 2001:db8::1"], Some(45));
    assert!(out.contains("Match: 2001:db8::1"), "{out}");
    assert!(out.lines().all(|line| line.width() <= 45), "{out}");
}
