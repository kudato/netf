//! Exact columns, explicit layouts, and compatibility at application boundaries.
mod common;
use common::{World, runtime};

#[test]
fn exact_order_has_no_hidden_fields_in_pipe_or_file() {
    let world = World::standard();
    world.base_config("fields = [\"net.country\", \"as.abuse\"]\n");
    let args = [
        "--columns",
        "as.asn,route",
        "--format",
        "table",
        "as.asn: 64498",
    ];
    let (text, _) = world.ok(&args);
    assert_eq!(text, "Origin AS  BGP route\nAS64498    192.0.2.64/27\n");
    let mut file_args = args.to_vec();
    file_args.extend(["-f", "result.txt"]);
    let (stdout, _) = world.ok(&file_args);
    assert!(stdout.is_empty());
    assert_eq!(
        std::fs::read_to_string(world.home.path().join("result.txt")).unwrap(),
        text
    );
    let (out, _) = world.ok(&["--columns", "as.asn", "ip: 192.0.2.140"]);
    assert_eq!(out, "Origin AS\nAS64499\nAS64500\n");
    let (out, _) = world.ok(&["--columns", "route", "ip: 192.0.2.140"]);
    assert_eq!(out, "BGP route\n192.0.2.128/27\n");
}

#[test]
fn moas_details_keep_field_order_and_association() {
    let world = World::standard();
    let (text, _) = world.ok(&[
        "--columns",
        "as.org,as.asn,match",
        "--format",
        "details",
        "ip: 192.0.2.140",
    ]);
    assert_eq!(
        text,
        "AS organization: Set One GmbH\nOrigin AS: AS64499\nMatch: 192.0.2.140\n\nAS organization: Set Two GmbH\nOrigin AS: AS64500\n"
    );
    for format in ["auto", "table", "details"] {
        let (text, _) = world.ok(&[
            "-6",
            "--columns",
            "match,route",
            "--format",
            format,
            "ip: 2001:db8::1",
        ]);
        assert!(text.contains("2001:db8::1"), "{text}");
        assert!(
            !text.contains("Network holder") && !text.contains("Registry network"),
            "{text}"
        );
    }
}

#[test]
fn plain_is_the_original_bytes_even_in_a_terminal() {
    let world = World::standard();
    let args = ["--fields", "as.name,net.country", "ip: 192.0.2.140"];
    let (plain, _) = world.ok(&args);
    let mut args = args.to_vec();
    args.extend(["--format", "plain"]);
    let (mut invocation, reporter) = world.invocation(&args);
    invocation.env.stdout_is_terminal = true;
    invocation.env.stdout_columns = Some(45);
    let out = runtime().block_on(netf::run(invocation));
    assert_eq!(out.code, 0, "{:?}", reporter.lines());
    assert_eq!(out.stdout, plain.as_bytes());
}

#[test]
fn format_conflicts_fail_before_network_or_file_work() {
    for args in [
        vec!["--columns", "route", "--fields", "as.name", "route: *"],
        vec!["--columns", "route", "--format", "plain", "route: *"],
        vec!["--format", "table", "--ipset", "route: *"],
        vec!["--columns", "route", "-s", "example"],
        vec!["--format", "details", "-i", "route: *"],
        vec!["--format", "json", "route: *"],
        vec!["--columns", "net.countri", "route: *"],
    ] {
        let world = World::new();
        let mut args = args;
        args.extend(["-f", "result.txt"]);
        let (out, notices) = world.run(&args);
        assert_eq!(out.code, 2, "{args:?}: {notices:?}");
        assert!(out.stdout.is_empty());
        assert!(world.transport.requests().is_empty());
        assert!(!world.home.path().join("result.txt").exists());
    }
}
