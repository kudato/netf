//! Counts, completeness, and completion messages through the real pipeline.
mod common;
use common::{World, runtime};

fn run(world: &World, args: &[&str], terminal: bool) -> (netf::Outcome, Vec<String>) {
    let (mut invocation, reporter) = world.invocation(args);
    invocation.env.stdout_is_terminal = terminal;
    invocation.env.stderr_is_terminal = terminal;
    invocation.env.stdout_columns = Some(200);
    let outcome = runtime().block_on(netf::run(invocation));
    (outcome, reporter.lines())
}

#[test]
fn empty_and_saved_results_only_add_terminal_completion_messages() {
    let world = World::standard();
    for (flags, family) in [
        (vec![], "IPv4"),
        (vec!["-6"], "IPv6"),
        (vec!["-4", "-6"], "IPv4, IPv6"),
    ] {
        let mut args = flags;
        args.push("as.asn: 64498 and as.asn: 64503");
        for terminal in [false, true] {
            let (out, notices) = run(&world, &args, terminal);
            assert_eq!(out.code, 0, "{notices:?}");
            assert!(out.stdout.is_empty());
            assert_eq!(
                notices
                    .iter()
                    .any(|s| s == &format!("netf: no matches ({family}).")),
                terminal
            );
        }
    }
    let args = ["--ipset", "-f", "result.txt", "ip: 192.0.2.1"];
    for terminal in [false, true] {
        let (out, notices) = run(&world, &args, terminal);
        assert_eq!(out.code, 0);
        assert!(out.stdout.is_empty());
        assert_eq!(
            std::fs::read_to_string(world.home.path().join("result.txt")).unwrap(),
            "192.0.2.1/32\n"
        );
        assert_eq!(
            notices.contains(&"netf: saved 1 CIDR to result.txt (IPv4).".into()),
            terminal
        );
    }
}

#[test]
fn limits_and_origins_are_not_presentation_row_counts() {
    let world = World::standard();
    let (out, notices) = run(&world, &["ip: 192.0.2.140"], true);
    assert_eq!(out.code, 0, "{notices:?}");
    let text = String::from_utf8(out.stdout).unwrap();
    assert!(
        text.contains("1 record · 1 route · 2 origin AS · IPv4"),
        "{text}"
    );
    assert!(text.contains("1 unique address · 1 CIDR"), "{text}");
    let (out, _) = run(&world, &["--limit", "2", "as.asn: 64503"], true);
    let text = String::from_utf8(out.stdout).unwrap();
    assert!(text.contains("Showing 2 of 8 matches."), "{text}");
    assert!(
        text.contains("Source: RIPE RIS (ris-v4); retrieved/revalidated:"),
        "{text}"
    );
    assert!(
        text.contains("Source: rdap: apnic; retrieved/revalidated:"),
        "{text}"
    );
    assert!(text.contains("Source snapshot dates: unknown."), "{text}");
}

#[test]
fn failures_never_report_empty_or_saved_success() {
    let world = World::new();
    let (out, notices) = run(
        &world,
        &["--ipset", "-f", "missing/result.txt", "ip: 192.0.2.1"],
        true,
    );
    assert_eq!(out.code, 1);
    assert!(out.stdout.is_empty());
    assert!(
        !notices
            .iter()
            .any(|s| s.contains("saved") || s.contains("no matches"))
    );
    assert!(world.transport.requests().is_empty());
}

#[test]
fn local_and_registry_limits_coexist_and_limit_zero_keeps_registry_warning() {
    let world = World::search();
    for limit in ["1", "0"] {
        let (out, notices) = run(&world, &["--limit", limit, "net.org: ORG-EN1-RIPE"], true);
        assert_eq!(out.code, 0, "{notices:?}");
        let text = String::from_utf8(out.stdout).unwrap();
        assert!(
            text.contains("Partial result: ripencc limited its search response."),
            "{text}"
        );
        assert!(
            text.contains("--limit cannot remove the registry's limit"),
            "{text}"
        );
        assert_eq!(text.contains("Showing 1 of"), limit == "1", "{text}");
    }
    let (out, notices) = run(
        &world,
        &[
            "--limit",
            "2",
            "--concurrency",
            "1",
            "as.asn: 64503 and net.mnt: *",
        ],
        true,
    );
    assert_eq!(out.code, 0, "{notices:?}");
    let text = String::from_utf8(out.stdout).unwrap();
    assert!(text.contains("candidates remain unchecked."), "{text}");
    assert!(
        text.contains("The total number of matches is unknown."),
        "{text}"
    );
}

#[test]
fn cache_time_is_reused_until_revalidation_and_never_called_snapshot_age() {
    use std::time::Duration;
    let world = World::standard();
    let (first, _) = run(&world, &["as.asn: 64498"], true);
    world.clock.advance(Duration::from_secs(60));
    let (cached, _) = run(&world, &["as.asn: 64498"], true);
    assert_eq!(first.stdout, cached.stdout);
    let (fresh, _) = run(&world, &["--ttl", "0", "as.asn: 64498"], true);
    let text = String::from_utf8(fresh.stdout).unwrap();
    assert!(
        text.contains("retrieved/revalidated: Thu, 01 Jan 2026 00:01:00 GMT"),
        "{text}"
    );
    assert!(
        text.contains("Source Last-Modified: Thu, 01 Jan 2026 00:00:00 GMT"),
        "{text}"
    );
}

#[test]
fn unrouted_networks_and_duplicate_input_lines_are_counted_as_sets() {
    let world = World::standard();
    let (out, _) = run(&world, &["ip: 203.0.113.200"], true);
    let text = String::from_utf8(out.stdout).unwrap();
    assert!(
        text.contains("1 record · 0 routes · 0 origin AS · IPv4"),
        "{text}"
    );
    std::fs::write(
        world.home.path().join("addresses.txt"),
        "192.0.2.140\n192.0.2.140\n192.0.2.141\n",
    )
    .unwrap();
    let (out, notices) = run(&world, &["ip: @addresses.txt"], true);
    assert_eq!(out.code, 0, "{notices:?}");
    let text = String::from_utf8(out.stdout).unwrap();
    assert!(text.contains("2 unique addresses · 1 CIDR"), "{text}");
    assert!(text.contains("1 route · 2 origin AS"), "{text}");
}
