//! The command line: `--help` and `--version`, in process through
//! [`netf::run`] and through the binary.

mod common;

use std::process::Command;

use common::{CLOSED_BASE, TempHome, World};

/// General help keeps the first query and mode choices on the first screen.
fn check_help(stdout: &[u8]) {
    let help = String::from_utf8(stdout.to_vec()).expect("UTF-8 help");
    assert!(help.contains("Usage: netf "), "{help}");
    let first: Vec<_> = help.lines().take(24).collect();
    for fragment in [
        "netf 'route:",
        "netf 'as.asn:",
        "netf --ipset",
        "--help=query",
    ] {
        assert!(
            first.iter().any(|line| line.contains(fragment)),
            "{fragment}: {help}"
        );
    }
    for option in [
        "-s, --set",
        "-c, --config",
        "--ipset",
        "-i ",
        "-4 ",
        "-6 ",
        "-f, --file",
        "--fields",
        "--limit",
        "--ttl",
        "--cache-dir",
        "--no-cache",
        "--proxy",
        "--concurrency",
        "--ripe-emails",
        "--doh",
        "-h, --help",
        "-V, --version",
    ] {
        assert!(
            help.lines()
                .any(|line| line.trim_start().starts_with(option)),
            "help lacks {option}"
        );
    }
}

fn version_line() -> String {
    format!("netf {}\n", env!("CARGO_PKG_VERSION"))
}

#[test]
fn help_in_process() {
    let world = World::new();
    for flag in ["--help", "-h"] {
        let (outcome, stderr) = world.run(&[flag]);
        assert_eq!(outcome.code, 0);
        assert!(stderr.is_empty(), "{stderr:?}");
        check_help(&outcome.stdout);
    }
    assert!(world.transport.requests().is_empty());
}

#[test]
fn version_in_process() {
    let world = World::new();
    for flag in ["--version", "-V"] {
        let (outcome, stderr) = world.run(&[flag]);
        assert_eq!(outcome.code, 0);
        assert!(stderr.is_empty(), "{stderr:?}");
        assert_eq!(String::from_utf8(outcome.stdout).unwrap(), version_line());
    }
}

/// Runs the binary with a temporary home and sources on a closed port.
fn netf(args: &[&str]) -> std::process::Output {
    let home = TempHome::new();
    Command::new(env!("CARGO_BIN_EXE_netf"))
        .args(args)
        .current_dir(home.path())
        .env("HOME", home.path())
        .env("USERPROFILE", home.path())
        .env("NETF_SOURCE_BASE", CLOSED_BASE)
        .output()
        .expect("run netf")
}

#[test]
fn help_from_the_binary() {
    let output = netf(&["--help"]);
    assert_eq!(output.status.code(), Some(0));
    assert!(output.stderr.is_empty());
    check_help(&output.stdout);
}

#[test]
fn version_from_the_binary() {
    let output = netf(&["--version"]);
    assert_eq!(output.status.code(), Some(0));
    assert!(output.stderr.is_empty());
    assert_eq!(String::from_utf8(output.stdout).unwrap(), version_line());
}

#[test]
fn topics_and_first_run_need_neither_home_config_nor_network() {
    let world = World::bare();
    std::fs::write(world.home.path().join("invalid.toml"), "invalid TOML [").unwrap();
    for topic in [
        "--help",
        "--help=query",
        "--help=fields",
        "--help=all",
        "--version",
    ] {
        let (mut invocation, reporter) = world.invocation(&["-c", "invalid.toml", topic]);
        invocation.env.home = None;
        invocation.env.vars.clear();
        let outcome = common::runtime().block_on(netf::run(invocation));
        assert_eq!(outcome.code, 0, "{topic}: {:?}", reporter.lines());
        assert!(!outcome.stdout.is_empty());
        assert!(reporter.lines().is_empty());
    }
    let (mut invocation, reporter) = world.invocation(&[]);
    invocation.env.home = None;
    let outcome = common::runtime().block_on(netf::run(invocation));
    assert_eq!(outcome.code, 2);
    assert!(outcome.stdout.is_empty());
    let screen = reporter.lines().join("\n");
    assert!(screen.starts_with("netf: enter a query"), "{screen}");
    assert!(screen.lines().count() <= 24);
    assert!(screen.contains("netf --ipset 'as.asn: 64498'"));
    assert!(world.transport.requests().is_empty());
}

#[test]
fn all_help_contains_query_and_output_catalogs() {
    let world = World::bare();
    let (out, _) = world.run(&["--help=all"]);
    let all = String::from_utf8(out.stdout).unwrap();
    for topic in ["query", "fields"] {
        let (out, _) = world.run(&[&format!("--help={topic}")]);
        assert!(all.contains(&String::from_utf8(out.stdout).unwrap()));
    }
    for name in [
        "route",
        "net.country",
        "net.org",
        "net.rir",
        "net.mnt",
        "net.contact",
        "as.asn",
        "as.name",
        "as.org",
        "as.country",
        "as.rir",
        "as.mnt",
        "as.contact",
        "match",
        "net.holder",
        "net.range",
        "net.abuse",
        "as.abuse",
    ] {
        assert!(
            all.lines()
                .any(|line| line.trim_start().starts_with(&format!("{name} "))),
            "missing {name}"
        );
    }
}

#[test]
fn unknown_topic_is_usage_error_and_no_arguments_use_stderr() {
    let output = netf(&["--help=unknown"]);
    assert_eq!(output.status.code(), Some(2));
    assert!(output.stdout.is_empty());
    let error = String::from_utf8(output.stderr).unwrap();
    for topic in ["--help=query", "--help=fields", "--help=all"] {
        assert!(error.contains(topic), "{error}");
    }
    let output = netf(&[]);
    assert_eq!(output.status.code(), Some(2));
    assert!(output.stdout.is_empty());
    assert!(
        String::from_utf8(output.stderr)
            .unwrap()
            .contains("Usage: netf")
    );
}
