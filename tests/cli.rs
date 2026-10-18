//! The command line: `--help` and `--version`, in process through
//! [`netf::run`] and through the binary.

mod common;

use std::process::Command;

use common::{CLOSED_BASE, TempHome, World};

/// Joins all whitespace into single spaces, to look for sentences that the
/// help wraps across lines.
fn words(text: &str) -> String {
    text.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn check_help(stdout: &[u8]) {
    let help = String::from_utf8(stdout.to_vec()).expect("UTF-8 help");
    // The help starts with the usage and lists every option.
    assert!(help.starts_with("Usage: netf "), "{help}");
    for option in [
        "-s, --set <NAME>",
        "-c, --config <FILE>",
        "--ipset",
        "-4",
        "-6",
        "-f, --file <PATH>",
        "--fields <LIST>",
        "--limit <N>",
        "--ttl <DURATION>",
        "--cache-dir <DIR>",
        "--no-cache",
        "--proxy <URL>",
        "--concurrency <N>",
        "--ripe-emails",
        "--doh <URL>",
        "-h, --help",
        "-V, --version",
    ] {
        assert!(
            help.lines()
                .any(|line| line.trim_start().starts_with(option)),
            "help lacks the option {option}"
        );
    }
    // Sentences of the help that must stay word for word.
    for sentence in [
        "Route, a prefix announced in BGP (RIPE RIS):",
        "Registry network of the route: the block from the registry and records inside it \
         (RDAP ip network, RIPE inetnum):",
        "Names and organizations are case-insensitive.",
        "ARIN and LACNIC have no maintainers; LACNIC cannot be searched by contact; \
         AFRINIC has no abuse contact.",
        "Conditions on as.* must hold for one AS of the route, on net.* for one network.",
    ] {
        assert!(words(&help).contains(sentence), "help lacks {sentence:?}");
    }
    // Every field and selector is listed.
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
        "ip",
        "domain",
        "set",
    ] {
        assert!(
            help.lines()
                .any(|line| line.trim_start().starts_with(&format!("{name} "))),
            "help lacks the field {name}"
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
