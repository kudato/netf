//! The command line, the config files, and `~/.netf`, in process through
//! [`netf::run`] with a temporary home.
//!
//! A successful run of an `--ipset` query made only of `ip:` shows that a
//! configuration is good. Such a run needs no dataset, so it reads the
//! command line, `~/.netf`, and both config files without a single request.

mod common;

use std::{fs, path::PathBuf};

use common::World;

/// The output of a successful run of the `ip: 192.0.2.1` set or query.
const PASSED: &str = "192.0.2.1/32\n";

/// Runs `args` and returns the exit code and the only stderr line.
///
/// # Panics
///
/// Panics if the run prints to stdout or makes a request, or if stderr does
/// not hold exactly one line.
fn run(world: &World, args: &[&str]) -> (u8, String) {
    let (outcome, stderr) = world.run(args);
    assert!(outcome.stdout.is_empty(), "stdout on {args:?}");
    assert_eq!(stderr.len(), 1, "{args:?}: {stderr:?}");
    assert!(
        world.transport.requests().is_empty(),
        "requests on {args:?}"
    );
    (outcome.code, stderr[0].clone())
}

/// Runs `args`, which must succeed without requests and notices, and returns
/// stdout.
///
/// # Panics
///
/// Panics if the run fails, prints to stderr, or makes a request.
fn passes(world: &World, args: &[&str]) -> String {
    let (outcome, stderr) = world.run(args);
    assert_eq!(outcome.code, 0, "{args:?}: {stderr:?}");
    assert!(stderr.is_empty(), "{args:?}: {stderr:?}");
    assert!(
        world.transport.requests().is_empty(),
        "requests on {args:?}"
    );
    String::from_utf8(outcome.stdout).unwrap()
}

fn netf_dir(world: &World) -> PathBuf {
    world.home.path().join(".netf")
}

/// Writes `text` alone to the base config, without
/// [`common::SOURCES_CONFIG`], and creates `~/.netf` with mode 0700.
fn base_config(world: &World, text: &str) {
    fs::create_dir_all(netf_dir(world)).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        fs::set_permissions(netf_dir(world), fs::Permissions::from_mode(0o700)).unwrap();
    }
    fs::write(netf_dir(world).join("config.toml"), text).unwrap();
}

#[test]
fn first_run_creates_the_home() {
    let world = World::bare();
    assert_eq!(passes(&world, &["--ipset", "ip:", "192.0.2.1"]), PASSED);
    let dir = netf_dir(&world);
    assert!(dir.is_dir());
    assert_eq!(fs::read(dir.join("config.toml")).unwrap(), b"");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        let mode = fs::metadata(&dir).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o700, "{mode:o}");
    }
    // The second run uses what is there.
    assert_eq!(passes(&world, &["--ipset", "ip:", "192.0.2.1"]), PASSED);
}

#[test]
fn existing_config_is_kept() {
    let world = World::bare();
    let text = "ttl = \"7d\"\n[set.a]\nquery = \"ip: 192.0.2.1\"\n";
    base_config(&world, text);
    assert_eq!(passes(&world, &["-s", "a"]), PASSED);
    assert_eq!(
        fs::read_to_string(netf_dir(&world).join("config.toml")).unwrap(),
        text
    );
}

#[test]
fn help_and_errors_in_options_touch_nothing() {
    let world = World::bare();
    let (outcome, _) = world.run(&["--help"]);
    assert_eq!(outcome.code, 0);
    assert_eq!(
        run(&world, &["--bogus", "x"]),
        (
            2,
            "netf: --bogus: unknown option; see netf --help\n\n  --bogus\n  ^^^^^^^\n".to_owned()
        )
    );
    assert!(!netf_dir(&world).exists());
}

#[cfg(unix)]
#[test]
fn open_home_is_refused() {
    use std::os::unix::fs::PermissionsExt as _;

    let world = World::bare();
    let dir = netf_dir(&world);
    fs::create_dir(&dir).unwrap();
    for (mode, shown) in [(0o755, "0755"), (0o750, "0750"), (0o701, "0701")] {
        fs::set_permissions(&dir, fs::Permissions::from_mode(mode)).unwrap();
        assert_eq!(
            run(&world, &["ip:", "192.0.2.1"]),
            (
                1,
                format!(
                    "netf: ~/.netf is group- or world-accessible (mode {shown}); expected 0700"
                )
            )
        );
    }
    // Nothing is created in a directory that failed the check.
    assert!(!dir.join("config.toml").exists());
    fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).unwrap();
    assert_eq!(passes(&world, &["--ipset", "ip:", "192.0.2.1"]), PASSED);
}

#[test]
fn home_that_is_a_file() {
    let world = World::bare();
    fs::write(netf_dir(&world), "").unwrap();
    assert_eq!(
        run(&world, &["ip:", "192.0.2.1"]),
        (1, "netf: ~/.netf is not a directory".to_owned())
    );
}

#[test]
fn bad_base_config() {
    let world = World::bare();
    base_config(&world, "ttl = \"1h\"\ncach = false\n");
    let (code, line) = run(&world, &["x"]);
    assert_eq!(code, 2);
    assert!(
        line.starts_with("netf: ~/.netf/config.toml: line 2: unknown field `cach`"),
        "{line}"
    );

    base_config(&world, "[set.a]\nquery = \"x\"\nipv6 = \"yes\"\n");
    let (code, line) = run(&world, &["x"]);
    assert_eq!(code, 2);
    assert!(
        line.starts_with("netf: ~/.netf/config.toml: line 3: "),
        "{line}"
    );

    base_config(&world, "ttl = \"forever\"\n");
    assert_eq!(
        run(&world, &["x"]),
        (
            2,
            "netf: ~/.netf/config.toml: line 1: ttl \"forever\": expected a duration such as \
             30m, 12h, 7d, or 0"
                .to_owned()
        )
    );

    base_config(&world, "not toml at all");
    let (code, line) = run(&world, &["x"]);
    assert_eq!(code, 2);
    assert!(
        line.starts_with("netf: ~/.netf/config.toml: line 1: "),
        "{line}"
    );
}

#[test]
fn config_option_is_merged_over_the_base() {
    let world = World::bare();
    base_config(&world, "[set.alpha]\nquery = \"ip: 192.0.2.1\"\n");
    fs::write(
        world.home.path().join("router.toml"),
        "cache_dir = \"/tmp/netf-cache\"\n\
         [set.vpn]\nquery = \"set: alpha\"\n\
         [set.vpn6]\nquery = \"set: vpn\"\nipv6 = true\n",
    )
    .unwrap();

    // A set of -c exists only in runs with -c.
    assert_eq!(
        run(&world, &["-s", "vpn"]),
        (2, "netf: -s vpn: no such set; sets: alpha".to_owned())
    );
    // The path of -c is relative to the current directory. The base sets
    // stay available.
    for set in ["vpn", "alpha"] {
        assert_eq!(
            passes(&world, &["-c", "router.toml", "-s", set]),
            PASSED,
            "{set}"
        );
    }
    // The family of vpn6 comes from its own keys.
    assert_eq!(
        run(&world, &["-c", "router.toml", "-s", "vpn6"]),
        (0, "netf: 1 IPv4 address skipped, use -4".to_owned())
    );
    assert_eq!(
        run(&world, &["-c", "router.toml", "-s", "nope"]),
        (
            2,
            "netf: -s nope: no such set; sets: alpha, vpn, vpn6".to_owned()
        )
    );
    let absolute = world.home.path().join("router.toml");
    assert_eq!(
        passes(
            &world,
            &[
                "--config",
                absolute.to_str().unwrap(),
                "set: vpn",
                "--ipset"
            ]
        ),
        PASSED
    );
}

#[test]
fn bad_config_option() {
    let world = World::bare();
    let (code, line) = run(&world, &["-c", "missing.toml", "x"]);
    assert_eq!(code, 2);
    assert!(line.starts_with("netf: -c missing.toml: "), "{line}");
    assert!(!line.contains("os error"), "{line}");

    fs::write(
        world.home.path().join("bad.toml"),
        "\n\n[set.a]\nquery = 1\n",
    )
    .unwrap();
    let (code, line) = run(&world, &["-c", "bad.toml", "x"]);
    assert_eq!(code, 2);
    assert!(line.starts_with("netf: bad.toml: line 4: "), "{line}");

    fs::write(
        world.home.path().join("names.toml"),
        "[set.\"a b\"]\nquery = \"x\"\n",
    )
    .unwrap();
    assert_eq!(
        run(&world, &["-c", "names.toml", "x"]),
        (
            2,
            "netf: names.toml: set \"a b\": invalid name; use letters, digits, '-' and '_'"
                .to_owned()
        )
    );
}

#[test]
fn option_errors() {
    let world = World::bare();
    for (args, message) in [
        (
            &["as.asn:", "-4", "64510"][..],
            "netf: -4: option inside the query; put options before or after the query",
        ),
        (
            &["--ipset", "--fields", "net.org", "x"][..],
            "netf: --fields cannot be combined with --ipset: the list has no columns",
        ),
        (
            &["x", "--limit"][..],
            "netf: --limit: missing value; see netf --help",
        ),
        (
            &["--limit", "many", "x"][..],
            "netf: --limit many: expected a number\n\n  --limit many\n          ^^^^\n",
        ),
        (
            &["--ttl", "1w", "x"][..],
            "netf: --ttl 1w: expected a duration such as 30m, 12h, 7d, or 0\n\n  --ttl 1w\n        ^^\n",
        ),
    ] {
        assert_eq!(run(&world, args), (2, message.to_owned()), "{args:?}");
    }
    // Options on both sides of the query are accepted.
    assert_eq!(
        passes(
            &world,
            &["-4", "-f", "out.txt", "ip:", "192.0.2.1", "--ipset"]
        ),
        ""
    );
}

#[test]
fn options_are_checked_before_the_config() {
    let world = World::bare();
    base_config(&world, "bogus = 1\n");
    assert_eq!(
        run(&world, &["--fields", "holder", "x"]),
        (
            2,
            "netf: --fields: holder: unknown field; see netf --help=fields\n\n  --fields holder\n           ^^^^^^\n".to_owned()
        )
    );
}
