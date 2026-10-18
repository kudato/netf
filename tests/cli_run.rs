//! The binary end to end: real HTTP to the stub server on 127.0.0.1, a
//! temporary home, and the fixtures in `tests/fixtures/<host>/<path>`.
//!
//! No test here resolves a domain, because the binary would ask the system
//! resolver. A `domain:` query that fails to parse is fine.

mod common;

use std::{fs, path::Path, process::Command};

use common::{TempHome, files_under, stub::StubServer, table};

/// The paths of the datasets on the stub, under `NETF_SOURCE_BASE`.
const RIS_V4: &str = "/ris.ripe.test/dumps/riswhoisdump.IPv4.gz";
const ASN_TXT: &str = "/ftp.ripe.test/ripe/asnames/asn.txt";

/// The exit code and the output of a run of the binary.
struct Run {
    code: i32,
    stdout: String,
    stderr: String,
}

/// Runs netf in `home` with the sources at `base`.
fn netf_at(home: &Path, base: &str, args: &[&str]) -> Run {
    let output = Command::new(env!("CARGO_BIN_EXE_netf"))
        .args(args)
        .current_dir(home)
        .env("HOME", home)
        .env("NETF_SOURCE_BASE", base)
        .output()
        .expect("run netf");
    Run {
        code: output.status.code().expect("an exit code"),
        stdout: String::from_utf8(output.stdout).expect("UTF-8 stdout"),
        stderr: String::from_utf8(output.stderr).expect("UTF-8 stderr"),
    }
}

/// Runs netf against `stub`.
fn netf(home: &TempHome, stub: &StubServer, args: &[&str]) -> Run {
    netf_at(home.path(), stub.base(), args)
}

/// Runs netf against `stub` and returns stdout.
///
/// # Panics
///
/// Panics if the code is not 0 or if stderr is not empty.
fn quiet(home: &TempHome, stub: &StubServer, args: &[&str]) -> String {
    let run = netf(home, stub, args);
    assert_eq!(run.code, 0, "netf {args:?}: {}", run.stderr);
    assert_eq!(run.stderr, "", "netf {args:?}");
    run.stdout
}

#[test]
fn rows_over_http() {
    let (home, stub) = (TempHome::new(), StubServer::start());
    let t = table(&quiet(&home, &stub, &["as.asn: 64498"]));
    assert_eq!(t.routes(), ["192.0.2.64/27"]);
    assert_eq!(t.rows[0].ases, "AS64498 DOCNET");
    let t = table(&quiet(&home, &stub, &["ip:", "192.0.2.140"]));
    assert_eq!(t.routes(), ["192.0.2.128/27"]);
    assert_eq!(t.rows[0].part.as_deref(), Some("192.0.2.140"));
    assert_eq!(t.rows[0].ases, "AS64499 SETONE, AS64500 SETTWO");
    // Options can follow the query.
    let t = table(&quiet(&home, &stub, &["as.name:", "docnet", "-4"]));
    assert_eq!(t.routes(), ["192.0.2.64/27"]);
}

#[test]
fn notices_go_to_stderr_with_code_0() {
    // An AS without networks and a query that matches nothing are
    // notices, not errors.
    let (home, stub) = (TempHome::new(), StubServer::start());
    let run = netf(&home, &stub, &["as.asn: 64505"]);
    assert_eq!((run.code, run.stdout.as_str()), (0, ""));
    assert_eq!(
        run.stderr,
        "netf: AS64505 QUIET-AS - Quiet Networks, Inc., XE: no networks\n"
    );
    let run = netf(&home, &stub, &["nosuchword"]);
    assert_eq!((run.code, run.stdout.as_str()), (0, ""));
    assert_eq!(run.stderr, "netf: nosuchword: nothing found\n");
}

#[test]
fn cache_spares_the_second_download() {
    let (home, stub) = (TempHome::new(), StubServer::start());
    let first = quiet(&home, &stub, &["as.name: example*"]);
    assert_eq!(quiet(&home, &stub, &["as.name: example*"]), first);
    assert_eq!(stub.count(RIS_V4), 1);
    assert_eq!(stub.count(ASN_TXT), 1);
    let cache = files_under(&home.path().join(".netf/cache"));
    assert!(cache.iter().any(|f| f == "ris-v4.bin"), "{cache:?}");

    // With `--ttl 0`, netf sends a conditional request, and the stub answers
    // 304.
    assert_eq!(
        quiet(&home, &stub, &["--ttl", "0", "as.name: example*"]),
        first
    );
    assert_eq!(stub.count(RIS_V4), 2);
    let last = stub
        .received()
        .into_iter()
        .rfind(|r| r.path == RIS_V4)
        .expect("a request");
    assert!(last.header("if-none-match").is_some(), "{last:?}");
}

#[test]
fn no_cache_writes_no_cache() {
    let (home, stub) = (TempHome::new(), StubServer::start());
    for _ in 0..2 {
        assert_eq!(
            quiet(&home, &stub, &["--no-cache", "--ipset", "as.asn: 64498"]),
            "192.0.2.64/27\n"
        );
    }
    assert_eq!(stub.count(RIS_V4), 2);
    let cache = files_under(&home.path().join(".netf/cache"));
    assert!(cache.is_empty(), "{cache:?}");
}

#[test]
fn file_is_replaced_only_on_success() {
    let (home, stub) = (TempHome::new(), StubServer::start());
    let out = home.path().join("out.txt");
    let run = netf(&home, &stub, &["-f", "out.txt", "--ipset", "as.asn: 64498"]);
    assert_eq!((run.code, run.stdout.as_str()), (0, ""), "{}", run.stderr);
    assert_eq!(fs::read_to_string(&out).unwrap(), "192.0.2.64/27\n");

    // A source that answers 404 leaves the file unchanged, and the run exits
    // with code 1.
    let missing = format!("{}/missing", stub.base());
    let run = netf_at(
        home.path(),
        &missing,
        &["--no-cache", "-f", "out.txt", "--ipset", "as.asn: 64496"],
    );
    assert_eq!(run.code, 1, "{}", run.stderr);
    assert_eq!(run.stdout, "");
    assert!(run.stderr.starts_with("netf: ris-v4: "), "{}", run.stderr);
    assert_eq!(fs::read_to_string(&out).unwrap(), "192.0.2.64/27\n");
    let files = files_under(home.path());
    assert!(
        files
            .iter()
            .all(|f| !f.contains(".tmp") && f != ".out.txt.lock"),
        "{files:?}"
    );
}

#[test]
fn router_config_with_a_set() {
    // The router use case: `netf -c router.toml -s both -f vpn4.txt`.
    let (home, stub) = (TempHome::new(), StubServer::start());
    let cache = home.path().join("router-cache");
    let config = format!(
        "cache_dir = {:?}\n\n\
         [set.docs]\nquery = \"as.asn: 64498\"\n\n\
         [set.rogue]\nquery = \"ip: 198.51.100.0/24 and not as.asn: 64501\"\n\n\
         [set.both]\nquery = \"set: docs or set: rogue\"\n\n\
         [set.six]\nquery = \"as.asn: 64506\"\nipv6 = true\n",
        cache.to_string_lossy()
    );
    fs::write(home.path().join("router.toml"), config).unwrap();
    for (set, file, want) in [
        ("both", "vpn4.txt", "192.0.2.64/27\n198.51.100.128/25\n"),
        ("six", "vpn6.txt", "2001:db8:100::/40\n"),
    ] {
        let run = netf(&home, &stub, &["-c", "router.toml", "-s", set, "-f", file]);
        assert_eq!((run.code, run.stdout.as_str()), (0, ""), "{}", run.stderr);
        let got = fs::read_to_string(home.path().join(file)).unwrap();
        assert_eq!(got, want, "{set}");
    }
    let files = files_under(&cache);
    assert!(files.iter().any(|f| f == "ris-v4.bin"), "{files:?}");
    assert!(files.iter().any(|f| f == "ris-v6.bin"), "{files:?}");
    assert!(files_under(&home.path().join(".netf/cache")).is_empty());
    // A query can join a named set and a condition.
    let t = table(&quiet(
        &home,
        &stub,
        &["-c", "router.toml", "set: both and as.country: XB"],
    ));
    assert_eq!(t.routes(), ["198.51.100.128/25"]);
}

#[test]
fn errors_in_the_query_are_code_2() {
    let (home, stub) = (TempHome::new(), StubServer::start());
    for args in [
        &["as.asn:", "-4", "64496"][..],
        &["bogus: 1"][..],
        &["domain: {ip: 192.0.2.1}"][..],
        &["--fields", "net.org", "--ipset", "as.asn: 64496"][..],
    ] {
        let run = netf(&home, &stub, args);
        assert_eq!(run.code, 2, "{args:?}: {}", run.stderr);
        assert_eq!(run.stdout, "", "{args:?}");
        assert!(run.stderr.starts_with("netf: "), "{args:?}: {}", run.stderr);
    }
    // Nothing was downloaded for a query that cannot run.
    assert!(stub.received().is_empty(), "{:?}", stub.received());
}
