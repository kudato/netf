//! Tests of the cache of datasets, end to end.
//!
//! A second run does not go to the sources, and the TTL leads to a
//! conditional request. A corrupt file is rebuilt. `--no-cache` streams and
//! writes nothing, and an interrupted run leaves no temporary files.
//!
//! A cache file is named after its source, such as `ris-v4.bin` or
//! `asn.bin`. A cache file is written to `<name>.tmp-<pid>-<n>` first, and
//! the file of `-f` to `PATH.tmp-<pid>`.

mod common;

use std::{fs, time::Duration};

use common::{
    ASN_TXT, ETAG, LAST_MODIFIED, RDAP_HOSTS, REST_SEARCH, RIS_V4, RIS_V6, Scripted, World,
    files_in, files_under, fixture, runtime, table,
};
use netf::Request;

const HOUR: Duration = Duration::from_secs(3600);

/// Returns the value of the header `name` of `request`, ignoring the case of
/// the name.
fn header<'a>(request: &'a Request, name: &str) -> Option<&'a str> {
    request
        .headers
        .iter()
        .find(|(n, _)| n.eq_ignore_ascii_case(name))
        .map(|(_, v)| v.as_str())
}

/// Checks that `request` carries the validators of the fixtures, `ETag`
/// and `Last-Modified`.
fn assert_conditional(request: &Request) {
    assert_eq!(header(request, "If-None-Match"), Some(ETAG), "{request:?}");
    assert_eq!(
        header(request, "If-Modified-Since"),
        Some(LAST_MODIFIED),
        "{request:?}"
    );
}

/// Checks that no temporary file is left anywhere in the home.
fn assert_no_temporaries(world: &World) {
    let files = files_under(world.home.path());
    assert!(
        files.iter().all(|f| !f.contains(".tmp")),
        "temporary files left: {files:?}"
    );
}

/// `--ipset` of 64496 in IPv4, which needs only the RIS IPv4 dump.
const IPSET_64496: [&str; 2] = ["--ipset", "as.asn: 64496"];

/// [`IPSET_64496`] in IPv6, which needs only the RIS IPv6 dump.
const IPSET_V6_64496: [&str; 3] = ["-6", "--ipset", "as.asn: 64496"];

#[test]
fn second_run_goes_nowhere() {
    let world = World::standard();
    let first = world.ok(&["as.name: example*"]);
    assert_eq!(world.transport.count(RIS_V4), 1);
    assert_eq!(world.transport.count(ASN_TXT), 1);
    let names = files_in(&world.cache_dir());
    for name in ["ris-v4.bin", "asn.bin"] {
        assert!(names.iter().any(|n| n == name), "{name} in {names:?}");
    }
    assert!(!names.iter().any(|n| n == "ris-v6.bin"), "{names:?}");

    // Within the TTL, netf does not ask a source again.
    let made = world.transport.requests().len();
    assert_eq!(world.ok(&["as.name: example*"]), first);
    assert_eq!(world.transport.requests().len(), made);
    // A query for a new row does not download the datasets again.
    assert!(!world.ok(&["as.asn: 64498"]).0.is_empty());
    assert_eq!(world.transport.count(RIS_V4), 1);
    assert_eq!(world.transport.count(ASN_TXT), 1);

    // A new family downloads only its dump.
    let made = world.transport.requests().len();
    world.ok(&IPSET_V6_64496);
    assert_eq!(world.transport.count(RIS_V6), 1);
    assert_eq!(world.transport.requests().len(), made + 1);
    assert_no_temporaries(&world);
}

#[test]
fn after_the_ttl_a_conditional_request_and_304() {
    let world = World::standard();
    let want = world.ok(&IPSET_64496);
    assert_eq!(want.0, "192.0.2.0/24\n");

    // The TTL is 24h by default, counted from the mtime of the file.
    world.clock.advance(23 * HOUR);
    assert_eq!(world.ok(&IPSET_64496), want);
    assert_eq!(world.transport.count(RIS_V4), 1);

    world.clock.advance(2 * HOUR);
    world.transport.get(RIS_V4, Scripted::status(304));
    assert_eq!(world.ok(&IPSET_64496), want);
    let requests = world.transport.requests_to(RIS_V4);
    assert_eq!(requests.len(), 2);
    assert_conditional(&requests[1]);
    assert!(world.transport.unused().is_empty(), "the 304 was not asked");

    // A 304 touches the file, so it is fresh for another TTL.
    world.clock.advance(23 * HOUR);
    assert_eq!(world.ok(&IPSET_64496), want);
    assert_eq!(world.transport.count(RIS_V4), 2);
    assert_no_temporaries(&world);
}

#[test]
fn ttl_from_the_config_and_the_flag() {
    // `ttl` in the config sets the TTL, and the flag overrides the config.
    let world = World::standard();
    world.base_config("ttl = \"1h\"\n");
    let want = world.ok(&IPSET_64496);
    world.clock.advance(HOUR / 2);
    world.ok(&IPSET_64496);
    assert_eq!(world.transport.count(RIS_V4), 1);
    world.clock.advance(HOUR);
    world.transport.get(RIS_V4, Scripted::status(304));
    assert_eq!(world.ok(&IPSET_64496), want);
    assert_eq!(world.transport.count(RIS_V4), 2);
    // Two hours later, the cache is stale for the config but fresh for
    // `--ttl 7d`.
    world.clock.advance(2 * HOUR);
    let mut args = vec!["--ttl", "7d"];
    args.extend(IPSET_64496);
    assert_eq!(world.ok(&args), want);
    assert_eq!(world.transport.count(RIS_V4), 2);
}

#[test]
fn ttl_zero_keeps_the_responses_of_its_run() {
    // `--ttl 0` asks the registries again, and the answers it gets stay in
    // the cache: RDAP and the RIPE REST API share `responses/`, and one
    // sweep of the run must not remove what the other client wrote.
    let world = World::search();
    let query = "net.mnt: MAINT-XG-EXAMPLECDN";
    let want = world.ok(&["--ttl", "0", query]);
    let rest = |world: &World| {
        let requests = world.transport.requests();
        requests
            .iter()
            .filter(|r| r.url.starts_with(REST_SEARCH))
            .count()
    };
    assert!(rest(&world) >= 1);
    let rdap = world
        .transport
        .requests()
        .iter()
        .filter(|r| RDAP_HOSTS.iter().any(|host| r.url.contains(host)))
        .count();
    assert!(rdap >= 1);
    let made = world.transport.requests().len();
    assert_eq!(world.ok(&[query]), want);
    let again: Vec<String> = world.transport.requests()[made..]
        .iter()
        .map(|request| request.url.clone())
        .collect();
    assert!(again.is_empty(), "{again:?}");
}

#[test]
fn a_stale_cache_does_not_replace_a_failed_source() {
    // The file is there but stale, and the source responds with 404. The
    // run fails, because netf prints the whole result or nothing.
    let world = World::standard();
    world.ok(&IPSET_64496);
    world.clock.advance(25 * HOUR);
    world.transport.get(RIS_V4, Scripted::status(404));
    let (code, stderr) = world.fail(&IPSET_64496);
    assert_eq!(code, 1, "{stderr:?}");
}

/// A function that makes a damaged cache file of a good one.
type Damage = fn(Vec<u8>) -> Vec<u8>;

/// Replaces the cache file `name` with what `damage` makes of it.
fn damage(world: &World, name: &str, damage: impl FnOnce(Vec<u8>) -> Vec<u8>) {
    let path = world.cache_dir().join(name);
    let data = fs::read(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
    fs::write(&path, damage(data)).expect("write the damaged file");
}

#[test]
fn a_corrupt_file_is_downloaded_again() {
    // The damages leave out a file of another format version, because netf
    // rebuilds that file silently, without a notice.
    let damages: [(&str, Damage); 3] = [
        ("garbage", |_| b"not a cache file at all".to_vec()),
        ("truncated", |mut d: Vec<u8>| {
            d.truncate(d.len() / 2);
            d
        }),
        ("empty", |_| Vec::new()),
    ];
    for (what, how) in damages {
        let world = World::standard();
        let want = world.ok(&["as.asn: 64496"]);
        damage(&world, "ris-v4.bin", how);
        // The file is removed and the data are downloaded again, with one
        // notice.
        let (stdout, stderr) = world.ok(&["as.asn: 64496"]);
        assert_eq!(stdout, want.0, "{what}");
        assert_eq!(
            stderr,
            ["netf: cache: ris-v4: corrupt, downloading again"],
            "{what}"
        );
        assert_eq!(world.transport.count(RIS_V4), 2, "{what}");
        // The rebuilt file serves the next run.
        assert_eq!(world.ok(&["as.asn: 64496"]), want, "{what}");
        assert_eq!(world.transport.count(RIS_V4), 2, "{what}");
        assert_no_temporaries(&world);
    }
}

#[test]
fn no_cache_streams_and_writes_nothing() {
    let world = World::standard();
    let mut args = vec!["--no-cache"];
    args.extend(IPSET_64496);
    for _ in 0..2 {
        assert_eq!(world.ok(&args).0, "192.0.2.0/24\n");
    }
    // The cache is neither read nor written.
    assert_eq!(world.transport.count(RIS_V4), 2);
    assert_eq!(files_in(&world.cache_dir()), Vec::<String>::new());
    assert_no_temporaries(&world);
    // The rows are the same as with the cache.
    let streamed = world.ok(&["--no-cache", "as.name: example*"]).0;
    assert_eq!(files_in(&world.cache_dir()), Vec::<String>::new());
    assert_eq!(streamed, world.ok(&["as.name: example*"]).0);
}

#[test]
fn a_scope_reads_the_file_twice() {
    // A scope whose inner and outer queries read one file needs a second
    // pass. With the cache, the pass is a lookup in the same file. With
    // `--no-cache`, the file is downloaded again.
    let query = "as.asn: {ip: 198.51.100.130}";
    let world = World::standard();
    assert_eq!(
        world.ok(&["--no-cache", "--ipset", query]).0,
        "198.51.100.128/25\n"
    );
    assert_eq!(world.transport.count(RIS_V4), 2);

    let world = World::standard();
    assert_eq!(world.ok(&["--ipset", query]).0, "198.51.100.128/25\n");
    assert_eq!(world.transport.count(RIS_V4), 1);
}

/// Runs `args` and drops the run after `after`.
///
/// Dropping the future of the run models Ctrl+C.
///
/// # Panics
///
/// Panics if the run finishes before `after`.
fn interrupt(world: &World, args: &[&str], after: Duration) {
    let (invocation, _reporter) = world.invocation(args);
    let runtime = runtime();
    let finished = runtime.block_on(async {
        tokio::time::timeout(after, netf::run(invocation))
            .await
            .is_ok()
    });
    assert!(!finished, "netf {args:?} finished before the interruption");
}

/// Returns a response that sends the first half of the RIS IPv4 dump and
/// then stalls, like a download that hangs.
fn hanging_dump() -> Scripted {
    let whole = fixture(common::RIS_V4_FIXTURE);
    let half = whole.slice(..whole.len() / 2);
    Scripted::ok(half)
        .header("ETag", ETAG)
        .header("Last-Modified", LAST_MODIFIED)
        .stall()
}

#[test]
fn interrupted_download_leaves_nothing() {
    for args in [&IPSET_64496[..], &["--no-cache", "as.asn: 64496"][..]] {
        let world = World::standard();
        world.transport.get(RIS_V4, hanging_dump());
        interrupt(&world, args, Duration::from_millis(300));
        assert_eq!(world.transport.count(RIS_V4), 1, "{args:?}");
        let names = files_in(&world.cache_dir());
        assert!(
            !names.iter().any(|n| n.starts_with("ris-v4")),
            "{args:?}: {names:?}"
        );
        assert_no_temporaries(&world);
        // The next run starts over and succeeds.
        assert_eq!(world.ok(&IPSET_64496).0, "192.0.2.0/24\n", "{args:?}");
        assert_eq!(world.transport.count(RIS_V4), 2, "{args:?}");
    }
}

#[test]
fn interrupted_refresh_keeps_the_old_cache() {
    // The new dataset is written to a temporary file and renamed over the
    // old one. An interrupted refresh leaves the old file in place.
    let world = World::standard();
    world.ok(&IPSET_64496);
    let before = fs::read(world.cache_dir().join("ris-v4.bin")).expect("the cache file");
    world.clock.advance(25 * HOUR);
    world.transport.get(RIS_V4, hanging_dump());
    interrupt(&world, &IPSET_64496, Duration::from_millis(300));
    let after = fs::read(world.cache_dir().join("ris-v4.bin")).expect("the cache file");
    assert!(before == after, "the old cache file changed");
    assert_no_temporaries(&world);
}

#[test]
fn interrupted_run_keeps_the_file_of_f() {
    // The old file of `-f` is replaced only on success, and the temporary
    // `PATH.tmp-<pid>` is removed.
    let world = World::standard();
    let out = world.write("out.txt", "old\n");
    world.transport.get(RIS_V4, hanging_dump());
    interrupt(
        &world,
        &["-f", "out.txt", "--ipset", "as.asn: 64496"],
        Duration::from_millis(300),
    );
    assert_eq!(fs::read_to_string(&out).unwrap(), "old\n");
    assert_no_temporaries(&world);
    world.ok(&["-f", "out.txt", "--ipset", "as.asn: 64496"]);
    assert_eq!(fs::read_to_string(&out).unwrap(), "192.0.2.0/24\n");
}

#[test]
fn rows_from_the_cache_match_the_stream() {
    // The cache changes where the data come from, not the answer.
    let world = World::standard();
    for args in [
        &["-4", "-6", "as.asn: (64496 or 64500)"][..],
        &["route: * and not as.country: *"][..],
        &["ip: 192.0.2.0/25"][..],
    ] {
        let mut streamed = vec!["--no-cache"];
        streamed.extend_from_slice(args);
        let a = world.ok(&streamed);
        let b = world.ok(args);
        assert_eq!(a, b, "{args:?}");
        assert!(!table(&b.0).rows.is_empty(), "{args:?}");
    }
}
