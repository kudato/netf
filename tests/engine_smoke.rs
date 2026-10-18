//! Smoke tests of the engine and the output, run in process over the
//! fixtures of [`World::standard`]. They check the exact text of the table
//! and of `--ipset`, the error of `-i`, the downloads of `--no-cache`, and the
//! file of `-f`.

mod common;

use std::fs;

use common::{ASN_TXT, RIS_V4, RIS_V6, World};

/// Runs `args` and returns stdout.
///
/// # Panics
///
/// Panics if the exit code is not 0 or stderr is not empty.
fn quiet(world: &World, args: &[&str]) -> String {
    let (stdout, stderr) = world.ok(args);
    assert!(stderr.is_empty(), "netf {args:?}: stderr {stderr:?}");
    stdout
}

#[test]
fn table_text_is_aligned() {
    let world = World::standard();
    // Two spaces separate the columns, and the widest cell sets the width
    // of its column. The last column has no padding. The network, holder,
    // and abuse columns come from the registry.
    assert_eq!(
        quiet(
            &world,
            &["route:", "192.0.2.0/24", "or", "as.asn:", "64498"]
        ),
        "192.0.2.0/24   AS64496 EXAMPLE-NET, AS64497 TELE-EDGE  192.0.2.0/24  \
         Example Networks LLC, XA  abuse@example.net / as-abuse@example.net, abuse@tele-edge.example\n\
         192.0.2.64/27  AS64498 DOCNET                          192.0.2.0/24  \
         Example Networks LLC, XA  abuse@example.net / abuse@docnet.example\n"
    );
    // The part column shows `-` for a row that takes the whole route.
    assert_eq!(
        quiet(&world, &["ip: 192.0.2.10 or route: 198.51.100.0/24"]),
        "192.0.2.10  192.0.2.0/26     AS64496 EXAMPLE-NET  192.0.2.0/26     \
         Client Hosting Ltd, XB     abuse@client-hosting.example / as-abuse@example.net\n\
         -           198.51.100.0/24  AS64501 HOMENET      198.51.100.0/24  \
         Documentation Net Inc, XE  abuse@docnet.example / abuse@homenet.example\n"
    );
    // An address that no route covers gives a `no route` row.
    assert_eq!(
        quiet(&world, &["ip: 203.0.113.200"]),
        "203.0.113.200  no route  -  203.0.113.192/27  Ilha Exemplo Ltda, XH  abuse@ilha.example\n"
    );
}

#[test]
fn ipset_text() {
    let world = World::standard();
    assert_eq!(
        quiet(
            &world,
            &["--ipset", "as.asn: 64496 and not ip: 192.0.2.0/25"]
        ),
        "192.0.2.128/25\n"
    );
    // A query made only of `ip:` selectors makes no requests.
    let world = World::standard();
    assert_eq!(
        quiet(
            &world,
            &[
                "--ipset",
                "ip: 10.0.0.0/8 and not ip: 10.0.0.0/9 or ip: 10.0.0.1"
            ]
        ),
        "10.0.0.1/32\n10.128.0.0/9\n"
    );
    assert!(world.transport.requests().is_empty());
}

#[test]
fn interactive_tree_needs_a_terminal() {
    // The tree needs a terminal. `tests/tree.rs` drives it on a fake
    // terminal.
    let world = World::standard();
    let (code, stderr) = world.fail(&["-i", "ip: 192.0.2.1"]);
    assert_eq!(code, 2, "{stderr:?}");
    assert_eq!(
        stderr,
        ["netf: -i: the interactive tree needs a terminal on stdin and stdout"],
        "{stderr:?}"
    );
    assert!(world.transport.requests().is_empty());
}

#[test]
fn no_cache_downloads_each_dataset_once() {
    let world = World::standard();
    // A name search streams `asn.txt` once and keeps every line for the AS
    // column. The run reads each RIS dump once.
    let stdout = quiet(
        &world,
        &[
            "--no-cache",
            "-4",
            "-6",
            "as.name: example-net or as.asn: 64506",
        ],
    );
    assert!(stdout.starts_with("192.0.2.0/24"), "{stdout}");
    assert_eq!(world.transport.count(ASN_TXT), 1);
    assert_eq!(world.transport.count(RIS_V4), 1);
    assert_eq!(world.transport.count(RIS_V6), 1);
    assert!(fs::read_dir(world.cache_dir()).map_or(true, |mut dir| dir.next().is_none()));
}

#[test]
fn cached_and_streaming_answers_agree() {
    let queries: [&[&str]; 5] = [
        &["as.name: example*"],
        &["-4", "-6", "as.country: XB"],
        &["ip: 192.0.2.0/24 and not ip: 192.0.2.64/27"],
        &["route: {domain: www.example.test}"],
        &["--ipset", "as.asn: {ip: 192.0.2.200}"],
    ];
    for query in queries {
        let cached = quiet(&World::standard(), query);
        let mut streamed = vec!["--no-cache"];
        streamed.extend_from_slice(query);
        assert_eq!(quiet(&World::standard(), &streamed), cached, "{query:?}");
    }
}

#[test]
fn file_is_written_whole() {
    let world = World::standard();
    let path = world.write("out.txt", "old\n");
    let file = path.to_str().unwrap();
    assert_eq!(quiet(&world, &["--ipset", "-f", file, "ip: 192.0.2.1"]), "");
    assert_eq!(fs::read_to_string(&path).unwrap(), "192.0.2.1/32\n");
    // A failed run leaves the old file and no temporary file.
    let (code, _) = world.fail(&["--ipset", "-f", file, "domain: nx.example.test"]);
    assert_eq!(code, 1);
    assert_eq!(fs::read_to_string(&path).unwrap(), "192.0.2.1/32\n");
    let names: Vec<String> = fs::read_dir(path.parent().unwrap())
        .unwrap()
        .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
        .filter(|name| name.starts_with("out.txt"))
        .collect();
    assert_eq!(names, ["out.txt"]);
}

#[test]
fn stats_conditions_ask_no_registry() {
    // `net.country`, `net.rir`, and `as.rir` come from the delegated stats,
    // so they need no RDAP.
    let world = World::standard();
    assert_eq!(
        quiet(&world, &["--ipset", "net.country: XA"]),
        "192.0.2.0/24\n"
    );
    assert_eq!(
        quiet(&world, &["--ipset", "net.rir: arin and route: *"]),
        "198.51.100.0/24\n"
    );
    assert_eq!(
        quiet(&world, &["--ipset", "as.rir: arin and as.asn: 64498"]),
        "192.0.2.64/27\n"
    );
    assert!(world.rdap_calls().is_empty(), "{:?}", world.rdap_calls());
}

#[test]
fn no_cache_reads_each_stats_file_once() {
    // Without the cache, a run downloads every stats file once, however
    // often the engine reads the stats.
    let world = World::standard();
    let stdout = quiet(
        &world,
        &[
            "--no-cache",
            "--fields",
            "net.country,as.rir",
            "net.country: XA or net.rir: arin",
        ],
    );
    assert!(stdout.starts_with("192.0.2.0/24"), "{stdout}");
    for (_, url, _) in common::STATS {
        assert_eq!(world.transport.count(url), 1, "{url}");
    }
}

#[test]
fn fields_add_columns() {
    // The added columns come after the usual ones. An `as.*` column joins
    // the values of every AS with commas. A missing value is `-`.
    let world = World::standard();
    let stdout = quiet(
        &world,
        &["--fields", "as.name,net.rir", "route: 192.0.2.0/24"],
    );
    assert!(
        stdout.ends_with("  EXAMPLE-NET, TELE-EDGE  ripencc\n"),
        "{stdout}"
    );
    let stdout = quiet(&world, &["--fields", "as.name", "ip: 203.0.113.200"]);
    assert!(stdout.ends_with("abuse@ilha.example  -\n"), "{stdout}");
}
