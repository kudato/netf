//! Redirect failures through `netf::run` with a fake transport.

mod common;

use common::{CLOSED_BASE, RIS_V4, RIS_V4_FIXTURE, Scripted, World, fixture};

#[test]
fn dataset_https_to_http_redirect_stops_the_run() {
    let world = World::standard();
    let secure = "https://ris.ripe.test/dumps/riswhoisdump.IPv4.gz";
    let insecure = "http://downloads.test/riswhoisdump.IPv4.gz";
    world
        .transport
        .get(RIS_V4, Scripted::status(302).header("Location", secure))
        .get(secure, Scripted::status(307).header("Location", insecure))
        .get(insecure, Scripted::ok(fixture(RIS_V4_FIXTURE)));

    let (code, stderr) = world.fail(&["--ipset", "as.asn: 64496"]);
    assert_eq!(code, 1);
    assert_eq!(
        stderr,
        [format!(
            "netf: ris-v4: {RIS_V4}: redirect from HTTPS to HTTP is not allowed"
        )]
    );
    assert_eq!(world.transport.count(RIS_V4), 1);
    assert_eq!(world.transport.count(secure), 1);
    assert_eq!(world.transport.count(insecure), 0);
}

#[test]
fn rdap_https_to_http_redirect_stops_the_run() {
    let world = World::standard();
    let initial = format!("{CLOSED_BASE}/rdap.db.ripe.test/entity/ORG-EN1-RIPE");
    let secure = "https://rdap.db.ripe.test/entity/ORG-EN1-RIPE";
    let insecure = "http://rdap.db.ripe.test/entity/ORG-EN1-RIPE";
    world
        .transport
        .get(&initial, Scripted::status(302).header("Location", secure))
        .get(secure, Scripted::status(307).header("Location", insecure))
        .get(insecure, Scripted::status(404));

    let (code, stderr) = world.fail(&["--ipset", "net.org: ORG-EN1-RIPE"]);
    assert_eq!(code, 1);
    assert_eq!(
        stderr,
        ["netf: rdap: ripencc: redirect from HTTPS to HTTP is not allowed"]
    );
    assert_eq!(world.transport.count(&initial), 1);
    assert_eq!(world.transport.count(secure), 1);
    assert_eq!(world.transport.count(insecure), 0);
}
