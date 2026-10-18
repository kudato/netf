//! Tests of `--ripe-emails` and the RIPE limit, end to end in process.
//!
//! RIPE hides the e-mail of persons in the answer about a network. Without
//! `--ripe-emails`, netf does not ask for person records, so the RIPE limit
//! of 1000 queries per egress and UTC day is not spent. With the flag, netf
//! makes one request per person. It counts the queries per egress and keeps
//! the counter in the cache, also with `--no-cache`.
//!
//! The tests raise the counter through runs of netf. They do not write its
//! file, because its layout is internal.

mod common;

use std::time::Duration;

use common::{FullRow, World, full_table};
use serde_json::{Value, json};

/// The number of persons of the crowded network, two more than the limit.
const PERSONS: usize = 1002;

/// The RIPE limit, in queries per egress and UTC day.
const DAILY: usize = 1000;

/// Returns the handle of person `i` of the crowded network.
fn person(i: usize) -> String {
    format!("P{i:04}-RIPE")
}

/// Returns a vCard in the form of RFC 9083.
fn vcard(name: &str, kind: &str, email: Option<&str>) -> Value {
    let mut card = vec![
        json!(["version", {}, "text", "4.0"]),
        json!(["fn", {}, "text", name]),
        json!(["kind", {}, "text", kind]),
        json!(["tel", {"type": "voice"}, "text", "+1 555 0199"]),
    ];
    if let Some(email) = email {
        card.push(json!(["email", {}, "text", email]));
    }
    json!(["vcard", card])
}

/// Returns the standard world with a crowded RIPE network.
///
/// The RIPE record of 192.0.2.0/24 has [`PERSONS`] administrative persons
/// without e-mail. The world serves the records of the persons with
/// e-mail.
fn crowded_world() -> World {
    let world = World::standard();
    let rdap = world.serve_registries();
    let mut entities = vec![
        json!({
            "objectClassName": "entity",
            "handle": "ORG-EN1-RIPE",
            "roles": ["registrant"],
            "vcardArray": vcard("Example Networks LLC", "org", None),
        }),
        json!({
            "objectClassName": "entity",
            "handle": "AR-EN1-RIPE",
            "roles": ["abuse"],
            "vcardArray": vcard("Example Networks Abuse", "group", Some("abuse@example.net")),
        }),
    ];
    for i in 1..=PERSONS {
        let handle = person(i);
        entities.push(json!({
            "objectClassName": "entity",
            "handle": handle,
            "roles": ["administrative"],
            "vcardArray": vcard(&format!("Person {i}"), "individual", None),
        }));
        rdap.insert(
            "rdap.db.ripe.test",
            &json!({
                "rdapConformance": ["rdap_level_0"],
                "objectClassName": "entity",
                "handle": handle,
                "vcardArray": vcard(
                    &format!("Person {i}"),
                    "individual",
                    Some(&format!("p{i:04}@example.net")),
                ),
            }),
        );
    }
    rdap.insert(
        "rdap.db.ripe.test",
        &json!({
            "rdapConformance": ["rdap_level_0", "cidr0"],
            "objectClassName": "ip network",
            "handle": "192.0.2.0 - 192.0.2.255",
            "startAddress": "192.0.2.0",
            "endAddress": "192.0.2.255",
            "ipVersion": "v4",
            "name": "EXNET-XA",
            "type": "ALLOCATED PA",
            "country": "XA",
            "cidr0_cidrs": [{"v4prefix": "192.0.2.0", "length": 24}],
            "status": ["active"],
            "entities": entities,
        }),
    );
    world
}

/// The arguments of a run that wants the e-mail of every person.
const CROWDED: [&str; 5] = [
    "--no-cache",
    "--ripe-emails",
    "--fields",
    "net.contact.administrative",
    "ip: 192.0.2.70",
];

/// Returns how many person records were asked of RIPE so far.
fn person_requests(world: &World) -> usize {
    world
        .rdap_values("rdap.db.ripe.test", "entity")
        .iter()
        .filter(|h| h.starts_with('P') && h.ends_with("-RIPE"))
        .count()
}

/// Returns the only row of a run and the number of e-mails of persons in it.
///
/// # Panics
///
/// Panics if the run does not have exactly one row or the row does not show
/// every person.
fn crowded_row(stdout: &str) -> (FullRow, usize) {
    let rows = full_table(stdout);
    assert_eq!(rows.len(), 1, "{rows:#?}");
    let row = rows.into_iter().next().expect("a row");
    let contacts = row.extra[0].split("; ").count();
    assert_eq!(contacts, PERSONS, "every contact is shown");
    let emails = row.extra[0].matches("@example.net").count();
    (row, emails)
}

/// Returns the notice of a spent RIPE limit on one egress, with `missing`
/// e-mails not fetched.
fn limit_notice(missing: usize) -> String {
    format!("netf: ripe: daily limit reached on 1 of 1 IPs; {missing} e-mails not fetched")
}

#[test]
fn without_the_flag_no_person_is_asked() {
    // Without `--ripe-emails`, contact records are not asked for. The
    // address lies in the /26 of the client inside the /24, so `net.*`
    // shows both records.
    let world = World::owners();
    let (stdout, stderr) = world.ok(&["--fields", "net.contact.administrative", "ip: 192.0.2.10"]);
    assert!(stderr.is_empty(), "{stderr:?}");
    assert_eq!(
        full_table(&stdout)[0].extra,
        ["JD1-RIPE John Doe +1 555 0100 > MR1-RIPE Mary Roe +1 555 0110"]
    );
    assert_eq!(
        world.rdap_values("rdap.db.ripe.test", "entity"),
        Vec::<String>::new()
    );
}

#[test]
fn with_the_flag_the_email_is_fetched_once() {
    // netf makes one request per person. Responses are cached, so a second
    // run within the TTL asks nothing.
    let world = World::owners();
    let args = [
        "--ripe-emails",
        "--fields",
        "net.contact.administrative",
        "ip: 192.0.2.10",
    ];
    let (stdout, stderr) = world.ok(&args);
    assert!(stderr.is_empty(), "{stderr:?}");
    assert_eq!(
        full_table(&stdout)[0].extra,
        ["JD1-RIPE John Doe jdoe@example.net +1 555 0100 \
          > MR1-RIPE Mary Roe mroe@example.net +1 555 0110"]
    );
    let persons = || {
        let mut asked = world.rdap_values("rdap.db.ripe.test", "entity");
        asked.sort_unstable();
        asked
    };
    assert_eq!(persons(), ["JD1-RIPE", "MR1-RIPE"]);
    let (again, _) = world.ok(&args);
    assert_eq!(again, stdout);
    assert_eq!(persons(), ["JD1-RIPE", "MR1-RIPE"]);
}

#[test]
fn daily_limit_per_ip() {
    // netf sends at most 1000 queries per egress and UTC day. The other
    // persons show without e-mail, the code is 0, and stderr says how many
    // e-mails are missing.
    // The counter is kept in the cache, also with `--no-cache`.
    let world = crowded_world();
    let (stdout, stderr) = world.ok(&CROWDED);
    let asked = person_requests(&world);
    assert_eq!(
        asked, DAILY,
        "at most 1000 person requests a day per egress"
    );
    let (_, emails) = crowded_row(&stdout);
    assert_eq!(emails, asked);
    assert!(
        stderr.contains(&limit_notice(PERSONS - asked)),
        "{stderr:?}"
    );

    // On the same UTC day, nothing more is asked of RIPE.
    world.clock.advance(Duration::from_secs(3600));
    let (stdout, stderr) = world.ok(&CROWDED);
    assert_eq!(person_requests(&world), asked, "the limit is spent");
    let (_, emails) = crowded_row(&stdout);
    assert_eq!(emails, 0);
    assert!(stderr.contains(&limit_notice(PERSONS)), "{stderr:?}");

    // On the next UTC day, the limit is back.
    world.clock.advance(Duration::from_secs(23 * 3600));
    let (stdout, stderr) = world.ok(&CROWDED);
    assert_eq!(person_requests(&world), 2 * DAILY);
    let (_, emails) = crowded_row(&stdout);
    assert_eq!(emails, DAILY);
    assert!(
        stderr.contains(&limit_notice(PERSONS - DAILY)),
        "{stderr:?}"
    );
}
