//! The RIPE database REST API: inverse searches by maintainer and contact,
//! which RDAP does not offer.
//!
//! ```text
//! GET https://rest.db.ripe.net/search.json?query-string=<handle>
//!     &inverse-attribute=<attr>&type-filter=<class>&flags=r&flags=no-referenced
//! ```
//!
//! [`RipeRest::search`] answers a [`WhoisRequest`] as the APNIC and AFRINIC
//! dumps do (`dataset::whoisdb`), with the same steps. First it finds the
//! organizations of the contacts asked for. Then it finds the records by
//! every condition and by those organizations. Each handle is asked once
//! per attribute and class, and the requests of a step go out together.
//! The attributes are `mnt-by`, `org`, and the contact attributes: one of
//! `admin-c`, `tech-c`, or `abuse-c` for a contact of one role, or all
//! three. The classes are `inetnum`, `inet6num`, and `aut-num`. The first
//! step asks for the class `organisation` instead.
//!
//! - The objects of a response (`objects.object[].attributes.attribute[]`)
//!   become [`WhoisRecord`]s. Persons and roles are not asked for
//!   (`no-referenced`) and are dropped if sent. Of the other objects, netf
//!   reads only the attributes it keeps. The records are
//!   [`NetRecord`](crate::model::NetRecord)s and
//!   [`AsRecord`](crate::model::AsRecord)s of `ripencc` with origin
//!   [`RecordOrigin::RipeRest`]. Their contacts are handles and roles, with
//!   the e-mail hidden. `--ripe-emails` asks RDAP for the e-mail. The
//!   holder's name is known only for organizations found by the first step.
//! - A 404 means "no entries" and is not an error. RIPE explains the 404 in
//!   `errormessages`. Any other non-2xx status is `ripe: HTTP <n>:
//!   <message>`.
//! - A message in `errormessages` that says the response was cut is
//!   reported once per response per run, from the network or the cache. An
//!   example is `netf: ripencc: limited search results to 100 maximum`.
//! - Every URL is asked at most once per run, through an in-memory memo.
//!   A failed request is not remembered, so the next search asks again.
//!   The records of each response are kept in the response cache like RDAP
//!   responses, unless `--no-cache` is set. The transport handles 429 and
//!   5xx with a pause and retries.
//! - These requests do not spend the RIPE limit, because the responses hold
//!   no person objects. For the same reason, the requests are not pinned to
//!   an egress.

use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};

use futures_util::future::try_join_all;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tokio::sync::OnceCell;

use crate::{
    cache::responses::Responses,
    dataset::whoisdb::{
        Attr, Found, Lookup, ObjectClass, WhoisAnswer, WhoisRecord, WhoisRequest, assemble,
        org_lookup, record_lookup, record_of_pairs,
    },
    error::{Error, Result},
    fetch,
    model::{RecordOrigin, Rir},
    report::{Notice, Reporter},
    sources::rewrite,
    text::Pattern,
    transport::{Class, Method, Transport},
};

/// The response to one search, as kept in the response cache.
#[derive(Clone, Debug, Default, Deserialize, PartialEq, Serialize)]
struct RestSearch {
    /// The records found, in the order of the response.
    objects: Vec<WhoisRecord>,
    /// RIPE's message that it cut the response.
    truncated: Option<String>,
}

/// The client of the RIPE REST API for one run.
pub(crate) struct RipeRest {
    transport: Arc<dyn Transport>,
    responses: Option<Arc<Responses>>,
    /// The API root, `https://rest.db.ripe.net` by default.
    root: String,
    base: Option<String>,
    reporter: Arc<dyn Reporter>,
    memo: Mutex<HashMap<String, Arc<OnceCell<Arc<RestSearch>>>>>,
}

impl RipeRest {
    /// Creates the client that sends through `transport`.
    ///
    /// The client asks the API at `root` and keeps responses in `responses`,
    /// which is `None` with `--no-cache`. Its URLs are rewritten with `base`
    /// (`NETF_SOURCE_BASE`).
    pub(crate) fn new(
        transport: Arc<dyn Transport>,
        responses: Option<Arc<Responses>>,
        root: &str,
        base: Option<String>,
        reporter: Arc<dyn Reporter>,
    ) -> Self {
        Self {
            transport,
            responses,
            root: root.trim_end_matches('/').to_owned(),
            base,
            reporter,
            memo: Mutex::default(),
        }
    }

    /// Returns the networks and AS of RIPE by maintainer, contact, and
    /// holder.
    ///
    /// # Errors
    ///
    /// Returns an error if RIPE cannot be reached, responds with a status other
    /// than 2xx or 404, or sends a body that is not valid JSON. Also returns an
    /// error if the response cannot be written to the cache.
    pub(crate) async fn search(&self, request: &WhoisRequest) -> Result<WhoisAnswer> {
        if request.is_empty() {
            return Ok(WhoisAnswer::empty(request));
        }
        let step1 = self.lookup(&org_lookup(request, false)).await?;
        let plan = record_lookup(request, &step1.hits);
        let found = self.lookup(&plan.lookup).await?;
        let orgs: Vec<WhoisRecord> = step1.hits.into_iter().flatten().collect();
        Ok(assemble(
            request,
            &plan,
            &found,
            &orgs,
            Rir::Ripencc,
            RecordOrigin::RipeRest,
        ))
    }

    /// Returns the organizations of RIPE named like `pattern`, as
    /// `(handle, name)` in the order of the response.
    ///
    /// netf searches RIPE organizations by name here, not through RDAP.
    /// RIPE is asked by the words of the name, without the wildcards
    /// (`query-string=Example%20CDN&type-filter=organisation`). Its search
    /// by name matches whole words, not globs. Of the response, only the
    /// organizations whose name matches `pattern` are kept. A pattern
    /// without a word, such as `*`, asks nothing.
    ///
    /// # Errors
    ///
    /// Returns an error if RIPE cannot be reached, responds with a status other
    /// than 2xx or 404, or sends a body that is not valid JSON. Also returns an
    /// error if the response cannot be written to the cache.
    pub(crate) async fn organisations(&self, pattern: &Pattern) -> Result<Vec<(String, String)>> {
        let Some(words) = words(pattern) else {
            return Ok(Vec::new());
        };
        let url = format!(
            "{}/search.json?query-string={}\
             &type-filter=organisation&flags=r&flags=no-referenced",
            self.root,
            encode(&words)
        );
        let answer = self.query(&rewrite(self.base.as_deref(), &url)).await?;
        let mut out: Vec<(String, String)> = Vec::new();
        for record in &answer.objects {
            if record.class != ObjectClass::Organisation {
                continue;
            }
            let Some(name) = &record.name else {
                continue;
            };
            let known = out
                .iter()
                .any(|(handle, _)| handle.eq_ignore_ascii_case(&record.handle));
            if pattern.matches(name) && !known {
                out.push((record.handle.clone(), name.clone()));
            }
        }
        Ok(out)
    }

    /// Answers a lookup by asking every pair of attribute and class for
    /// each search, all at once.
    async fn lookup(&self, lookup: &Lookup) -> Result<Found> {
        let mut asks: Vec<(usize, String)> = Vec::new();
        for (q, query) in lookup.queries.iter().enumerate() {
            for attr in query.attrs.iter() {
                let Some(attribute) = inverse_attribute(attr) else {
                    continue;
                };
                for class in lookup.classes.iter() {
                    asks.push((q, self.url(&query.handle, attribute, class)));
                }
            }
        }
        let answers = try_join_all(asks.iter().map(|(_, url)| self.query(url))).await?;
        let mut found = Found::empty(lookup);
        for ((q, _), answer) in asks.iter().zip(answers) {
            let query = &lookup.queries[*q];
            let hits = &mut found.hits[*q];
            for record in &answer.objects {
                let wanted = lookup.classes.contains(record.class)
                    && record.has(query.attrs, &query.handle)
                    && !hits
                        .iter()
                        .any(|known| known.class == record.class && known.handle == record.handle);
                if wanted {
                    hits.push(record.clone());
                }
            }
        }
        Ok(found)
    }

    /// Returns the URL of one search, rewritten with `NETF_SOURCE_BASE`.
    fn url(&self, handle: &str, attribute: &str, class: ObjectClass) -> String {
        let url = format!(
            "{}/search.json?query-string={}&inverse-attribute={attribute}\
             &type-filter={}&flags=r&flags=no-referenced",
            self.root,
            encode(handle),
            class.name()
        );
        rewrite(self.base.as_deref(), &url)
    }

    /// Returns the response to `url`, asking for it at most once per run.
    /// An error is not remembered, so the next call asks again.
    async fn query(&self, url: &str) -> Result<Arc<RestSearch>> {
        let cell = {
            let mut memo = self.memo.lock().unwrap_or_else(|p| p.into_inner());
            Arc::clone(memo.entry(url.to_owned()).or_default())
        };
        cell.get_or_try_init(|| async {
            if let Some(search) = self.cached(url) {
                return Ok(Arc::new(search));
            }
            let (status, value) = fetch::json(&*self.transport, url, Class::RipeRest).await?;
            let search = answer(status, &value)?;
            if let Some(responses) = &self.responses {
                responses.put(Method::Get, url, &search)?;
            }
            self.report(&search);
            Ok(Arc::new(search))
        })
        .await
        .cloned()
    }

    /// Returns the cached response to `url`, if it is fresh.
    fn cached(&self, url: &str) -> Option<RestSearch> {
        let search: RestSearch = self.responses.as_ref()?.get(Method::Get, url)?;
        self.report(&search);
        Some(search)
    }

    fn report(&self, search: &RestSearch) {
        if let Some(message) = &search.truncated {
            self.reporter.notice(&Notice::Truncated {
                rir: Rir::Ripencc.to_string(),
                message: message.clone(),
            });
        }
    }
}

/// Returns the words of a name pattern, without wildcards and escapes,
/// joined by one space.
///
/// Returns `None` if there are no words.
fn words(pattern: &Pattern) -> Option<String> {
    let text = match pattern {
        Pattern::Exact(text) => text.as_str(),
        Pattern::Glob(glob) => glob.source(),
        Pattern::Any => return None,
    };
    let words: Vec<&str> = text
        .split(|c: char| c.is_whitespace() || matches!(c, '*' | '?' | '\\'))
        .filter(|word| !word.is_empty())
        .collect();
    (!words.is_empty()).then(|| words.join(" "))
}

/// Returns the inverse attribute that RIPE searches for `attr`, or `None`
/// for `Attr::Key`.
fn inverse_attribute(attr: Attr) -> Option<&'static str> {
    match attr {
        Attr::Key => None,
        Attr::Mnt => Some("mnt-by"),
        Attr::Admin => Some("admin-c"),
        Attr::Tech => Some("tech-c"),
        Attr::Abuse => Some("abuse-c"),
        Attr::Org => Some("org"),
    }
}

/// Turns an HTTP response into a search.
///
/// A 2xx response is read, and a 404 means "no entries". Any other status is
/// an error.
fn answer(status: u16, value: &Value) -> Result<RestSearch> {
    let messages = messages(value);
    if status == 404 {
        return Ok(RestSearch::default());
    }
    if !(200..300).contains(&status) {
        let cause = messages
            .iter()
            .flat_map(|m| m.lines())
            .map(str::trim)
            .find(|line| !line.is_empty());
        let message = match cause {
            Some(cause) => format!("HTTP {status}: {cause}"),
            None => format!("HTTP {status}"),
        };
        return Err(Error::runtime(message).with_prefix(Class::RipeRest));
    }
    let objects = value
        .pointer("/objects/object")
        .and_then(Value::as_array)
        .map(Vec::as_slice)
        .unwrap_or_default();
    let objects = objects.iter().filter_map(record).collect();
    let truncated = messages
        .iter()
        .flat_map(|m| m.lines())
        .map(|line| line.trim().trim_start_matches('%').trim())
        .find(|line| {
            let lower = line.to_ascii_lowercase();
            lower.contains("limited search results") || lower.contains("truncated")
        })
        .map(str::to_owned);
    Ok(RestSearch { objects, truncated })
}

/// Returns the record of one object of a response.
fn record(object: &Value) -> Option<WhoisRecord> {
    let attributes = object.pointer("/attributes/attribute")?.as_array()?;
    record_of_pairs(attributes.iter().filter_map(|attribute| {
        Some((
            attribute.get("name")?.as_str()?,
            attribute.get("value")?.as_str()?,
        ))
    }))
}

/// Returns the texts of `errormessages`, with their `%s` replaced by the
/// arguments.
fn messages(value: &Value) -> Vec<String> {
    let Some(list) = value
        .pointer("/errormessages/errormessage")
        .and_then(Value::as_array)
    else {
        return Vec::new();
    };
    list.iter()
        .filter_map(|message| {
            let text = message.get("text")?.as_str()?;
            let mut args = message
                .get("args")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
                .map(|arg| arg.get("value").and_then(Value::as_str).unwrap_or(""));
            let mut out = String::with_capacity(text.len());
            let mut parts = text.split("%s");
            out.push_str(parts.next().unwrap_or(""));
            for part in parts {
                out.push_str(args.next().unwrap_or("%s"));
                out.push_str(part);
            }
            Some(out)
        })
        .collect()
}

/// Percent-encodes every byte of a query value except the unreserved
/// characters.
fn encode(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || b"-._~".contains(&byte) {
            out.push(char::from(byte));
        } else {
            out.push_str(&format!("%{byte:02X}"));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;
    use crate::{
        addr::Families,
        dataset::Urls,
        fetch::testing::{Collect, FakeClock, Reply, Stub, TempDir},
        model::Role,
    };

    const BASE: &str = "http://127.0.0.1:9";

    fn url(handle: &str, attribute: &str, class: &str) -> String {
        format!(
            "{BASE}/rest.ripe.test/search.json?query-string={handle}\
             &inverse-attribute={attribute}&type-filter={class}&flags=r&flags=no-referenced"
        )
    }

    /// Builds a response with the objects given as `(name, value)` lists.
    fn objects(list: &[&[(&str, &str)]], messages: &[&str]) -> String {
        let objects: Vec<Value> = list
            .iter()
            .map(|attrs| {
                let attribute: Vec<Value> = attrs
                    .iter()
                    .map(|(name, value)| serde_json::json!({"name": name, "value": value}))
                    .collect();
                serde_json::json!({
                    "type": attrs[0].0,
                    "source": {"id": "ripe"},
                    "attributes": {"attribute": attribute},
                })
            })
            .collect();
        let errors: Vec<Value> = messages
            .iter()
            .map(|text| serde_json::json!({"severity": "Warning", "text": text}))
            .collect();
        serde_json::json!({
            "objects": {"object": objects},
            "errormessages": {"errormessage": errors},
        })
        .to_string()
    }

    fn no_entries() -> Reply {
        Reply::status(404).body(
            serde_json::json!({
                "errormessages": {"errormessage": [{
                    "severity": "Error",
                    "text": "ERROR:101: no entries found\n\nNo entries found in source %s.\n",
                    "args": [{"value": "RIPE"}],
                }]}
            })
            .to_string(),
        )
    }

    const NET: &[(&str, &str)] = &[
        ("inetnum", "192.0.2.0 - 192.0.2.255"),
        ("netname", "EXAMPLE-NET"),
        ("descr", "Example network, 1 Example Street"),
        ("country", "XD"),
        ("org", "ORG-EX1-RIPE"),
        ("admin-c", "EA1-RIPE"),
        ("tech-c", "EA1-RIPE"),
        ("mnt-by", "EXAMPLE-MNT"),
        ("mnt-lower", "EXAMPLE-LOWER-MNT"),
    ];

    const ORG: &[(&str, &str)] = &[
        ("organisation", "ORG-EX1-RIPE"),
        ("org-name", "Example B.V."),
        ("address", "1 Example Street"),
        ("e-mail", "noc@example.net"),
        ("abuse-c", "AB1-RIPE"),
        ("mnt-by", "EXAMPLE-MNT"),
    ];

    const AS: &[(&str, &str)] = &[
        ("aut-num", "AS64496"),
        ("as-name", "EXAMPLE-AS"),
        ("org", "ORG-EX1-RIPE"),
        ("mnt-by", "EXAMPLE-MNT"),
    ];

    const PERSON: &[(&str, &str)] = &[
        ("person", "John Doe"),
        ("nic-hdl", "EA1-RIPE"),
        ("mnt-by", "EXAMPLE-MNT"),
    ];

    fn client(stub: &Arc<Stub>, dir: Option<&TempDir>) -> (RipeRest, Arc<Collect>) {
        let reporter = Arc::new(Collect::default());
        let responses = dir.map(|dir| {
            Arc::new(Responses::new(
                dir.path().join("responses"),
                Duration::from_secs(86_400),
                Arc::new(FakeClock::new()),
                reporter.clone(),
            ))
        });
        let client = RipeRest::new(
            stub.clone(),
            responses,
            Urls::test().ripe_rest(),
            Some(BASE.into()),
            reporter.clone(),
        );
        (client, reporter)
    }

    fn by_mnt() -> WhoisRequest {
        WhoisRequest {
            mnt: vec!["EXAMPLE-MNT".into()],
            families: Families::V4,
            autnums: true,
            ..WhoisRequest::default()
        }
    }

    fn serve_mnt(stub: &Stub) {
        stub.on(
            &url("EXAMPLE-MNT", "mnt-by", "inetnum"),
            Reply::ok(objects(
                &[NET, PERSON],
                &["%  limited search results to 100 maximum"],
            )),
        );
        stub.on(
            &url("EXAMPLE-MNT", "mnt-by", "aut-num"),
            Reply::ok(objects(&[AS], &[])),
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn searches_by_maintainer() {
        let stub = Arc::new(Stub::new());
        serve_mnt(&stub);
        let (client, reporter) = client(&stub, None);
        let answer = client.search(&by_mnt()).await.unwrap();
        // Without contacts there is no step 1. Two requests go out: inetnum
        // and aut-num.
        assert_eq!(stub.count(), 2);
        assert_eq!(
            reporter.lines(),
            ["netf: ripencc: limited search results to 100 maximum"]
        );
        let net = &answer.mnt[0].networks[0];
        assert_eq!(answer.mnt[0].networks.len(), 1);
        assert_eq!(net.rir, Rir::Ripencc);
        assert_eq!(net.origin, RecordOrigin::RipeRest);
        assert_eq!(net.handle, "192.0.2.0 - 192.0.2.255");
        assert_eq!(net.name.as_deref(), Some("EXAMPLE-NET"));
        assert_eq!(net.mnt, ["EXAMPLE-MNT", "EXAMPLE-LOWER-MNT"]);
        let org = net.org.as_ref().unwrap();
        assert_eq!(
            (org.handle.as_str(), org.name.as_deref()),
            ("ORG-EX1-RIPE", None)
        );
        assert_eq!(net.contacts.len(), 1);
        assert!(net.contacts[0].emails_hidden);
        assert_eq!(
            net.contacts[0].roles,
            [Role::Administrative, Role::Technical]
        );
        assert_eq!(answer.mnt[0].autnums[0].asn, 64496);
        // The same search again in the run comes from the memo. The notice
        // is still reported once.
        client.search(&by_mnt()).await.unwrap();
        assert_eq!(stub.count(), 2);
        assert_eq!(reporter.lines().len(), 1);
        // A request with no class to look in asks nothing.
        let empty = WhoisRequest {
            mnt: vec!["X".into()],
            ..WhoisRequest::default()
        };
        assert_eq!(client.search(&empty).await.unwrap().mnt.len(), 1);
        assert_eq!(stub.count(), 2);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn organisations_by_name() {
        use crate::text::Glob;
        const OTHER: &[(&str, &str)] = &[
            ("organisation", "ORG-OE1-RIPE"),
            ("org-name", "Other Example Ltd"),
        ];
        let stub = Arc::new(Stub::new());
        stub.on(
            &format!(
                "{BASE}/rest.ripe.test/search.json?query-string=Example%20B.V.\
                 &type-filter=organisation&flags=r&flags=no-referenced"
            ),
            Reply::ok(objects(&[ORG, OTHER, NET, ORG], &[])),
        );
        let (client, _) = client(&stub, None);
        // RIPE is asked for the words without wildcards. The glob filters
        // the response locally.
        let found = client
            .organisations(&Pattern::Glob(Glob::new("Example* B.V.")))
            .await
            .unwrap();
        assert_eq!(
            found,
            [("ORG-EX1-RIPE".to_owned(), "Example B.V.".to_owned())]
        );
        let found = client
            .organisations(&Pattern::Exact("Example B.V.".into()))
            .await
            .unwrap();
        assert_eq!(found.len(), 1);
        assert_eq!(stub.count(), 1);
        // `*` alone has no word, so nothing is asked.
        assert!(
            client
                .organisations(&Pattern::Any)
                .await
                .unwrap()
                .is_empty()
        );
        assert!(
            client
                .organisations(&Pattern::Glob(Glob::new("**")))
                .await
                .unwrap()
                .is_empty()
        );
        assert_eq!(stub.count(), 1);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn contacts_through_the_holder() {
        let stub = Arc::new(Stub::new());
        // Step 1: organizations with the abuse contact.
        stub.on(
            &url("AB1-RIPE", "abuse-c", "organisation"),
            Reply::ok(objects(&[ORG], &[])),
        );
        // Step 2: records with the contact itself, then by the holder.
        stub.on(&url("AB1-RIPE", "abuse-c", "inet6num"), no_entries());
        stub.on(
            &url("ORG-EX1-RIPE", "org", "inet6num"),
            Reply::ok(objects(
                &[&[
                    ("inet6num", "2001:db8::/32"),
                    ("netname", "EXAMPLE-V6"),
                    ("org", "ORG-EX1-RIPE"),
                    ("mnt-by", "EXAMPLE-MNT"),
                ]],
                &[],
            )),
        );
        let (client, reporter) = client(&stub, None);
        let request = WhoisRequest {
            contact: vec![(Some(Role::Abuse), "AB1-RIPE".into())],
            families: Families::V6,
            ..WhoisRequest::default()
        };
        let answer = client.search(&request).await.unwrap();
        assert_eq!(stub.count(), 3);
        assert!(reporter.lines().is_empty());
        let net = &answer.contact[0].networks[0];
        assert_eq!(net.handle, "2001:db8::/32");
        assert_eq!(
            net.org.as_ref().unwrap().name.as_deref(),
            Some("Example B.V.")
        );
        assert_eq!(net.contacts[0].handle, "AB1-RIPE");
        assert_eq!(net.contacts[0].roles, [Role::Abuse]);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn answers_are_cached_with_their_notice() {
        let dir = TempDir::new("ripe-rest-cache");
        let stub = Arc::new(Stub::new());
        serve_mnt(&stub);
        let (first, _) = client(&stub, Some(&dir));
        let answer = first.search(&by_mnt()).await.unwrap();
        assert_eq!(stub.count(), 2);
        // Nothing personal reaches the cache.
        for entry in std::fs::read_dir(dir.path().join("responses")).unwrap() {
            let bytes = std::fs::read(entry.unwrap().path()).unwrap();
            let text = String::from_utf8_lossy(&bytes);
            for secret in ["John", "Street", "example.net"] {
                assert!(!text.contains(secret), "{secret} cached");
            }
        }
        // A new run reads the cache and reports the notice again.
        let (second, reporter) = client(&stub, Some(&dir));
        assert_eq!(second.search(&by_mnt()).await.unwrap(), answer);
        assert_eq!(stub.count(), 2);
        assert_eq!(
            reporter.lines(),
            ["netf: ripencc: limited search results to 100 maximum"]
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn errors_and_empty_answers() {
        let stub = Arc::new(Stub::new());
        stub.on(&url("NOBODY", "mnt-by", "inetnum"), no_entries());
        stub.on(&url("A%20B%2FC", "mnt-by", "inetnum"), no_entries());
        let (client, _) = client(&stub, None);
        let request = WhoisRequest {
            mnt: vec!["NOBODY".into(), "A B/C".into()],
            families: Families::V4,
            ..WhoisRequest::default()
        };
        let answer = client.search(&request).await.unwrap();
        assert!(answer.mnt.iter().all(|found| found.is_empty()));
        assert_eq!(stub.count(), 2);

        stub.on(
            &url("BAD", "mnt-by", "inetnum"),
            Reply::status(400).body(
                serde_json::json!({"errormessages": {"errormessage": [{
                    "severity": "Error",
                    "text": "ERROR:111: invalid option supplied\n\n%s is not valid\n",
                    "args": [{"value": "BAD"}],
                }]}})
                .to_string(),
            ),
        );
        let bad = WhoisRequest {
            mnt: vec!["BAD".into()],
            families: Families::V4,
            ..WhoisRequest::default()
        };
        let error = client.search(&bad).await.unwrap_err().to_string();
        assert_eq!(
            error,
            "netf: ripe: HTTP 400: ERROR:111: invalid option supplied"
        );
        // Errors are not remembered. The next search goes out again.
        stub.on(&url("BAD", "mnt-by", "inetnum"), Reply::status(403));
        let error = client.search(&bad).await.unwrap_err().to_string();
        assert_eq!(error, "netf: ripe: HTTP 403");
        stub.on(&url("BAD", "mnt-by", "inetnum"), Reply::ok("<html>"));
        let error = client.search(&bad).await.unwrap_err().to_string();
        assert!(error.starts_with("netf: ripe: invalid JSON"), "{error}");
    }

    #[test]
    fn messages_and_truncation() {
        let value = serde_json::json!({"errormessages": {"errormessage": [
            {"text": "%s and %s", "args": [{"value": "one"}]},
            {"text": "plain"},
        ]}});
        assert_eq!(messages(&value), ["one and %s", "plain"]);
        let search = answer(200, &serde_json::json!({})).unwrap();
        assert_eq!(search, RestSearch::default());
        let value: Value =
            serde_json::from_str(&objects(&[NET], &["Result set truncated by the server"]))
                .unwrap();
        let search = answer(200, &value).unwrap();
        assert_eq!(search.objects.len(), 1);
        assert_eq!(
            search.truncated.as_deref(),
            Some("Result set truncated by the server")
        );
        assert_eq!(encode("ORG-EX1-RIPE"), "ORG-EX1-RIPE");
        assert_eq!(encode("é"), "%C3%A9");
    }
}
