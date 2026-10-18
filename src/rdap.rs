//! RDAP of the five registries: networks by address, AS by number,
//! entities by handle, and organizations by name. The IANA bootstrap picks
//! the registry for each request.
//!
//! [`RdapClient`] is the only way the engine reaches RDAP. The client
//! follows these rules:
//!
//! - The server comes from the [`bootstrap`]. An address or a number that
//!   no registry serves gives `Ok(None)`, the same as a 404.
//! - The client fetches each URL at most once per run, however many rows
//!   ask for it at the same time. A failed request is not remembered, so
//!   the next row asks again. The parsed response goes to the response
//!   cache ([`Responses`]) unless `--no-cache` is set. A 404 is cached too,
//!   as "no record".
//! - The client follows redirects: LACNIC sends Brazil to registro.br. A
//!   record belongs to the registry of the server asked, not of the host
//!   that responded. Redirects from HTTPS to HTTP fail before the next
//!   request.
//! - All URLs go through `NETF_SOURCE_BASE`, both those of the bootstrap
//!   and the `up` links.
//! - Errors read `rdap: <registry>: <cause>`. A 404 is not an error.
//! - When a registry says that it truncated the lists of an entity or a
//!   search, the client reports the message once per response:
//!   `netf: ripencc: Limited search results to 100 maximum`.
//!
//! [`RdapClient::org_by_name_in`] searches registries for organizations by
//! name ([`search`]). [`RdapClient::org_by_handle`] finds them by handle.
//! Both return each organization with the networks and AS that the
//! registry lists as its own.
//!
//! With `--ripe-emails`, [`RdapClient::ripe_emails`] asks RIPE for the
//! persons whose e-mail the network response hid. Each request spends the
//! RIPE limit of the egress it goes through ([`RipeLimit`]). The limit
//! counter works even with `--no-cache`, because it protects the egress and
//! is not a cache. Each request is pinned to one egress
//! ([`Transport::send_via`]). A 429 spends that egress until the end of the
//! UTC day. When every egress is spent, the client skips the remaining
//! persons and reports `netf: ripe: daily limit reached on …`. Responses
//! from the cache spend nothing.

pub(crate) mod bootstrap;
pub(crate) mod parse;
pub(crate) mod search;

use std::{
    collections::{HashMap, HashSet},
    path::PathBuf,
    sync::{Arc, Mutex},
    time::Duration,
};

use futures_util::future::try_join_all;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tokio::sync::OnceCell;

use self::{
    bootstrap::{Bootstrap, Server, rir_of_host, route},
    parse::Entity,
    search::Search,
};
use crate::{
    Clock,
    addr::{Addr, Prefix, Range},
    cache::{Cache, responses::Responses, ripe_limit::RipeLimit},
    dataset::Urls,
    error::{Error, Result},
    fetch::{self, JSON_LIMIT, MAX_REDIRECTS},
    model::{AsRecord, Asn, Contact, EntityKind, NetRecord, Org, Rir},
    report::{Notice, Reporter},
    text::Pattern,
    transport::{Class, EgressId, Method, Request, Transport, TransportError},
};

/// The most `up` links that [`RdapClient::up_chain`] follows.
const MAX_CHAIN: usize = 16;

/// The settings of the run that the client uses.
#[derive(Clone, Debug)]
pub(crate) struct RdapSettings {
    /// The cache directory: bootstrap files, `responses/`, the RIPE limit.
    pub(crate) cache_dir: PathBuf,
    /// `false` with `--no-cache`. The client then neither reads nor writes
    /// the cache, except the RIPE limit counter.
    pub(crate) cache: bool,
    /// How long cached files and responses are fresh.
    pub(crate) ttl: Duration,
    /// `--ripe-emails`.
    pub(crate) ripe_emails: bool,
    /// `NETF_SOURCE_BASE`.
    pub(crate) base: Option<String>,
    /// The source URLs, with the bootstrap files among them.
    pub(crate) sources: Urls,
}

/// A response as stored in the response cache.
///
/// A record is `None` after a 404. A search after a 404 finds nothing.
#[derive(Debug, Deserialize, Serialize)]
enum Stored {
    Net(Option<NetRecord>),
    As(Option<AsRecord>),
    Entity(Option<Entity>),
    Search(Search),
}

/// A response that all callers share within the run.
#[derive(Clone, Debug)]
enum Memo {
    Net(Option<Arc<NetRecord>>),
    As(Option<Arc<AsRecord>>),
    Entity(Option<Arc<Entity>>),
    Search(Arc<Search>),
}

impl From<Stored> for Memo {
    fn from(stored: Stored) -> Self {
        match stored {
            Stored::Net(record) => Self::Net(record.map(Arc::new)),
            Stored::As(record) => Self::As(record.map(Arc::new)),
            Stored::Entity(entity) => Self::Entity(entity.map(Arc::new)),
            Stored::Search(search) => Self::Search(Arc::new(search)),
        }
    }
}

/// The kind of response that a request expects.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum What {
    Net,
    As(Asn),
    Entity,
    Search,
}

impl What {
    fn matches(self, stored: &Stored) -> bool {
        matches!(
            (self, stored),
            (Self::Net, Stored::Net(_))
                | (Self::As(_), Stored::As(_))
                | (Self::Entity, Stored::Entity(_))
                | (Self::Search, Stored::Search(_))
        )
    }
}

/// Where a request goes: the URL after `NETF_SOURCE_BASE`, the registry name
/// for messages, and the registry of the records.
#[derive(Clone, Debug)]
struct Target {
    url: String,
    name: Arc<str>,
    rir: Option<Rir>,
}

impl Target {
    fn at(server: &Server, path: &str) -> Self {
        Self {
            url: format!("{}{path}", server.base),
            name: Arc::clone(&server.name),
            rir: server.rir,
        }
    }

    fn class(&self) -> Class {
        Class::Rdap(Arc::clone(&self.name))
    }

    /// An error about this request: `rdap: arin: <cause>`.
    fn error(&self, cause: impl Into<String>) -> Error {
        Error::runtime(cause).with_prefix(self.class())
    }
}

/// Why a request pinned to an egress gave no response.
enum Pinned {
    /// Every egress is spent for today.
    Spent,
    Failed(Error),
}

impl From<Error> for Pinned {
    fn from(error: Error) -> Self {
        Self::Failed(error)
    }
}

/// The RDAP client of one run.
pub(crate) struct RdapClient {
    transport: Arc<dyn Transport>,
    bootstrap: Bootstrap,
    responses: Option<Arc<Responses>>,
    limit: Option<RipeLimit>,
    base: Option<String>,
    reporter: Arc<dyn Reporter>,
    memo: Mutex<HashMap<String, Arc<OnceCell<Memo>>>>,
    /// The registries already reported as not supporting search. The
    /// client reports each one once per run.
    unsupported: Mutex<HashSet<Arc<str>>>,
}

impl RdapClient {
    /// Creates the client for a run with `settings` that sends through
    /// `transport`.
    pub(crate) fn new(
        settings: RdapSettings,
        transport: Arc<dyn Transport>,
        clock: Arc<dyn Clock>,
        reporter: Arc<dyn Reporter>,
    ) -> Self {
        let cache = settings.cache.then(|| {
            Cache::new(
                settings.cache_dir.clone(),
                settings.ttl,
                Arc::clone(&clock),
                Arc::clone(&reporter),
            )
        });
        let responses = settings.cache.then(|| {
            Arc::new(Responses::new(
                settings.cache_dir.join("responses"),
                settings.ttl,
                Arc::clone(&clock),
                Arc::clone(&reporter),
            ))
        });
        let limit = settings
            .ripe_emails
            .then(|| RipeLimit::open(settings.cache_dir.clone(), Arc::clone(&clock)));
        Self {
            bootstrap: Bootstrap::new(
                Arc::clone(&transport),
                cache,
                settings.base.clone(),
                settings.sources.clone(),
            ),
            transport,
            responses,
            limit,
            base: settings.base,
            reporter,
            memo: Mutex::new(HashMap::new()),
            unsupported: Mutex::new(HashSet::new()),
        }
    }

    /// Returns the cached responses of the client, `None` with `--no-cache`.
    ///
    /// Other clients of the run store their responses here too, so the
    /// directory is swept once per run.
    pub(crate) fn responses(&self) -> Option<Arc<Responses>> {
        self.responses.clone()
    }

    /// Returns the most specific registry network that holds all of
    /// `range`.
    ///
    /// The request is `ip/<cidr>`. A range that is not a CIDR is asked by the
    /// smallest CIDR that covers it. Returns `None` if no registry has such
    /// a network.
    ///
    /// # Errors
    ///
    /// Returns an error if the bootstrap file cannot be loaded or the registry
    /// cannot be reached. Also returns an error if the registry responds with a
    /// status other than 2xx or 404, sends a body that does not parse, or the
    /// response cannot be written to the cache.
    pub(crate) async fn ip(&self, range: Range) -> Result<Option<Arc<NetRecord>>> {
        let Some(server) = self.bootstrap.for_range(&range).await? else {
            return Ok(None);
        };
        let target = Target::at(&server, &format!("ip/{}", ip_path(&range)));
        match self.query(target, What::Net).await? {
            Memo::Net(record) => Ok(record),
            _ => unreachable!("a network query gives a network"),
        }
    }

    /// Returns the registry record of AS `asn`, or `None` if there is none.
    ///
    /// # Errors
    ///
    /// Returns an error if the bootstrap file cannot be loaded or the registry
    /// cannot be reached. Also returns an error if the registry responds with a
    /// status other than 2xx or 404, sends a body that does not parse, or the
    /// response cannot be written to the cache.
    pub(crate) async fn autnum(&self, asn: Asn) -> Result<Option<Arc<AsRecord>>> {
        let Some(server) = self.bootstrap.for_asn(asn).await? else {
            return Ok(None);
        };
        let target = Target::at(&server, &format!("autnum/{asn}"));
        match self.query(target, What::As(asn)).await? {
            Memo::As(record) => Ok(record),
            _ => unreachable!("an AS query gives an AS"),
        }
    }

    /// Returns the entity `handle` of `rir`, or `None` if there is none.
    ///
    /// The request does not spend the RIPE limit. For RIPE persons, use
    /// [`ripe_emails`](Self::ripe_emails).
    ///
    /// # Errors
    ///
    /// Returns an error if the bootstrap file cannot be loaded or the registry
    /// cannot be reached. Also returns an error if the registry responds with a
    /// status other than 2xx or 404, sends a body that does not parse, or the
    /// response cannot be written to the cache.
    pub(crate) async fn entity(&self, rir: Rir, handle: &str) -> Result<Option<Arc<Entity>>> {
        let Some(target) = self.entity_target(rir, handle).await? else {
            return Ok(None);
        };
        match self.query(target, What::Entity).await? {
            Memo::Entity(entity) => Ok(entity),
            _ => unreachable!("an entity query gives an entity"),
        }
    }

    /// Returns the records above `record` by their `up` links, widest
    /// first.
    ///
    /// The chain goes up to and including the first record that holds all
    /// of `block`, the block from the stats. If no record holds `block`, or
    /// `block` is `None`, the chain goes to the top. The chain is empty if
    /// `record` already holds `block` or has no `up` link.
    ///
    /// The chain stops early, without an error, at a link that responds
    /// with 404, at a link seen before, or at a record that does not hold
    /// the one below or has the same range. The chain also stops after
    /// [`MAX_CHAIN`] links.
    ///
    /// # Errors
    ///
    /// Returns an error if a link cannot be reached, responds with a status
    /// other than 2xx or 404, or sends a body that does not parse. Also returns
    /// an error if the response cannot be written to the cache.
    pub(crate) async fn up_chain(
        &self,
        record: &NetRecord,
        block: Option<&Range>,
    ) -> Result<Vec<Arc<NetRecord>>> {
        let mut chain: Vec<Arc<NetRecord>> = Vec::new();
        let mut seen = HashSet::new();
        let mut current_range = record.range;
        let mut link = record.parent_link.clone();
        let name: Arc<str> = Arc::from(record.rir.name());
        while let Some(href) = link.take() {
            if chain.len() >= MAX_CHAIN || block.is_some_and(|block| current_range.contains(block))
            {
                break;
            }
            let (url, _) = route(self.base.as_deref(), &href);
            if !seen.insert(url.clone()) {
                break;
            }
            let target = Target {
                url,
                name: Arc::clone(&name),
                rir: Some(record.rir),
            };
            let Memo::Net(Some(parent)) = self.query(target, What::Net).await? else {
                break;
            };
            if !parent.range.contains(&current_range) || parent.range == current_range {
                break;
            }
            current_range = parent.range;
            link.clone_from(&parent.parent_link);
            chain.push(parent);
        }
        chain.reverse();
        Ok(chain)
    }

    /// Fetches the e-mail of the RIPE persons `handles` for `--ripe-emails`.
    ///
    /// Returns a map from handle to addresses, for the handles that have
    /// addresses. Each request that the cache does not answer spends the
    /// RIPE limit of one egress. When all egresses are spent, the client skips
    /// the rest and reports `netf: ripe: daily limit reached on <n> of <m>
    /// IPs; <k> e-mails not fetched`. The message is a notice, not an
    /// error.
    /// Without `--ripe-emails`, the client asks nothing and the map is
    /// empty.
    ///
    /// # Errors
    ///
    /// Returns an error if the RIPE limit counter cannot be written, or if a
    /// request fails as in [`entity`](Self::entity).
    pub(crate) async fn ripe_emails(
        &self,
        handles: &[String],
    ) -> Result<HashMap<String, Vec<String>>> {
        let mut found = HashMap::new();
        let Some(limit) = &self.limit else {
            return Ok(found);
        };
        let mut unique: Vec<&String> = Vec::new();
        for handle in handles {
            if !unique.contains(&handle) {
                unique.push(handle);
            }
        }
        let egresses = self.transport.egresses();
        let mut missing = 0;
        for handle in unique {
            let Some(target) = self.entity_target(Rir::Ripencc, handle).await? else {
                break;
            };
            let cell = self.cell(&target.url);
            let answer = cell
                .get_or_try_init(|| async {
                    if let Some(memo) = self.cached(&target, What::Entity) {
                        return Ok(memo);
                    }
                    loop {
                        let Some(egress) = limit.take(&egresses)? else {
                            return Err(Pinned::Spent);
                        };
                        let (status, value) = self.send_json(&target, Some(egress.clone())).await?;
                        if status == 429 {
                            limit.exhaust(&egress)?;
                            continue;
                        }
                        let stored = self.answer(&target, What::Entity, status, &value)?;
                        return Ok(self.keep(&target, stored)?);
                    }
                })
                .await;
            match answer {
                Ok(Memo::Entity(Some(entity))) if !entity.email.is_empty() => {
                    found.insert(handle.clone(), entity.email.clone());
                }
                Ok(_) => {}
                Err(Pinned::Spent) => missing += 1,
                Err(Pinned::Failed(error)) => return Err(error),
            }
        }
        if missing > 0 {
            self.reporter.notice(&Notice::RipeLimit {
                exhausted: limit.exhausted(&egresses),
                total: egresses.len(),
                missing,
            });
        }
        Ok(found)
    }

    /// Returns the organization `handle` of `rir` with the networks and AS
    /// that the registry lists as its own ([`Entity::to_org`]).
    ///
    /// Returns `None` if the registry has no such entity or the entity is a
    /// person. The request is `entity/<handle>`, the same one that
    /// [`entity`](Self::entity) sends, so the two share the response.
    ///
    /// # Errors
    ///
    /// Returns an error if [`entity`](Self::entity) fails.
    pub(crate) async fn org(&self, rir: Rir, handle: &str) -> Result<Option<Org>> {
        let entity = self.entity(rir, handle).await?;
        Ok(entity
            .filter(|entity| entity.kind != EntityKind::Individual)
            .map(|entity| entity.to_org()))
    }

    /// Returns the organizations with `handle`, as in
    /// `net.org: ORG-EX1-RIPE`.
    ///
    /// The client builds each organization as [`org`](Self::org) does. A
    /// handle with the suffix of a registry (`-RIPE`, `-AP`, `-ARIN`,
    /// `-LACNIC`, or `-AFRINIC`) goes to that registry only. Any other
    /// handle goes to all five at once. The result has an organization from
    /// every registry that has the handle, in the order of [`Rir::ALL`].
    ///
    /// Opaque-ids from the stats are not RDAP handles. For an opaque-id, all
    /// five registries respond with 404 and the result is empty.
    ///
    /// # Errors
    ///
    /// Returns an error if [`org`](Self::org) fails for any registry asked.
    pub(crate) async fn org_by_handle(&self, handle: &str) -> Result<Vec<Org>> {
        let handle = handle.trim();
        if handle.is_empty() {
            return Ok(Vec::new());
        }
        if let Some(rir) = search::rir_of_handle(handle) {
            return Ok(self.org(rir, handle).await?.into_iter().collect());
        }
        let found = try_join_all(Rir::ALL.map(|rir| self.org(rir, handle))).await?;
        Ok(found.into_iter().flatten().collect())
    }

    /// Searches all five registries as
    /// [`org_by_name_in`](Self::org_by_name_in) does.
    ///
    /// Only tests use this method. The engine searches RIPE through the
    /// REST API instead.
    #[cfg(test)]
    pub(crate) async fn org_by_name(&self, pattern: &Pattern) -> Result<Vec<Org>> {
        self.org_by_name_in(&Rir::ALL, pattern).await
    }

    /// Returns the organizations named like `pattern` in the registries
    /// `rirs`, with their own networks and AS.
    ///
    /// The order is that of `rirs`, then of each registry's response. The
    /// client asks each registry `entities?fn=<pattern>` ([`search`]). Of
    /// the response, it keeps only the organizations whose name matches
    /// `pattern`, and builds each one as [`org_named`](Self::org_named)
    /// does.
    ///
    /// A registry that does not search (400 or 501) is skipped with
    /// `netf: rdap: <rir>: search not supported`, once per run. A truncated
    /// search is reported as `netf: <rir>: <message>`, once per response. `*`
    /// alone searches nothing, and the result is empty. The engine does not
    /// pass RIPE in `rirs`, because it searches RIPE through the REST API.
    ///
    /// # Errors
    ///
    /// Returns an error if a search fails as a request of
    /// [`entity`](Self::entity) does, or if [`org_named`](Self::org_named)
    /// fails. A response of 400 or 501 is not an error.
    pub(crate) async fn org_by_name_in(&self, rirs: &[Rir], pattern: &Pattern) -> Result<Vec<Org>> {
        let Some(path) = search::path(pattern) else {
            return Ok(Vec::new());
        };
        let found =
            try_join_all(rirs.iter().map(|rir| self.search_in(*rir, &path, pattern))).await?;
        Ok(found.into_iter().flatten().collect())
    }

    /// Returns the organization `handle` of `rir` that a search found under
    /// `name`.
    ///
    /// The client builds the organization as [`org`](Self::org) does. If
    /// the entity has no name, the organization takes `name`. If the
    /// registry has no such entity, the organization has `name` and no
    /// resources.
    ///
    /// # Errors
    ///
    /// Returns an error if [`org`](Self::org) fails.
    pub(crate) async fn org_named(&self, rir: Rir, handle: &str, name: &str) -> Result<Org> {
        Ok(match self.org(rir, handle).await? {
            Some(mut org) => {
                org.name = org.name.or_else(|| Some(name.to_owned()));
                org
            }
            None => search::Hit {
                handle: handle.to_owned(),
                name: name.to_owned(),
            }
            .to_org(rir),
        })
    }

    /// Returns the organizations that `pattern` finds in `rir` with the
    /// search `path`.
    async fn search_in(&self, rir: Rir, path: &str, pattern: &Pattern) -> Result<Vec<Org>> {
        let Some(server) = self.bootstrap.for_rir(rir).await? else {
            return Ok(Vec::new());
        };
        let mut target = Target::at(&server, path);
        target.rir = Some(rir);
        let Memo::Search(search) = self.query(target, What::Search).await? else {
            unreachable!("a search gives a search")
        };
        try_join_all(
            search
                .matching(pattern)
                .map(|hit| self.org_named(rir, &hit.handle, &hit.name)),
        )
        .await
    }

    /// Returns the request for the entity `handle` of `rir`, or `None` if the
    /// bootstrap names no server for `rir`.
    async fn entity_target(&self, rir: Rir, handle: &str) -> Result<Option<Target>> {
        let Some(server) = self.bootstrap.for_rir(rir).await? else {
            return Ok(None);
        };
        let mut target = Target::at(&server, &format!("entity/{}", encode(handle)));
        target.rir = Some(rir);
        Ok(Some(target))
    }

    /// Returns the memo cell of `url`, created on first use.
    fn cell(&self, url: &str) -> Arc<OnceCell<Memo>> {
        let mut memo = self
            .memo
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        Arc::clone(memo.entry(url.to_owned()).or_default())
    }

    /// Returns the response to `target`, which the client gets once per run
    /// from the cache or the network.
    async fn query(&self, target: Target, what: What) -> Result<Memo> {
        let cell = self.cell(&target.url);
        cell.get_or_try_init(|| async {
            if let Some(memo) = self.cached(&target, what) {
                return Ok(memo);
            }
            let (status, value) = if what == What::Search {
                // A search reads the status itself: 400 and 501 mean "no
                // search". A 5xx that the transport gave up on comes back
                // as a status too.
                self.send_json(&target, None).await?
            } else {
                fetch::json(&*self.transport, &target.url, target.class()).await?
            };
            let stored = self.answer(&target, what, status, &value)?;
            self.keep(&target, stored)
        })
        .await
        .cloned()
    }

    /// Returns the cached response to `target` if it is fresh and of the kind
    /// `what`.
    fn cached(&self, target: &Target, what: What) -> Option<Memo> {
        let stored: Stored = self.responses.as_ref()?.get(Method::Get, &target.url)?;
        if !what.matches(&stored) {
            return None;
        }
        self.report(target, &stored);
        Some(stored.into())
    }

    /// Writes a new response to the cache and reports it as
    /// [`report`](Self::report) does.
    fn keep(&self, target: &Target, stored: Stored) -> Result<Memo> {
        if let Some(responses) = &self.responses {
            responses.put(Method::Get, &target.url, &stored)?;
        }
        self.report(target, &stored);
        Ok(stored.into())
    }

    /// Reports what the registry said about a response: that it truncated
    /// the response, or that it does not search.
    fn report(&self, target: &Target, stored: &Stored) {
        let truncated = match stored {
            Stored::Entity(Some(entity)) => entity.truncated.as_ref(),
            Stored::Search(Search::Found { truncated, .. }) => truncated.as_ref(),
            Stored::Search(Search::Unsupported) => {
                let first = self
                    .unsupported
                    .lock()
                    .unwrap_or_else(|poison| poison.into_inner())
                    .insert(Arc::clone(&target.name));
                if first {
                    self.reporter.notice(&Notice::SearchNotSupported {
                        rir: target.name.to_string(),
                    });
                }
                None
            }
            _ => None,
        };
        if let Some(message) = truncated {
            self.reporter.notice(&Notice::Truncated {
                rir: target.name.to_string(),
                message: message.clone(),
            });
        }
    }

    /// Turns an HTTP response into a stored one.
    ///
    /// The client parses a 2xx response. A 404 means "no record", and so does
    /// a non-2xx response whose body has `errorCode` 404. A 400 or 501 to a
    /// search means "no search". Any other status is an error.
    fn answer(&self, target: &Target, what: What, status: u16, value: &Value) -> Result<Stored> {
        if status == 404 || (!(200..300).contains(&status) && parse::error_code(value) == Some(404))
        {
            return Ok(match what {
                What::Net => Stored::Net(None),
                What::As(_) => Stored::As(None),
                What::Entity => Stored::Entity(None),
                What::Search => Stored::Search(Search::empty()),
            });
        }
        if what == What::Search && search::unsupported(status) {
            return Ok(Stored::Search(Search::Unsupported));
        }
        if !(200..300).contains(&status) {
            return Err(target.error(format!("HTTP {status}")));
        }
        let rir = target
            .rir
            .or_else(|| {
                value
                    .get("port43")
                    .and_then(Value::as_str)
                    .and_then(rir_of_host)
            })
            .ok_or_else(|| target.error("an answer from a server of no known registry"))?;
        let invalid = |cause: String| target.error(format!("invalid answer: {cause}"));
        Ok(match what {
            What::Net => Stored::Net(Some(parse::network(value, rir).map_err(invalid)?)),
            What::As(asn) => {
                Stored::As(Some(parse::autnum(value, rir, Some(asn)).map_err(invalid)?))
            }
            What::Entity => Stored::Entity(Some(parse::entity(value, rir).map_err(invalid)?)),
            What::Search => Stored::Search(Search::found(
                parse::search_orgs(value),
                parse::truncated(value),
            )),
        })
    }

    /// Sends a `GET` of `target` and returns the status and the JSON body.
    ///
    /// The request goes through `egress` if one is given. The client follows
    /// redirects. A non-2xx body that is not JSON gives `null`. A 429
    /// through an egress comes back as a status, not an error. So does a
    /// status that the transport gave up on after its retries, such as a
    /// 503.
    ///
    /// Redirects from HTTPS to HTTP return an error before the next request.
    async fn send_json(&self, target: &Target, egress: Option<EgressId>) -> Result<(u16, Value)> {
        let mut current = target.url.clone();
        for _ in 0..=MAX_REDIRECTS {
            let request = Request::get(current.clone(), target.class());
            let sent = match &egress {
                Some(egress) => self.transport.send_via(request, egress.clone()).await,
                None => self.transport.send(request).await,
            };
            let response = match sent {
                Ok(response) => response,
                Err(TransportError::Status(status)) => return Ok((status, Value::Null)),
                Err(error) => return Err(target.error(error.to_string())),
            };
            match response.status {
                301 | 302 | 303 | 307 | 308 => {
                    current = fetch::redirect(&current, response.header("Location"))
                        .map_err(|cause| target.error(cause))?;
                }
                status => {
                    let body = response
                        .body
                        .collect(JSON_LIMIT)
                        .await
                        .map_err(|error| target.error(error.to_string()))?;
                    let success = (200..300).contains(&status);
                    return match serde_json::from_slice(&body) {
                        Ok(value) => Ok((status, value)),
                        Err(_) if !success => Ok((status, Value::Null)),
                        Err(error) => Err(target.error(format!("invalid JSON: {error}"))),
                    };
                }
            }
        }
        Err(target.error("too many redirects"))
    }
}

/// Returns the handles of `contacts` whose e-mail RIPE hid, without
/// repeats.
///
/// [`RdapClient::ripe_emails`] takes these handles.
pub(crate) fn hidden_emails<'a>(contacts: impl IntoIterator<Item = &'a Contact>) -> Vec<String> {
    let mut handles: Vec<String> = Vec::new();
    for contact in contacts {
        if contact.emails_hidden && !handles.contains(&contact.handle) {
            handles.push(contact.handle.clone());
        }
    }
    handles
}

/// Fills the hidden e-mail of `contacts` from what
/// [`RdapClient::ripe_emails`] found.
pub(crate) fn fill_emails(contacts: &mut [Contact], emails: &HashMap<String, Vec<String>>) {
    for contact in contacts {
        if contact.emails_hidden
            && let Some(found) = emails.get(&contact.handle)
        {
            contact.email.clone_from(found);
            contact.emails_hidden = false;
        }
    }
}

/// The path of an `ip` request: the address of a single host, the CIDR, or
/// the smallest CIDR that covers a range.
fn ip_path(range: &Range) -> String {
    let prefix = range.as_prefix().unwrap_or_else(|| covering(range));
    if prefix.len() == range.family().bits() {
        prefix.addr().to_string()
    } else {
        prefix.to_string()
    }
}

/// The smallest prefix that holds all of `range`.
fn covering(range: &Range) -> Prefix {
    let family = range.family();
    let bits = u32::from(family.bits());
    let diff = range.first() ^ range.last();
    // The common leading bits of the first and the last address.
    let common = (diff.leading_zeros() - (128 - bits)).min(bits);
    let len = u8::try_from(common).expect("at most 128");
    let host_bits = bits - common;
    let mask = if host_bits >= 128 {
        0
    } else {
        family.max() & !((1_u128 << host_bits) - 1)
    };
    let addr = Addr::new(family, range.first() & mask).expect("within the family");
    Prefix::new(addr, len).expect("a masked address")
}

/// Percent-encodes a handle for a URL path.
fn encode(handle: &str) -> String {
    let mut out = String::with_capacity(handle.len());
    for byte in handle.bytes() {
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
    use std::{collections::VecDeque, sync::Mutex};

    use serde_json::json;

    use super::{bootstrap::tests as fixtures, parse::tests as samples, *};
    use crate::{
        fetch::testing::{Collect, FakeClock, Reply, TempDir},
        model::Role,
        transport::{BodyStream, BoxFuture, Response, TransportError},
    };

    const RIPE_NET: &str = "https://rdap.db.ripe.test/ip/192.0.2.0/24";

    /// A transport with scripted replies per URL and a list of egresses.
    ///
    /// The transport logs the egress of each request, `None` for an
    /// unpinned one.
    struct Script {
        egresses: Vec<EgressId>,
        replies: Mutex<HashMap<String, VecDeque<Reply>>>,
        /// The URLs that the transport gives up on after its retries, with
        /// the status. The real transport does the same with a 5xx.
        given_up: Mutex<HashMap<String, u16>>,
        log: Mutex<Vec<(String, Option<EgressId>)>>,
    }

    impl Script {
        fn new(egresses: &[&str]) -> Arc<Self> {
            let script = Arc::new(Self {
                egresses: egresses
                    .iter()
                    .map(|name| EgressId(Arc::from(*name)))
                    .collect(),
                replies: Mutex::default(),
                given_up: Mutex::default(),
                log: Mutex::default(),
            });
            for (url, body) in [
                ("https://data.iana.test/rdap/asn.json", fixtures::ASN),
                ("https://data.iana.test/rdap/ipv4.json", fixtures::IPV4),
                ("https://data.iana.test/rdap/ipv6.json", fixtures::IPV6),
            ] {
                // Enough for several runs without the cache.
                for _ in 0..4 {
                    script.on(url, Reply::ok(body));
                }
            }
            script
        }

        fn on(&self, url: &str, reply: Reply) -> &Self {
            self.replies
                .lock()
                .unwrap()
                .entry(url.to_owned())
                .or_default()
                .push_back(reply);
            self
        }

        fn json(&self, url: &str, value: &Value) -> &Self {
            self.on(url, Reply::ok(value.to_string()))
        }

        fn give_up(&self, url: &str, status: u16) -> &Self {
            self.given_up.lock().unwrap().insert(url.to_owned(), status);
            self
        }

        /// Returns the requests, without those for the bootstrap files.
        fn log(&self) -> Vec<(String, Option<EgressId>)> {
            self.log
                .lock()
                .unwrap()
                .iter()
                .filter(|(url, _)| !url.contains("data.iana.test"))
                .cloned()
                .collect()
        }

        fn urls(&self) -> Vec<String> {
            self.log().into_iter().map(|(url, _)| url).collect()
        }

        fn reply(
            &self,
            request: Request,
            egress: Option<EgressId>,
        ) -> BoxFuture<'_, Result<Response, TransportError>> {
            if let Some(status) = self.given_up.lock().unwrap().remove(&request.url) {
                self.log.lock().unwrap().push((request.url, egress));
                return Box::pin(async move { Err(TransportError::Status(status)) });
            }
            let reply = self
                .replies
                .lock()
                .unwrap()
                .get_mut(&request.url)
                .and_then(VecDeque::pop_front)
                .unwrap_or_else(|| panic!("unexpected request: {}", request.url));
            self.log.lock().unwrap().push((request.url, egress.clone()));
            Box::pin(async move {
                Ok(Response {
                    status: reply.status,
                    headers: reply.headers,
                    body: BodyStream::from_bytes(reply.chunks.concat()),
                    egress: egress.unwrap_or_else(EgressId::direct),
                })
            })
        }
    }

    impl Transport for Script {
        fn send(&self, request: Request) -> BoxFuture<'_, Result<Response, TransportError>> {
            self.reply(request, None)
        }

        fn egresses(&self) -> Vec<EgressId> {
            self.egresses.clone()
        }

        fn send_via(
            &self,
            request: Request,
            egress: EgressId,
        ) -> BoxFuture<'_, Result<Response, TransportError>> {
            assert!(self.egresses.contains(&egress), "unknown egress {egress}");
            self.reply(request, Some(egress))
        }
    }

    struct Run {
        dir: TempDir,
        clock: Arc<FakeClock>,
        reporter: Arc<Collect>,
    }

    impl Run {
        fn new(name: &str) -> Self {
            Self {
                dir: TempDir::new(name),
                clock: Arc::new(FakeClock::new()),
                reporter: Arc::new(Collect::default()),
            }
        }

        fn settings(&self) -> RdapSettings {
            RdapSettings {
                cache_dir: self.dir.path().to_owned(),
                cache: true,
                ttl: Duration::from_secs(86_400),
                ripe_emails: false,
                base: None,
                sources: Urls::test(),
            }
        }

        fn client(&self, settings: RdapSettings, transport: &Arc<Script>) -> RdapClient {
            RdapClient::new(
                settings,
                Arc::clone(transport) as Arc<dyn Transport>,
                self.clock.clone(),
                self.reporter.clone(),
            )
        }
    }

    fn range(text: &str) -> Range {
        text.parse().unwrap()
    }

    #[tokio::test]
    async fn one_request_per_url_and_answers_from_the_cache() {
        let run = Run::new("rdap-dedup");
        let script = Script::new(&["direct"]);
        script.json(RIPE_NET, &samples::ripe_network());
        script.on(
            "https://rdap.arin.test/registry/autnum/64496",
            Reply::status(404),
        );
        let client = run.client(run.settings(), &script);
        let (a, b) = tokio::join!(
            client.ip(range("192.0.2.0/24")),
            client.ip(range("192.0.2.0/24"))
        );
        let a = a.unwrap().unwrap();
        assert!(Arc::ptr_eq(&a, &b.unwrap().unwrap()));
        assert_eq!(a.rir, Rir::Ripencc);
        assert_eq!(a.mnt, ["EXAMPLE-MNT"]);
        assert_eq!(client.autnum(64496).await.unwrap(), None);
        assert_eq!(client.autnum(64496).await.unwrap(), None);
        // No registry serves these, so the client sends no request.
        assert_eq!(client.autnum(64510).await.unwrap(), None);
        assert_eq!(client.ip(range("10.0.0.0/8")).await.unwrap(), None);
        assert_eq!(
            script.urls(),
            [RIPE_NET, "https://rdap.arin.test/registry/autnum/64496"]
        );
        // The next run asks nothing: the record and the 404 are cached.
        let next = run.client(run.settings(), &script);
        assert_eq!(next.ip(range("192.0.2.0/24")).await.unwrap(), Some(a));
        assert_eq!(next.autnum(64496).await.unwrap(), None);
        assert_eq!(script.urls().len(), 2);
        assert!(run.reporter.lines().is_empty());
    }

    #[tokio::test]
    async fn base_rewrite_and_a_redirect_to_another_server() {
        let run = Run::new("rdap-redirect");
        let base = "http://127.0.0.1:9";
        let script = Script::new(&["direct"]);
        script.on(
            "http://127.0.0.1:9/data.iana.test/rdap/ipv4.json",
            Reply::ok(fixtures::IPV4),
        );
        script.on(
            "http://127.0.0.1:9/rdap.lacnic.test/rdap/ip/203.0.113.192/26",
            Reply::status(307).header(
                "Location",
                "http://127.0.0.1:9/rdap.registro.test/ip/203.0.113.192/26",
            ),
        );
        script.json(
            "http://127.0.0.1:9/rdap.registro.test/ip/203.0.113.192/26",
            &json!({
                "handle": "203.0.113.128/25",
                "startAddress": "203.0.113.128",
                "endAddress": "203.0.113.255",
                "links": [{"rel": "up", "href": "https://rdap.registro.test/ip/203.0.113.0/24"}]
            }),
        );
        script.json(
            "http://127.0.0.1:9/rdap.registro.test/ip/203.0.113.0/24",
            &json!({"startAddress": "203.0.113.0", "endAddress": "203.0.113.255"}),
        );
        let settings = RdapSettings {
            base: Some(base.to_owned()),
            ..run.settings()
        };
        let client = run.client(settings, &script);
        let net = client.ip(range("203.0.113.192/26")).await.unwrap().unwrap();
        assert_eq!(net.rir, Rir::Lacnic);
        assert_eq!(net.range, range("203.0.113.128/25"));
        let chain = client.up_chain(&net, None).await.unwrap();
        assert_eq!(chain.len(), 1);
        assert_eq!(chain[0].range, range("203.0.113.0/24"));
        assert_eq!(chain[0].rir, Rir::Lacnic);
    }

    #[tokio::test]
    async fn https_to_http_redirects_are_rejected() {
        for status in [301, 302, 303, 307, 308] {
            for egress in [None, Some(EgressId::direct())] {
                let run = Run::new("rdap-https-to-http");
                let script = Script::new(&["direct"]);
                let next = "http://rdap.db.ripe.test/ip/192.0.2.0/24";
                script.on(RIPE_NET, Reply::status(status).header("Location", next));
                script.json(next, &samples::ripe_network());
                let client = run.client(run.settings(), &script);
                let target = Target {
                    url: RIPE_NET.to_owned(),
                    name: Arc::from("ripencc"),
                    rir: Some(Rir::Ripencc),
                };
                let error = client.send_json(&target, egress.clone()).await.unwrap_err();
                assert_eq!(
                    error.message(),
                    "rdap: ripencc: redirect from HTTPS to HTTP is not allowed"
                );
                assert_eq!(script.log(), [(RIPE_NET.to_owned(), egress)]);
            }
        }
    }

    #[tokio::test]
    async fn https_redirects_resolve_relative_locations() {
        let run = Run::new("rdap-relative-redirect");
        let script = Script::new(&["direct"]);
        let second = "https://rdap.other.test/net/start";
        let third = "https://rdap.other.test/ip/192.0.2.0/24";
        script.on(
            RIPE_NET,
            Reply::status(307).header("Location", "//rdap.other.test/net/start"),
        );
        script.on(
            second,
            Reply::status(302).header("Location", "../ip/192.0.2.0/24"),
        );
        script.json(third, &samples::ripe_network());
        let client = run.client(run.settings(), &script);
        let net = client.ip(range("192.0.2.0/24")).await.unwrap().unwrap();
        assert_eq!(net.rir, Rir::Ripencc);
        assert_eq!(net.range, range("192.0.2.0/24"));
        assert_eq!(script.urls(), [RIPE_NET, second, third]);
    }

    #[tokio::test]
    async fn the_chain_up_stops_at_the_block() {
        let run = Run::new("rdap-chain");
        let script = Script::new(&["direct"]);
        let net = |first: &str, last: &str, up: Option<&str>| {
            let mut value = json!({"startAddress": first, "endAddress": last});
            if let Some(up) = up {
                value["links"] = json!([{"rel": "up", "href": up}]);
            }
            value
        };
        let base = "https://rdap.db.ripe.test/ip/";
        script.json(
            &format!("{base}192.0.2.192/26"),
            &net(
                "192.0.2.192",
                "192.0.2.255",
                Some(&format!("{base}192.0.2.128/25")),
            ),
        );
        script.json(
            &format!("{base}192.0.2.128/25"),
            &net(
                "192.0.2.128",
                "192.0.2.255",
                Some(&format!("{base}192.0.2.0/24")),
            ),
        );
        script.json(
            &format!("{base}192.0.2.0/24"),
            &net(
                "192.0.2.0",
                "192.0.2.255",
                Some(&format!("{base}192.0.2.192/26")),
            ),
        );
        let client = run.client(run.settings(), &script);
        let record = client.ip(range("192.0.2.192/26")).await.unwrap().unwrap();
        let block = range("192.0.2.128/25");
        let chain = client.up_chain(&record, Some(&block)).await.unwrap();
        let ranges: Vec<_> = chain.iter().map(|net| net.range.to_string()).collect();
        assert_eq!(ranges, ["192.0.2.128/25"]);
        assert!(
            client
                .up_chain(&chain[0], Some(&block))
                .await
                .unwrap()
                .is_empty()
        );
        // Without a block, the chain goes to the top. The client does not
        // follow the link back down.
        let chain = client.up_chain(&record, None).await.unwrap();
        let ranges: Vec<_> = chain.iter().map(|net| net.range.to_string()).collect();
        assert_eq!(ranges, ["192.0.2.0/24", "192.0.2.128/25"]);
        assert_eq!(script.urls().len(), 3);
    }

    #[tokio::test]
    async fn errors_name_the_registry() {
        let run = Run::new("rdap-errors");
        let script = Script::new(&["direct"]);
        script.on(
            "https://rdap.arin.test/registry/autnum/64497",
            Reply::status(503),
        );
        script.json(
            "https://rdap.apnic.test/autnum/64504",
            &json!({"name": "NO-NUMBER"}),
        );
        script.on(
            "https://rdap.afrinic.test/rdap/autnum/64508",
            Reply::ok("<html>"),
        );
        let client = run.client(run.settings(), &script);
        let error = client.autnum(64497).await.unwrap_err();
        assert_eq!(error.message(), "rdap: arin: HTTP 503");
        // A response without a number takes the number asked about.
        let record = client.autnum(64504).await.unwrap().unwrap();
        assert_eq!((record.asn, record.rir), (64504, Rir::Apnic));
        let error = client.autnum(64508).await.unwrap_err();
        assert!(
            error.message().starts_with("rdap: afrinic: invalid JSON"),
            "{}",
            error.message()
        );
        script.on(
            "https://rdap.arin.test/registry/entity/EXAMP-ARIN",
            Reply::status(500),
        );
        let error = client.org_by_handle("EXAMP-ARIN").await.unwrap_err();
        assert_eq!(error.message(), "rdap: arin: HTTP 500");
    }

    const RIPE_SEARCH: &str = "https://rdap.db.ripe.test/entities?fn=example*";
    const ARIN_SEARCH: &str = "https://rdap.arin.test/registry/entities?fn=example*";
    const APNIC_SEARCH: &str = "https://rdap.apnic.test/entities?fn=example*";
    const LACNIC_SEARCH: &str = "https://rdap.lacnic.test/rdap/entities?fn=example*";
    const AFRINIC_SEARCH: &str = "https://rdap.afrinic.test/rdap/entities?fn=example*";

    fn found(entities: &[Value]) -> Value {
        json!({"rdapConformance": ["rdap_level_0"], "entitySearchResults": entities})
    }

    fn found_entity(handle: &str, name: &str, kind: &str) -> Value {
        json!({"objectClassName": "entity", "handle": handle,
               "vcardArray": samples::vcard(name, kind, &[])})
    }

    fn glob(source: &str) -> Pattern {
        Pattern::Glob(crate::text::Glob::new(source))
    }

    fn sorted(mut lines: Vec<String>) -> Vec<String> {
        lines.sort();
        lines
    }

    /// Scripts the five responses to `fn=example*`.
    ///
    /// RIPE finds three organizations, a person, and a role, and truncates
    /// the response. Two of the organizations match `example*`. ARIN finds one
    /// organization. APNIC does not search (501). LACNIC redirects to an
    /// empty response. AFRINIC refuses the pattern (400).
    fn script_search(script: &Script) {
        let mut ripe = found(&[
            found_entity("ORG-EH1-RIPE", "Example Holdings", "org"),
            found_entity("EP1-RIPE", "Example Person", "individual"),
            found_entity("ER1-RIPE", "Example Role", "group"),
            found_entity("ORG-OT1-RIPE", "Other Example", "org"),
            found_entity("ORG-EC1-RIPE", "Example Cloud", "org"),
        ]);
        ripe["notices"] = json!([{"title": "Truncated",
            "description": ["Limited search results to 100 maximum"]}]);
        script.json(RIPE_SEARCH, &ripe);
        script.json(
            ARIN_SEARCH,
            &found(&[found_entity("EXAMP", "Example Networks", "org")]),
        );
        script.give_up(APNIC_SEARCH, 501);
        script.on(
            LACNIC_SEARCH,
            Reply::status(307).header(
                "Location",
                "https://rdap.registro.test/entities?fn=example*",
            ),
        );
        script.json(
            "https://rdap.registro.test/entities?fn=example*",
            &found(&[]),
        );
        script.on(AFRINIC_SEARCH, Reply::status(400));
        let held = |start: &str, end: &str, holder: &str| {
            json!({"startAddress": start, "endAddress": end, "entities": [
                {"handle": holder, "roles": ["registrant"],
                 "vcardArray": samples::vcard(holder, "org", &[])}]})
        };
        script.json(
            "https://rdap.db.ripe.test/entity/ORG-EH1-RIPE",
            &json!({
                "handle": "ORG-EH1-RIPE",
                "vcardArray": samples::vcard("Example Holdings", "org", &[]),
                "networks": [
                    held("192.0.2.0", "192.0.2.255", "ORG-EH1-RIPE"),
                    held("198.51.100.0", "198.51.100.255", "ORG-CUST1-RIPE")
                ],
                "autnums": [{"startAutnum": 64500, "endAutnum": 64500}]
            }),
        );
        script.on(
            "https://rdap.db.ripe.test/entity/ORG-EC1-RIPE",
            Reply::status(404),
        );
        script.json(
            "https://rdap.arin.test/registry/entity/EXAMP",
            &json!({
                "handle": "EXAMP",
                "vcardArray": samples::vcard("Example Networks", "org", &[]),
                "networks": [held("203.0.113.0", "203.0.113.255", "EXAMP")]
            }),
        );
    }

    #[tokio::test]
    async fn organizations_by_name_in_all_five_registries() {
        let run = Run::new("rdap-org-search");
        let script = Script::new(&["direct"]);
        script_search(&script);
        let client = run.client(run.settings(), &script);
        let orgs = client.org_by_name(&glob("example*")).await.unwrap();
        let handles: Vec<_> = orgs
            .iter()
            .map(|org| (org.rir, org.handle.as_str()))
            .collect();
        assert_eq!(
            handles,
            [
                (Rir::Arin, "EXAMP"),
                (Rir::Ripencc, "ORG-EH1-RIPE"),
                (Rir::Ripencc, "ORG-EC1-RIPE")
            ]
        );
        assert_eq!(orgs[0].networks[0].range, range("203.0.113.0/24"));
        // The organization keeps only what it holds itself. The sponsored
        // network is dropped, and the AS without a holder is kept.
        let ripe = &orgs[1];
        assert_eq!(ripe.name.as_deref(), Some("Example Holdings"));
        assert_eq!(ripe.networks.len(), 1);
        assert_eq!(ripe.networks[0].range, range("192.0.2.0/24"));
        assert_eq!(ripe.autnums[0].asn, 64500);
        // The search found this organization, but the registry has no
        // entity with its handle, so the organization has no resources.
        assert_eq!(orgs[2].name.as_deref(), Some("Example Cloud"));
        assert!(orgs[2].networks.is_empty() && orgs[2].autnums.is_empty());
        let notices = [
            "netf: rdap: afrinic: search not supported",
            "netf: rdap: apnic: search not supported",
            "netf: ripencc: Limited search results to 100 maximum",
        ];
        assert_eq!(sorted(run.reporter.lines()), notices);
        let asked = script.urls().len();
        assert_eq!(asked, 9);
        // The same search with a narrower local pattern asks nothing and
        // reports nothing again.
        let orgs = client.org_by_name(&glob("example*holdings")).await.unwrap();
        assert_eq!(orgs.len(), 1);
        assert_eq!(orgs[0].handle, "ORG-EH1-RIPE");
        assert_eq!(script.urls().len(), asked);
        assert_eq!(run.reporter.lines().len(), 3);
        // The next run answers from the cache and reports again. The
        // person is not in the cache.
        let next = run.client(run.settings(), &script);
        assert_eq!(next.org_by_name(&glob("example*")).await.unwrap().len(), 3);
        assert_eq!(script.urls().len(), asked);
        assert_eq!(sorted(run.reporter.lines()[3..].to_vec()), notices);
        let mut cached = String::new();
        for file in std::fs::read_dir(run.dir.path().join("responses")).unwrap() {
            let bytes = std::fs::read(file.unwrap().path()).unwrap();
            cached.push_str(&String::from_utf8_lossy(&bytes));
        }
        assert!(cached.contains("Example Cloud"));
        assert!(!cached.contains("Example Person") && !cached.contains("EP1-RIPE"));
        assert!(!cached.contains("Example Role"));
    }

    #[tokio::test]
    async fn organization_searches_that_find_nothing() {
        let run = Run::new("rdap-org-none");
        let script = Script::new(&["direct"]);
        let client = run.client(run.settings(), &script);
        // `*` alone and patterns of only wildcards ask nothing.
        assert!(client.org_by_name(&Pattern::Any).await.unwrap().is_empty());
        assert!(client.org_by_name(&glob("**")).await.unwrap().is_empty());
        assert!(script.urls().is_empty());
        let urls = [
            "https://rdap.afrinic.test/rdap/entities?fn=Example%20Holdings",
            "https://rdap.apnic.test/entities?fn=Example%20Holdings",
            "https://rdap.arin.test/registry/entities?fn=Example%20Holdings",
            "https://rdap.lacnic.test/rdap/entities?fn=Example%20Holdings",
            "https://rdap.db.ripe.test/entities?fn=Example%20Holdings",
        ];
        script.on(urls[0], Reply::status(404));
        script.json(urls[1], &json!({"errorCode": 404, "title": "Not Found"}));
        script.json(urls[2], &found(&[]));
        // A person with the name is not an organization.
        script.json(
            urls[3],
            &found(&[found_entity("EH-LACNIC", "Example Holdings", "individual")]),
        );
        script.json(
            urls[4],
            &found(&[found_entity("ORG-EX9-RIPE", "Example Holdings Two", "org")]),
        );
        let exact = Pattern::Exact("Example Holdings".into());
        assert!(client.org_by_name(&exact).await.unwrap().is_empty());
        assert_eq!(
            sorted(script.urls()),
            sorted(urls.map(str::to_owned).to_vec())
        );
        assert!(run.reporter.lines().is_empty());
        // A failing registry fails the whole search, and the error names
        // the registry.
        let run = Run::new("rdap-org-error");
        let client = run.client(run.settings(), &script);
        let pattern = Pattern::Exact("Example".into());
        for url in [
            "https://rdap.afrinic.test/rdap/entities?fn=Example",
            "https://rdap.apnic.test/entities?fn=Example",
            "https://rdap.lacnic.test/rdap/entities?fn=Example",
            "https://rdap.db.ripe.test/entities?fn=Example",
        ] {
            script.json(url, &found(&[]));
        }
        script.give_up("https://rdap.arin.test/registry/entities?fn=Example", 503);
        let error = client.org_by_name(&pattern).await.unwrap_err();
        assert_eq!(error.message(), "rdap: arin: HTTP 503");
    }

    #[tokio::test]
    async fn organizations_by_handle() {
        let run = Run::new("rdap-org-handle");
        let script = Script::new(&["direct"]);
        script.json(
            "https://rdap.db.ripe.test/entity/ORG-EH1-RIPE",
            &json!({
                "handle": "ORG-EH1-RIPE",
                "vcardArray": samples::vcard("Example Holdings", "org", &[]),
                "networks": [{"startAddress": "192.0.2.0", "endAddress": "192.0.2.255"}],
                "notices": [{"type": "result set truncated due to excessive load"}]
            }),
        );
        script.json(
            "https://rdap.db.ripe.test/entity/JD1-RIPE",
            &person("JD1-RIPE", Some("jane@example.net")),
        );
        let client = run.client(run.settings(), &script);
        // A handle with a registry suffix goes to that registry only.
        let orgs = client.org_by_handle("ORG-EH1-RIPE").await.unwrap();
        assert_eq!(orgs.len(), 1);
        assert_eq!(orgs[0].rir, Rir::Ripencc);
        assert_eq!(orgs[0].networks.len(), 1);
        assert_eq!(
            orgs[0].truncated.as_deref(),
            Some("result set truncated due to excessive load")
        );
        // A person is not an organization.
        assert!(client.org_by_handle("JD1-RIPE").await.unwrap().is_empty());
        assert_eq!(client.org(Rir::Ripencc, "JD1-RIPE").await.unwrap(), None);
        // A handle without a suffix goes to all five. ARIN has it.
        for url in [
            "https://rdap.afrinic.test/rdap/entity/EXAMP",
            "https://rdap.apnic.test/entity/EXAMP",
            "https://rdap.lacnic.test/rdap/entity/EXAMP",
            "https://rdap.db.ripe.test/entity/EXAMP",
        ] {
            script.on(url, Reply::status(404));
        }
        script.json(
            "https://rdap.arin.test/registry/entity/EXAMP",
            &json!({
                "handle": "EXAMP",
                "vcardArray": samples::vcard("Example Networks", "org", &[]),
                "autnums": [{"startAutnum": 64496, "endAutnum": 64496, "name": "EXAMPLE"}]
            }),
        );
        let orgs = client.org_by_handle(" EXAMP ").await.unwrap();
        assert_eq!(orgs.len(), 1);
        assert_eq!((orgs[0].rir, orgs[0].autnums[0].asn), (Rir::Arin, 64496));
        assert!(client.org_by_handle("").await.unwrap().is_empty());
        assert_eq!(script.urls().len(), 7);
        assert_eq!(
            run.reporter.lines(),
            ["netf: ripencc: result set truncated due to excessive load"]
        );
    }

    fn person(handle: &str, email: Option<&str>) -> Value {
        let more: Vec<Value> = email
            .map(|email| json!(["email", {}, "text", email]))
            .into_iter()
            .collect();
        json!({"handle": handle, "vcardArray": samples::vcard("Jane Doe", "individual", &more)})
    }

    #[tokio::test]
    async fn ripe_emails_spend_the_limit_per_egress() {
        let run = Run::new("rdap-ripe-emails");
        let script = Script::new(&["http://192.0.2.1:3128", "http://192.0.2.2:3128"]);
        let entity = |handle: &str| format!("https://rdap.db.ripe.test/entity/{handle}");
        // The first egress is already blocked. The second responds once.
        script.on(&entity("JR1-TEST"), Reply::status(429));
        script.json(
            &entity("JR1-TEST"),
            &person("JR1-TEST", Some("jane@example.net")),
        );
        script.on(&entity("JD1-TEST"), Reply::status(429));
        let settings = RdapSettings {
            ripe_emails: true,
            ..run.settings()
        };
        let client = run.client(settings.clone(), &script);
        let handles = ["JR1-TEST", "JR1-TEST", "JD1-TEST", "XX1-TEST"].map(str::to_owned);
        let found = client.ripe_emails(&handles).await.unwrap();
        assert_eq!(found.len(), 1);
        assert_eq!(found["JR1-TEST"], ["jane@example.net"]);
        let egresses: Vec<_> = script
            .log()
            .into_iter()
            .map(|(_, egress)| egress.unwrap().to_string())
            .collect();
        assert_eq!(
            egresses,
            [
                "http://192.0.2.1:3128",
                "http://192.0.2.2:3128",
                "http://192.0.2.2:3128"
            ]
        );
        assert_eq!(
            run.reporter.lines(),
            ["netf: ripe: daily limit reached on 2 of 2 IPs; 2 e-mails not fetched"]
        );
        // In the next run, the cached response spends nothing. The other
        // handles wait for the next UTC day, even without the cache.
        let next = run.client(settings.clone(), &script);
        let found = next.ripe_emails(&handles[..1]).await.unwrap();
        assert_eq!(found["JR1-TEST"], ["jane@example.net"]);
        let uncached = RdapSettings {
            cache: false,
            ..settings.clone()
        };
        let next = run.client(uncached, &script);
        assert!(next.ripe_emails(&handles[2..3]).await.unwrap().is_empty());
        assert_eq!(script.log().len(), 3);
        // A new UTC day.
        run.clock.advance(Duration::from_secs(86_400));
        script.json(&entity("JD1-TEST"), &person("JD1-TEST", None));
        let next = run.client(settings, &script);
        assert!(next.ripe_emails(&handles[2..3]).await.unwrap().is_empty());
        assert_eq!(script.log().len(), 4);
    }

    #[test]
    fn hidden_emails_are_collected_and_filled() {
        let net = parse::network(&samples::ripe_network(), Rir::Ripencc).unwrap();
        let handles = hidden_emails(&net.contacts);
        assert_eq!(handles, ["JR1-TEST"]);
        let mut contacts = net.contacts.clone();
        let found = HashMap::from([("JR1-TEST".to_owned(), vec!["john@example.net".to_owned()])]);
        fill_emails(&mut contacts, &found);
        let john = contacts.iter().find(|c| c.handle == "JR1-TEST").unwrap();
        assert_eq!(john.email, ["john@example.net"]);
        assert!(!john.emails_hidden);
        assert!(john.roles.contains(&Role::Technical));
    }

    #[test]
    fn query_paths() {
        assert_eq!(ip_path(&range("192.0.2.0/24")), "192.0.2.0/24");
        assert_eq!(ip_path(&range("192.0.2.1/32")), "192.0.2.1");
        assert_eq!(ip_path(&range("192.0.2.1-192.0.2.6")), "192.0.2.0/29");
        assert_eq!(ip_path(&range("2001:db8::/32")), "2001:db8::/32");
        assert_eq!(ip_path(&range("2001:db8::1-2001:db8::2")), "2001:db8::/126");
        assert_eq!(ip_path(&range("0.0.0.0-255.255.255.254")), "0.0.0.0/0");
        assert_eq!(encode("ORG-EX1-TEST"), "ORG-EX1-TEST");
        assert_eq!(encode("A B/C"), "A%20B%2FC");
    }
}
