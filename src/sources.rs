//! Lazy access to every source a plan needs.
//!
//! Sources are loaded only if `Needs` asks for them, through the cache or,
//! with `--no-cache`, as a stream. The hidden variable `NETF_SOURCE_BASE`
//! rewrites every source URL to `<BASE>/<host>/<path>`. Tests point it at
//! a stub server or at a closed port, so nothing reaches the internet. It
//! is read in every build and is not in `--help`.
//!
//! [`Sources`] is the one place that knows which backend answers:
//!
//! - **With the cache**, a dataset is loaded once per run. The first
//!   request opens or builds its index, and later requests reuse it.
//!   Requests are answered from the mapped file. [`Sources::prepare`]
//!   loads the routes, `asn.txt`, and the delegated stats of a plan at
//!   once, so downloads overlap. The WHOIS dumps load when
//!   [`Sources::whois`] first needs them. If a
//!   lookup finds the index damaged, the file is reported, rebuilt, and
//!   asked again.
//! - **Without the cache**, every request is one pass over a fresh
//!   download, so the engine batches what it needs from a dataset into one
//!   request. A dataset is downloaded again only for a second batch.
//!
//! The delegated stats of the five registries are asked together
//! ([`Sources::stats`]), and so are the APNIC and AFRINIC dumps
//! ([`Sources::whois`]). RDAP and the RIPE REST API have their own
//! clients, and [`rewrite`] rewrites their URLs in the same way.

use std::sync::Arc;

use tokio::sync::Mutex;

use crate::{
    Environment,
    addr::Family,
    cache::{Builder, Cache, CacheFile, Entry, container::Corrupt},
    dataset::{
        Kind, Urls,
        asn::{AsnAnswer, AsnBuilder, AsnIndex, AsnRequest, AsnStream},
        ris::{RisBuilder, RisIndex, RisStream, RouteAnswer, RouteRequest},
        stats::{StatsAnswer, StatsBuilder, StatsIndex, StatsRequest, StatsStream},
        whoisdb::{
            Classes, Found, Lookup, WhoisAnswer, WhoisBuilder, WhoisIndex, WhoisRecord,
            WhoisRequest, WhoisStream, assemble, org_lookup, record_lookup, referenced_orgs,
        },
    },
    error::{Error, Result},
    fetch::{self, Fetched, lines::LineSink},
    model::{RecordOrigin, Rir},
    plan::Needs,
    transport::{Class, Transport},
};

/// The hidden variable that redirects every source.
pub(crate) const SOURCE_BASE_VAR: &str = "NETF_SOURCE_BASE";

/// Returns the value of `NETF_SOURCE_BASE`, if set and not empty.
pub(crate) fn source_base(env: &Environment) -> Option<String> {
    env.var(SOURCE_BASE_VAR)
        .map(str::trim)
        .filter(|base| !base.is_empty())
        .map(str::to_owned)
}

/// Rewrites `https://host/path` to `<base>/host/path`.
///
/// Without a base, returns the URL as is.
pub(crate) fn rewrite(base: Option<&str>, url: &str) -> String {
    let Some(base) = base else {
        return url.to_owned();
    };
    let rest = url.split_once("://").map_or(url, |(_, rest)| rest);
    format!("{}/{rest}", base.trim_end_matches('/'))
}

/// The datasets of one run, loaded on first use.
pub(crate) struct Sources {
    reporting: Option<(Arc<dyn crate::Reporter>, Arc<dyn crate::Clock>)>,
    transport: Arc<dyn Transport>,
    cache: Option<Cache>,
    base: Option<String>,
    urls: Urls,
    ris_v4: Mutex<Option<Arc<RisIndex>>>,
    ris_v6: Mutex<Option<Arc<RisIndex>>>,
    asn: Mutex<Option<Arc<AsnIndex>>>,
    /// The delegated stats, in the order of [`Rir::ALL`].
    stats: [Mutex<Option<Arc<StatsIndex>>>; 5],
    /// The database dumps, in the order of [`WHOIS_KINDS`].
    whois: [Mutex<Option<Arc<WhoisIndex>>>; 5],
}

/// The datasets of the database dumps.
const WHOIS_KINDS: [Kind; 5] = [
    Kind::ApnicInetnum,
    Kind::ApnicInet6num,
    Kind::ApnicAutNum,
    Kind::ApnicOrganisation,
    Kind::AfrinicDb,
];

/// Returns the datasets of a registry's database dumps that a request
/// reads: those of its records, and that of the organizations.
///
/// Returns `None` for a registry without a database dump. RIPE is asked
/// through its REST API, in `ripe_rest`.
fn whois_kinds(rir: Rir, request: &WhoisRequest) -> Option<(Vec<Kind>, Kind)> {
    match rir {
        Rir::Apnic => {
            let records = [
                (Kind::ApnicInetnum, request.families.v4()),
                (Kind::ApnicInet6num, request.families.v6()),
                (Kind::ApnicAutNum, request.autnums),
            ];
            let records = records
                .into_iter()
                .filter(|(_, wanted)| *wanted)
                .map(|(kind, _)| kind)
                .collect();
            Some((records, Kind::ApnicOrganisation))
        }
        Rir::Afrinic => Some((vec![Kind::AfrinicDb], Kind::AfrinicDb)),
        Rir::Arin | Rir::Lacnic | Rir::Ripencc => None,
    }
}

impl Sources {
    /// Creates the sources at `urls` over `transport`.
    ///
    /// Datasets go through `cache` unless it is `None`, as with
    /// `--no-cache`. URLs are rewritten to `base` if it is given.
    pub(crate) fn new(
        transport: Arc<dyn Transport>,
        cache: Option<Cache>,
        base: Option<String>,
        urls: Urls,
    ) -> Self {
        Self {
            reporting: None,
            transport,
            cache,
            base,
            urls,
            ris_v4: Mutex::new(None),
            ris_v6: Mutex::new(None),
            asn: Mutex::new(None),
            stats: std::array::from_fn(|_| Mutex::new(None)),
            whois: std::array::from_fn(|_| Mutex::new(None)),
        }
    }

    /// Returns `true` without the cache, when every request downloads.
    pub(crate) fn is_streaming(&self) -> bool {
        self.cache.is_none()
    }

    /// Adds provenance reporting for downloads made without a cache.
    pub(crate) fn with_reporting(
        mut self,
        reporter: Arc<dyn crate::Reporter>,
        clock: Arc<dyn crate::Clock>,
    ) -> Self {
        self.reporting = Some((reporter, clock));
        self
    }

    /// Returns the URL of a dataset, after `NETF_SOURCE_BASE`.
    pub(crate) fn url(&self, kind: Kind) -> String {
        self.rewrite(self.urls.of(kind))
    }

    /// Rewrites a source URL with the base of these sources.
    pub(crate) fn rewrite(&self, url: &str) -> String {
        rewrite(self.base.as_deref(), url)
    }

    /// Returns the transport, whose egresses set the size of the RDAP
    /// window.
    pub(crate) fn transport(&self) -> &Arc<dyn Transport> {
        &self.transport
    }

    /// Loads, at once, the routes, `asn.txt`, and the delegated stats that
    /// `needs` asks for. The WHOIS dumps are not loaded here.
    ///
    /// With the cache, this opens or builds the indexes concurrently, so the
    /// downloads overlap. Without the cache, there is nothing to prepare.
    ///
    /// # Errors
    ///
    /// Returns the first error of [`Cache::load`] among the datasets: the
    /// source fails, the download is unusable, or the file system fails.
    pub(crate) async fn prepare(&self, needs: &Needs) -> Result<()> {
        if self.cache.is_none() {
            return Ok(());
        }
        let v4 = async {
            if needs.ris.contains(Family::V4) {
                self.ris_index(Family::V4, false).await?;
            }
            Ok::<_, Error>(())
        };
        let v6 = async {
            if needs.ris.contains(Family::V6) {
                self.ris_index(Family::V6, false).await?;
            }
            Ok::<_, Error>(())
        };
        let asn = async {
            if needs.asn {
                self.asn_index(false).await?;
            }
            Ok::<_, Error>(())
        };
        let stats = async {
            if needs.stats {
                futures_util::future::try_join_all(
                    Rir::ALL.map(|rir| self.stats_index(rir, false)),
                )
                .await?;
            }
            Ok::<_, Error>(())
        };
        futures_util::future::try_join4(v4, v6, asn, stats).await?;
        Ok(())
    }

    /// Answers a request on the routes of `family`.
    ///
    /// # Errors
    ///
    /// Returns an error if one of these happens:
    ///
    /// - The source fails or responds with a status other than 2xx.
    /// - The download is unusable, for example because it has no records.
    /// - The cache fails.
    /// - The index is still damaged after it was downloaded again.
    pub(crate) async fn routes(
        &self,
        family: Family,
        request: &RouteRequest,
    ) -> Result<RouteAnswer> {
        if self.cache.is_none() {
            let mut stream = RisStream::new(family, request);
            let kind = Kind::ris(family);
            self.stream(kind, &mut stream).await?;
            return stream.finish().map_err(|error| self.name(kind, error));
        }
        let index = self.ris_index(family, false).await?;
        match index.answer(request) {
            Ok(answer) => Ok(answer),
            Err(Corrupt) => {
                let index = self.ris_index(family, true).await?;
                index
                    .answer(request)
                    .map_err(|_| corrupt_again(Kind::ris(family)))
            }
        }
    }

    /// Returns every route of `families` with an origin in `asns`: IPv4
    /// first, then IPv6, each sorted by prefix.
    ///
    /// The tree (`-i`) calls it once for all its AS, to count their routes
    /// and to expand them without another request. The call costs one
    /// lookup in each index with the cache, and one pass over each dump
    /// without the cache.
    ///
    /// # Errors
    ///
    /// Returns the errors of [`Sources::routes`].
    pub(crate) async fn routes_of(
        &self,
        families: crate::addr::Families,
        asns: &crate::dataset::AsnSet,
    ) -> Result<Vec<crate::model::Route>> {
        let mut routes = Vec::new();
        if asns.is_empty() {
            return Ok(routes);
        }
        let request = RouteRequest {
            by_asn: asns.clone(),
            ..RouteRequest::default()
        };
        for family in families.iter() {
            routes.extend(self.routes(family, &request).await?.routes);
        }
        Ok(routes)
    }

    /// Answers a request on asn.txt.
    ///
    /// # Errors
    ///
    /// Returns the same errors as [`Sources::routes`], for asn.txt.
    pub(crate) async fn asns(&self, request: &AsnRequest) -> Result<AsnAnswer> {
        if self.cache.is_none() {
            let mut stream = AsnStream::new(request);
            self.stream(Kind::Asn, &mut stream).await?;
            return stream.finish().map_err(|error| self.name(Kind::Asn, error));
        }
        let index = self.asn_index(false).await?;
        match index.answer(request) {
            Ok(answer) => Ok(answer),
            Err(Corrupt) => {
                let index = self.asn_index(true).await?;
                index.answer(request).map_err(|_| corrupt_again(Kind::Asn))
            }
        }
    }

    /// Answers a request on the delegated stats of all five registries at
    /// once.
    ///
    /// With the cache, the answer comes from the five indexes, each loaded
    /// once per run. Without the cache, it comes from one pass over each
    /// file, with the files downloaded together. A request that asks for
    /// nothing reads no file.
    ///
    /// # Errors
    ///
    /// Returns the first error of [`Sources::stats_of`] among the five
    /// registries.
    pub(crate) async fn stats(&self, request: &StatsRequest) -> Result<StatsAnswer> {
        if request.is_empty() {
            return Ok(StatsAnswer::empty(request));
        }
        let answers =
            futures_util::future::try_join_all(Rir::ALL.map(|rir| self.stats_of(rir, request)))
                .await?;
        Ok(StatsAnswer::merge(answers))
    }

    /// Answers a request on the delegated stats of one registry.
    ///
    /// # Errors
    ///
    /// Returns the same errors as [`Sources::routes`], for the delegated
    /// stats of `rir`.
    pub(crate) async fn stats_of(&self, rir: Rir, request: &StatsRequest) -> Result<StatsAnswer> {
        let kind = Kind::Stats(rir);
        if self.cache.is_none() {
            let mut stream = StatsStream::new(request);
            self.stream(kind, &mut stream).await?;
            return stream.finish().map_err(|error| self.name(kind, error));
        }
        let index = self.stats_index(rir, false).await?;
        match index.answer(request) {
            Ok(answer) => Ok(answer),
            Err(Corrupt) => {
                let index = self.stats_index(rir, true).await?;
                index.answer(request).map_err(|_| corrupt_again(kind))
            }
        }
    }

    /// Searches the APNIC and AFRINIC database dumps at once.
    ///
    /// Finds networks and AS by maintainer, contact, and holder, with one
    /// list per condition and both registries merged. A request that asks
    /// for nothing reads no file.
    ///
    /// # Errors
    ///
    /// Returns the first error of [`Sources::whois_of`] for APNIC or
    /// AFRINIC.
    pub(crate) async fn whois(&self, request: &WhoisRequest) -> Result<WhoisAnswer> {
        if request.is_empty() {
            return Ok(WhoisAnswer::empty(request));
        }
        let (apnic, afrinic) = futures_util::future::try_join(
            self.whois_of(Rir::Apnic, request),
            self.whois_of(Rir::Afrinic, request),
        )
        .await?;
        Ok(WhoisAnswer::merge([apnic, afrinic]))
    }

    /// Searches the database dumps of one registry.
    ///
    /// A registry without a dump finds nothing. The steps are those of
    /// `dataset::whoisdb`: the organizations of the contacts, the records
    /// by every condition and by those organizations, and the holders of
    /// what was found. With the cache, every file is loaded once per run
    /// and asked. Without the cache, each step is one pass over a download.
    ///
    /// # Errors
    ///
    /// Returns the same errors as [`Sources::routes`], for any file of the
    /// database dumps of `rir`.
    pub(crate) async fn whois_of(&self, rir: Rir, request: &WhoisRequest) -> Result<WhoisAnswer> {
        let Some((records, orgs)) = whois_kinds(rir, request).filter(|_| !request.is_empty())
        else {
            return Ok(WhoisAnswer::empty(request));
        };
        let origin = match rir {
            Rir::Afrinic => RecordOrigin::AfrinicDb,
            _ => RecordOrigin::ApnicDb,
        };
        if self.cache.is_none() {
            return self
                .whois_streamed(rir, origin, &records, orgs, request)
                .await;
        }
        // Load every file first, so the downloads overlap.
        let mut kinds = records.clone();
        if !kinds.contains(&orgs) {
            kinds.push(orgs);
        }
        futures_util::future::try_join_all(kinds.iter().map(|kind| self.whois_index(*kind, false)))
            .await?;
        let step1 = self
            .whois_ask(orgs, |index| index.lookup(&org_lookup(request, false)))
            .await?;
        let plan = record_lookup(request, &step1.hits);
        let mut found = Found::empty(&plan.lookup);
        for kind in &records {
            found.merge(
                self.whois_ask(*kind, |index| index.lookup(&plan.lookup))
                    .await?,
            );
        }
        let holders = referenced_orgs(&found);
        let table = self
            .whois_ask(orgs, |index| index.organisations(&holders))
            .await?;
        Ok(assemble(request, &plan, &found, &table, rir, origin))
    }

    /// Answers a request without the cache.
    ///
    /// For APNIC, the answer takes a pass over the organizations, for the
    /// table of holders and the organizations of the contacts, and then a
    /// pass over each file of records. With contacts in the request, the
    /// passes over the records wait for the pass over the organizations,
    /// because the records whose `org` names an organization of a contact
    /// can be picked only once those organizations are known. Without
    /// contacts, all passes run together. AFRINIC has one file: one pass,
    /// or two if the request has contacts.
    async fn whois_streamed(
        &self,
        rir: Rir,
        origin: RecordOrigin,
        records: &[Kind],
        orgs: Kind,
        request: &WhoisRequest,
    ) -> Result<WhoisAnswer> {
        let records_of = |plan_lookup: &Lookup| {
            let plan_lookup = plan_lookup.clone();
            async move {
                let passes = records
                    .iter()
                    .map(|kind| self.whois_pass(*kind, &plan_lookup));
                let mut found = Found::empty(&plan_lookup);
                for more in futures_util::future::try_join_all(passes).await? {
                    found.merge(more);
                }
                Ok::<_, Error>(found)
            }
        };
        let (plan, found, table): (_, Found, Vec<WhoisRecord>) = if !request.contact.is_empty() {
            let step1 = self.whois_pass(orgs, &org_lookup(request, true)).await?;
            let plan = record_lookup(request, &step1.hits);
            let found = records_of(&plan.lookup).await?;
            (plan, found, step1.orgs)
        } else if records == [orgs] {
            let mut plan = record_lookup(request, &[]);
            plan.lookup.orgs = true;
            let mut found = self.whois_pass(orgs, &plan.lookup).await?;
            let table = std::mem::take(&mut found.orgs);
            (plan, found, table)
        } else {
            let plan = record_lookup(request, &[]);
            let table_lookup = Lookup {
                classes: Classes::ORGANISATION,
                queries: Vec::new(),
                orgs: true,
            };
            let (table, found) = futures_util::future::try_join(
                self.whois_pass(orgs, &table_lookup),
                records_of(&plan.lookup),
            )
            .await?;
            (plan, found, table.orgs)
        };
        Ok(assemble(request, &plan, &found, &table, rir, origin))
    }

    /// Makes one pass over a database dump for `lookup`.
    async fn whois_pass(&self, kind: Kind, lookup: &Lookup) -> Result<Found> {
        let mut stream = WhoisStream::new(lookup);
        self.stream(kind, &mut stream).await?;
        stream.finish().map_err(|error| self.name(kind, error))
    }

    /// Asks the index of `kind`.
    ///
    /// If the index is found damaged, rebuilds it and asks again.
    async fn whois_ask<T>(
        &self,
        kind: Kind,
        ask: impl Fn(&WhoisIndex) -> Result<T, Corrupt>,
    ) -> Result<T> {
        let index = self.whois_index(kind, false).await?;
        match ask(&index) {
            Ok(answer) => Ok(answer),
            Err(Corrupt) => {
                drop(index);
                let index = self.whois_index(kind, true).await?;
                ask(&index).map_err(|_| corrupt_again(kind))
            }
        }
    }

    /// Returns the index of a database dump, rebuilt if `rebuild` is
    /// set.
    async fn whois_index(&self, kind: Kind, rebuild: bool) -> Result<Arc<WhoisIndex>> {
        let slot = WHOIS_KINDS.iter().position(|k| *k == kind).unwrap_or(0);
        self.index(
            &self.whois[slot],
            kind,
            rebuild,
            WhoisBuilder::new,
            WhoisIndex::open,
        )
        .await
    }

    /// Returns the index of the delegated stats of `rir`, rebuilt if
    /// `rebuild` is set.
    async fn stats_index(&self, rir: Rir, rebuild: bool) -> Result<Arc<StatsIndex>> {
        let slot = Rir::ALL.iter().position(|r| *r == rir).unwrap_or(0);
        self.index(
            &self.stats[slot],
            Kind::Stats(rir),
            rebuild,
            StatsBuilder::new,
            StatsIndex::open,
        )
        .await
    }

    /// Returns the index of the RIS dump of `family`, rebuilt if `rebuild`
    /// is set.
    async fn ris_index(&self, family: Family, rebuild: bool) -> Result<Arc<RisIndex>> {
        let slot = match family {
            Family::V4 => &self.ris_v4,
            Family::V6 => &self.ris_v6,
        };
        self.index(
            slot,
            Kind::ris(family),
            rebuild,
            || RisBuilder::new(family),
            |file| RisIndex::open(file, family),
        )
        .await
    }

    /// Returns the index of asn.txt, rebuilt if `rebuild` is set.
    async fn asn_index(&self, rebuild: bool) -> Result<Arc<AsnIndex>> {
        self.index(
            &self.asn,
            Kind::Asn,
            rebuild,
            AsnBuilder::new,
            AsnIndex::open,
        )
        .await
    }

    /// Returns the index in `slot`, loading it through the cache first if
    /// there is none yet or if `rebuild` is set.
    ///
    /// The lock is held while loading, so concurrent requests for one
    /// dataset wait for one download instead of starting their own.
    async fn index<T, B: Builder>(
        &self,
        slot: &Mutex<Option<Arc<T>>>,
        kind: Kind,
        rebuild: bool,
        make: impl FnOnce() -> B,
        open: impl Fn(CacheFile) -> Result<T, Corrupt>,
    ) -> Result<Arc<T>> {
        let cache = self.cache.as_ref().expect("indexes only with the cache");
        let mut guard = slot.lock().await;
        if let Some(index) = guard.as_ref()
            && !rebuild
        {
            return Ok(index.clone());
        }
        // The old index must be closed before its file is replaced.
        *guard = None;
        let url = self.url(kind);
        let entry = Entry {
            name: kind.source().file,
            kind: kind.code(),
            url: &url,
        };
        let transport = self.transport.as_ref();
        let index = if rebuild {
            cache.reload(transport, &entry, make, open).await?
        } else {
            cache.load(transport, &entry, make, open).await?
        };
        let index = Arc::new(index);
        *guard = Some(index.clone());
        Ok(index)
    }

    /// Prefixes an error of a dataset's contents with its name and URL, as
    /// the cache does for the same error.
    fn name(&self, kind: Kind, error: Error) -> Error {
        error.with_prefix(format_args!("{}: {}", kind.source().file, self.url(kind)))
    }

    /// Downloads a dataset into `sink`, for the streaming backends.
    async fn stream(&self, kind: Kind, sink: &mut dyn LineSink) -> Result<()> {
        let url = self.url(kind);
        let class = Class::Dataset(kind.source().file);
        let Fetched::Body(body) = fetch::get(self.transport.as_ref(), &url, class, None).await?
        else {
            return Err(Error::runtime(format!(
                "{}: {url}: HTTP 304",
                kind.source().file
            )));
        };
        if !body.is_success() {
            return Err(body.status_error());
        }
        let modified = body.validators.last_modified.clone();
        body.lines(sink).await?;
        if let Some((reporter, clock)) = &self.reporting {
            reporter.source(crate::Source::new(
                Class::Dataset(kind.source().file),
                Some(clock.now()),
                modified,
            ));
        }
        Ok(())
    }
}

/// The error of a file found damaged right after it was rebuilt.
fn corrupt_again(kind: Kind) -> Error {
    Error::runtime(format!(
        "cache: {}: corrupt after downloading again",
        kind.source().file
    ))
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;
    use crate::{
        addr::{Families, Prefix, Range},
        dataset::AsnSet,
        dataset::stats::StatsRequest,
        fetch::testing::{Collect, FakeClock, Reply, Stub, TempDir, gzip},
        model::Route,
    };

    const BASE: &str = "http://127.0.0.1:9/";
    const RIS_V4: &str = "http://127.0.0.1:9/ris.ripe.test/dumps/riswhoisdump.IPv4.gz";
    const RIS_V6: &str = "http://127.0.0.1:9/ris.ripe.test/dumps/riswhoisdump.IPv6.gz";
    const ASN: &str = "http://127.0.0.1:9/ftp.ripe.test/ripe/asnames/asn.txt";

    const DUMP_V4: &[u8] = b"% synthetic\n64496\t192.0.2.0/24\t10\n64497\t192.0.2.0/24\t3\n\
        64498\t192.0.2.128/25\t2\n{64499,64500}\t198.51.100.0/24\t1\n";
    const DUMP_V6: &[u8] = b"64510\t2001:db8::/32\t4\n";
    const ASN_TXT: &[u8] = b"64496 EXAMPLE-AS Example LLC, XD\n64497 DOC-AS Doc, XE\n";

    fn stub() -> Arc<Stub> {
        let stub = Arc::new(Stub::new());
        stub.on(RIS_V4, Reply::status(200).chunked(&gzip(DUMP_V4), 9));
        stub.on(RIS_V6, Reply::ok(gzip(DUMP_V6)));
        stub.on(ASN, Reply::status(200).chunked(ASN_TXT, 4));
        stub
    }

    fn cached(stub: &Arc<Stub>, dir: &TempDir) -> (Sources, Arc<Collect>) {
        let reporter = Arc::new(Collect::default());
        let cache = Cache::new(
            dir.path().to_owned(),
            Duration::from_secs(86_400),
            Arc::new(FakeClock::new()),
            reporter.clone(),
        );
        let sources = Sources::new(stub.clone(), Some(cache), Some(BASE.into()), Urls::test());
        (sources, reporter)
    }

    fn request() -> RouteRequest {
        RouteRequest {
            by_asn: AsnSet::from_ranges([(64500, 64500)]),
            covering: vec![Range::from_addr("192.0.2.200".parse().unwrap())],
            ..RouteRequest::default()
        }
    }

    fn route(prefix: &str, origins: &[u32]) -> Route {
        Route {
            prefix: prefix.parse::<Prefix>().unwrap(),
            origins: origins.to_vec(),
        }
    }

    #[test]
    fn rewrites_urls() {
        let url = "https://ris.ripe.test/dumps/riswhoisdump.IPv4.gz";
        assert_eq!(rewrite(None, url), url);
        assert_eq!(rewrite(Some(BASE), url), RIS_V4);
        assert_eq!(rewrite(Some("http://127.0.0.1:9"), url), RIS_V4);
        assert_eq!(
            rewrite(
                Some("http://s"),
                "https://rest.ripe.test/search.json?query-string=X"
            ),
            "http://s/rest.ripe.test/search.json?query-string=X"
        );
        let mut env = Environment::default();
        assert_eq!(source_base(&env), None);
        env.vars.insert(SOURCE_BASE_VAR.into(), " ".into());
        assert_eq!(source_base(&env), None);
        env.vars.insert(SOURCE_BASE_VAR.into(), BASE.into());
        assert_eq!(source_base(&env).as_deref(), Some(BASE));
        let sources = Sources::new(Arc::new(Stub::new()), None, None, Urls::test());
        assert_eq!(
            sources.url(Kind::Asn),
            "https://ftp.ripe.test/ripe/asnames/asn.txt"
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn cached_and_streaming_agree() {
        let dir = TempDir::new("sources-agree");
        let stub = stub();
        let (sources, _) = cached(&stub, &dir);
        let cached = sources.routes(Family::V4, &request()).await.unwrap();
        // Loaded once: the second request uses the index.
        assert_eq!(
            sources.routes(Family::V4, &request()).await.unwrap(),
            cached
        );
        assert_eq!(stub.count(), 1);

        let streaming = Sources::new(stub.clone(), None, Some(BASE.into()), Urls::test());
        stub.on(RIS_V4, Reply::ok(gzip(DUMP_V4)));
        assert_eq!(
            streaming.routes(Family::V4, &request()).await.unwrap(),
            cached
        );
        assert_eq!(cached.routes, [route("198.51.100.0/24", &[64499, 64500])]);
        assert_eq!(cached.covering, [Some(route("192.0.2.128/25", &[64498]))]);

        let asns = AsnRequest {
            by_asn: AsnSet::from_ranges([(64497, 64497)]),
            ..AsnRequest::default()
        };
        let from_cache = sources.asns(&asns).await.unwrap();
        stub.on(ASN, Reply::ok(ASN_TXT));
        assert_eq!(streaming.asns(&asns).await.unwrap(), from_cache);
        assert_eq!(from_cache.entries[0].name, "DOC-AS");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn prepare_loads_only_what_is_needed() {
        let dir = TempDir::new("sources-lazy");
        let stub = stub();
        let (sources, _) = cached(&stub, &dir);
        let needs = Needs {
            ris: Families::V4,
            ..Needs::default()
        };
        sources.prepare(&needs).await.unwrap();
        let urls: Vec<String> = stub.log().into_iter().map(|r| r.url).collect();
        assert_eq!(urls, [RIS_V4]);
        let needs = Needs {
            ris: Families::BOTH,
            asn: true,
            ..Needs::default()
        };
        sources.prepare(&needs).await.unwrap();
        let mut urls: Vec<String> = stub.log().into_iter().map(|r| r.url).collect();
        urls.sort();
        assert_eq!(urls, [ASN, RIS_V4, RIS_V6]);
        // Streaming prepares nothing.
        let streaming = Sources::new(stub.clone(), None, Some(BASE.into()), Urls::test());
        streaming.prepare(&needs).await.unwrap();
        assert_eq!(stub.count(), 3);
        assert!(streaming.is_streaming());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn damage_found_by_a_query_rebuilds_the_index() {
        let dir = TempDir::new("sources-reload");
        let stub = stub();
        let (sources, _) = cached(&stub, &dir);
        sources
            .prepare(&Needs {
                ris: Families::V4,
                ..Needs::default()
            })
            .await
            .unwrap();
        drop(sources);
        // Make route 2 (198.51.100.0/24) its own parent, in a new file with
        // the same validators and mtime: the damage passes the open checks
        // and is found only by a lookup that walks the parents.
        let path = dir.path().join("ris-v4.bin");
        let mut bytes = std::fs::read(&path).unwrap();
        let layout = crate::cache::container::Layout::parse(&bytes).unwrap();
        let routes = layout.section(&bytes, 1).unwrap();
        let at = routes.as_ptr() as usize - bytes.as_ptr() as usize + 2 * 16 + 12;
        bytes[at..at + 4].copy_from_slice(&2u32.to_le_bytes());
        let mtime = std::fs::metadata(&path).unwrap().modified().unwrap();
        let next = dir.path().join("damaged");
        std::fs::write(&next, &bytes).unwrap();
        std::fs::File::options()
            .write(true)
            .open(&next)
            .unwrap()
            .set_modified(mtime)
            .unwrap();
        std::fs::rename(&next, &path).unwrap();
        // A new run opens the damaged file without downloading.
        let (sources, reporter) = cached(&stub, &dir);
        let request = RouteRequest {
            covering: vec![
                Range::from_addr("203.0.113.1".parse().unwrap()),
                Range::from_prefix("192.0.2.128/26".parse().unwrap()),
            ],
            ..RouteRequest::default()
        };
        sources
            .prepare(&Needs {
                ris: Families::V4,
                ..Needs::default()
            })
            .await
            .unwrap();
        assert_eq!(stub.count(), 1);
        assert!(reporter.lines().is_empty());
        stub.on(RIS_V4, Reply::ok(gzip(DUMP_V4)));
        let answer = sources.routes(Family::V4, &request).await.unwrap();
        assert_eq!(
            answer.covering,
            [None, Some(route("192.0.2.128/25", &[64498]))]
        );
        assert_eq!(
            reporter.lines(),
            ["netf: cache: ris-v4: corrupt, downloading again"]
        );
        assert_eq!(stub.count(), 2);
    }

    /// Synthetic delegated stats, one file per registry.
    fn stats_files() -> [(Rir, &'static str); 5] {
        [
            (
                Rir::Afrinic,
                "2|afrinic|1|1|2|3|+0000\nafrinic||ipv4|203.0.113.0|256||available|\n",
            ),
            (
                Rir::Apnic,
                "apnic|XK|ipv4|192.0.2.0|128|20100101|allocated|A-1\n\
                 apnic|XK|asn|64500|2|20100101|assigned|A-1\n",
            ),
            (
                Rir::Arin,
                "arin|XE|ipv4|192.0.2.0|256|20100101|allocated|org-x\n\
                 arin|XE|ipv6|2001:db8::|32|20100101|allocated|org-x\n",
            ),
            (Rir::Lacnic, "lacnic|XH|asn|64510|2|20100101|assigned|\n"),
            (
                Rir::Ripencc,
                "ripencc|XD|ipv4|198.18.0.0|384|20100101|allocated|ORG-X\n\
                 ripencc|XD|asn|64496|4|20100101|assigned|org-x\n",
            ),
        ]
    }

    /// Queues one download of each stats file, `broken` served as HTML.
    fn serve_stats(stub: &Stub, sources: &Sources, broken: Option<Rir>) {
        for (rir, text) in stats_files() {
            let url = sources.url(Kind::Stats(rir));
            if broken == Some(rir) {
                stub.on(&url, Reply::ok("<html>maintenance</html>"));
            } else {
                stub.on(&url, Reply::status(200).chunked(text.as_bytes(), 7));
            }
        }
    }

    fn stats_stub(sources: &Sources) -> Arc<Stub> {
        let stub = Arc::new(Stub::new());
        serve_stats(&stub, sources, None);
        stub
    }

    fn stats_request() -> StatsRequest {
        StatsRequest {
            covering: vec![
                Range::from_addr("192.0.2.1".parse().unwrap()),
                Range::from_addr("192.0.2.200".parse().unwrap()),
                Range::from_addr("203.0.113.1".parse().unwrap()),
            ],
            by_opaque: vec!["org-x".into()],
            asn: AsnSet::from_ranges([(64499, 64501)]),
            as_by_rir: vec![Rir::Lacnic],
            ..StatsRequest::default()
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn stats_of_five_registries_cached_and_streaming() {
        let dir = TempDir::new("sources-stats");
        let urls = Sources::new(Arc::new(Stub::new()), None, Some(BASE.into()), Urls::test());
        let stub = stats_stub(&urls);
        let (sources, _) = cached(&stub, &dir);
        let cached = sources.stats(&stats_request()).await.unwrap();
        // Each index is loaded once per run.
        assert_eq!(sources.stats(&stats_request()).await.unwrap(), cached);
        assert_eq!(stub.count(), 5);
        let streaming = Sources::new(stub.clone(), None, Some(BASE.into()), Urls::test());
        serve_stats(&stub, &streaming, None);
        assert_eq!(streaming.stats(&stats_request()).await.unwrap(), cached);
        assert_eq!(stub.count(), 10);

        // The narrowest block of all five. None in an available block.
        let covering: Vec<Option<(Rir, String)>> = cached
            .covering
            .iter()
            .map(|b| b.as_ref().map(|b| (b.rir, b.range.to_string())))
            .collect();
        assert_eq!(
            covering,
            [
                Some((Rir::Apnic, "192.0.2.0/25".into())),
                Some((Rir::Arin, "192.0.2.0/24".into())),
                None,
            ]
        );
        let blocks: Vec<(Rir, String)> = cached
            .blocks
            .iter()
            .map(|b| (b.rir, b.range.to_string()))
            .collect();
        assert_eq!(
            blocks,
            [
                (Rir::Arin, "192.0.2.0/24".into()),
                (Rir::Ripencc, "198.18.0.0-198.18.1.127".into()),
                (Rir::Arin, "2001:db8::/32".into()),
            ]
        );
        let ases: Vec<(u32, Rir)> = cached.as_blocks.iter().map(|b| (b.first, b.rir)).collect();
        assert_eq!(
            ases,
            [
                (64496, Rir::Ripencc),
                (64500, Rir::Apnic),
                (64510, Rir::Lacnic)
            ]
        );

        // One registry alone. A request for nothing reads nothing.
        let arin = sources.stats_of(Rir::Arin, &stats_request()).await.unwrap();
        assert_eq!(arin.blocks.len(), 2);
        let empty = StatsRequest {
            covering: vec![Range::from_addr("192.0.2.1".parse().unwrap())],
            ..StatsRequest::default()
        };
        let before = stub.count();
        let fresh = Sources::new(stub.clone(), None, Some(BASE.into()), Urls::test());
        assert_eq!(
            fresh
                .stats(&StatsRequest {
                    covering: Vec::new(),
                    ..empty.clone()
                })
                .await
                .unwrap(),
            StatsAnswer::default()
        );
        assert_eq!(stub.count(), before);
        serve_stats(&stub, &fresh, None);
        assert_eq!(fresh.stats(&empty).await.unwrap().covering.len(), 1);
        assert_eq!(stub.count(), before + 5);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn prepare_loads_the_five_stats() {
        let dir = TempDir::new("sources-stats-prepare");
        let urls = Sources::new(Arc::new(Stub::new()), None, Some(BASE.into()), Urls::test());
        let stub = stats_stub(&urls);
        let (sources, _) = cached(&stub, &dir);
        sources
            .prepare(&Needs {
                stats: true,
                ..Needs::default()
            })
            .await
            .unwrap();
        let mut got: Vec<String> = stub.log().into_iter().map(|r| r.url).collect();
        got.sort();
        let mut want: Vec<String> = Rir::ALL
            .iter()
            .map(|rir| urls.url(Kind::Stats(*rir)))
            .collect();
        want.sort();
        assert_eq!(got, want);
        sources.stats(&stats_request()).await.unwrap();
        assert_eq!(stub.count(), 5);
        assert!(dir.path().join("stats-ripencc.bin").exists());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn stats_errors_name_the_file() {
        let stub = Arc::new(Stub::new());
        let streaming = Sources::new(stub.clone(), None, Some(BASE.into()), Urls::test());
        serve_stats(&stub, &streaming, Some(Rir::Lacnic));
        let lacnic = streaming.url(Kind::Stats(Rir::Lacnic));
        let error = streaming.stats(&stats_request()).await.unwrap_err();
        assert_eq!(
            error.to_string(),
            format!("netf: stats-lacnic: {lacnic}: no records in the file")
        );
        let dir = TempDir::new("sources-stats-error");
        let (sources, _) = cached(&stub, &dir);
        serve_stats(&stub, &sources, Some(Rir::Lacnic));
        let error = sources.stats(&stats_request()).await.unwrap_err();
        assert!(
            error.to_string().contains("stats-lacnic") && error.to_string().contains("no records"),
            "{error}"
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn errors_name_the_dataset() {
        let stub = Arc::new(Stub::new());
        stub.on(ASN, Reply::status(404));
        let sources = Sources::new(stub.clone(), None, Some(BASE.into()), Urls::test());
        let error = sources.asns(&AsnRequest::default()).await.unwrap_err();
        assert_eq!(error.to_string(), format!("netf: asn: {ASN}: HTTP 404"));
        stub.on(RIS_V6, Reply::ok("<html>not a dump</html>"));
        let error = sources
            .routes(Family::V6, &RouteRequest::default())
            .await
            .unwrap_err();
        assert_eq!(
            error.to_string(),
            format!("netf: ris-v6: {RIS_V6}: no routes in the dump")
        );
    }

    const APNIC_INETNUM: &str = "http://127.0.0.1:9/ftp.apnic.test/apnic/whois/apnic.db.inetnum.gz";
    const APNIC_INET6NUM: &str =
        "http://127.0.0.1:9/ftp.apnic.test/apnic/whois/apnic.db.inet6num.gz";
    const APNIC_AUT_NUM: &str = "http://127.0.0.1:9/ftp.apnic.test/apnic/whois/apnic.db.aut-num.gz";
    const APNIC_ORGANISATION: &str =
        "http://127.0.0.1:9/ftp.apnic.test/apnic/whois/apnic.db.organisation.gz";
    const AFRINIC_DB: &str = "http://127.0.0.1:9/ftp.afrinic.test/dbase/afrinic.db.gz";

    const INETNUM: &str = "inetnum: 192.0.2.0 - 192.0.2.255\nnetname: EXAMPLE-NET\n\
        org: ORG-EX1-AP\nmnt-by: MAINT-EXAMPLE\n\n\
        inetnum: 198.51.100.0 - 198.51.100.255\nnetname: OTHER-NET\nmnt-by: MAINT-OTHER\n";
    const INET6NUM: &str = "inet6num: 2001:db8::/32\nnetname: EXAMPLE-V6\nmnt-by: MAINT-EXAMPLE\n";
    const AUT_NUM: &str = "aut-num: AS64496\nas-name: EXAMPLE-AS\norg: ORG-EX1-AP\n\
        mnt-by: MAINT-OTHER\n";
    const ORGANISATION: &str = "organisation: ORG-EX1-AP\norg-name: Example Pty\n\
        abuse-c: IRT1-AP\nmnt-by: MAINT-EXAMPLE\n";
    const AFRINIC: &str = "inetnum: 203.0.113.0 - 203.0.113.255\nnetname: AF-NET\n\
        org: ORG-AF1-AFRINIC\nmnt-by: EXAMPLE-AF-HM-MNT\nmnt-lower: MAINT-EXAMPLE\n\n\
        person: John Doe\nnic-hdl: JD1-AFRINIC\n\n\
        organisation: ORG-AF1-AFRINIC\norg-name: Example Afrique\nabuse-c: IRT1-AP\n\n\
        aut-num: AS64500\nmnt-by: EXAMPLE-AF-HM-MNT\norg: ORG-AF1-AFRINIC\n";

    fn serve_whois(stub: &Stub) {
        stub.on(
            APNIC_INETNUM,
            Reply::status(200).chunked(&gzip(INETNUM.as_bytes()), 7),
        );
        stub.on(APNIC_INET6NUM, Reply::ok(gzip(INET6NUM.as_bytes())));
        stub.on(APNIC_AUT_NUM, Reply::ok(gzip(AUT_NUM.as_bytes())));
        stub.on(APNIC_ORGANISATION, Reply::ok(gzip(ORGANISATION.as_bytes())));
        stub.on(
            AFRINIC_DB,
            Reply::status(200).chunked(&gzip(AFRINIC.as_bytes()), 5),
        );
    }

    fn whois_request() -> WhoisRequest {
        WhoisRequest {
            mnt: vec!["maint-example".into()],
            contact: vec![(Some(crate::model::Role::Abuse), "IRT1-AP".into())],
            org: vec!["ORG-EX1-AP".into()],
            families: Families::BOTH,
            autnums: true,
        }
    }

    fn handles(found: &crate::dataset::whoisdb::WhoisFound) -> Vec<String> {
        found
            .networks
            .iter()
            .map(|n| n.handle.clone())
            .chain(found.autnums.iter().map(|a| format!("AS{}", a.asn)))
            .collect()
    }

    #[tokio::test(flavor = "current_thread")]
    async fn whois_cached_and_streaming_agree() {
        let dir = TempDir::new("sources-whois");
        let stub = Arc::new(Stub::new());
        serve_whois(&stub);
        let (sources, _) = cached(&stub, &dir);
        let answer = sources.whois(&whois_request()).await.unwrap();
        assert_eq!(stub.count(), 5);
        // Loaded once per run.
        assert_eq!(sources.whois(&whois_request()).await.unwrap(), answer);
        assert_eq!(stub.count(), 5);
        assert_eq!(
            handles(&answer.mnt[0]),
            [
                "192.0.2.0 - 192.0.2.255",
                "203.0.113.0 - 203.0.113.255",
                "2001:db8::/32"
            ]
        );
        // The abuse contact of the holders, in both registries.
        assert_eq!(
            handles(&answer.contact[0]),
            [
                "192.0.2.0 - 192.0.2.255",
                "203.0.113.0 - 203.0.113.255",
                "AS64496",
                "AS64500"
            ]
        );
        assert_eq!(
            handles(&answer.org[0]),
            ["192.0.2.0 - 192.0.2.255", "AS64496"]
        );
        let net = &answer.mnt[0].networks[1];
        assert_eq!(
            (net.rir, net.origin),
            (Rir::Afrinic, RecordOrigin::AfrinicDb)
        );
        assert_eq!(
            net.org.as_ref().and_then(|o| o.name.as_deref()),
            Some("Example Afrique")
        );
        assert_eq!(answer.mnt[0].networks[0].origin, RecordOrigin::ApnicDb);

        // Without the cache: the same answer, each file read once for a
        // request without contacts, AFRINIC twice with contacts.
        let streaming = Sources::new(stub.clone(), None, Some(BASE.into()), Urls::test());
        serve_whois(&stub);
        stub.on(AFRINIC_DB, Reply::ok(gzip(AFRINIC.as_bytes())));
        assert_eq!(streaming.whois(&whois_request()).await.unwrap(), answer);
        assert_eq!(stub.count(), 11);
        let no_contacts = WhoisRequest {
            contact: Vec::new(),
            families: Families::V4,
            autnums: false,
            ..whois_request()
        };
        let from_cache = sources.whois(&no_contacts).await.unwrap();
        assert_eq!(stub.count(), 11);
        stub.on(APNIC_INETNUM, Reply::ok(gzip(INETNUM.as_bytes())));
        stub.on(APNIC_ORGANISATION, Reply::ok(gzip(ORGANISATION.as_bytes())));
        stub.on(AFRINIC_DB, Reply::ok(gzip(AFRINIC.as_bytes())));
        assert_eq!(streaming.whois(&no_contacts).await.unwrap(), from_cache);
        assert_eq!(stub.count(), 14);
        // Registries without a dump and empty requests read nothing.
        assert!(
            sources
                .whois_of(Rir::Ripencc, &whois_request())
                .await
                .unwrap()
                .mnt[0]
                .networks
                .is_empty()
        );
        let empty = WhoisRequest {
            families: Families::NONE,
            autnums: false,
            ..whois_request()
        };
        assert_eq!(
            streaming.whois(&empty).await.unwrap(),
            WhoisAnswer::empty(&empty)
        );
        assert_eq!(stub.count(), 14);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn whois_errors_name_the_file() {
        let stub = Arc::new(Stub::new());
        stub.on(APNIC_INETNUM, Reply::ok(gzip(b"<html>moved</html>\n")));
        stub.on(APNIC_ORGANISATION, Reply::ok(gzip(ORGANISATION.as_bytes())));
        let sources = Sources::new(stub.clone(), None, Some(BASE.into()), Urls::test());
        let request = WhoisRequest {
            mnt: vec!["MAINT-EXAMPLE".into()],
            families: Families::V4,
            ..WhoisRequest::default()
        };
        let error = sources.whois_of(Rir::Apnic, &request).await.unwrap_err();
        assert_eq!(
            error.to_string(),
            format!("netf: whois-apnic-inetnum: {APNIC_INETNUM}: no records in the dump")
        );
    }
}
