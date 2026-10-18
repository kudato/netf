//! The candidates of a selection: the rows that the generator produces, a
//! superset of the matching rows.
//!
//! Everything a selection needs from one dataset is asked in one request,
//! because without the cache every request downloads the dataset again.
//! [`find`] asks in an order fixed by the dependencies:
//!
//! 1. asn.txt, if the generator searches names or countries: the numbers
//!    of the matching AS. Without the cache the whole file is kept, so it
//!    is not downloaded a second time for the names of the rows.
//! 2. The stats: the blocks of the countries, registries, and holder ids
//!    of the generator, and the AS blocks of its registries and holder ids.
//! 3. The registries, all at once: the organizations by handle and by
//!    name, and the maintainers and contacts by reverse search. If RDAP
//!    leaves the list of an organization empty or cuts it short, the RIPE
//!    REST API and the APNIC and AFRINIC dumps give the rest.
//! 4. RIS, one request per family of the run, all at once: the routes of
//!    the generator, and the most specific route covering every positive
//!    `ip:` and every `route: <ip>` of the query. The predicate reads these
//!    routes from [`Facts`] for any generator.
//! 5. asn.txt for the origins of the routes, unless already known.
//! 6. The stats of the candidates, for `net.*` and `as.rir`.
//!
//! The addresses that no route covers, from an `ip:` or from a network of
//! the generator, become rows without a route.
//!
//! [`Facts`]: crate::plan::eval::Facts

use std::{
    cmp::Reverse,
    collections::{BTreeSet, HashMap, HashSet},
    sync::Arc,
};

use futures_util::future::{try_join, try_join_all, try_join3};

use super::{Engine, intervals::Intervals};
use crate::{
    addr::{Families, Family, Prefix, Range, set::AddrSet},
    dataset::{
        AsnSet,
        asn::AsnRequest,
        ris::RouteRequest,
        stats::StatsRequest,
        whoisdb::{WhoisAnswer, WhoisFound, WhoisRequest},
    },
    error::Result,
    model::{
        AsBlock, AsInfo, AsRecord, Asn, AsnEntry, Block, NetCandidate, Org, Rir, Role, Route, Row,
    },
    plan::{
        self, Generator, HandleKind, HandleSeed, NameSeed, OrgSeed, OrgSide, Seeds, eval::OrgFacts,
    },
    query::{
        Expr,
        expr::{AsnMatch, Leaf, OrgMatch, RouteMatch},
    },
    report::Notice,
    text::Pattern,
};

/// The asn.txt lines by number.
pub(crate) type Entries = HashMap<Asn, AsnEntry>;

/// The sort key of a range: family, first address, wider first.
pub(crate) fn key(range: Range) -> (Family, u128, Reverse<u128>) {
    (range.family(), range.first(), Reverse(range.last()))
}

/// A candidate without a route: addresses of an `ip:` or of a network of
/// the generator that no route covers.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct Unrouted {
    /// The part: the `ip:` kept whole, or a CIDR of a rest. `None` for a
    /// network left whole.
    pub(crate) part: Option<Range>,
    /// The network left whole: the first network of the row, its base.
    pub(crate) net: Option<NetCandidate>,
}

impl Unrouted {
    /// Returns the addresses of the candidate.
    fn range(&self) -> Option<Range> {
        self.part
            .or_else(|| self.net.as_ref().map(NetCandidate::range))
    }
}

/// What the datasets answered for a selection.
#[derive(Debug, Default)]
pub(crate) struct Found {
    /// The candidate routes, in address order, without duplicates.
    routes: Vec<Route>,
    /// Addresses no route covers, in address order: candidates without a
    /// route.
    unrouted: Vec<Unrouted>,
    /// The covering routes of the `ip:` prefixes and `route: <ip>`
    /// addresses, for the predicate.
    pub(crate) cover: HashMap<Prefix, Option<Prefix>>,
    /// The organizations looked up, for the predicate.
    pub(crate) orgs: HashMap<(OrgSide, String), OrgFacts>,
    /// The organizations looked up by name, for the predicate.
    pub(crate) org_names: HashMap<(OrgSide, Pattern), OrgFacts>,
    /// The maintainers and contacts searched in reverse, for the
    /// predicate.
    pub(crate) handles: HashMap<(OrgSide, HandleKind, String), OrgFacts>,
    /// The asn.txt lines of the AS involved.
    entries: Entries,
    /// The numbers of `as.asn: N` that the generator looked up, for the
    /// `no networks` notice. Ranges of numbers are not reported.
    ones: Vec<Asn>,
    /// The origins of the routes found.
    origins: HashSet<Asn>,
    /// The `as.name` patterns searched in asn.txt, and whether any AS
    /// matched. Operands without a field are reported as a whole instead.
    names: Vec<(Pattern, bool)>,
    /// The notices of the organization conditions that found nothing.
    empty_orgs: Vec<Notice>,
    /// The registry networks of the candidates: stats blocks and records
    /// of the organizations looked up.
    nets: Intervals<NetCandidate>,
    /// The AS blocks of the stats, by first number.
    as_blocks: Vec<AsBlock>,
}

impl Found {
    /// Keeps the notice of an organization condition that found nothing.
    ///
    /// The notice is `not found` unless the organization is `known`, and
    /// `notice` otherwise. A `quiet` condition keeps no notice.
    fn empty_org(
        &mut self,
        quiet: bool,
        known: bool,
        side: OrgSide,
        value: &str,
        notice: Option<Notice>,
    ) {
        if quiet {
            return;
        }
        let notice = if known {
            notice
        } else {
            Some(Notice::OrgNotFound {
                field: side.field(),
                value: value.to_owned(),
            })
        };
        if let Some(notice) = notice
            && !self.empty_orgs.contains(&notice)
        {
            self.empty_orgs.push(notice);
        }
    }

    /// Returns the candidate rows in address order, with the routes and the
    /// addresses without a route merged.
    pub(crate) fn candidates(&self) -> impl Iterator<Item = Row> + '_ {
        let mut routes = self
            .routes
            .iter()
            .map(|route| self.route_row(route))
            .peekable();
        let mut unrouted = self
            .unrouted
            .iter()
            .map(|rest| self.unrouted_row(rest))
            .peekable();
        std::iter::from_fn(move || {
            let take_route = match (routes.peek(), unrouted.peek()) {
                (Some(route), Some(rest)) => route.key() <= rest.key(),
                (Some(_), None) => true,
                (None, Some(_)) => false,
                (None, None) => return None,
            };
            if take_route {
                routes.next()
            } else {
                unrouted.next()
            }
        })
    }

    /// Returns the candidate row of a route, with the asn.txt lines and
    /// stats of its AS and the networks it intersects.
    fn route_row(&self, route: &Route) -> Row {
        Row {
            ases: route
                .origins
                .iter()
                .map(|asn| AsInfo {
                    asn: *asn,
                    entry: self.entries.get(asn).cloned(),
                    block: self.as_block(*asn).cloned(),
                    rdap: None,
                })
                .collect(),
            nets: self.nets_of(route.prefix.range()),
            route: Some(route.clone()),
            ..Row::default()
        }
    }

    /// Returns the candidate row of addresses without a route.
    fn unrouted_row(&self, rest: &Unrouted) -> Row {
        let mut nets: Vec<NetCandidate> = rest.net.iter().cloned().collect();
        if let Some(range) = rest.range() {
            for net in self.nets_of(range) {
                if !nets.contains(&net) {
                    nets.push(net);
                }
            }
        }
        Row {
            part: rest.part,
            nets,
            ..Row::default()
        }
    }

    /// Returns the networks that share an address with `range`.
    fn nets_of(&self, range: Range) -> Vec<NetCandidate> {
        self.nets
            .intersecting(range)
            .into_iter()
            .map(|(_, net)| net.clone())
            .collect()
    }

    /// Returns the AS block that holds `asn`.
    fn as_block(&self, asn: Asn) -> Option<&AsBlock> {
        let next = self.as_blocks.partition_point(|block| block.last < asn);
        self.as_blocks.get(next).filter(|block| block.first <= asn)
    }

    /// Reports what found nothing: `as.name` patterns without AS, numbers
    /// without routes, organizations without resources, and operands
    /// without a field that match no row.
    pub(crate) fn report(&self, engine: &Engine<'_>, bare: &[Bare<'_>]) {
        for notice in &self.empty_orgs {
            engine.notice(notice.clone());
        }
        for (pattern, found) in &self.names {
            if !found {
                engine.notice(Notice::NoAs {
                    pattern: pattern_text(pattern),
                });
            }
        }
        for asn in &self.ones {
            if self.origins.contains(asn) {
                continue;
            }
            engine.notice(match (engine.rows_mode, self.entries.get(asn)) {
                (true, Some(entry)) => Notice::NoNetworks {
                    asn: *asn,
                    entry: Some(entry.raw.clone()),
                },
                (true, None) => Notice::UnknownAs { asn: *asn },
                (false, _) => Notice::NoNetworks {
                    asn: *asn,
                    entry: None,
                },
            });
        }
        for bare in bare {
            if !bare.found {
                engine.notice(Notice::NothingFound {
                    word: bare.word.to_owned(),
                });
            }
        }
    }
}

/// An operand without a field, and whether it matched a candidate.
///
/// An operand that matched no candidate gets the notice
/// `netf: <word>: nothing found`.
#[derive(Debug)]
pub(crate) struct Bare<'e> {
    /// The word as written.
    pub(crate) word: &'e str,
    /// Its expansion.
    pub(crate) inner: &'e Expr,
    /// Whether it matched a candidate.
    pub(crate) found: bool,
}

/// Returns the operands without a field in `expr`.
pub(crate) fn bare(expr: &Expr) -> Vec<Bare<'_>> {
    fn walk<'e>(expr: &'e Expr, out: &mut Vec<Bare<'e>>) {
        match expr {
            Expr::Bare { word, inner } => out.push(Bare {
                word,
                inner,
                found: false,
            }),
            Expr::Or(items) | Expr::And(items) => items.iter().for_each(|item| walk(item, out)),
            Expr::Not(inner) => walk(inner, out),
            Expr::Leaf(_) | Expr::False => {}
        }
    }
    let mut out = Vec::new();
    walk(expr, &mut out);
    out
}

/// Returns the text of a pattern as written, for notices.
fn pattern_text(pattern: &Pattern) -> String {
    match pattern {
        Pattern::Exact(text) => text.clone(),
        Pattern::Glob(glob) => glob.source().to_owned(),
        Pattern::Any => "*".to_owned(),
    }
}

/// The leaves of an expression that the requests depend on for any
/// generator.
#[derive(Debug, Default)]
struct Leaves {
    /// Prefixes whose covering route the predicate needs: positive `ip:`,
    /// and `route: <ip>` as host prefixes.
    cover: Vec<Prefix>,
    /// The prefixes of positive `ip:`.
    ips: Vec<Prefix>,
    /// The `as.name` patterns of operands without a field.
    bare_names: Vec<Pattern>,
}

impl Leaves {
    fn of(expr: &Expr) -> Self {
        let mut leaves = Self::default();
        leaves.walk(expr, true, false);
        leaves
    }

    fn walk(&mut self, expr: &Expr, positive: bool, bare: bool) {
        match expr {
            Expr::Or(items) | Expr::And(items) => {
                for item in items {
                    self.walk(item, positive, bare);
                }
            }
            Expr::Not(inner) => self.walk(inner, !positive, bare),
            Expr::Bare { inner, .. } => self.walk(inner, positive, true),
            Expr::Leaf(Leaf::Ip(range)) if positive => {
                for prefix in range.prefixes() {
                    self.cover.push(prefix);
                    self.ips.push(prefix);
                }
            }
            Expr::Leaf(Leaf::Route(RouteMatch::Covering(addr))) => {
                self.cover.push(Prefix::host(*addr));
            }
            Expr::Leaf(Leaf::AsName(pattern)) if bare => self.bare_names.push(pattern.clone()),
            Expr::Leaf(_) | Expr::False => {}
        }
    }
}

/// Asks the datasets for the candidates of `expr`.
///
/// If `want_asn` is set, also loads the asn.txt lines of the origins, for
/// `as.*` conditions on co-origins and for the AS column.
///
/// # Errors
///
/// Returns an error if a source, a registry, or the RIPE REST API fails.
pub(crate) async fn find(engine: &Engine<'_>, expr: &Expr, want_asn: bool) -> Result<Found> {
    let sources = engine.sources;
    let generator = plan::generator(expr);
    let leaves = Leaves::of(expr);
    let (seeds, universe) = match generator {
        Generator::Seeds(seeds) => (*seeds, false),
        Generator::Universe => (Seeds::default(), true),
    };
    let mut found = Found::default();

    // 1. asn.txt: the AS of names and countries.
    let mut origins: Vec<(Asn, Asn)> = seeds
        .asns
        .iter()
        .filter_map(|matcher| match *matcher {
            AsnMatch::One(asn) => {
                found.ones.push(asn);
                Some((asn, asn))
            }
            AsnMatch::Range { min, max } => Some((min, max)),
            AsnMatch::Any => None,
        })
        .collect();
    let mut complete = false;
    if !seeds.names.is_empty() || !seeds.countries.is_empty() {
        let request = if sources.is_streaming() {
            AsnRequest {
                all: true,
                ..AsnRequest::default()
            }
        } else {
            AsnRequest {
                name: seeds.names.clone(),
                country: seeds.countries.clone(),
                ..AsnRequest::default()
            }
        };
        let answer = sources.asns(&request).await?;
        complete = sources.is_streaming();
        for entry in answer.entries {
            let named = seeds.names.iter().any(|name| name.matches(&entry.name));
            let located = entry
                .country
                .is_some_and(|cc| seeds.countries.contains(&cc));
            if named || located {
                origins.push((entry.asn, entry.asn));
            }
            found.entries.insert(entry.asn, entry);
        }
        found.names = seeds
            .names
            .iter()
            .filter(|name| !leaves.bare_names.contains(name))
            .map(|name| {
                let any = found
                    .entries
                    .values()
                    .any(|entry| name.matches(&entry.name));
                (name.clone(), any)
            })
            .collect();
    }

    // 2. The stats: blocks of countries, registries, and holder ids.
    let mut networks = Networks::default();
    let opaque = |side: OrgSide| -> Vec<Arc<str>> {
        seeds
            .orgs
            .iter()
            .filter(|seed| seed.side == side)
            .map(|seed| Arc::from(seed.handle.as_str()))
            .collect()
    };
    let request = StatsRequest {
        by_cc: seeds.net_cc.clone(),
        by_rir: seeds.net_rir.clone(),
        by_opaque: opaque(OrgSide::Net),
        all_blocks: seeds.net_all || (universe && plan::unannounced(expr)),
        as_by_rir: seeds.as_rir.clone(),
        as_by_opaque: opaque(OrgSide::As),
        all_as: seeds.as_all,
        ..StatsRequest::default()
    };
    let seeded = engine.stats.answer(sources, &request).await?;
    let seeded_blocks: Vec<Block> = seeded
        .blocks
        .into_iter()
        .filter(|block| engine.families.contains(block.range.family()))
        .collect();
    for block in &seeded_blocks {
        networks.source(NetCandidate::Block(block.clone()));
    }
    for block in &seeded.as_blocks {
        origins.push((block.first, block.last));
    }
    networks.as_blocks.extend(seeded.as_blocks.iter().cloned());

    // 3. The registries, all at once: the organizations by handle and by
    // name, and the maintainers and contacts by reverse search.
    let (orgs, named, (request, reverse)) = try_join3(
        lookup(engine, &seeds.orgs),
        names(engine, &seeds.org_names),
        reverse(engine, &seeds.handles),
    )
    .await?;
    // RDAP may leave the lists of these organizations empty or cut them
    // short, so `fallback` finds what RDAP left out.
    let mut held: Vec<(OrgSide, &Org)> = Vec::new();
    for seed in &seeds.orgs {
        let of = orgs.get(&seed.handle.to_uppercase());
        held.extend(of.into_iter().flatten().map(|org| (seed.side, org)));
    }
    for seed in &seeds.org_names {
        let of = named.get(&seed.pattern);
        held.extend(of.into_iter().flatten().map(|org| (seed.side, org)));
    }
    let extra = fallback(engine, held).await?;
    for seed in &seeds.orgs {
        let held = orgs
            .get(&seed.handle.to_uppercase())
            .map_or(&[][..], Vec::as_slice);
        let facts = found
            .orgs
            .entry((seed.side, seed.handle.to_uppercase()))
            .or_default();
        let opaque_of = |id: &Option<Arc<str>>| {
            id.as_deref()
                .is_some_and(|id| id.eq_ignore_ascii_case(&seed.handle))
        };
        let notice = match seed.side {
            OrgSide::Net => {
                let blocks: Vec<&Block> = seeded_blocks
                    .iter()
                    .filter(|block| opaque_of(&block.opaque_id))
                    .collect();
                facts.ranges.extend(blocks.iter().map(|block| block.range));
                let any =
                    !blocks.is_empty() | held_networks(held, &extra, facts, &mut networks, engine);
                (!any).then(|| Notice::OrgNoNetworks {
                    value: seed.handle.clone(),
                })
            }
            OrgSide::As => {
                let blocks: Vec<&AsBlock> = seeded
                    .as_blocks
                    .iter()
                    .filter(|block| opaque_of(&block.opaque_id))
                    .collect();
                facts
                    .asns
                    .extend(blocks.iter().map(|block| (block.first, block.last)));
                let any = !blocks.is_empty() | held_autnums(held, &extra, facts, &mut origins);
                (!any).then(|| Notice::OrgNoAs {
                    value: seed.handle.clone(),
                })
            }
        };
        let known = !held.is_empty()
            || seeded_blocks
                .iter()
                .any(|block| opaque_of(&block.opaque_id))
            || seeded
                .as_blocks
                .iter()
                .any(|block| opaque_of(&block.opaque_id));
        let quiet =
            seed.bare || engine.is_quiet(seed.side, &OrgMatch::HandleOrName(seed.handle.clone()));
        found.empty_org(quiet, known, seed.side, &seed.handle, notice);
    }
    for seed in &seeds.org_names {
        let held = named.get(&seed.pattern).map_or(&[][..], Vec::as_slice);
        let facts = found
            .org_names
            .entry((seed.side, seed.pattern.clone()))
            .or_default();
        let value = pattern_text(&seed.pattern);
        let notice = match seed.side {
            OrgSide::Net => {
                (!held_networks(held, &extra, facts, &mut networks, engine)).then(|| {
                    Notice::OrgNoNetworks {
                        value: value.clone(),
                    }
                })
            }
            OrgSide::As => {
                (!held_autnums(held, &extra, facts, &mut origins)).then(|| Notice::OrgNoAs {
                    value: value.clone(),
                })
            }
        };
        let quiet = seed.bare || engine.is_quiet(seed.side, &OrgMatch::Name(seed.pattern.clone()));
        found.empty_org(quiet, !held.is_empty(), seed.side, &value, notice);
    }
    for seed in &seeds.handles {
        let answer = reverse_found(&request, &reverse, seed);
        let facts = found
            .handles
            .entry((seed.side, seed.kind, seed.handle.to_uppercase()))
            .or_default();
        match seed.side {
            OrgSide::Net => {
                for record in answer.iter().flat_map(|answer| &answer.networks) {
                    facts.ranges.push(record.range);
                    if engine.families.contains(record.range.family()) {
                        networks.source(NetCandidate::Record(Arc::clone(record)));
                    }
                }
            }
            OrgSide::As => {
                for record in answer.iter().flat_map(|answer| &answer.autnums) {
                    facts.asns.push((record.asn, record.asn));
                    origins.push((record.asn, record.asn));
                }
            }
        }
    }

    // 4. RIS, the families of the run at once.
    let by_asn = AsnSet::from_ranges(origins);
    let ips = if universe { &leaves.ips } else { &seeds.ips };
    let mut requests = Vec::new();
    for family in engine.families.iter() {
        let of = |prefix: &&Prefix| prefix.family() == family;
        let cover: Vec<Prefix> = leaves.cover.iter().filter(of).copied().collect();
        let request = RouteRequest {
            by_asn: by_asn.clone(),
            exact: seeds.exact.iter().filter(of).copied().collect(),
            covering: cover.iter().map(|prefix| prefix.range()).collect(),
            within: if universe {
                Vec::new()
            } else {
                seeds.ips.iter().filter(of).map(|p| p.range()).collect()
            },
            intersecting: if universe {
                Vec::new()
            } else {
                networks
                    .sources
                    .iter()
                    .map(NetCandidate::range)
                    .filter(|range| range.family() == family)
                    .collect()
            },
            all: universe,
        };
        let empty = request.by_asn.is_empty()
            && request.exact.is_empty()
            && request.covering.is_empty()
            && request.within.is_empty()
            && request.intersecting.is_empty()
            && !request.all;
        if !empty {
            requests.push((family, cover, request));
        }
    }
    let answers = try_join_all(
        requests
            .iter()
            .map(|(family, _, request)| sources.routes(*family, request)),
    )
    .await?;
    let mut routes: Vec<Route> = Vec::new();
    for ((_, cover, _), answer) in requests.iter().zip(answers) {
        for (prefix, route) in cover.iter().zip(answer.covering) {
            found
                .cover
                .insert(*prefix, route.as_ref().map(|route| route.prefix));
            routes.extend(route);
        }
        routes.extend(answer.routes);
    }
    routes.sort_by_key(|route| key(route.prefix.range()));
    routes.dedup_by_key(|route| route.prefix);
    found.origins = routes
        .iter()
        .flat_map(|route| route.origins.iter().copied())
        .collect();

    // 5. asn.txt: the names of the origins.
    if !complete {
        let mut wanted: BTreeSet<Asn> = BTreeSet::new();
        if want_asn {
            wanted.extend(found.origins.iter().copied());
        }
        if engine.rows_mode {
            wanted.extend(found.ones.iter().copied());
        }
        wanted.retain(|asn| !found.entries.contains_key(asn));
        if !wanted.is_empty() {
            let request = AsnRequest {
                by_asn: AsnSet::from_ranges(wanted.into_iter().map(|asn| (asn, asn))),
                ..AsnRequest::default()
            };
            for entry in sources.asns(&request).await?.entries {
                found.entries.insert(entry.asn, entry);
            }
        }
    }

    found.unrouted = unrouted(ips, &found.cover, &networks.sources, &routes);

    // 6. The stats of the candidates: their blocks and the blocks of
    // their AS, for `net.*` and `as.rir`.
    if engine.need_stats {
        let mut intersecting: Vec<Range> =
            routes.iter().map(|route| route.prefix.range()).collect();
        intersecting.extend(found.unrouted.iter().filter_map(Unrouted::range));
        let request = StatsRequest {
            intersecting,
            asn: AsnSet::from_ranges(found.origins.iter().map(|asn| (*asn, *asn))),
            ..StatsRequest::default()
        };
        let answer = engine.stats.answer(sources, &request).await?;
        for block in answer.blocks {
            if engine.families.contains(block.range.family()) {
                networks.add(NetCandidate::Block(block));
            }
        }
        networks.as_blocks.extend(answer.as_blocks);
    }

    let (nets, as_blocks) = networks.finish();
    found.nets = nets;
    found.as_blocks = as_blocks;
    found.routes = routes;
    Ok(found)
}

/// The registry networks of a selection, while they are gathered.
#[derive(Debug, Default)]
struct Networks {
    /// The networks of the generator, in the order found.
    sources: Vec<NetCandidate>,
    /// Every network, without duplicates.
    all: Vec<NetCandidate>,
    /// The keys of the networks in `all`.
    seen: HashSet<NetKey>,
    /// The AS blocks.
    as_blocks: Vec<AsBlock>,
}

/// The key that tells two networks apart.
#[derive(Debug, Eq, Hash, PartialEq)]
enum NetKey {
    Block(Block),
    Record(Range, String),
}

impl Networks {
    /// Adds a network of the generator.
    fn source(&mut self, net: NetCandidate) {
        if self.add(net.clone()) {
            self.sources.push(net);
        }
    }

    /// Adds a network.
    ///
    /// Returns `false` if the network is known already.
    fn add(&mut self, net: NetCandidate) -> bool {
        let key = match &net {
            NetCandidate::Block(block) => NetKey::Block(block.clone()),
            NetCandidate::Record(record) => NetKey::Record(record.range, record.handle.clone()),
        };
        if !self.seen.insert(key) {
            return false;
        }
        self.all.push(net);
        true
    }

    /// Returns the index of the networks, and the AS blocks by first
    /// number.
    fn finish(self) -> (Intervals<NetCandidate>, Vec<AsBlock>) {
        let mut as_blocks = self.as_blocks;
        as_blocks.sort_by_key(|block| (block.first, block.last, block.rir));
        as_blocks.dedup();
        let nets = Intervals::new(self.all.into_iter().map(|net| (net.range(), net)));
        (nets, as_blocks)
    }
}

/// Looks up the organizations of `seeds` by handle, all at once, with
/// [`RdapClient::org_by_handle`].
///
/// Maps each uppercase handle to what the registries hold of it.
///
/// [`RdapClient::org_by_handle`]: crate::rdap::RdapClient::org_by_handle
async fn lookup(engine: &Engine<'_>, seeds: &[OrgSeed]) -> Result<HashMap<String, Vec<Org>>> {
    let mut handles: Vec<String> = Vec::new();
    for seed in seeds {
        let handle = seed.handle.to_uppercase();
        if !handles.contains(&handle) {
            handles.push(handle);
        }
    }
    let rdap = engine.rdap;
    let answers = try_join_all(handles.iter().map(|handle| rdap.org_by_handle(handle))).await?;
    Ok(handles.into_iter().zip(answers).collect())
}

/// Looks up the organizations of `seeds` by name, all at once.
///
/// RIPE is searched with its REST API, and the other registries with RDAP
/// `entities?fn=`.
async fn names(engine: &Engine<'_>, seeds: &[NameSeed]) -> Result<HashMap<Pattern, Vec<Org>>> {
    let mut patterns: Vec<&Pattern> = Vec::new();
    for seed in seeds {
        if !patterns.contains(&&seed.pattern) {
            patterns.push(&seed.pattern);
        }
    }
    let answers = try_join_all(patterns.iter().map(|pattern| by_name(engine, pattern))).await?;
    Ok(patterns.into_iter().cloned().zip(answers).collect())
}

/// Returns the organizations named like `pattern` in the five registries,
/// in the order of [`Rir::ALL`].
async fn by_name(engine: &Engine<'_>, pattern: &Pattern) -> Result<Vec<Org>> {
    let others: Vec<Rir> = Rir::ALL
        .into_iter()
        .filter(|rir| *rir != Rir::Ripencc)
        .collect();
    let rdap = engine.rdap;
    let (mut found, ripe) = try_join(
        rdap.org_by_name_in(&others, pattern),
        engine.rest.organisations(pattern),
    )
    .await?;
    let ripe = try_join_all(
        ripe.iter()
            .map(|(handle, name)| rdap.org_named(Rir::Ripencc, handle, name)),
    )
    .await?;
    found.extend(ripe);
    Ok(found)
}

/// Searches in reverse for the maintainers and contacts of `seeds`.
///
/// One request goes to the APNIC and AFRINIC dumps and to the RIPE REST
/// API. It asks for networks in the families of the run if a seed is on
/// `net.*`, and for AS if a seed is on `as.*`.
async fn reverse(engine: &Engine<'_>, seeds: &[HandleSeed]) -> Result<(WhoisRequest, WhoisAnswer)> {
    let mut request = WhoisRequest {
        mnt: Vec::new(),
        contact: Vec::new(),
        org: Vec::new(),
        families: Families::NONE,
        autnums: false,
    };
    for seed in seeds {
        match seed.kind {
            HandleKind::Mnt => {
                if position(&request.mnt, &seed.handle).is_none() {
                    request.mnt.push(seed.handle.clone());
                }
            }
            HandleKind::Contact(role) => {
                if contact_position(&request.contact, role, &seed.handle).is_none() {
                    request.contact.push((role, seed.handle.clone()));
                }
            }
        }
        match seed.side {
            OrgSide::Net => request.families = engine.families,
            OrgSide::As => request.autnums = true,
        }
    }
    if request.is_empty() {
        let answer = WhoisAnswer::empty(&request);
        return Ok((request, answer));
    }
    let (dumps, ripe) =
        try_join(engine.sources.whois(&request), engine.rest.search(&request)).await?;
    let answer = WhoisAnswer::merge([dumps, ripe]);
    Ok((request, answer))
}

/// The records that the dumps and the RIPE REST API hold of organizations,
/// by registry and handle in uppercase.
type Fallback = HashMap<(Rir, String), WhoisFound>;

/// The registries whose records are searched by `org`: RIPE by the REST
/// API, and APNIC and AFRINIC by the dumps.
const FALLBACK: [Rir; 3] = [Rir::Ripencc, Rir::Apnic, Rir::Afrinic];

/// Searches by `org` for the records of the organizations `held`, if RDAP
/// left their list for the side empty or cut it short.
///
/// Sends one request per registry, so a RIPE organization downloads no
/// dump.
async fn fallback(engine: &Engine<'_>, held: Vec<(OrgSide, &Org)>) -> Result<Fallback> {
    let mut requests: [WhoisRequest; 3] = Default::default();
    for (side, org) in held {
        let Some(at) = FALLBACK.iter().position(|rir| *rir == org.rir) else {
            continue;
        };
        let listed = match side {
            OrgSide::Net => !org.networks.is_empty(),
            OrgSide::As => !org.autnums.is_empty(),
        };
        if listed && org.truncated.is_none() {
            continue;
        }
        let request = &mut requests[at];
        if position(&request.org, &org.handle).is_none() {
            request.org.push(org.handle.clone());
        }
        match side {
            OrgSide::Net => request.families = engine.families,
            OrgSide::As => request.autnums = true,
        }
    }
    let answers = try_join_all(
        FALLBACK
            .iter()
            .zip(&requests)
            .map(|(rir, request)| async move {
                match rir {
                    Rir::Ripencc => engine.rest.search(request).await,
                    _ => engine.sources.whois_of(*rir, request).await,
                }
            }),
    )
    .await?;
    let mut found = Fallback::new();
    for ((rir, request), answer) in FALLBACK.into_iter().zip(&requests).zip(answers) {
        for (handle, records) in request.org.iter().zip(answer.org) {
            found.insert((rir, handle.to_uppercase()), records);
        }
    }
    Ok(found)
}

/// Returns the index of `handle` among the maintainers in `list`.
fn position(list: &[String], handle: &str) -> Option<usize> {
    list.iter()
        .position(|item| item.eq_ignore_ascii_case(handle))
}

/// Returns the index of `(role, handle)` among the contacts in `list`.
fn contact_position(
    list: &[(Option<Role>, String)],
    role: Option<Role>,
    handle: &str,
) -> Option<usize> {
    list.iter()
        .position(|(other, item)| *other == role && item.eq_ignore_ascii_case(handle))
}

/// Returns the answer of the reverse search to `seed`.
fn reverse_found<'a>(
    request: &WhoisRequest,
    answer: &'a WhoisAnswer,
    seed: &HandleSeed,
) -> Option<&'a WhoisFound> {
    match seed.kind {
        HandleKind::Mnt => answer.mnt.get(position(&request.mnt, &seed.handle)?),
        HandleKind::Contact(role) => {
            answer
                .contact
                .get(contact_position(&request.contact, role, &seed.handle)?)
        }
    }
}

/// Adds the networks of the organizations `held` to `facts`, and those in
/// the families of the run to the networks of the generator.
///
/// The networks come from RDAP and from the `extra` records that RDAP left
/// out. Returns `true` if there is at least one network.
fn held_networks(
    held: &[Org],
    extra: &Fallback,
    facts: &mut OrgFacts,
    networks: &mut Networks,
    engine: &Engine<'_>,
) -> bool {
    let mut any = false;
    for org in held {
        let listed = org.networks.iter().map(|record| Arc::new(record.clone()));
        let more = extra
            .get(&(org.rir, org.handle.to_uppercase()))
            .into_iter()
            .flat_map(|found| &found.networks)
            .filter(|record| org.networks.iter().all(|own| own.range != record.range))
            .cloned();
        for record in listed.chain(more) {
            any = true;
            facts.ranges.push(record.range);
            if engine.families.contains(record.range.family()) {
                networks.source(NetCandidate::Record(record));
            }
        }
    }
    any
}

/// Adds the AS of the organizations `held` to `facts` and to the origins
/// to look up.
///
/// The AS come from RDAP and from the `extra` records that RDAP left out.
/// Returns `true` if there is at least one AS.
fn held_autnums(
    held: &[Org],
    extra: &Fallback,
    facts: &mut OrgFacts,
    origins: &mut Vec<(Asn, Asn)>,
) -> bool {
    let mut any = false;
    for org in held {
        let more = extra
            .get(&(org.rir, org.handle.to_uppercase()))
            .into_iter()
            .flat_map(|found| &found.autnums)
            .filter(|record| org.autnums.iter().all(|own| own.asn != record.asn));
        for numbers in org
            .autnums
            .iter()
            .chain(more.map(|record| &**record))
            .map(AsRecord::numbers)
        {
            any = true;
            facts.asns.push(numbers);
            origins.push(numbers);
        }
    }
    any
}

/// Returns the addresses that no route covers, among the `ip:` prefixes
/// without a covering route and the networks of the generator.
///
/// The addresses are split by where they came from. An `ip:` left whole is
/// one candidate with that part. A network left whole is one candidate
/// with that network. Any other rest is one candidate per CIDR.
fn unrouted(
    ips: &[Prefix],
    cover: &HashMap<Prefix, Option<Prefix>>,
    nets: &[NetCandidate],
    routes: &[Route],
) -> Vec<Unrouted> {
    let mut sources: Vec<(Range, Option<&NetCandidate>)> = ips
        .iter()
        .filter(|prefix| cover.get(prefix) == Some(&None))
        .map(|prefix| (prefix.range(), None))
        .chain(nets.iter().map(|net| (net.range(), Some(net))))
        .collect();
    if sources.is_empty() {
        return Vec::new();
    }
    // Wider first, so a source inside another adds nothing. An `ip:` comes
    // before a network of the same addresses.
    sources.sort_by_key(|(range, net)| (key(*range), net.is_some()));
    sources.dedup_by(|a, b| a.0 == b.0 && a.1.is_none() && b.1.is_none());
    let mut rest: AddrSet = sources.iter().map(|(range, _)| *range).collect();
    let routed: AddrSet = routes
        .iter()
        .map(|route| route.prefix.range())
        .filter(|range| rest.intersects(range))
        .collect();
    rest = rest.subtract(&routed);
    let mut pieces = Vec::new();
    for (range, net) in sources {
        let whole = AddrSet::from(range);
        let piece = rest.intersect(&whole);
        if piece.is_empty() {
            continue;
        }
        if piece == whole {
            pieces.push(match net {
                None => Unrouted {
                    part: Some(range),
                    net: None,
                },
                Some(net) => Unrouted {
                    part: None,
                    net: Some(net.clone()),
                },
            });
        } else {
            for left in piece.pieces() {
                pieces.extend(left.prefixes().map(|prefix| Unrouted {
                    part: Some(prefix.into()),
                    net: None,
                }));
            }
        }
        rest = rest.subtract(&piece);
    }
    pieces.sort_by_key(|piece| piece.range().map(key));
    pieces
}

#[cfg(test)]
mod tests {
    use super::*;

    fn route(text: &str) -> Route {
        Route {
            prefix: text.parse().unwrap(),
            origins: vec![64496],
        }
    }

    #[test]
    fn unrouted_rest_of_an_ip() {
        let ip: Prefix = "192.0.2.0/24".parse().unwrap();
        let cover = HashMap::from([(ip, None)]);
        let routes = [route("192.0.2.0/26"), route("198.51.100.0/24")];
        let pieces = unrouted(&[ip], &cover, &[], &routes);
        let text: Vec<String> = pieces
            .iter()
            .filter_map(|piece| piece.part.map(|part| part.to_string()))
            .collect();
        assert_eq!(text, ["192.0.2.64/26", "192.0.2.128/25"]);
        // Covered, or not asked: nothing.
        let covered = HashMap::from([(ip, Some("192.0.2.0/24".parse().unwrap()))]);
        assert!(unrouted(&[ip], &covered, &[], &routes).is_empty());
        assert!(unrouted(&[ip], &HashMap::new(), &[], &routes).is_empty());
    }

    fn block(range: &str) -> NetCandidate {
        NetCandidate::Block(Block {
            rir: Rir::Lacnic,
            range: range.parse().unwrap(),
            cc: "XH".parse().unwrap(),
            opaque_id: None,
        })
    }

    #[test]
    fn unrouted_rest_of_networks() {
        // A block of 96 addresses with two routes leaves a rest of one CIDR.
        // A block without routes is itself the row. An `ip:` inside it adds
        // nothing, and an `ip:` of the same addresses comes first.
        let partly = block("203.0.113.128-203.0.113.223");
        let whole = block("203.0.113.224/27");
        let routes = [route("203.0.113.128/27"), route("203.0.113.160/27")];
        let pieces = unrouted(&[], &HashMap::new(), &[partly, whole.clone()], &routes);
        assert_eq!(
            pieces,
            [
                Unrouted {
                    part: Some("203.0.113.192/27".parse().unwrap()),
                    net: None
                },
                Unrouted {
                    part: None,
                    net: Some(whole.clone())
                },
            ]
        );
        let inside: Prefix = "203.0.113.230/32".parse().unwrap();
        let cover = HashMap::from([(inside, None)]);
        let pieces = unrouted(&[inside], &cover, std::slice::from_ref(&whole), &[]);
        assert_eq!(pieces.len(), 1);
        assert_eq!(pieces[0].net, Some(whole.clone()));
        let same: Prefix = "203.0.113.224/27".parse().unwrap();
        let cover = HashMap::from([(same, None)]);
        let pieces = unrouted(&[same], &cover, &[whole], &[]);
        assert_eq!(
            pieces,
            [Unrouted {
                part: Some(same.range()),
                net: None
            }]
        );
    }

    #[test]
    fn bare_operands_are_found() {
        let expr = Expr::And(vec![
            Expr::Bare {
                word: "sample".into(),
                inner: Box::new(Expr::Leaf(Leaf::AsName(Pattern::Exact("sample".into())))),
            },
            Expr::Leaf(Leaf::Route(RouteMatch::Any)),
        ]);
        let bare = bare(&expr);
        assert_eq!(bare.len(), 1);
        assert_eq!(bare[0].word, "sample");
        let leaves = Leaves::of(&expr);
        assert_eq!(leaves.bare_names, [Pattern::Exact("sample".into())]);
    }

    #[test]
    fn leaves_follow_polarity() {
        let ip = |text: &str| Expr::Leaf(Leaf::Ip(text.parse().unwrap()));
        let expr = Expr::And(vec![
            ip("192.0.2.0/24"),
            Expr::Not(Box::new(ip("192.0.2.1"))),
        ]);
        let leaves = Leaves::of(&expr);
        assert_eq!(leaves.ips, ["192.0.2.0/24".parse::<Prefix>().unwrap()]);
        assert_eq!(leaves.cover, leaves.ips);
    }
}
