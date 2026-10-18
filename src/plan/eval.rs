//! The predicate of a query on a row.
//!
//! A row matches if the whole expression holds for one AS `a` of the route
//! and one network `n` of the row. Leaves on `as.*` are evaluated on `a`,
//! and leaves on `net.*` on `n`. A row without AS or without networks uses
//! an absent one, ⊥, on which every field is missing. So `field: *` is
//! false on ⊥, and `not field: *` is true.
//!
//! Evaluation is three-valued: true, false, or unknown until an RDAP record
//! is fetched. The engine fetches records only for rows where the cheap
//! leaves of the expression did not decide the outcome.
//!
//! # Values are address sets
//!
//! The value of the expression on a row is not a boolean. It is the set of
//! addresses of the row's base, the route or the part, for which the
//! expression holds:
//!
//! - Conditions on the record, `route` and `as.*`, hold for all of the
//!   base or for none of it.
//! - `ip:` holds for the addresses it names.
//! - `net.*` holds for the addresses of the network `n`.
//! - `and` intersects, `or` unites, and `not` complements within the base.
//!
//! One evaluation gives two answers: the row matches if the set is not
//! empty, and the set holds the row's addresses. So `not ip:` cuts addresses
//! out of a route without a separate pass, and a condition on `net.*`
//! keeps only the addresses of the network inside the route.
//!
//! A three-valued result is a pair of sets. `sure` holds the addresses
//! where the expression holds whatever the unknown leaves turn out to be.
//! `maybe` holds the addresses where the expression may hold. `sure` is a
//! subset of `maybe`, and the two are equal when no unknown leaf matters.
//!
//! # `ip:` and the route that covers it
//!
//! In a positive position, `ip: X` matches two kinds of routes. One is the
//! most specific route that covers all of `X`, with `X` as its part. The
//! others are the routes inside `X`, whole. A less specific route around
//! `X` does not match, because the more specific route routes the
//! addresses of `X`. Inside a scope, only the covering route matches.
//!
//! Under `not`, `ip: X` is plain address arithmetic. `not ip: X` removes
//! the addresses of `X` from every route, covering or not.

use std::collections::HashMap;

use super::{HandleKind, OrgSide};
use crate::{
    addr::{Prefix, Range, set::AddrSet},
    model::{AsInfo, Asn, Block, Contact, NetCandidate, NetRecord, OrgRef, Role, Route, Row},
    query::{
        Expr, Field,
        expr::{AsnMatch, HandleMatch, Leaf, OrgMatch, RouteMatch},
    },
    text::Pattern,
};

/// What the evaluation knows besides the row: answers that depend on more
/// than the row, such as covering routes and the lookups of the generator.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub(crate) struct Facts {
    /// For each prefix of `ip:` and each address of `route: <ip>`, the most
    /// specific route that contains all of it, or `None` if no route does.
    /// An address is a host prefix here.
    pub(crate) cover: HashMap<Prefix, Option<Prefix>>,
    /// `true` inside a scope, where `ip: X` matches only the route that
    /// covers `X`.
    pub(crate) scope: bool,
    /// The organizations that the generator looked up, keyed by side and
    /// uppercase handle. Their conditions are known without an RDAP
    /// request per row.
    pub(crate) orgs: HashMap<(OrgSide, String), OrgFacts>,
    /// The organizations that the generator looked up by name, keyed by
    /// side and pattern.
    pub(crate) names: HashMap<(OrgSide, Pattern), OrgFacts>,
    /// The maintainers and contacts that the generator searched in
    /// reverse, keyed by side, kind, and uppercase handle. Each value holds
    /// all networks and AS of the answer, and the `ranges` of a value are
    /// the ranges of records.
    pub(crate) handles: HashMap<(OrgSide, HandleKind, String), OrgFacts>,
}

/// What the registries and the stats know about one organization.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub(crate) struct OrgFacts {
    /// The networks: the organization's RDAP records and the stats blocks
    /// with its `opaque-id`.
    pub(crate) ranges: Vec<Range>,
    /// The AS, as inclusive ranges: the organization's RDAP records and the
    /// AS blocks with its `opaque-id`.
    pub(crate) asns: Vec<(Asn, Asn)>,
}

impl Facts {
    /// Returns the facts of the organization `handle` on `side`, if the
    /// generator looked it up.
    fn org(&self, side: OrgSide, handle: &str) -> Option<&OrgFacts> {
        self.orgs.get(&(side, handle.to_uppercase()))
    }

    /// Returns the facts of the organizations named like `pattern` on
    /// `side`, if the generator looked them up.
    fn name(&self, side: OrgSide, pattern: &Pattern) -> Option<&OrgFacts> {
        self.names.get(&(side, pattern.clone()))
    }

    /// Returns the answer of the reverse search of `handle` as `kind` on
    /// `side`, if the generator searched it.
    fn handle(&self, side: OrgSide, kind: HandleKind, handle: &str) -> Option<&OrgFacts> {
        self.handles.get(&(side, kind, handle.to_uppercase()))
    }

    /// Returns the prefix of the most specific route covering `prefix`.
    ///
    /// Returns `None` if the cover is unknown or no route covers `prefix`.
    fn cover(&self, prefix: Prefix) -> Option<Prefix> {
        self.cover.get(&prefix).copied().flatten()
    }
}

/// What one evaluation looks at: a row with one choice of `a` and `n`.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Subject<'a> {
    /// The route, or `None` for addresses that no route covers.
    pub(crate) route: Option<&'a Route>,
    /// The addresses under evaluation: the route or the part.
    pub(crate) base: Range,
    /// The AS `a`. `None` is ⊥, for a row without AS.
    pub(crate) asn: Option<&'a AsInfo>,
    /// The network `n`. `None` is ⊥, for a row without networks.
    pub(crate) net: Option<&'a NetCandidate>,
    /// Every network of the row. The block of a record is among them.
    pub(crate) nets: &'a [NetCandidate],
    /// `true` if the RDAP records of the row were fetched, as in
    /// [`Row::fetched`].
    pub(crate) fetched: bool,
}

/// A subset of the base of a subject.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum Part {
    /// No address.
    Empty,
    /// The whole base.
    Full,
    /// Some addresses, neither none nor all.
    Some(AddrSet),
}

impl Part {
    /// Returns `set`, a subset of `base`, as a `Part` of `base`.
    fn of(set: AddrSet, base: Range) -> Self {
        if set.is_empty() {
            Self::Empty
        } else if set.contains(&base) {
            Self::Full
        } else {
            Self::Some(set)
        }
    }

    /// Returns the `Part` of `base` inside `range`.
    fn within(base: Range, range: Range) -> Self {
        if range.contains(&base) {
            Self::Full
        } else {
            base.intersection(&range)
                .map_or(Self::Empty, |both| Self::Some(AddrSet::from(both)))
        }
    }

    /// Returns `true` if the `Part` has no address.
    pub(crate) fn is_empty(&self) -> bool {
        matches!(self, Self::Empty)
    }

    /// Returns the addresses of this `Part` of `base`.
    pub(crate) fn addresses(&self, base: Range) -> AddrSet {
        match self {
            Self::Empty => AddrSet::new(),
            Self::Full => AddrSet::from(base),
            Self::Some(set) => set.clone(),
        }
    }

    fn and(self, other: Self, base: Range) -> Self {
        match (self, other) {
            (Self::Empty, _) | (_, Self::Empty) => Self::Empty,
            (Self::Full, part) | (part, Self::Full) => part,
            (Self::Some(a), Self::Some(b)) => Self::of(a.intersect(&b), base),
        }
    }

    fn or(self, other: Self, base: Range) -> Self {
        match (self, other) {
            (Self::Full, _) | (_, Self::Full) => Self::Full,
            (Self::Empty, part) | (part, Self::Empty) => part,
            (Self::Some(a), Self::Some(b)) => Self::of(a.union(&b), base),
        }
    }

    fn not(self, base: Range) -> Self {
        match self {
            Self::Empty => Self::Full,
            Self::Full => Self::Empty,
            Self::Some(set) => Self::of(AddrSet::from(base).subtract(&set), base),
        }
    }
}

/// The three-valued outcome on a subject.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Truth {
    /// Holds for some addresses, whatever the unknown leaves turn out to be.
    True,
    /// Holds for no address, whatever the unknown leaves turn out to be.
    False,
    /// Depends on a record that is not fetched yet.
    Unknown,
}

/// The value of an expression on a subject: where it surely holds and
/// where it may hold.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct Value {
    /// The addresses where the expression holds whatever the unknown
    /// leaves are.
    pub(crate) sure: Part,
    /// The addresses where the expression may hold. A superset of `sure`.
    pub(crate) maybe: Part,
}

impl Value {
    /// Holds nowhere.
    pub(crate) const FALSE: Self = Self {
        sure: Part::Empty,
        maybe: Part::Empty,
    };
    /// Holds on the whole base.
    pub(crate) const TRUE: Self = Self {
        sure: Part::Full,
        maybe: Part::Full,
    };
    /// Not known until a record is fetched.
    pub(crate) const UNKNOWN: Self = Self {
        sure: Part::Empty,
        maybe: Part::Full,
    };

    fn known(part: Part) -> Self {
        Self {
            sure: part.clone(),
            maybe: part,
        }
    }

    fn of(holds: bool) -> Self {
        if holds { Self::TRUE } else { Self::FALSE }
    }

    /// Returns the three-valued outcome.
    pub(crate) fn truth(&self) -> Truth {
        if self.maybe.is_empty() {
            Truth::False
        } else if self.sure == self.maybe {
            Truth::True
        } else {
            Truth::Unknown
        }
    }

    /// Returns `self and other`.
    pub(crate) fn and(self, other: Self, base: Range) -> Self {
        Self {
            sure: self.sure.and(other.sure, base),
            maybe: self.maybe.and(other.maybe, base),
        }
    }

    /// Returns `self or other`.
    pub(crate) fn or(self, other: Self, base: Range) -> Self {
        Self {
            sure: self.sure.or(other.sure, base),
            maybe: self.maybe.or(other.maybe, base),
        }
    }

    /// Returns `not self`.
    pub(crate) fn not(self, base: Range) -> Self {
        Self {
            sure: self.maybe.not(base),
            maybe: self.sure.not(base),
        }
    }
}

/// Evaluates `expr` on one subject.
pub(crate) fn eval(expr: &Expr, subject: &Subject<'_>, facts: &Facts) -> Value {
    walk(expr, subject, facts, true)
}

/// Evaluates `expr` like [`eval`].
///
/// `positive` is `false` under an odd number of `not`.
fn walk(expr: &Expr, subject: &Subject<'_>, facts: &Facts, positive: bool) -> Value {
    let base = subject.base;
    match expr {
        Expr::False => Value::FALSE,
        Expr::Bare { inner, .. } => walk(inner, subject, facts, positive),
        Expr::Not(inner) => walk(inner, subject, facts, !positive).not(base),
        Expr::And(items) => {
            let mut value = Value::TRUE;
            for item in items {
                value = value.and(walk(item, subject, facts, positive), base);
                if value.maybe.is_empty() {
                    break;
                }
            }
            value
        }
        Expr::Or(items) => {
            let mut value = Value::FALSE;
            for item in items {
                value = value.or(walk(item, subject, facts, positive), base);
                if value.sure == Part::Full {
                    break;
                }
            }
            value
        }
        Expr::Leaf(leaf) => leaf_value(leaf, subject, facts, positive),
    }
}

/// Returns the value of one leaf.
fn leaf_value(leaf: &Leaf, subject: &Subject<'_>, facts: &Facts, positive: bool) -> Value {
    let route = subject.route.map(|route| route.prefix);
    let entry = subject.asn.and_then(|info| info.entry.as_ref());
    let block = subject.asn.and_then(|info| info.block.as_ref());
    match leaf {
        Leaf::Ip(range) => Value::known(ip(*range, subject, facts, positive)),
        Leaf::Route(RouteMatch::Exact(prefix)) => Value::of(route == Some(*prefix)),
        Leaf::Route(RouteMatch::Covering(addr)) => {
            Value::of(route.is_some() && route == facts.cover(Prefix::host(*addr)))
        }
        Leaf::Route(RouteMatch::Any) => Value::of(route.is_some()),
        Leaf::Asn(matcher) => Value::of(subject.asn.is_some_and(|info| asn(*matcher, info.asn))),
        Leaf::AsName(pattern) => Value::of(entry.is_some_and(|entry| pattern.matches(&entry.name))),
        Leaf::AsCountry(cc) => Value::of(entry.is_some_and(|entry| entry.country == Some(*cc))),
        Leaf::AsRir(rir) => Value::of(block.is_some_and(|block| block.rir == *rir)),
        Leaf::Present(Field::AsCountry) => {
            Value::of(entry.is_some_and(|entry| entry.country.is_some()))
        }
        Leaf::Present(Field::AsRir) => Value::of(block.is_some()),
        // `net.country` and `net.rir` come only from the blocks of the
        // registries. They hold on the addresses of the network `n`.
        Leaf::NetCountry(cc) => net_block(subject, |block| block.cc == *cc),
        Leaf::NetRir(rir) => net_block(subject, |block| block.rir == *rir),
        Leaf::Present(Field::NetCountry | Field::NetRir) => net_block(subject, |_| true),
        Leaf::NetOrg(matcher) => net_org(matcher, subject, facts),
        Leaf::AsOrg(matcher) => as_org(matcher, subject, facts),
        Leaf::NetMnt(HandleMatch::Any) => net_record(subject, |record| !record.mnt.is_empty()),
        Leaf::NetContact(role, HandleMatch::Any) => {
            net_record(subject, |record| has_contact(&record.contacts, *role))
        }
        Leaf::AsMnt(HandleMatch::Any) => as_record(subject, |info| {
            info.rdap
                .as_ref()
                .is_some_and(|record| !record.mnt.is_empty())
        }),
        Leaf::AsContact(role, HandleMatch::Any) => as_record(subject, |info| {
            info.rdap
                .as_ref()
                .is_some_and(|record| has_contact(&record.contacts, *role))
        }),
        Leaf::NetMnt(HandleMatch::Handle(handle)) => {
            net_handle(subject, facts, HandleKind::Mnt, handle)
        }
        Leaf::NetContact(role, HandleMatch::Handle(handle)) => {
            net_handle(subject, facts, HandleKind::Contact(*role), handle)
        }
        Leaf::AsMnt(HandleMatch::Handle(handle)) => {
            as_handle(subject, facts, HandleKind::Mnt, handle)
        }
        Leaf::AsContact(role, HandleMatch::Handle(handle)) => {
            as_handle(subject, facts, HandleKind::Contact(*role), handle)
        }
        // Domains and scopes are resolved into other leaves before
        // evaluation.
        Leaf::Present(_) | Leaf::Domain(_) | Leaf::Scope { .. } | Leaf::IpScope(_) => {
            Value::UNKNOWN
        }
    }
}

/// Returns `known` once the RDAP records of the row are fetched.
///
/// Before the fetch, the rest of the base is unknown, because a record may
/// still hold there.
fn pending(known: Value, subject: &Subject<'_>) -> Value {
    if subject.fetched {
        known
    } else {
        known.or(Value::UNKNOWN, subject.base)
    }
}

/// Evaluates `net.org` on the network `n`.
///
/// `n` matches if it has the handle or `opaque-id` of the organization, or
/// if it is one of the records or blocks that the generator found. A
/// lookup by the generator makes the answer final. Without one, the
/// condition waits for the RDAP records of the row, so it is an expensive
/// filter.
fn net_org(matcher: &OrgMatch, subject: &Subject<'_>, facts: &Facts) -> Value {
    let Some(net) = subject.net else {
        // A row without networks has no network of a searched
        // organization.
        return if org_searched(OrgSide::Net, matcher, facts) {
            Value::FALSE
        } else {
            pending(Value::FALSE, subject)
        };
    };
    let (holds, searched) = match matcher {
        OrgMatch::Any => (
            match net {
                NetCandidate::Block(block) => block.opaque_id.is_some(),
                NetCandidate::Record(record) => record.org.is_some(),
            },
            false,
        ),
        OrgMatch::HandleOrName(handle) => {
            let org = facts.org(OrgSide::Net, handle);
            let holds = match net {
                NetCandidate::Block(block) => opaque_is(block, handle),
                NetCandidate::Record(record) => org_is(record.org.as_ref(), handle),
            } || org.is_some_and(|org| org.ranges.contains(&net.range()));
            (holds, org.is_some())
        }
        OrgMatch::Name(pattern) => {
            let org = facts.name(OrgSide::Net, pattern);
            let holds = match net {
                NetCandidate::Block(_) => false,
                NetCandidate::Record(record) => named(record.org.as_ref(), pattern),
            } || org.is_some_and(|org| org.ranges.contains(&net.range()));
            (holds, org.is_some())
        }
    };
    let known = if holds {
        Value::known(Part::within(subject.base, net.range()))
    } else {
        Value::FALSE
    };
    if searched {
        known
    } else {
        pending(known, subject)
    }
}

/// Evaluates `as.org` on the AS `a`, like [`net_org`].
fn as_org(matcher: &OrgMatch, subject: &Subject<'_>, facts: &Facts) -> Value {
    let Some(info) = subject.asn else {
        return if org_searched(OrgSide::As, matcher, facts) {
            Value::FALSE
        } else {
            pending(Value::FALSE, subject)
        };
    };
    let record = info.rdap.as_ref().and_then(|record| record.org.as_ref());
    let block = info.block.as_ref();
    let (holds, searched) = match matcher {
        OrgMatch::Any => (
            record.is_some() || block.is_some_and(|block| block.opaque_id.is_some()),
            false,
        ),
        OrgMatch::HandleOrName(handle) => {
            let org = facts.org(OrgSide::As, handle);
            let holds = org_is(record, handle)
                || block.is_some_and(|block| {
                    block
                        .opaque_id
                        .as_deref()
                        .is_some_and(|id| id.eq_ignore_ascii_case(handle))
                })
                || org.is_some_and(|org| holds_asn(org, info.asn));
            (holds, org.is_some())
        }
        OrgMatch::Name(pattern) => {
            let org = facts.name(OrgSide::As, pattern);
            let holds = named(record, pattern) || org.is_some_and(|org| holds_asn(org, info.asn));
            (holds, org.is_some())
        }
    };
    let known = Value::of(holds);
    if searched || info.rdap.is_some() {
        known
    } else {
        pending(known, subject)
    }
}

/// Returns `true` if the generator looked up the organization of `matcher`
/// on `side`.
///
/// The answer of such a lookup is complete.
fn org_searched(side: OrgSide, matcher: &OrgMatch, facts: &Facts) -> bool {
    match matcher {
        OrgMatch::Any => false,
        OrgMatch::HandleOrName(handle) => facts.org(side, handle).is_some(),
        OrgMatch::Name(pattern) => facts.name(side, pattern).is_some(),
    }
}

/// Returns `true` if `asn` is among the AS of `org`.
fn holds_asn(org: &OrgFacts, asn: Asn) -> bool {
    org.asns
        .iter()
        .any(|(first, last)| (*first..=*last).contains(&asn))
}

/// Returns `true` if the holder `org` has a name that `pattern` matches.
fn named(org: Option<&OrgRef>, pattern: &Pattern) -> bool {
    org.and_then(|org| org.name.as_deref())
        .is_some_and(|name| pattern.matches(name))
}

/// Evaluates `net.mnt: X` and `net.contact: X` on the network `n`.
///
/// `n` matches if it is a record with the handle, or a record in the
/// answer of the reverse search. A search by the generator makes the
/// answer final. Without one, the condition waits for the RDAP records of
/// the row, so it is an expensive filter.
fn net_handle(subject: &Subject<'_>, facts: &Facts, kind: HandleKind, handle: &str) -> Value {
    let found = facts.handle(OrgSide::Net, kind, handle);
    let known = match subject.net {
        Some(NetCandidate::Record(record))
            if has_handle(&record.mnt, &record.contacts, kind, handle)
                || found.is_some_and(|found| found.ranges.contains(&record.range)) =>
        {
            Value::known(Part::within(subject.base, record.range))
        }
        _ => Value::FALSE,
    };
    if found.is_some() {
        known
    } else {
        pending(known, subject)
    }
}

/// Evaluates `as.mnt: X` and `as.contact: X` on the AS `a`, like
/// [`net_handle`].
fn as_handle(subject: &Subject<'_>, facts: &Facts, kind: HandleKind, handle: &str) -> Value {
    let found = facts.handle(OrgSide::As, kind, handle);
    let Some(info) = subject.asn else {
        return if found.is_some() {
            Value::FALSE
        } else {
            pending(Value::FALSE, subject)
        };
    };
    let holds = info
        .rdap
        .as_ref()
        .is_some_and(|record| has_handle(&record.mnt, &record.contacts, kind, handle))
        || found.is_some_and(|found| holds_asn(found, info.asn));
    let known = Value::of(holds);
    if found.is_some() || info.rdap.is_some() {
        known
    } else {
        pending(known, subject)
    }
}

/// Returns `true` if a record with the maintainers `mnt` and the contacts
/// `contacts` has `handle` as `kind`.
fn has_handle(mnt: &[String], contacts: &[Contact], kind: HandleKind, handle: &str) -> bool {
    match kind {
        HandleKind::Mnt => mnt.iter().any(|mnt| mnt.eq_ignore_ascii_case(handle)),
        HandleKind::Contact(role) => contacts
            .iter()
            .any(|contact| contact.handle.eq_ignore_ascii_case(handle) && in_role(contact, role)),
    }
}

/// Returns `true` if the holder `org` has the handle `handle`.
fn org_is(org: Option<&OrgRef>, handle: &str) -> bool {
    org.is_some_and(|org| org.handle.eq_ignore_ascii_case(handle))
}

/// Returns `true` if the block has the `opaque-id` `handle`.
fn opaque_is(block: &Block, handle: &str) -> bool {
    block
        .opaque_id
        .as_deref()
        .is_some_and(|id| id.eq_ignore_ascii_case(handle))
}

/// Returns `true` if one of `contacts` is in `role`.
///
/// Without a role, any role in [`Role::CONTACT`] counts.
fn has_contact(contacts: &[Contact], role: Option<Role>) -> bool {
    contacts.iter().any(|contact| in_role(contact, role))
}

/// Returns `true` if `contact` is in `role`.
///
/// Without a role, any role in [`Role::CONTACT`] counts.
fn in_role(contact: &Contact, role: Option<Role>) -> bool {
    match role {
        Some(role) => contact.roles.contains(&role),
        None => contact
            .roles
            .iter()
            .any(|role| Role::CONTACT.contains(role)),
    }
}

/// Evaluates a condition on the RDAP record `n`.
///
/// The value is the addresses of the record within the base, and it stays
/// unknown until the records of the row are fetched.
fn net_record(subject: &Subject<'_>, test: impl Fn(&NetRecord) -> bool) -> Value {
    let known = match subject.net {
        Some(NetCandidate::Record(record)) if test(record) => {
            Value::known(Part::within(subject.base, record.range))
        }
        _ => Value::FALSE,
    };
    pending(known, subject)
}

/// Evaluates a condition on the RDAP record of the AS `a`.
fn as_record(subject: &Subject<'_>, test: impl Fn(&AsInfo) -> bool) -> Value {
    let Some(info) = subject.asn else {
        return pending(Value::FALSE, subject);
    };
    let known = Value::of(test(info));
    if info.rdap.is_some() {
        known
    } else {
        pending(known, subject)
    }
}

/// Returns `true` if `matcher`, the value of `as.asn`, matches `asn`.
fn asn(matcher: AsnMatch, asn: Asn) -> bool {
    match matcher {
        AsnMatch::One(one) => asn == one,
        AsnMatch::Range { min, max } => (min..=max).contains(&asn),
        AsnMatch::Any => true,
    }
}

/// Evaluates a condition on the block of the network `n`.
///
/// The value is the addresses of `n` within the base. For a record `n`, the
/// block is the narrowest block of the row that holds the record. A network
/// has the country and the registry of its block, so
/// `not net.country: NL` does not hold on a record inside an NL block.
fn net_block(subject: &Subject<'_>, test: impl Fn(&Block) -> bool) -> Value {
    let (block, range) = match subject.net {
        Some(NetCandidate::Block(block)) => (Some(block), block.range),
        Some(NetCandidate::Record(record)) => (block_of(subject.nets, record.range), record.range),
        None => (None, subject.base),
    };
    match block {
        Some(block) if test(block) => Value::known(Part::within(subject.base, range)),
        _ => Value::FALSE,
    }
}

/// Returns the narrowest block among `nets` that holds `range`.
pub(crate) fn block_of(nets: &[NetCandidate], range: Range) -> Option<&Block> {
    nets.iter()
        .filter_map(|net| match net {
            NetCandidate::Block(block) if block.range.contains(&range) => Some(block),
            _ => None,
        })
        .min_by_key(|block| block.range.last() - block.range.first())
}

/// Returns the addresses that `ip: range` selects in the subject.
fn ip(range: Range, subject: &Subject<'_>, facts: &Facts, positive: bool) -> Part {
    let base = subject.base;
    let (Some(route), Some(prefix), true) = (subject.route, range.as_prefix(), positive) else {
        // Under `not`, without a route, or for a range that is not one
        // CIDR, `ip:` selects plain addresses. The engine splits such
        // ranges into prefixes.
        return Part::within(base, range);
    };
    if facts.cover(prefix) == Some(route.prefix) {
        // This route routes the addresses, so the part is `range`.
        Part::within(base, range)
    } else if !facts.scope && range.contains(&route.prefix.range()) {
        // A route inside `range` matches whole.
        Part::within(base, range)
    } else {
        Part::Empty
    }
}

/// Evaluates `expr` on a row over every AS `a` and every network `n` of
/// the row.
///
/// The value is the union of the values of all choices of `a` and `n`.
/// Returns the value on `base` and the AS for which the expression surely
/// holds on some address. The tree highlights these AS.
pub(crate) fn eval_row(expr: &Expr, row: &Row, base: Range, facts: &Facts) -> (Value, Vec<Asn>) {
    let ases: Vec<Option<&AsInfo>> = if row.ases.is_empty() {
        vec![None]
    } else {
        row.ases.iter().map(Some).collect()
    };
    let nets: Vec<Option<&NetCandidate>> = if row.nets.is_empty() {
        vec![None]
    } else {
        row.nets.iter().map(Some).collect()
    };
    let mut value = Value::FALSE;
    let mut marks = Vec::new();
    for asn in &ases {
        let mut of_asn = Value::FALSE;
        for net in &nets {
            let subject = Subject {
                route: row.route.as_ref(),
                base,
                asn: *asn,
                net: *net,
                nets: &row.nets,
                fetched: row.fetched,
            };
            of_asn = of_asn.or(eval(expr, &subject, facts), base);
        }
        if let (Some(info), false) = (asn, of_asn.sure.is_empty()) {
            marks.push(info.asn);
        }
        value = value.or(of_asn, base);
    }
    (value, marks)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        model::{AsnEntry, Block, Rir},
        text::Pattern,
    };

    fn prefix(text: &str) -> Prefix {
        text.parse().unwrap()
    }

    fn range(text: &str) -> Range {
        text.parse().unwrap()
    }

    fn info(asn: Asn, name: &str, cc: &str) -> AsInfo {
        AsInfo {
            asn,
            entry: Some(AsnEntry {
                asn,
                name: name.into(),
                org_text: String::new(),
                country: Some(cc.parse().unwrap()),
                raw: format!("{name} {name}, {cc}"),
            }),
            block: None,
            rdap: None,
        }
    }

    fn row(route: &str, ases: Vec<AsInfo>) -> Row {
        Row {
            route: Some(Route {
                prefix: prefix(route),
                origins: ases.iter().map(|a| a.asn).collect(),
            }),
            ases,
            ..Row::default()
        }
    }

    fn leaf(leaf: Leaf) -> Expr {
        Expr::Leaf(leaf)
    }

    fn not(expr: Expr) -> Expr {
        Expr::Not(Box::new(expr))
    }

    fn name(text: &str) -> Expr {
        leaf(Leaf::AsName(Pattern::Exact(text.into())))
    }

    fn country(text: &str) -> Expr {
        leaf(Leaf::AsCountry(text.parse().unwrap()))
    }

    fn ip_leaf(text: &str) -> Expr {
        leaf(Leaf::Ip(range(text)))
    }

    /// 10.45.192.0/18, announced by SAMPLE from XA and TESTTECH from XB.
    fn shared() -> Row {
        row(
            "10.45.192.0/18",
            vec![info(64510, "SAMPLE", "XA"), info(65550, "TESTTECH", "XB")],
        )
    }

    fn truth(expr: &Expr, row: &Row) -> Truth {
        let base = row.base().unwrap();
        eval_row(expr, row, base, &Facts::default()).0.truth()
    }

    #[test]
    fn one_as_must_meet_all_as_conditions() {
        let row = shared();
        // Sample is from XA, the AS from XB is TESTTECH.
        let both = Expr::And(vec![name("sample"), country("XB")]);
        assert_eq!(truth(&both, &row), Truth::False);
        // An AS of Sample not from XA: none.
        let not_xa = Expr::And(vec![name("sample"), not(country("XA"))]);
        assert_eq!(truth(&not_xa, &row), Truth::False);
        // Separately, any AS from XB and any AS of Sample hold.
        let either = Expr::Or(vec![name("sample"), country("XB")]);
        assert_eq!(truth(&either, &row), Truth::True);
        let (_, marks) = eval_row(&either, &row, row.base().unwrap(), &Facts::default());
        assert_eq!(marks, [64510, 65550]);
        let (_, marks) = eval_row(
            &name("testtech"),
            &row,
            row.base().unwrap(),
            &Facts::default(),
        );
        assert_eq!(marks, [65550]);
    }

    #[test]
    fn absent_as_has_no_fields() {
        let none = Row {
            part: Some(range("192.0.2.0/24")),
            ..Row::default()
        };
        let any = leaf(Leaf::Asn(AsnMatch::Any));
        assert_eq!(truth(&any, &none), Truth::False);
        assert_eq!(truth(&not(any.clone()), &none), Truth::True);
        assert_eq!(
            truth(&leaf(Leaf::Route(RouteMatch::Any)), &none),
            Truth::False
        );
        assert_eq!(truth(&any, &shared()), Truth::True);
        let range = leaf(Leaf::Asn(AsnMatch::Range {
            min: 65_540,
            max: 65_551,
        }));
        assert_eq!(truth(&range, &shared()), Truth::True);
        // `not net.rir: *` holds without any block (⊥).
        let unregistered = not(leaf(Leaf::Present(Field::NetRir)));
        assert_eq!(truth(&unregistered, &shared()), Truth::True);
    }

    #[test]
    fn three_valued_logic() {
        let base = range("192.0.2.0/24");
        let unknown = Value::UNKNOWN;
        assert_eq!(unknown.truth(), Truth::Unknown);
        assert_eq!(
            unknown.clone().and(Value::FALSE, base).truth(),
            Truth::False
        );
        assert_eq!(
            unknown.clone().and(Value::TRUE, base).truth(),
            Truth::Unknown
        );
        assert_eq!(unknown.clone().or(Value::TRUE, base).truth(), Truth::True);
        assert_eq!(
            unknown.clone().or(Value::FALSE, base).truth(),
            Truth::Unknown
        );
        assert_eq!(unknown.not(base).truth(), Truth::Unknown);
        assert_eq!(Value::TRUE.not(base).truth(), Truth::False);
        // An RDAP leaf leaves the row undecided unless the cheap leaves
        // decide it.
        let org = leaf(Leaf::AsOrg(crate::query::expr::OrgMatch::Any));
        assert_eq!(truth(&org, &shared()), Truth::Unknown);
        let decided = Expr::And(vec![name("nobody"), org.clone()]);
        assert_eq!(truth(&decided, &shared()), Truth::False);
        let decided = Expr::Or(vec![name("sample"), org]);
        assert_eq!(truth(&decided, &shared()), Truth::True);
    }

    #[test]
    fn not_ip_cuts_addresses() {
        let row = row("10.88.0.0/18", vec![info(64510, "SAMPLE", "XA")]);
        let base = row.base().unwrap();
        let expr = Expr::And(vec![
            leaf(Leaf::Asn(AsnMatch::One(64510))),
            not(ip_leaf("10.88.55.0/24")),
        ]);
        let (value, _) = eval_row(&expr, &row, base, &Facts::default());
        assert_eq!(value.truth(), Truth::True);
        let left = value.sure.addresses(base);
        assert!(!left.intersects(&range("10.88.55.0/24")));
        assert!(left.contains(&range("10.88.0.0/19")));
        assert!(left.contains(&range("10.88.56.0/21")));
        // A cut that takes the whole route drops it.
        let all = Expr::And(vec![
            leaf(Leaf::Asn(AsnMatch::One(64510))),
            not(ip_leaf("10.0.0.0/8")),
        ]);
        assert_eq!(
            eval_row(&all, &row, base, &Facts::default()).0.truth(),
            Truth::False
        );
    }

    #[test]
    fn ip_selects_the_covering_route_and_routes_inside() {
        let mut facts = Facts::default();
        facts
            .cover
            .insert(prefix("10.88.55.242/32"), Some(prefix("10.88.55.0/24")));
        facts
            .cover
            .insert(prefix("10.88.0.0/16"), Some(prefix("10.0.0.0/8")));
        let address = ip_leaf("10.88.55.242");
        let covering = row("10.88.55.0/24", vec![info(64510, "SAMPLE", "XA")]);
        let wider = row("10.88.0.0/18", vec![info(64510, "SAMPLE", "XA")]);
        let base = covering.base().unwrap();
        let (value, _) = eval_row(&address, &covering, base, &facts);
        assert_eq!(
            value.sure,
            Part::Some(AddrSet::from(range("10.88.55.242/32")))
        );
        // A less specific route around the address is not its route.
        assert_eq!(truth_with(&address, &wider, &facts), Truth::False);
        // A network: its covering route and the routes inside it.
        let network = ip_leaf("10.88.0.0/16");
        assert_eq!(truth_with(&network, &wider, &facts), Truth::True);
        let (value, _) = eval_row(&network, &wider, wider.base().unwrap(), &facts);
        assert_eq!(value.sure, Part::Full);
        // In a scope, only the covering route matches.
        facts.scope = true;
        assert_eq!(truth_with(&network, &wider, &facts), Truth::False);
        assert_eq!(truth_with(&address, &covering, &facts), Truth::True);
        // Under `not` it is plain arithmetic, also on the wider route.
        let cut = Expr::And(vec![leaf(Leaf::Route(RouteMatch::Any)), not(address)]);
        let (value, _) = eval_row(&cut, &wider, wider.base().unwrap(), &facts);
        assert_eq!(value.truth(), Truth::True);
        assert!(
            !value
                .sure
                .addresses(wider.base().unwrap())
                .intersects(&range("10.88.55.242/32"))
        );
    }

    fn truth_with(expr: &Expr, row: &Row, facts: &Facts) -> Truth {
        eval_row(expr, row, row.base().unwrap(), facts).0.truth()
    }

    #[test]
    fn route_conditions() {
        let row = shared();
        let mut facts = Facts::default();
        facts
            .cover
            .insert(prefix("10.45.200.1/32"), Some(prefix("10.45.192.0/18")));
        let exact = leaf(Leaf::Route(RouteMatch::Exact(prefix("10.45.192.0/18"))));
        assert_eq!(truth_with(&exact, &row, &facts), Truth::True);
        let other = leaf(Leaf::Route(RouteMatch::Exact(prefix("10.45.192.0/19"))));
        assert_eq!(truth_with(&other, &row, &facts), Truth::False);
        let covering = leaf(Leaf::Route(RouteMatch::Covering(
            "10.45.200.1".parse().unwrap(),
        )));
        assert_eq!(truth_with(&covering, &row, &facts), Truth::True);
        let unknown = leaf(Leaf::Route(RouteMatch::Covering(
            "10.45.200.2".parse().unwrap(),
        )));
        assert_eq!(truth_with(&unknown, &row, &facts), Truth::False);
    }

    #[test]
    fn net_witnesses_give_the_addresses() {
        let block = |text: &str, cc: &str| {
            NetCandidate::Block(Block {
                rir: Rir::Ripencc,
                range: range(text),
                cc: cc.parse().unwrap(),
                opaque_id: None,
            })
        };
        let mut row = row("10.172.88.0/22", vec![info(64511, "X", "XA")]);
        row.nets = vec![block("10.172.88.0/23", "XA"), block("10.172.90.0/23", "XL")];
        let base = row.base().unwrap();
        let xa = leaf(Leaf::NetCountry("XA".parse().unwrap()));
        let (value, _) = eval_row(&xa, &row, base, &Facts::default());
        assert_eq!(
            value.sure,
            Part::Some(AddrSet::from(range("10.172.88.0/23")))
        );
        // One network must meet both conditions.
        let both = Expr::And(vec![xa, leaf(Leaf::NetCountry("XL".parse().unwrap()))]);
        assert_eq!(truth(&both, &row), Truth::False);
    }

    fn record(text: &str, org: &str, mnt: &[&str]) -> NetCandidate {
        NetCandidate::Record(std::sync::Arc::new(NetRecord {
            rir: Rir::Ripencc,
            range: range(text),
            handle: text.into(),
            name: None,
            country: None,
            org: Some(OrgRef {
                handle: org.into(),
                name: None,
            }),
            mnt: mnt.iter().map(|m| (*m).to_owned()).collect(),
            contacts: Vec::new(),
            parent_link: None,
            origin: crate::model::RecordOrigin::Rdap,
        }))
    }

    #[test]
    fn records_are_unknown_until_fetched() {
        let mut row = row("192.0.2.0/24", vec![info(64496, "X", "XA")]);
        let mnt = leaf(Leaf::NetMnt(HandleMatch::Any));
        let as_mnt = leaf(Leaf::AsMnt(HandleMatch::Any));
        assert_eq!(truth(&mnt, &row), Truth::Unknown);
        assert_eq!(truth(&as_mnt, &row), Truth::Unknown);
        assert_eq!(truth(&not(mnt.clone()), &row), Truth::Unknown);
        row.nets = vec![record("192.0.2.0/25", "ORG-A", &["A-MNT"])];
        row.fetched = true;
        let (value, _) = eval_row(&mnt, &row, row.base().unwrap(), &Facts::default());
        assert_eq!(value.sure, Part::Some(AddrSet::from(range("192.0.2.0/25"))));
        assert_eq!(value.maybe, value.sure);
        // After the fetch, the AS has no record, so it has no maintainers.
        assert_eq!(truth(&as_mnt, &row), Truth::False);
    }

    #[test]
    fn organizations_looked_up_are_known() {
        let row = {
            let mut row = row("192.0.2.0/24", vec![info(64496, "X", "XA")]);
            row.nets = vec![record("192.0.2.0/24", "ORG-A", &[])];
            row
        };
        let net_org = |handle: &str| leaf(Leaf::NetOrg(OrgMatch::HandleOrName(handle.into())));
        let as_org = |handle: &str| leaf(Leaf::AsOrg(OrgMatch::HandleOrName(handle.into())));
        let mut facts = Facts::default();
        facts.orgs.insert(
            (OrgSide::Net, "ORG-B".into()),
            OrgFacts {
                ranges: vec![range("192.0.2.0/24")],
                asns: Vec::new(),
            },
        );
        facts.orgs.insert(
            (OrgSide::As, "ORG-B".into()),
            OrgFacts {
                ranges: Vec::new(),
                asns: vec![(64496, 64496)],
            },
        );
        let base = row.base().unwrap();
        let truth = |expr: &Expr| eval_row(expr, &row, base, &facts).0.truth();
        // By the record of the row, without a lookup.
        assert_eq!(truth(&net_org("org-a")), Truth::True);
        // Not looked up and not the record: the row's RDAP may tell.
        assert_eq!(truth(&net_org("ORG-C")), Truth::Unknown);
        // Looked up: known either way.
        assert_eq!(truth(&net_org("ORG-B")), Truth::True);
        assert_eq!(truth(&as_org("ORG-B")), Truth::True);
        let mut other = row.clone();
        other.ases[0].asn = 64497;
        assert_eq!(
            eval_row(&as_org("ORG-B"), &other, base, &facts).0.truth(),
            Truth::False
        );
    }

    #[test]
    fn searched_names_and_handles_are_known() {
        use super::super::HandleKind;
        let row = {
            let mut row = row("192.0.2.0/24", vec![info(64496, "X", "XA")]);
            row.nets = vec![record("192.0.2.0/24", "ORG-A", &["A-MNT"])];
            row
        };
        let base = row.base().unwrap();
        let name = |text: &str| Pattern::Glob(crate::text::Glob::new(text));
        let net_name = |text: &str| leaf(Leaf::NetOrg(OrgMatch::Name(name(text))));
        let net_mnt = |handle: &str| leaf(Leaf::NetMnt(HandleMatch::Handle(handle.into())));
        let as_mnt = |handle: &str| leaf(Leaf::AsMnt(HandleMatch::Handle(handle.into())));
        let mut facts = Facts::default();
        facts.names.insert(
            (OrgSide::Net, name("Client*")),
            OrgFacts {
                ranges: vec![range("192.0.2.0/26")],
                asns: Vec::new(),
            },
        );
        facts.handles.insert(
            (OrgSide::Net, HandleKind::Mnt, "B-MNT".into()),
            OrgFacts {
                ranges: vec![range("192.0.2.0/24")],
                asns: Vec::new(),
            },
        );
        facts.handles.insert(
            (OrgSide::As, HandleKind::Mnt, "B-MNT".into()),
            OrgFacts {
                ranges: Vec::new(),
                asns: vec![(64496, 64496)],
            },
        );
        facts.handles.insert(
            (OrgSide::Net, HandleKind::Mnt, "C-MNT".into()),
            OrgFacts::default(),
        );
        let truth = |expr: &Expr| eval_row(expr, &row, base, &facts).0.truth();
        // Searched: the networks of the answer, known without RDAP.
        assert_eq!(truth(&net_name("Client*")), Truth::False);
        assert_eq!(truth(&net_mnt("b-mnt")), Truth::True);
        assert_eq!(truth(&as_mnt("B-MNT")), Truth::True);
        assert_eq!(truth(&net_mnt("C-MNT")), Truth::False);
        // The record of the row tells without a search.
        assert_eq!(truth(&net_mnt("A-MNT")), Truth::True);
        // Neither searched nor in the record: the row's RDAP may tell.
        assert_eq!(truth(&net_name("Other*")), Truth::Unknown);
        assert_eq!(truth(&net_mnt("D-MNT")), Truth::Unknown);
        // A row without networks has no holder when searched.
        let bare = Row {
            part: Some(range("198.51.100.0/24")),
            ..Row::default()
        };
        let base = bare.base().unwrap();
        assert_eq!(
            eval_row(&net_mnt("C-MNT"), &bare, base, &facts).0.truth(),
            Truth::False
        );
    }

    #[test]
    fn record_country_is_its_block() {
        let mut row = row("192.0.2.0/24", vec![info(64496, "X", "XA")]);
        row.nets = vec![
            NetCandidate::Block(Block {
                rir: Rir::Ripencc,
                range: range("192.0.2.0/24"),
                cc: "XA".parse().unwrap(),
                opaque_id: None,
            }),
            record("192.0.2.0/26", "ORG-A", &[]),
        ];
        let xa = leaf(Leaf::NetCountry("XA".parse().unwrap()));
        assert_eq!(truth(&xa, &row), Truth::True);
        // No network of the row is outside XA. The route covers the /26, so
        // `ip:` selects it.
        let mut facts = Facts::default();
        facts
            .cover
            .insert(prefix("192.0.2.0/26"), Some(prefix("192.0.2.0/24")));
        let ip = leaf(Leaf::Ip(range("192.0.2.0/26")));
        assert_ne!(truth_with(&ip, &row, &facts), Truth::False);
        assert_eq!(
            truth_with(&Expr::And(vec![ip, not(xa)]), &row, &facts),
            Truth::False
        );
        assert_eq!(
            block_of(&row.nets, range("192.0.2.1/32")).map(|b| b.range),
            Some(range("192.0.2.0/24"))
        );
    }
}
