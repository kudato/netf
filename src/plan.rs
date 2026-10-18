//! The plan of a query: what to show, which sources to load, and how to
//! find candidates.
//!
//! [`build`] makes a [`Plan`] from the expanded [`Expr`] and the options of
//! the run. [`Needs`] lists the sources that the answer depends on. The
//! engine loads exactly these, so `--ipset 'ip: …'` never downloads
//! asn.txt, and a query without `-6` never reads the IPv6 RIS dump.
//!
//! [`generator`] decides where the candidates of a conjunction come from.
//! The cheapest child produces them, and the other children only filter.
//! [`eval`] evaluates the predicate on a row.

pub(crate) mod eval;

use crate::{
    addr::{Addr, Families, Prefix},
    error::{Error, Result},
    model::{Cc, Rir, Role},
    query::{
        Expr, Field,
        expr::{AsnMatch, HandleMatch, Leaf, OrgMatch, RouteMatch},
    },
    text::Pattern,
};

/// What the answer is.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum Mode {
    /// Rows of the table.
    Rows {
        /// The most rows to show. `None` comes from `--limit 0` and means no
        /// limit.
        limit: Option<usize>,
        /// Extra columns from `--fields`. They need RDAP for the shown rows.
        fields: Vec<Field>,
    },
    /// The collapsed CIDR list of `--ipset`. It has no limit.
    Ipset,
}

/// The sources a query needs.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
pub(crate) struct Needs {
    /// RIS dumps of these families.
    pub(crate) ris: Families,
    /// asn.txt.
    pub(crate) asn: bool,
    /// Delegated stats of all five registries.
    pub(crate) stats: bool,
    /// The APNIC database dump.
    pub(crate) whois_apnic: bool,
    /// The AFRINIC database dump.
    pub(crate) whois_afrinic: bool,
    /// RDAP of the registries.
    pub(crate) rdap: bool,
    /// The RIPE database REST API.
    pub(crate) ripe_rest: bool,
    /// DNS, for `domain:`.
    pub(crate) dns: bool,
}

impl Needs {
    /// Returns what either needs.
    pub(crate) fn union(self, other: Needs) -> Needs {
        Needs {
            ris: self.ris.union(other.ris),
            asn: self.asn || other.asn,
            stats: self.stats || other.stats,
            whois_apnic: self.whois_apnic || other.whois_apnic,
            whois_afrinic: self.whois_afrinic || other.whois_afrinic,
            rdap: self.rdap || other.rdap,
            ripe_rest: self.ripe_rest || other.ripe_rest,
            dns: self.dns || other.dns,
        }
    }
}

/// An executable query.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct Plan {
    /// The whole predicate. Generators only narrow the candidates, and the
    /// engine checks every candidate against this predicate.
    pub(crate) root: Expr,
    /// The sources to load.
    pub(crate) needs: Needs,
    /// Rows or `--ipset`.
    pub(crate) mode: Mode,
    /// The address families of the run.
    pub(crate) families: Families,
}

/// Builds the plan of `root`.
///
/// # Errors
///
/// Returns a usage error if a `not ip:` or `not domain:` has no positive
/// condition to cut addresses from, as in the query `not ip: X` alone.
pub(crate) fn build(root: Expr, mode: Mode, families: Families) -> Result<Plan> {
    check_cuts(&root, true)?;
    let needs = needs(&root, &mode, families);
    Ok(Plan {
        root,
        needs,
        mode,
        families,
    })
}

/// Returns the sources that `root` needs in `mode`.
///
/// The result includes every source that the answer depends on, such as
/// the stats, RDAP, and the dumps.
pub(crate) fn needs(root: &Expr, mode: &Mode, families: Families) -> Needs {
    let mut needs = Needs::default();
    // Any condition on a field of the record needs the routes.
    let mut fields = false;
    root.for_each_leaf(&mut |leaf| match leaf {
        Leaf::Ip(_) | Leaf::IpScope(_) => {}
        Leaf::Domain(_) => needs.dns = true,
        Leaf::Route(_) | Leaf::Asn(_) => fields = true,
        Leaf::AsName(_) | Leaf::AsCountry(_) => {
            fields = true;
            needs.asn = true;
        }
        Leaf::AsRir(_) | Leaf::NetCountry(_) | Leaf::NetRir(_) => {
            fields = true;
            needs.stats = true;
        }
        // The registries find the organization, and the stats find the
        // blocks with its `opaque-id`.
        Leaf::AsOrg(_) | Leaf::NetOrg(_) => {
            fields = true;
            needs.stats = true;
            needs.rdap = true;
        }
        Leaf::AsMnt(handle)
        | Leaf::NetMnt(handle)
        | Leaf::AsContact(_, handle)
        | Leaf::NetContact(_, handle) => {
            fields = true;
            needs = needs.union(handle_needs(handle));
        }
        Leaf::Present(field) => {
            fields = true;
            needs = needs.union(field_needs(*field));
        }
        // A scope becomes conditions on `field`. Handles of maintainers and
        // contacts need the reverse searches. Organizations also need the
        // stats, for the `opaque-id` of their blocks.
        Leaf::Scope { field, .. } => {
            fields = true;
            needs = needs.union(field_needs(*field));
            match field {
                Field::AsOrg | Field::NetOrg => needs.stats = true,
                Field::AsMnt | Field::NetMnt | Field::AsContact(_) | Field::NetContact(_) => {
                    needs = needs.union(handle_needs(&HandleMatch::Handle(String::new())));
                }
                _ => {}
            }
        }
    });
    if let Mode::Rows { fields: extra, .. } = mode {
        // The route, AS, network, holder, and abuse columns need asn.txt
        // and RDAP, but not the stats. `--fields` adds the sources of its
        // fields. A `net.*` column starts its chain at the stats block.
        fields = true;
        needs.asn = true;
        needs.rdap = true;
        for field in extra {
            needs = needs.union(column_needs(*field));
        }
    }
    if fields {
        needs.ris = families;
    }
    needs
}

/// Returns the sources of the values of `field`, for `field: *` and scopes.
fn field_needs(field: Field) -> Needs {
    let mut needs = Needs::default();
    match field {
        Field::Route | Field::AsAsn => {}
        Field::AsName | Field::AsCountry => needs.asn = true,
        Field::AsRir | Field::NetCountry | Field::NetRir => needs.stats = true,
        Field::AsOrg
        | Field::NetOrg
        | Field::AsMnt
        | Field::NetMnt
        | Field::AsContact(_)
        | Field::NetContact(_) => needs.rdap = true,
    }
    needs
}

/// Returns the sources of a `--fields` column.
///
/// A column shows values of the shown rows only, so `*.mnt` and
/// `*.contact` come from RDAP, not from the reverse searches.
fn column_needs(field: Field) -> Needs {
    let mut needs = field_needs(field);
    if field.name().starts_with("net.") {
        needs.stats = true;
    }
    needs
}

/// Returns the sources of a condition on maintainers or contacts.
fn handle_needs(handle: &HandleMatch) -> Needs {
    match handle {
        // The reverse searches: the RIPE REST API and the two dumps.
        HandleMatch::Handle(_) => Needs {
            ripe_rest: true,
            whois_apnic: true,
            whois_afrinic: true,
            ..Needs::default()
        },
        // Checked on the RDAP record of every route.
        HandleMatch::Any => Needs {
            rdap: true,
            ..Needs::default()
        },
    }
}

/// Checks that every `not ip:` and `not domain:` is in a conjunction with
/// a positive condition to cut addresses from.
///
/// `alone` is `true` where a cut would be the whole condition: the root, a
/// branch of `or`, the inside of `not` or of a scope, or an item of an `and`
/// whose items are all negations.
fn check_cuts(expr: &Expr, alone: bool) -> Result<()> {
    if let Some(selector) = cut(expr) {
        if alone {
            return Err(Error::usage(format!(
                "not {selector}: needs a positive condition"
            )));
        }
        return Ok(());
    }
    match expr {
        Expr::And(items) => {
            let positive = items.iter().any(|item| !matches!(item, Expr::Not(_)));
            for item in items {
                check_cuts(item, !positive)?;
            }
            Ok(())
        }
        Expr::Or(items) => items.iter().try_for_each(|item| check_cuts(item, true)),
        Expr::Not(inner) | Expr::Bare { inner, .. } => check_cuts(inner, true),
        Expr::Leaf(Leaf::Scope { inner, .. } | Leaf::IpScope(inner)) => check_cuts(inner, true),
        Expr::Leaf(_) | Expr::False => Ok(()),
    }
}

/// Returns `ip` or `domain` if `expr` is a cut: `not` of addresses only.
fn cut(expr: &Expr) -> Option<&'static str> {
    let Expr::Not(inner) = expr else {
        return None;
    };
    let mut domain = false;
    addresses_only(inner, &mut domain).then_some(if domain { "domain" } else { "ip" })
}

/// Returns `true` if `expr` selects only addresses: `ip:`, `domain:`, and
/// `ip: {…}`, combined with `and` and `or`.
fn addresses_only(expr: &Expr, domain: &mut bool) -> bool {
    match expr {
        Expr::Leaf(Leaf::Ip(_) | Leaf::IpScope(_)) => true,
        Expr::Leaf(Leaf::Domain(_)) => {
            *domain = true;
            true
        }
        Expr::Or(items) | Expr::And(items) => {
            !items.is_empty() && items.iter().all(|item| addresses_only(item, domain))
        }
        Expr::Bare { inner, .. } => addresses_only(inner, domain),
        Expr::Leaf(_) | Expr::Not(_) | Expr::False => false,
    }
}

/// How costly a generator is.
///
/// In a conjunction, the cheapest child produces the candidates, and the
/// other children only filter them.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub(crate) enum Cost {
    /// Nothing to produce: `Expr::False`.
    Empty,
    /// An index lookup by address: `route:`, `ip:`.
    Address,
    /// An index lookup by origin: `as.asn:`.
    Origin,
    /// A pass over a column of asn.txt or of the stats: `as.name:`,
    /// `as.country:`, `net.country:`, `net.rir:`, `as.rir:`.
    Scan,
    /// A search in the registries: `net.org:`, `as.org:`, `*.mnt:`,
    /// `*.contact:` with a value.
    Search,
    /// Every route.
    Universe,
}

/// Where the candidates of a conjunction come from.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum Generator {
    /// The union of these lookups.
    Seeds(Box<Seeds>),
    /// Every route, for a conjunction with nothing to look up, such as
    /// `not as.asn: 1` or `route: *`. If a row without a route can match,
    /// also every block of the stats ([`unannounced`]).
    Universe,
}

/// The lookups that produce candidates.
///
/// Their union is a superset of the matching rows.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub(crate) struct Seeds {
    /// Routes with exactly these prefixes: `route: P`.
    pub(crate) exact: Vec<Prefix>,
    /// The most specific routes covering these addresses: `route: A`.
    pub(crate) covering: Vec<Addr>,
    /// `ip: X`: the most specific route covering `X`, the routes inside
    /// `X`, and the addresses of `X` that no route covers.
    pub(crate) ips: Vec<Prefix>,
    /// Routes originated by these AS numbers: one number or a range. The
    /// engine reports a single number that has no routes. The list never
    /// holds `Any`, because `as.asn: *` gives [`Generator::Universe`].
    pub(crate) asns: Vec<AsnMatch>,
    /// Routes of the AS whose name matches.
    pub(crate) names: Vec<Pattern>,
    /// Routes of the AS of these countries.
    pub(crate) countries: Vec<Cc>,
    /// Networks of the stats blocks of these countries: `net.country`.
    pub(crate) net_cc: Vec<Cc>,
    /// Networks of the stats blocks of these registries: `net.rir`.
    pub(crate) net_rir: Vec<Rir>,
    /// Every stats block: `net.country: *`, `net.rir: *`.
    pub(crate) net_all: bool,
    /// Routes of the AS of the stats blocks of these registries: `as.rir`.
    pub(crate) as_rir: Vec<Rir>,
    /// Routes of every AS of the stats: `as.rir: *`.
    pub(crate) as_all: bool,
    /// Organizations to look up by handle: `net.org: X`, `as.org: X`.
    pub(crate) orgs: Vec<OrgSeed>,
    /// Organizations to look up by name: `net.org: "X"`, `as.org: x*`.
    pub(crate) org_names: Vec<NameSeed>,
    /// Maintainers and contacts to search in reverse: `*.mnt: X`,
    /// `*.contact: X`.
    pub(crate) handles: Vec<HandleSeed>,
}

/// Which side an organization condition is on.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub(crate) enum OrgSide {
    /// `net.org`: the networks of the organization.
    Net,
    /// `as.org`: the AS of the organization.
    As,
}

impl OrgSide {
    /// Returns the field name, for notices.
    pub(crate) fn field(self) -> &'static str {
        match self {
            Self::Net => "net.org",
            Self::As => "as.org",
        }
    }
}

/// An organization that a generator looks up by handle in the registries
/// and by `opaque-id` in the stats.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct OrgSeed {
    /// `net.org` or `as.org`.
    pub(crate) side: OrgSide,
    /// The value as written.
    pub(crate) handle: String,
    /// `true` if the lookup is part of an operand without a field, such as
    /// `netf sample`. The engine gives no notice when such a lookup alone
    /// finds nothing.
    pub(crate) bare: bool,
}

/// An organization that a generator looks up by name.
///
/// The RIPE REST API answers for RIPE, and RDAP `entities?fn=` answers for
/// the other four registries.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct NameSeed {
    /// `net.org` or `as.org`.
    pub(crate) side: OrgSide,
    /// The name, never `Any`.
    pub(crate) pattern: Pattern,
    /// `true` if the lookup is part of an operand without a field, such as
    /// `netf sample`. The engine gives no notice when such a lookup alone
    /// finds nothing.
    pub(crate) bare: bool,
}

/// What a handle of a reverse search is in the record: a maintainer or a
/// contact.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub(crate) enum HandleKind {
    /// A maintainer: `*.mnt`.
    Mnt,
    /// A contact: `Some(role)` for `*.contact.<role>`, or `None` for any
    /// role of `*.contact`.
    Contact(Option<Role>),
}

/// A maintainer or contact that a generator searches in reverse, in the
/// RIPE REST API and the dumps of APNIC and AFRINIC.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct HandleSeed {
    /// `net.*` for the networks or `as.*` for the AS.
    pub(crate) side: OrgSide,
    /// A maintainer or a contact.
    pub(crate) kind: HandleKind,
    /// The handle as written.
    pub(crate) handle: String,
}

impl Seeds {
    /// Returns the cost of the costliest lookup.
    pub(crate) fn cost(&self) -> Cost {
        if !self.orgs.is_empty() || !self.org_names.is_empty() || !self.handles.is_empty() {
            Cost::Search
        } else if !self.names.is_empty()
            || !self.countries.is_empty()
            || !self.net_cc.is_empty()
            || !self.net_rir.is_empty()
            || self.net_all
            || !self.as_rir.is_empty()
            || self.as_all
        {
            Cost::Scan
        } else if !self.asns.is_empty() {
            Cost::Origin
        } else if !self.exact.is_empty() || !self.covering.is_empty() || !self.ips.is_empty() {
            Cost::Address
        } else {
            Cost::Empty
        }
    }

    /// Adds the lookups of `other`.
    fn extend(&mut self, other: Seeds) {
        self.exact.extend(other.exact);
        self.covering.extend(other.covering);
        self.ips.extend(other.ips);
        self.asns.extend(other.asns);
        self.names.extend(other.names);
        self.countries.extend(other.countries);
        self.net_cc.extend(other.net_cc);
        self.net_rir.extend(other.net_rir);
        self.net_all |= other.net_all;
        self.as_rir.extend(other.as_rir);
        self.as_all |= other.as_all;
        self.orgs.extend(other.orgs);
        self.org_names.extend(other.org_names);
        self.handles.extend(other.handles);
    }
}

impl Generator {
    /// Returns the cost of producing the candidates.
    pub(crate) fn cost(&self) -> Cost {
        match self {
            Self::Seeds(seeds) => seeds.cost(),
            Self::Universe => Cost::Universe,
        }
    }
}

/// Returns how to produce the candidates of `expr`.
///
/// The domains and scopes of `expr` are already resolved into `ip:` and
/// value leaves. `or` unites the generators of its branches. `and` takes
/// its cheapest child. `not` produces nothing, so a conjunction of
/// negations falls back to every route. So does a condition that no index
/// answers.
pub(crate) fn generator(expr: &Expr) -> Generator {
    generate(expr, false).unwrap_or(Generator::Universe)
}

/// Returns the generator of `expr`, or `None` for a pure filter.
///
/// `bare` is `true` inside an operand without a field.
fn generate(expr: &Expr, bare: bool) -> Option<Generator> {
    let mut seeds = Seeds::default();
    match expr {
        Expr::False => {}
        Expr::Not(_) => return None,
        Expr::Bare { inner, .. } => return generate(inner, true),
        Expr::And(items) => {
            return items
                .iter()
                .filter_map(|item| generate(item, bare))
                .min_by_key(Generator::cost);
        }
        Expr::Or(items) => {
            for item in items {
                match generate(item, bare) {
                    Some(Generator::Seeds(more)) => seeds.extend(*more),
                    Some(Generator::Universe) | None => return Some(Generator::Universe),
                }
            }
        }
        Expr::Leaf(leaf) => match leaf {
            Leaf::Route(RouteMatch::Exact(prefix)) => seeds.exact.push(*prefix),
            Leaf::Route(RouteMatch::Covering(addr)) => seeds.covering.push(*addr),
            Leaf::Asn(matcher @ (AsnMatch::One(_) | AsnMatch::Range { .. })) => {
                seeds.asns.push(*matcher);
            }
            Leaf::AsName(pattern) if *pattern != Pattern::Any => seeds.names.push(pattern.clone()),
            Leaf::AsCountry(cc) => seeds.countries.push(*cc),
            Leaf::Ip(range) => seeds.ips.extend(range.prefixes()),
            Leaf::NetCountry(cc) => seeds.net_cc.push(*cc),
            Leaf::NetRir(rir) => seeds.net_rir.push(*rir),
            Leaf::Present(Field::NetCountry | Field::NetRir) => seeds.net_all = true,
            Leaf::AsRir(rir) => seeds.as_rir.push(*rir),
            Leaf::Present(Field::AsRir) => seeds.as_all = true,
            Leaf::NetOrg(OrgMatch::HandleOrName(handle)) => seeds.orgs.push(OrgSeed {
                side: OrgSide::Net,
                handle: handle.clone(),
                bare,
            }),
            Leaf::AsOrg(OrgMatch::HandleOrName(handle)) => seeds.orgs.push(OrgSeed {
                side: OrgSide::As,
                handle: handle.clone(),
                bare,
            }),
            Leaf::NetOrg(OrgMatch::Name(pattern)) if *pattern != Pattern::Any => {
                seeds.org_names.push(NameSeed {
                    side: OrgSide::Net,
                    pattern: pattern.clone(),
                    bare,
                });
            }
            Leaf::AsOrg(OrgMatch::Name(pattern)) if *pattern != Pattern::Any => {
                seeds.org_names.push(NameSeed {
                    side: OrgSide::As,
                    pattern: pattern.clone(),
                    bare,
                });
            }
            Leaf::NetMnt(HandleMatch::Handle(handle)) => {
                seeds.handles.push(HandleSeed {
                    side: OrgSide::Net,
                    kind: HandleKind::Mnt,
                    handle: handle.clone(),
                });
            }
            Leaf::AsMnt(HandleMatch::Handle(handle)) => {
                seeds.handles.push(HandleSeed {
                    side: OrgSide::As,
                    kind: HandleKind::Mnt,
                    handle: handle.clone(),
                });
            }
            Leaf::NetContact(role, HandleMatch::Handle(handle)) => {
                seeds.handles.push(HandleSeed {
                    side: OrgSide::Net,
                    kind: HandleKind::Contact(*role),
                    handle: handle.clone(),
                });
            }
            Leaf::AsContact(role, HandleMatch::Handle(handle)) => {
                seeds.handles.push(HandleSeed {
                    side: OrgSide::As,
                    kind: HandleKind::Contact(*role),
                    handle: handle.clone(),
                });
            }
            // No index narrows these. Every route has a prefix, and nearly
            // every route has an origin. Nearly every AS has a name.
            // `*.org: *`, `*.mnt: *`, and `*.contact: *` are checked on the
            // record of every route.
            _ => return Some(Generator::Universe),
        },
    }
    Some(Generator::Seeds(Box::new(seeds)))
}

/// Returns `true` if a row without a route can match `expr`.
///
/// Such a row has no AS either, so conditions on `route` and on `as.*` are
/// false on it. Conditions on `net.*` and `ip:` depend on its network.
pub(crate) fn unannounced(expr: &Expr) -> bool {
    unrouted(expr) != Some(false)
}

/// Returns the value of `expr` on a row without a route and without an AS,
/// or `None` if the value depends on the network of the row.
fn unrouted(expr: &Expr) -> Option<bool> {
    match expr {
        Expr::False => Some(false),
        Expr::Bare { inner, .. } => unrouted(inner),
        Expr::Not(inner) => unrouted(inner).map(|value| !value),
        Expr::And(items) => {
            let mut value = Some(true);
            for item in items {
                match unrouted(item) {
                    Some(false) => return Some(false),
                    Some(true) => {}
                    None => value = None,
                }
            }
            value
        }
        Expr::Or(items) => {
            let mut value = Some(false);
            for item in items {
                match unrouted(item) {
                    Some(true) => return Some(true),
                    Some(false) => {}
                    None => value = None,
                }
            }
            value
        }
        Expr::Leaf(
            Leaf::Route(_)
            | Leaf::Asn(_)
            | Leaf::AsName(_)
            | Leaf::AsOrg(_)
            | Leaf::AsCountry(_)
            | Leaf::AsRir(_)
            | Leaf::AsMnt(_)
            | Leaf::AsContact(..)
            | Leaf::Present(Field::AsCountry | Field::AsRir),
        ) => Some(false),
        Expr::Leaf(_) => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(text: &str) -> Expr {
        Expr::Leaf(Leaf::Ip(text.parse().unwrap()))
    }

    fn leaf(leaf: Leaf) -> Expr {
        Expr::Leaf(leaf)
    }

    fn not(expr: Expr) -> Expr {
        Expr::Not(Box::new(expr))
    }

    fn rows() -> Mode {
        Mode::Rows {
            limit: Some(100),
            fields: Vec::new(),
        }
    }

    /// Each kind of condition and each mode needs its own sources.
    #[test]
    fn needs_follow_the_table() {
        let v4 = Families::V4;
        // Addresses alone with `--ipset` need nothing but DNS for `domain:`.
        let pure = Expr::And(vec![ip("192.0.2.0/24"), not(ip("192.0.2.1"))]);
        assert_eq!(needs(&pure, &Mode::Ipset, v4), Needs::default());
        let domain = leaf(Leaf::Domain("ex.test".into()));
        assert_eq!(
            needs(&domain, &Mode::Ipset, v4),
            Needs {
                dns: true,
                ..Needs::default()
            }
        );
        // `route` and `as.asn` need only RIS of the families.
        let asn = leaf(Leaf::Asn(AsnMatch::One(64510)));
        assert_eq!(
            needs(&asn, &Mode::Ipset, Families::BOTH),
            Needs {
                ris: Families::BOTH,
                ..Needs::default()
            }
        );
        // `as.name` and `as.country` add asn.txt.
        let name = leaf(Leaf::AsName(Pattern::Exact("sample".into())));
        let ipset = needs(&name, &Mode::Ipset, v4);
        assert!(ipset.asn && ipset.ris == v4 && !ipset.stats && !ipset.rdap);
        // Rows need the sources of every column.
        let shown = needs(&pure, &rows(), v4);
        assert!(shown.ris == v4 && shown.asn && !shown.stats && shown.rdap && !shown.dns);
        // `--fields net.*` adds the stats, for the block the chain starts at.
        let chain = Mode::Rows {
            limit: Some(100),
            fields: vec![Field::NetOrg],
        };
        assert!(needs(&pure, &chain, v4).stats);
        // `net.*` and `as.rir` add the stats. `*.org` adds RDAP.
        let rir = leaf(Leaf::AsRir(Rir::Ripencc));
        assert!(needs(&rir, &Mode::Ipset, v4).stats);
        let org = needs(&leaf(Leaf::NetOrg(OrgMatch::Any)), &Mode::Ipset, v4);
        assert!(org.rdap && org.stats);
        // `*.mnt` with a value needs the reverse searches. `*.mnt: *` needs
        // RDAP.
        let mnt = needs(
            &leaf(Leaf::NetMnt(HandleMatch::Handle("SAMPLE-MNT".into()))),
            &Mode::Ipset,
            v4,
        );
        assert!(mnt.ripe_rest && mnt.whois_apnic && mnt.whois_afrinic && !mnt.rdap);
        assert!(needs(&leaf(Leaf::AsMnt(HandleMatch::Any)), &Mode::Ipset, v4).rdap);
        // A scope needs its field and its inside.
        let scope = leaf(Leaf::Scope {
            field: Field::AsName,
            inner: Box::new(domain),
        });
        let scoped = needs(&scope, &Mode::Ipset, v4);
        assert!(scoped.asn && scoped.dns && scoped.ris == v4);
    }

    #[test]
    fn searches_generate() {
        // Names of organizations and values of maintainers and contacts are
        // searches in the registries. The plan keeps them as they are.
        let name = leaf(Leaf::NetOrg(OrgMatch::Name(Pattern::Exact(
            "Sample LLC".into(),
        ))));
        let mnt = leaf(Leaf::AsMnt(HandleMatch::Handle("SAMPLE-MNT".into())));
        let contact = leaf(Leaf::NetContact(
            Some(Role::Abuse),
            HandleMatch::Handle("AR1-RIPE".into()),
        ));
        let scope = leaf(Leaf::Scope {
            field: Field::NetOrg,
            inner: Box::new(ip("192.0.2.0/24")),
        });
        for ok in [name.clone(), mnt.clone(), contact.clone(), scope.clone()] {
            let plan = build(ok.clone(), Mode::Ipset, Families::V4).unwrap();
            assert_eq!(plan.root, ok);
        }
        let Generator::Seeds(seeds) = generator(&Expr::Or(vec![mnt, contact])) else {
            panic!("universe");
        };
        assert_eq!(
            seeds.handles,
            [
                HandleSeed {
                    side: OrgSide::As,
                    kind: HandleKind::Mnt,
                    handle: "SAMPLE-MNT".into(),
                },
                HandleSeed {
                    side: OrgSide::Net,
                    kind: HandleKind::Contact(Some(Role::Abuse)),
                    handle: "AR1-RIPE".into(),
                },
            ]
        );
        assert_eq!(seeds.cost(), Cost::Search);
        // A scope over an organization needs the stats, for the `opaque-id`
        // of the blocks. A scope over a maintainer needs the reverse search.
        assert!(needs(&scope, &Mode::Ipset, Families::V4).stats);
        let mnt_scope = leaf(Leaf::Scope {
            field: Field::NetMnt,
            inner: Box::new(ip("192.0.2.0/24")),
        });
        let mnt_needs = needs(&mnt_scope, &Mode::Ipset, Families::V4);
        assert!(mnt_needs.rdap && mnt_needs.ripe_rest && mnt_needs.whois_apnic);
        // An operand without a field also searches the name, with no
        // notice.
        let bare = Expr::Bare {
            word: "sample".into(),
            inner: Box::new(Expr::Or(vec![
                leaf(Leaf::AsName(Pattern::Exact("sample".into()))),
                name,
                leaf(Leaf::AsOrg(OrgMatch::HandleOrName("sample".into()))),
            ])),
        };
        let plan = build(bare, Mode::Ipset, Families::V4).unwrap();
        let Generator::Seeds(seeds) = generator(&plan.root) else {
            panic!("universe");
        };
        assert_eq!(
            seeds.orgs,
            [OrgSeed {
                side: OrgSide::As,
                handle: "sample".into(),
                bare: true,
            }]
        );
        assert_eq!(
            seeds.org_names,
            [NameSeed {
                side: OrgSide::Net,
                pattern: Pattern::Exact("Sample LLC".into()),
                bare: true,
            }]
        );
        assert_eq!(seeds.cost(), Cost::Search);
        // A name of any holder is checked on every route.
        assert_eq!(
            generator(&leaf(Leaf::AsOrg(OrgMatch::Name(Pattern::Any)))),
            Generator::Universe
        );
        // A search costs more than an address. `ip: X and net.mnt: Y`
        // reads the maintainer from the record of the row.
        let both = Expr::And(vec![
            ip("192.0.2.0/24"),
            leaf(Leaf::NetMnt(HandleMatch::Handle("A-MNT".into()))),
        ]);
        assert_eq!(generator(&both).cost(), Cost::Address);
    }

    #[test]
    fn stats_seeds_scan() {
        let Generator::Seeds(seeds) = generator(&Expr::Or(vec![
            leaf(Leaf::NetCountry("XA".parse().unwrap())),
            leaf(Leaf::Present(Field::AsRir)),
        ])) else {
            panic!("universe");
        };
        assert_eq!(seeds.net_cc, ["XA".parse().unwrap()]);
        assert!(seeds.as_all && !seeds.net_all);
        assert_eq!(seeds.cost(), Cost::Scan);
        // A number is cheaper than a search of the stats.
        let both = Expr::And(vec![
            leaf(Leaf::NetRir(Rir::Arin)),
            leaf(Leaf::Asn(AsnMatch::One(64496))),
        ]);
        assert_eq!(generator(&both).cost(), Cost::Origin);
        // `net.org: *` is checked on every route.
        assert_eq!(
            generator(&leaf(Leaf::NetOrg(OrgMatch::Any))),
            Generator::Universe
        );
    }

    #[test]
    fn a_cut_needs_a_positive_part() {
        let error = build(not(ip("192.0.2.1")), Mode::Ipset, Families::V4).unwrap_err();
        assert_eq!(error.message(), "not ip: needs a positive condition");
        let cut = Expr::And(vec![
            leaf(Leaf::Asn(AsnMatch::One(64510))),
            not(ip("192.0.2.1")),
        ]);
        assert!(build(cut, Mode::Ipset, Families::V4).is_ok());
    }

    #[test]
    fn generators_take_the_cheapest_child() {
        let asn = leaf(Leaf::Asn(AsnMatch::One(64510)));
        let name = leaf(Leaf::AsName(Pattern::Exact("sample".into())));
        let addr = ip("192.0.2.0/24");
        // `and` takes the cheapest child. The other children filter.
        let Generator::Seeds(seeds) =
            generator(&Expr::And(vec![name.clone(), asn.clone(), addr.clone()]))
        else {
            panic!("universe");
        };
        assert_eq!(seeds.ips, ["192.0.2.0/24".parse().unwrap()]);
        assert!(seeds.asns.is_empty() && seeds.names.is_empty());
        // `or` takes the union.
        let Generator::Seeds(seeds) = generator(&Expr::Or(vec![name.clone(), asn.clone()])) else {
            panic!("universe");
        };
        assert_eq!(seeds.asns, [AsnMatch::One(64510)]);
        assert_eq!(seeds.cost(), Cost::Scan);
        // `not` produces nothing. A conjunction of negations is every route.
        assert_eq!(generator(&not(asn.clone())), Generator::Universe);
        assert_eq!(
            generator(&Expr::And(vec![not(asn.clone()), not(name.clone())])),
            Generator::Universe
        );
        // A filter beside a generator does not widen it.
        assert_eq!(
            generator(&Expr::And(vec![asn.clone(), not(addr.clone())])).cost(),
            Cost::Origin
        );
        // `or` with a pure filter is every route.
        assert_eq!(
            generator(&Expr::Or(vec![asn, not(addr)])),
            Generator::Universe
        );
        assert_eq!(
            generator(&leaf(Leaf::Route(RouteMatch::Any))),
            Generator::Universe
        );
        assert_eq!(generator(&Expr::False).cost(), Cost::Empty);
        // A range that is not one CIDR gives its prefixes.
        let Generator::Seeds(seeds) = generator(&ip("192.0.2.1-192.0.2.2")) else {
            panic!("universe");
        };
        assert_eq!(seeds.ips.len(), 2);
    }

    #[test]
    fn rows_without_a_route() {
        let route = leaf(Leaf::Route(RouteMatch::Any));
        let asn = leaf(Leaf::Asn(AsnMatch::One(64510)));
        let rir = leaf(Leaf::Present(Field::NetRir));
        // A row without a route has no AS.
        assert!(unannounced(&not(route.clone())));
        assert!(unannounced(&not(asn.clone())));
        assert!(!unannounced(&route));
        assert!(!unannounced(&leaf(Leaf::AsName(Pattern::Any))));
        assert!(!unannounced(&Expr::And(vec![
            not(asn.clone()),
            asn.clone()
        ])));
        // A network decides the rest.
        assert!(unannounced(&rir));
        assert!(unannounced(&Expr::And(vec![not(asn.clone()), rir.clone()])));
        assert!(unannounced(&Expr::Or(vec![asn, not(rir)])));
        assert!(!unannounced(&Expr::False));
    }
}
