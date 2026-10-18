//! Scopes, `field: {…}`: the engine runs the inner query first, and the
//! values of `field` among its rows become a list. `ip: {…}` takes the
//! addresses of the rows. Each domain is resolved once per run.
//!
//! [`resolve`] rewrites an expression into one that the candidates and the
//! predicate understand:
//!
//! - `domain:` becomes the `ip:` of its addresses.
//! - An `ip:` range that is not one CIDR becomes the `or` of its prefixes.
//! - A scope becomes the `or` of its values, or `Expr::False` when there
//!   are none.
//!
//! The values of `*.org`, `*.mnt`, and `*.contact` come from the RDAP
//! records of the inner rows: the most specific record of the row for
//! `net.*`, and the autnum of every AS of the row for `as.*`. An
//! organization gives its handle, its name, and the `opaque-id` of the
//! stats block. These organization values come from real registry responses,
//! so the engine does not report them as not found or empty.

use std::{collections::HashMap, sync::Arc};

use futures_util::future::{LocalBoxFuture, try_join_all};

use super::{Collect, Engine};
use crate::{
    addr::{Family, Range, set::AddrSet},
    error::Result,
    model::{AsRecord, Asn, Contact, NetCandidate, NetRecord, OrgRef, Role, Row},
    plan::{self, Mode, OrgSide, eval},
    query::{
        Expr, Field,
        expr::{AsnMatch, HandleMatch, Leaf, OrgMatch, RouteMatch},
    },
    report::Notice,
    text::Pattern,
};

/// Resolves the domains, ranges, and scopes of `expr`.
///
/// # Errors
///
/// Returns an error if a domain lookup, a source, or a registry fails.
pub(crate) fn resolve<'a>(
    engine: &'a Engine<'_>,
    expr: &'a Expr,
) -> LocalBoxFuture<'a, Result<Expr>> {
    Box::pin(async move {
        Ok(match expr {
            Expr::Or(items) => Expr::Or(resolve_all(engine, items).await?),
            Expr::And(items) => Expr::And(resolve_all(engine, items).await?),
            Expr::Not(inner) => Expr::Not(Box::new(resolve(engine, inner).await?)),
            Expr::Bare { word, inner } => Expr::Bare {
                word: word.clone(),
                inner: Box::new(resolve(engine, inner).await?),
            },
            Expr::Leaf(leaf) => resolve_leaf(engine, leaf).await?,
            Expr::False => Expr::False,
        })
    })
}

/// Resolves every item, in order.
async fn resolve_all(engine: &Engine<'_>, items: &[Expr]) -> Result<Vec<Expr>> {
    let mut resolved = Vec::with_capacity(items.len());
    for item in items {
        resolved.push(resolve(engine, item).await?);
    }
    Ok(resolved)
}

async fn resolve_leaf(engine: &Engine<'_>, leaf: &Leaf) -> Result<Expr> {
    match leaf {
        Leaf::Domain(name) => domain(engine, name).await,
        Leaf::Ip(range) => Ok(ip(*range)),
        Leaf::Scope { field, inner } => {
            let inner = resolve(engine, inner).await?;
            let want_asn = plan::needs(&inner, &Mode::Ipset, engine.families).asn
                || matches!(field, Field::AsName | Field::AsCountry);
            let selection = engine
                .select(&inner, want_asn, true, Collect::Rows { limit: None })
                .await?;
            if registry_field(*field) {
                registry_values(engine, *field, &selection.rows).await
            } else {
                Ok(values(*field, &selection.rows))
            }
        }
        Leaf::IpScope(inner) => {
            let inner = resolve(engine, inner).await?;
            let needs = plan::needs(&inner, &Mode::Ipset, engine.families);
            let addresses = if needs.ris.is_empty() {
                super::parts::addresses(&inner, engine.families)
            } else {
                engine
                    .select(&inner, needs.asn, false, Collect::Addresses)
                    .await?
                    .addresses
            };
            Ok(set(&addresses))
        }
        other => Ok(Expr::Leaf(other.clone())),
    }
}

/// Returns the `ip:` of the addresses of `domain: name` in the families of
/// the run.
///
/// A family without addresses is reported only on the first lookup of
/// `name`.
async fn domain(engine: &Engine<'_>, name: &str) -> Result<Expr> {
    let (resolved, first) = engine.resolve_domain(name).await?;
    let families = engine.families;
    let mut addresses = AddrSet::new();
    if families.v4() {
        resolved
            .v4
            .iter()
            .for_each(|addr| addresses.insert(Range::from_addr((*addr).into())));
    }
    if families.v6() {
        resolved
            .v6
            .iter()
            .for_each(|addr| addresses.insert(Range::from_addr((*addr).into())));
    }
    if first {
        for family in families.iter() {
            let none = match family {
                Family::V4 => resolved.v4.is_empty(),
                Family::V6 => resolved.v6.is_empty(),
            };
            if none {
                engine.notice(Notice::NoAddress {
                    domain: name.to_owned(),
                    family,
                });
            }
        }
    }
    Ok(set(&addresses))
}

/// Returns `ip: range`, split into CIDR prefixes if the range is not one
/// prefix.
fn ip(range: Range) -> Expr {
    if range.as_prefix().is_some() {
        Expr::Leaf(Leaf::Ip(range))
    } else {
        or(range
            .prefixes()
            .map(|prefix| Expr::Leaf(Leaf::Ip(prefix.into()))))
    }
}

/// Returns the `ip:` of the CIDR prefixes of `set`.
fn set(set: &AddrSet) -> Expr {
    or(set
        .pieces()
        .flat_map(|range| range.prefixes().collect::<Vec<_>>())
        .map(|prefix| Expr::Leaf(Leaf::Ip(prefix.into()))))
}

/// Joins `items` with `or`.
///
/// Returns a single item as it is, and `Expr::False` for no items.
fn or(items: impl Iterator<Item = Expr>) -> Expr {
    let mut items: Vec<Expr> = items.collect();
    match items.len() {
        0 => Expr::False,
        1 => items.remove(0),
        _ => Expr::Or(items),
    }
}

/// Returns `true` for the fields whose values are read from the RDAP
/// records of the rows.
fn registry_field(field: Field) -> bool {
    matches!(
        field,
        Field::NetOrg
            | Field::AsOrg
            | Field::NetMnt
            | Field::AsMnt
            | Field::NetContact(_)
            | Field::AsContact(_)
    )
}

/// Returns the values of `field` among `rows` as the `or` of exact
/// conditions.
///
/// `field` is one of the [`registry_field`] fields. Each record is fetched
/// once per run.
async fn registry_values(engine: &Engine<'_>, field: Field, rows: &[Row]) -> Result<Expr> {
    let mut leaves: Vec<Leaf> = Vec::new();
    let mut add = |leaf: Leaf| {
        if !leaves.contains(&leaf) {
            leaves.push(leaf);
        }
    };
    if field.name().starts_with("net.") {
        let mut bases: Vec<(Range, Option<Arc<str>>)> = Vec::new();
        for row in rows {
            if let Some(base) = row.base() {
                let opaque =
                    eval::block_of(&row.nets, base).and_then(|block| block.opaque_id.clone());
                if !bases.contains(&(base, opaque.clone())) {
                    bases.push((base, opaque));
                }
            }
        }
        let records = try_join_all(bases.iter().map(|(base, _)| engine.rdap.ip(*base))).await?;
        for ((_, opaque), record) in bases.iter().zip(records) {
            for leaf in net_values(field, record.as_deref(), opaque.as_deref()) {
                add(leaf);
            }
        }
    } else {
        let mut known: HashMap<Asn, Option<Arc<AsRecord>>> = HashMap::new();
        let mut opaque: Vec<(Asn, Option<Arc<str>>)> = Vec::new();
        for info in rows.iter().flat_map(|row| &row.ases) {
            if let Some(record) = &info.rdap {
                known.insert(info.asn, Some(Arc::clone(record)));
            }
            let id = info
                .block
                .as_ref()
                .and_then(|block| block.opaque_id.clone());
            if !opaque.contains(&(info.asn, id.clone())) {
                opaque.push((info.asn, id));
            }
        }
        let missing: Vec<Asn> = opaque
            .iter()
            .map(|(asn, _)| *asn)
            .filter(|asn| !known.contains_key(asn))
            .collect::<std::collections::BTreeSet<_>>()
            .into_iter()
            .collect();
        let records = try_join_all(missing.iter().map(|asn| engine.rdap.autnum(*asn))).await?;
        known.extend(missing.into_iter().zip(records));
        for (asn, id) in &opaque {
            let record = known.get(asn).cloned().flatten();
            for leaf in as_values(field, record.as_deref(), id.as_deref()) {
                add(leaf);
            }
        }
    }
    for leaf in &leaves {
        match leaf {
            Leaf::NetOrg(matcher) => engine.quiet(OrgSide::Net, matcher.clone()),
            Leaf::AsOrg(matcher) => engine.quiet(OrgSide::As, matcher.clone()),
            _ => {}
        }
    }
    Ok(or(leaves.into_iter().map(Expr::Leaf)))
}

/// Returns the values of a `net.*` [`registry_field`] from the most
/// specific record of a row and from the `opaque-id` of its block.
fn net_values(field: Field, record: Option<&NetRecord>, opaque: Option<&str>) -> Vec<Leaf> {
    match field {
        Field::NetOrg => org_values(record.and_then(|record| record.org.as_ref()), opaque)
            .into_iter()
            .map(Leaf::NetOrg)
            .collect(),
        Field::NetMnt => record
            .map(|record| handles(&record.mnt).map(Leaf::NetMnt).collect())
            .unwrap_or_default(),
        Field::NetContact(role) => record
            .map(|record| {
                contacts(&record.contacts, role)
                    .map(|handle| Leaf::NetContact(role, handle))
                    .collect()
            })
            .unwrap_or_default(),
        _ => Vec::new(),
    }
}

/// Returns the values of an `as.*` [`registry_field`] from the autnum of
/// an AS and from the `opaque-id` of its block.
fn as_values(field: Field, record: Option<&AsRecord>, opaque: Option<&str>) -> Vec<Leaf> {
    match field {
        Field::AsOrg => org_values(record.and_then(|record| record.org.as_ref()), opaque)
            .into_iter()
            .map(Leaf::AsOrg)
            .collect(),
        Field::AsMnt => record
            .map(|record| handles(&record.mnt).map(Leaf::AsMnt).collect())
            .unwrap_or_default(),
        Field::AsContact(role) => record
            .map(|record| {
                contacts(&record.contacts, role)
                    .map(|handle| Leaf::AsContact(role, handle))
                    .collect()
            })
            .unwrap_or_default(),
        _ => Vec::new(),
    }
}

/// Returns conditions on the holder by handle and by name, and on the
/// `opaque-id` of the block.
fn org_values(org: Option<&OrgRef>, opaque: Option<&str>) -> Vec<OrgMatch> {
    let mut values = Vec::new();
    if let Some(org) = org {
        values.push(OrgMatch::HandleOrName(org.handle.clone()));
        if let Some(name) = &org.name {
            values.push(OrgMatch::Name(Pattern::Exact(name.clone())));
        }
    }
    if let Some(id) = opaque {
        values.push(OrgMatch::HandleOrName(id.to_owned()));
    }
    values
}

/// Returns the maintainers as conditions.
fn handles(mnt: &[String]) -> impl Iterator<Item = HandleMatch> + '_ {
    mnt.iter().map(|mnt| HandleMatch::Handle(mnt.clone()))
}

/// Returns conditions on the contacts that have `role`.
///
/// Without a role, any role of [`Role::CONTACT`] matches.
fn contacts(contacts: &[Contact], role: Option<Role>) -> impl Iterator<Item = HandleMatch> + '_ {
    contacts
        .iter()
        .filter(move |contact| match role {
            Some(role) => contact.roles.contains(&role),
            None => contact
                .roles
                .iter()
                .any(|role| Role::CONTACT.contains(role)),
        })
        .map(|contact| HandleMatch::Handle(contact.handle.clone()))
}

/// Returns the values of `field` among `rows` as the `or` of exact
/// conditions.
///
/// The [`registry_field`] fields give no values here. [`registry_values`]
/// reads them from the records.
fn values(field: Field, rows: &[Row]) -> Expr {
    let mut leaves: Vec<Leaf> = Vec::new();
    let mut add = |leaf: Leaf| {
        if !leaves.contains(&leaf) {
            leaves.push(leaf);
        }
    };
    for row in rows {
        match field {
            Field::Route => {
                if let Some(route) = &row.route {
                    add(Leaf::Route(RouteMatch::Exact(route.prefix)));
                }
            }
            Field::AsAsn => {
                for info in &row.ases {
                    add(Leaf::Asn(AsnMatch::One(info.asn)));
                }
            }
            Field::AsName => {
                for entry in row.ases.iter().filter_map(|info| info.entry.as_ref()) {
                    add(Leaf::AsName(Pattern::Exact(entry.name.clone())));
                }
            }
            Field::AsCountry => {
                for cc in row
                    .ases
                    .iter()
                    .filter_map(|info| info.entry.as_ref()?.country)
                {
                    add(Leaf::AsCountry(cc));
                }
            }
            Field::AsRir => {
                for block in row.ases.iter().filter_map(|info| info.block.as_ref()) {
                    add(Leaf::AsRir(block.rir));
                }
            }
            Field::NetCountry | Field::NetRir => {
                for net in &row.nets {
                    if let NetCandidate::Block(block) = net {
                        add(if field == Field::NetCountry {
                            Leaf::NetCountry(block.cc)
                        } else {
                            Leaf::NetRir(block.rir)
                        });
                    }
                }
            }
            // `registry_values` reads these fields from the records.
            Field::NetOrg
            | Field::AsOrg
            | Field::NetMnt
            | Field::AsMnt
            | Field::NetContact(_)
            | Field::AsContact(_) => {}
        }
    }
    or(leaves.into_iter().map(Expr::Leaf))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{AsInfo, AsnEntry, Route};

    #[test]
    fn ranges_become_prefixes() {
        let range: Range = "192.0.2.1-192.0.2.6".parse().unwrap();
        let Expr::Or(items) = ip(range) else {
            panic!("not split");
        };
        assert_eq!(items.len(), 4);
        let one: Range = "192.0.2.0/24".parse().unwrap();
        assert_eq!(ip(one), Expr::Leaf(Leaf::Ip(one)));
        assert_eq!(set(&AddrSet::new()), Expr::False);
    }

    #[test]
    fn scope_values() {
        let entry = AsnEntry {
            asn: 64510,
            name: "SAMPLE".into(),
            org_text: String::new(),
            country: Some("XA".parse().unwrap()),
            raw: "SAMPLE, XA".into(),
        };
        let info = |asn, entry| AsInfo {
            asn,
            entry,
            block: None,
            rdap: None,
        };
        let row = Row {
            route: Some(Route {
                prefix: "10.45.192.0/18".parse().unwrap(),
                origins: vec![64510, 65550],
            }),
            ases: vec![info(64510, Some(entry)), info(65550, None)],
            ..Row::default()
        };
        let rows = [row.clone(), row];
        assert_eq!(
            values(Field::AsAsn, &rows),
            Expr::Or(vec![
                Expr::Leaf(Leaf::Asn(AsnMatch::One(64510))),
                Expr::Leaf(Leaf::Asn(AsnMatch::One(65550))),
            ])
        );
        assert_eq!(
            values(Field::AsName, &rows),
            Expr::Leaf(Leaf::AsName(Pattern::Exact("SAMPLE".into())))
        );
        assert_eq!(
            values(Field::Route, &rows),
            Expr::Leaf(Leaf::Route(RouteMatch::Exact(
                "10.45.192.0/18".parse().unwrap()
            )))
        );
        assert_eq!(values(Field::AsCountry, &[]), Expr::False);
        assert_eq!(values(Field::NetOrg, &rows[..1]), Expr::False);
    }

    #[test]
    fn registry_values_come_from_the_record() {
        use crate::model::{EntityKind, RecordOrigin, Rir};
        let contact = |handle: &str, roles: &[Role]| Contact {
            handle: handle.to_owned(),
            roles: roles.to_vec(),
            kind: EntityKind::Individual,
            name: None,
            address: None,
            phone: None,
            email: Vec::new(),
            rir: Rir::Ripencc,
            emails_hidden: false,
        };
        let record = NetRecord {
            rir: Rir::Ripencc,
            range: "192.0.2.0/24".parse().unwrap(),
            handle: "NET-1".into(),
            name: None,
            country: None,
            org: Some(OrgRef {
                handle: "ORG-EX1-RIPE".into(),
                name: Some("Example LLC".into()),
            }),
            mnt: vec!["EX-MNT".into(), "EX2-MNT".into()],
            contacts: vec![
                contact("AB1-RIPE", &[Role::Abuse]),
                contact("TE1-RIPE", &[Role::Technical, Role::Administrative]),
                contact("RG1-RIPE", &[Role::Registrant]),
            ],
            parent_link: None,
            origin: RecordOrigin::Rdap,
        };
        assert!(registry_field(Field::NetOrg) && !registry_field(Field::NetCountry));
        assert_eq!(
            net_values(Field::NetOrg, Some(&record), Some("ripencc-ex")),
            [
                Leaf::NetOrg(OrgMatch::HandleOrName("ORG-EX1-RIPE".into())),
                Leaf::NetOrg(OrgMatch::Name(Pattern::Exact("Example LLC".into()))),
                Leaf::NetOrg(OrgMatch::HandleOrName("ripencc-ex".into())),
            ]
        );
        assert_eq!(
            net_values(Field::NetOrg, None, Some("x")),
            [Leaf::NetOrg(OrgMatch::HandleOrName("x".into()))]
        );
        assert_eq!(
            net_values(Field::NetMnt, Some(&record), None),
            [
                Leaf::NetMnt(HandleMatch::Handle("EX-MNT".into())),
                Leaf::NetMnt(HandleMatch::Handle("EX2-MNT".into())),
            ]
        );
        assert_eq!(
            net_values(Field::NetContact(None), Some(&record), None),
            [
                Leaf::NetContact(None, HandleMatch::Handle("AB1-RIPE".into())),
                Leaf::NetContact(None, HandleMatch::Handle("TE1-RIPE".into())),
            ]
        );
        assert_eq!(
            net_values(
                Field::NetContact(Some(Role::Administrative)),
                Some(&record),
                None
            ),
            [Leaf::NetContact(
                Some(Role::Administrative),
                HandleMatch::Handle("TE1-RIPE".into())
            )]
        );
        assert!(net_values(Field::NetMnt, None, None).is_empty());
        let autnum = AsRecord {
            rir: Rir::Ripencc,
            asn: 64496,
            last: None,
            name: None,
            org: None,
            mnt: vec!["AS-MNT".into()],
            contacts: vec![contact("AB1-RIPE", &[Role::Abuse])],
        };
        assert_eq!(
            as_values(Field::AsOrg, Some(&autnum), Some("ripencc-as")),
            [Leaf::AsOrg(OrgMatch::HandleOrName("ripencc-as".into()))]
        );
        assert_eq!(
            as_values(Field::AsMnt, Some(&autnum), None),
            [Leaf::AsMnt(HandleMatch::Handle("AS-MNT".into()))]
        );
        assert_eq!(
            as_values(Field::AsContact(Some(Role::Abuse)), Some(&autnum), None),
            [Leaf::AsContact(
                Some(Role::Abuse),
                HandleMatch::Handle("AB1-RIPE".into())
            )]
        );
    }
}
