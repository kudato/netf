//! The columns of `--fields`.
//!
//! A `net.*` cell joins the values along the network chain with ` > `. An
//! `as.*` cell joins the values of each AS with `, `.
//!
//! The chain goes from the block in the stats down to the record in the
//! network column. If the block has the same range as the widest record,
//! the block and the record are one link: they describe the same network.
//! A block wider than the records is a link of its own, with only the
//! country and the registry. Several values in one link or one AS, such as
//! maintainers or contacts, are joined with `; `. A contact is shown whole,
//! without its postal address. A missing value is `-`.

use super::column::Column;
use crate::{
    addr::Family,
    model::{AsInfo, Block, Contact, NetRecord, Row},
    query::Field,
};

/// Returns a selected output field, retaining legacy field values.
pub(crate) fn output_cell(row: &Row, column: Column) -> String {
    match column {
        Column::Field(field) => cell(row, field),
        Column::Match => matched(row),
        Column::NetHolder => row
            .chain
            .records
            .last()
            .and_then(|record| record.org.as_ref())
            .map(|org| org.name.clone().unwrap_or_else(|| org.handle.clone()))
            .unwrap_or_else(|| NONE.into()),
        Column::NetRange => net(row, true, |link| {
            link.record
                .map(|record| record.range.to_string())
                .into_iter()
                .collect()
        }),
        Column::NetAbuse => row
            .chain
            .records
            .last()
            .map(|record| mailboxes(&record.contacts))
            .unwrap_or_else(|| NONE.into()),
        Column::AsAbuse => ases(row, |info| {
            vec![format!("AS{}: {}", info.asn, as_cell(info, column))]
        }),
    }
}

/// The complete selected address set, including every disjoint range.
pub(crate) fn matched(row: &Row) -> String {
    let values: Vec<_> = [Family::V4, Family::V6]
        .into_iter()
        .flat_map(|family| row.addresses.ranges(family))
        .map(|range| {
            if range.first() == range.last() {
                range.first_addr().to_string()
            } else {
                range.to_string()
            }
        })
        .collect();
    if values.is_empty() {
        NONE.into()
    } else {
        values.join(", ")
    }
}

/// A field of one origin AS, so the human layout retains its association.
pub(crate) fn as_cell(info: &AsInfo, column: Column) -> String {
    match column {
        Column::AsAbuse => info
            .rdap
            .as_ref()
            .map(|record| mailboxes(&record.contacts))
            .unwrap_or_else(|| NONE.into()),
        Column::Field(field) => joined(vec![as_values(info, field)], ", "),
        _ => NONE.into(),
    }
}

/// The abuse mailboxes of one record, without contact names or handles.
fn mailboxes(contacts: &[Contact]) -> String {
    let emails: Vec<_> = contacts
        .iter()
        .filter(|contact| contact.roles.contains(&crate::model::Role::Abuse))
        .flat_map(|contact| contact.email.iter().cloned())
        .collect();
    if emails.is_empty() {
        NONE.into()
    } else {
        emails.join(", ")
    }
}

/// The cell of a missing value.
const NONE: &str = "-";

/// One network of the chain.
#[derive(Clone, Copy, Debug)]
struct Link<'a> {
    /// The block from the stats, if the block is this network.
    block: Option<&'a Block>,
    /// The record, if the registry has one.
    record: Option<&'a NetRecord>,
}

/// Returns the links of the chain of `row`, from the block down.
fn links(row: &Row) -> Vec<Link<'_>> {
    let records = &row.chain.records;
    let mut links = Vec::with_capacity(records.len() + 1);
    let merged = match (&row.chain.block, records.first()) {
        (Some(block), Some(first)) => block.range == first.range,
        _ => false,
    };
    if let (Some(block), false) = (&row.chain.block, merged) {
        links.push(Link {
            block: Some(block),
            record: None,
        });
    }
    for (index, record) in records.iter().enumerate() {
        links.push(Link {
            block: (merged && index == 0)
                .then_some(row.chain.block.as_ref())
                .flatten(),
            record: Some(record),
        });
    }
    links
}

/// Returns the cell of `field` in `row`.
pub(crate) fn cell(row: &Row, field: Field) -> String {
    match field {
        Field::Route => row
            .route
            .as_ref()
            .map_or_else(|| NONE.to_owned(), |route| route.prefix.to_string()),
        Field::NetCountry => net(row, false, |link| {
            link.block
                .map(|block| block.cc)
                .or_else(|| link.record.and_then(|record| record.country))
                .map(|cc| cc.to_string())
                .into_iter()
                .collect()
        }),
        Field::NetRir => net(row, false, |link| {
            link.block
                .map(|block| block.rir)
                .or_else(|| link.record.map(|record| record.rir))
                .map(|rir| rir.name().to_owned())
                .into_iter()
                .collect()
        }),
        Field::NetOrg => net(row, true, |link| {
            link.record
                .and_then(|record| record.org.as_ref())
                .map(|org| org.name.clone().unwrap_or_else(|| org.handle.clone()))
                .into_iter()
                .collect()
        }),
        Field::NetMnt => net(row, true, |link| {
            link.record
                .map(|record| record.mnt.clone())
                .unwrap_or_default()
        }),
        Field::NetContact(role) => net(row, true, |link| {
            link.record
                .map(|record| contacts(&record.contacts, role))
                .unwrap_or_default()
        }),
        field => ases(row, |info| as_values(info, field)),
    }
}

/// Returns the values of one AS field.
fn as_values(info: &AsInfo, field: Field) -> Vec<String> {
    match field {
        Field::AsAsn => vec![format!("AS{}", info.asn)],
        Field::AsName => info
            .entry
            .as_ref()
            .map(|entry| entry.name.clone())
            .filter(|name| !name.is_empty())
            .or_else(|| info.rdap.as_ref().and_then(|record| record.name.clone()))
            .into_iter()
            .collect(),
        Field::AsOrg => info
            .rdap
            .as_ref()
            .and_then(|record| record.org.as_ref())
            .map(|org| org.name.clone().unwrap_or_else(|| org.handle.clone()))
            .or_else(|| {
                info.block
                    .as_ref()
                    .and_then(|block| block.opaque_id.as_deref().map(str::to_owned))
            })
            .into_iter()
            .collect(),
        Field::AsCountry => info
            .entry
            .as_ref()
            .and_then(|entry| entry.country)
            .or_else(|| info.block.as_ref().map(|block| block.cc))
            .map(|cc| cc.to_string())
            .into_iter()
            .collect(),
        Field::AsRir => info
            .block
            .as_ref()
            .map(|block| block.rir)
            .or_else(|| info.rdap.as_ref().map(|record| record.rir))
            .map(|rir| rir.name().to_owned())
            .into_iter()
            .collect(),
        Field::AsMnt => info
            .rdap
            .as_ref()
            .map(|record| record.mnt.clone())
            .unwrap_or_default(),
        Field::AsContact(role) => info
            .rdap
            .as_ref()
            .map(|record| contacts(&record.contacts, role))
            .unwrap_or_default(),
        _ => Vec::new(),
    }
}

/// Joins the values of every link with ` > `.
///
/// With `records` set, the links that are only a block are skipped.
fn net(row: &Row, records: bool, values: impl Fn(Link<'_>) -> Vec<String>) -> String {
    let cells: Vec<Vec<String>> = links(row)
        .into_iter()
        .filter(|link| !records || link.record.is_some())
        .map(values)
        .collect();
    joined(cells, " > ")
}

/// Joins the values of every AS with `, `.
fn ases(row: &Row, values: impl Fn(&AsInfo) -> Vec<String>) -> String {
    joined(row.ases.iter().map(values).collect(), ", ")
}

/// Joins the groups with `separator` and the values in a group with `; `.
///
/// An empty group is `-`. If all groups are empty, the cell is `-` alone.
fn joined(groups: Vec<Vec<String>>, separator: &str) -> String {
    if groups.iter().all(Vec::is_empty) {
        return NONE.to_owned();
    }
    groups
        .into_iter()
        .map(|values| {
            if values.is_empty() {
                NONE.to_owned()
            } else {
                values.join("; ")
            }
        })
        .collect::<Vec<_>>()
        .join(separator)
}

/// Returns the contacts in `role`, each once and shown whole.
///
/// With no `role`, a contact in any contact role counts.
fn contacts(contacts: &[Contact], role: Option<crate::model::Role>) -> Vec<String> {
    let mut seen: Vec<&str> = Vec::new();
    let mut shown = Vec::new();
    for contact in contacts
        .iter()
        .filter(|contact| crate::engine::enrich::in_role(contact, role))
    {
        if seen.contains(&contact.handle.as_str()) {
            continue;
        }
        seen.push(&contact.handle);
        shown.push(whole(contact));
    }
    shown
}

/// Formats a contact as `HANDLE name email… phone`, without the postal
/// address.
fn whole(contact: &Contact) -> String {
    let mut parts = vec![contact.handle.clone()];
    parts.extend(contact.name.clone());
    parts.extend(contact.email.iter().cloned());
    parts.extend(contact.phone.clone());
    parts.join(" ")
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;
    use crate::model::{AsRecord, AsnEntry, EntityKind, NetChain, OrgRef, RecordOrigin, Rir, Role};

    fn record(range: &str, org: &str, country: &str, contacts: Vec<Contact>) -> Arc<NetRecord> {
        Arc::new(NetRecord {
            rir: Rir::Ripencc,
            range: range.parse().unwrap(),
            handle: range.to_owned(),
            name: None,
            country: Some(country.parse().unwrap()),
            org: Some(OrgRef {
                handle: format!("ORG-{org}"),
                name: Some(org.to_owned()),
            }),
            mnt: Vec::new(),
            contacts,
            parent_link: None,
            origin: RecordOrigin::Rdap,
        })
    }

    fn contact(handle: &str, roles: &[Role], email: &[&str]) -> Contact {
        Contact {
            handle: handle.to_owned(),
            roles: roles.to_vec(),
            kind: EntityKind::Individual,
            name: Some("John Doe".to_owned()),
            address: Some("Street 1".to_owned()),
            phone: Some("+1 555 0100".to_owned()),
            email: email.iter().map(|e| (*e).to_owned()).collect(),
            rir: Rir::Ripencc,
            emails_hidden: false,
        }
    }

    fn block(range: &str, cc: &str) -> Block {
        Block {
            rir: Rir::Ripencc,
            range: range.parse().unwrap(),
            cc: cc.parse().unwrap(),
            opaque_id: None,
        }
    }

    fn info(asn: u32, name: &str, rdap: Option<AsRecord>) -> AsInfo {
        AsInfo {
            asn,
            entry: Some(AsnEntry {
                asn,
                name: name.to_owned(),
                org_text: String::new(),
                country: Some("XA".parse().unwrap()),
                raw: String::new(),
            }),
            block: None,
            rdap: rdap.map(Arc::new),
        }
    }

    #[test]
    fn net_values_go_down_the_chain() {
        let admin = contact("JD1-RIPE", &[Role::Administrative], &[]);
        let row = Row {
            chain: NetChain {
                block: Some(block("192.0.2.0/24", "XA")),
                records: vec![
                    record("192.0.2.0/24", "Example", "XD", vec![admin.clone()]),
                    record("192.0.2.0/26", "Client", "XB", vec![]),
                ],
            },
            ..Row::default()
        };
        assert_eq!(cell(&row, Field::NetOrg), "Example > Client");
        assert_eq!(cell(&row, Field::NetCountry), "XA > XB");
        assert_eq!(cell(&row, Field::NetRir), "ripencc > ripencc");
        assert_eq!(cell(&row, Field::NetMnt), "-");
        assert_eq!(
            cell(&row, Field::NetContact(Some(Role::Administrative))),
            "JD1-RIPE John Doe +1 555 0100 > -"
        );
        let wide = Row {
            chain: NetChain {
                block: Some(block("198.18.0.0/16", "XC")),
                records: vec![record("198.18.2.0/24", "Example", "XD", vec![])],
            },
            ..Row::default()
        };
        assert_eq!(cell(&wide, Field::NetCountry), "XC > XD");
        assert_eq!(cell(&wide, Field::NetOrg), "Example");
        assert_eq!(cell(&Row::default(), Field::NetOrg), "-");
    }

    #[test]
    fn as_values_and_contacts() {
        let both = contact(
            "NOC1-RIPE",
            &[Role::Abuse, Role::Technical],
            &["a@x", "b@x"],
        );
        let record = AsRecord {
            rir: Rir::Arin,
            asn: 64497,
            last: None,
            name: None,
            org: None,
            mnt: vec!["A-MNT".to_owned(), "B-MNT".to_owned()],
            contacts: vec![both.clone(), both],
        };
        let row = Row {
            ases: vec![info(64496, "ONE", None), info(64497, "TWO", Some(record))],
            ..Row::default()
        };
        assert_eq!(cell(&row, Field::AsName), "ONE, TWO");
        assert_eq!(cell(&row, Field::AsAsn), "AS64496, AS64497");
        assert_eq!(cell(&row, Field::AsMnt), "-, A-MNT; B-MNT");
        assert_eq!(cell(&row, Field::AsRir), "-, arin");
        assert_eq!(
            cell(&row, Field::AsContact(None)),
            "-, NOC1-RIPE John Doe a@x b@x +1 555 0100"
        );
        assert_eq!(cell(&Row::default(), Field::AsName), "-");
    }
}
