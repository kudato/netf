//! The table of rows.
//!
//! The columns are part, route, AS, network, holder, and abuse. An empty
//! cell is `-`, and a network without a route has `no route` in the route
//! column.
//!
//! The columns are left-aligned and two spaces apart. Each column is as wide
//! as its widest cell, counted in characters, but the last column is not
//! padded. The part column appears only if some row has a part. Enrichment
//! fills the network, holder, and abuse columns. `--fields` adds its columns
//! after them (see [`fields`]).

use super::fields;
use crate::{
    addr::Range,
    model::{Contact, Role, Row},
    query::Field,
};

/// The cell of a missing value.
const NONE: &str = "-";

/// Renders `rows` as a table, one line per row, with the columns of `extra`
/// after the usual ones.
///
/// An empty `rows` renders as an empty string.
pub(crate) fn render(rows: &[Row], extra: &[Field]) -> String {
    let with_part = rows.iter().any(|row| row.part.is_some());
    let lines: Vec<Vec<String>> = rows
        .iter()
        .map(|row| {
            let mut cells = Vec::with_capacity(6 + extra.len());
            if with_part {
                cells.push(row.part.map_or_else(|| NONE.to_owned(), part));
            }
            cells.extend([route(row), ases(row), network(row), holder(row), abuse(row)]);
            cells.extend(extra.iter().map(|field| fields::cell(row, *field)));
            cells
        })
        .collect();
    align(&lines)
}

/// Lays out `lines` in columns.
fn align(lines: &[Vec<String>]) -> String {
    let columns = lines.first().map_or(0, Vec::len);
    let widths: Vec<usize> = (0..columns)
        .map(|column| {
            lines
                .iter()
                .map(|cells| cells[column].chars().count())
                .max()
                .unwrap_or(0)
        })
        .collect();
    let mut out = String::new();
    for cells in lines {
        let mut line = String::new();
        for (column, cell) in cells.iter().enumerate() {
            if column > 0 {
                line.push_str("  ");
            }
            line.push_str(cell);
            if column + 1 < cells.len() {
                let pad = widths[column] - cell.chars().count();
                line.extend(std::iter::repeat_n(' ', pad));
            }
        }
        out.push_str(line.trim_end());
        out.push('\n');
    }
    out
}

/// Formats the part: an address alone, or a network as a CIDR or as
/// `first-last`.
fn part(range: Range) -> String {
    if range.first() == range.last() {
        range.first_addr().to_string()
    } else {
        range.to_string()
    }
}

/// Formats the route cell: the prefix of the route, or `no route`.
fn route(row: &Row) -> String {
    row.route
        .as_ref()
        .map_or_else(|| "no route".to_owned(), |route| route.prefix.to_string())
}

/// Formats the AS cell: the AS of the route with their names from
/// `asn.txt`, such as `AS64496 EXAMPLE-NET, AS64497 TELE-EDGE`.
///
/// The cell is `-` if the row has no route or no AS.
fn ases(row: &Row) -> String {
    if row.route.is_none() || row.ases.is_empty() {
        return NONE.to_owned();
    }
    row.ases
        .iter()
        .map(|info| match &info.entry {
            Some(entry) if !entry.name.is_empty() => format!("AS{} {}", info.asn, entry.name),
            _ => format!("AS{}", info.asn),
        })
        .collect::<Vec<_>>()
        .join(", ")
}

/// Formats the network cell: the range of the most specific record in the
/// network chain.
fn network(row: &Row) -> String {
    row.chain
        .records
        .last()
        .map_or_else(|| NONE.to_owned(), |record| record.range.to_string())
}

/// Formats the holder cell: `name, country` from the most specific record.
///
/// The handle of the holder stands in for a missing name.
fn holder(row: &Row) -> String {
    let Some(record) = row.chain.records.last() else {
        return NONE.to_owned();
    };
    let Some(org) = &record.org else {
        return NONE.to_owned();
    };
    let name = org.name.clone().unwrap_or_else(|| org.handle.clone());
    match record.country {
        Some(cc) => format!("{name}, {cc}"),
        None => name,
    }
}

/// Formats the abuse cell: `<abuse of the network> / <abuse of the AS>`.
///
/// Each half is `-` when it is empty. A row without an AS has only the
/// network half.
fn abuse(row: &Row) -> String {
    let net = row
        .chain
        .records
        .last()
        .map(|record| emails(&record.contacts))
        .unwrap_or_default();
    let ases: Vec<String> = row
        .ases
        .iter()
        .filter_map(|info| info.rdap.as_ref())
        .flat_map(|record| emails(&record.contacts))
        .collect();
    let half = |emails: &[String]| {
        if emails.is_empty() {
            NONE.to_owned()
        } else {
            emails.join(", ")
        }
    };
    if row.ases.is_empty() {
        return half(&net);
    }
    format!("{} / {}", half(&net), half(&ases))
}

/// Returns the abuse mailboxes of `contacts`.
fn emails(contacts: &[Contact]) -> Vec<String> {
    contacts
        .iter()
        .filter(|contact| contact.roles.contains(&Role::Abuse))
        .flat_map(|contact| contact.email.iter().cloned())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{AsInfo, AsnEntry, Route};

    fn info(asn: u32, name: Option<&str>) -> AsInfo {
        AsInfo {
            asn,
            entry: name.map(|name| AsnEntry {
                asn,
                name: name.to_owned(),
                org_text: String::new(),
                country: None,
                raw: name.to_owned(),
            }),
            block: None,
            rdap: None,
        }
    }

    fn row(part: Option<&str>, route: Option<&str>, ases: Vec<AsInfo>) -> Row {
        Row {
            part: part.map(|text| text.parse().unwrap()),
            route: route.map(|text| Route {
                prefix: text.parse().unwrap(),
                origins: ases.iter().map(|info| info.asn).collect(),
            }),
            ases,
            ..Row::default()
        }
    }

    #[test]
    fn columns_are_aligned() {
        let rows = [
            row(
                None,
                Some("10.45.192.0/18"),
                vec![info(64510, Some("SAMPLE"))],
            ),
            row(
                None,
                Some("10.255.255.0/24"),
                vec![info(64510, Some("SAMPLE")), info(65550, Some("TESTTECH"))],
            ),
        ];
        assert_eq!(
            render(&rows, &[]),
            "10.45.192.0/18   AS64510 SAMPLE                    -  -  - / -\n\
             10.255.255.0/24  AS64510 SAMPLE, AS65550 TESTTECH  -  -  - / -\n"
        );
    }

    #[test]
    fn part_column_only_when_some_row_has_a_part() {
        let rows = [
            row(
                Some("192.0.2.1"),
                Some("192.0.2.0/24"),
                vec![info(64512, None)],
            ),
            row(
                None,
                Some("192.0.2.128/25"),
                vec![info(64496, Some("ÉCOLE"))],
            ),
            row(Some("198.51.100.0/24"), None, vec![]),
        ];
        assert_eq!(
            render(&rows, &[]),
            "192.0.2.1        192.0.2.0/24    AS64512        -  -  - / -\n\
             -                192.0.2.128/25  AS64496 ÉCOLE  -  -  - / -\n\
             198.51.100.0/24  no route        -              -  -  -\n"
        );
        assert_eq!(render(&[], &[]), "");
    }

    fn abuse_desk(email: &str) -> Contact {
        Contact {
            handle: "AB1-RIPE".to_owned(),
            roles: vec![Role::Abuse],
            kind: crate::model::EntityKind::Group,
            name: None,
            address: None,
            phone: None,
            email: vec![email.to_owned()],
            rir: crate::model::Rir::Ripencc,
            emails_hidden: false,
        }
    }

    #[test]
    fn enriched_columns_and_fields() {
        use std::sync::Arc;

        use crate::model::{AsRecord, NetRecord, OrgRef, RecordOrigin, Rir};

        let record = NetRecord {
            rir: Rir::Apnic,
            range: "203.0.113.0-203.0.113.95".parse().unwrap(),
            handle: "NET".to_owned(),
            name: None,
            country: Some("XG".parse().unwrap()),
            org: Some(OrgRef {
                handle: "ORG-ECL1-AP".to_owned(),
                name: Some("Example CDN Ltd".to_owned()),
            }),
            mnt: Vec::new(),
            contacts: vec![abuse_desk("irt@cdn.example")],
            parent_link: None,
            origin: RecordOrigin::Rdap,
        };
        let mut routed = row(None, Some("203.0.113.0/28"), vec![info(64503, Some("CDN"))]);
        routed.chain.records.push(Arc::new(record.clone()));
        routed.ases[0].rdap = Some(Arc::new(AsRecord {
            rir: Rir::Apnic,
            asn: 64503,
            last: None,
            name: None,
            org: None,
            mnt: Vec::new(),
            contacts: vec![abuse_desk("abuse@cdn.example")],
        }));
        let mut alone = row(Some("203.0.113.90"), None, vec![]);
        let mut holder = record;
        holder.org.as_mut().unwrap().name = None;
        holder.contacts.clear();
        alone.chain.records.push(Arc::new(holder));
        assert_eq!(
            render(&[routed, alone], &[Field::NetRir]),
            "-             203.0.113.0/28  AS64503 CDN  203.0.113.0-203.0.113.95  \
             Example CDN Ltd, XG  irt@cdn.example / abuse@cdn.example  apnic\n\
             203.0.113.90  no route        -            203.0.113.0-203.0.113.95  \
             ORG-ECL1-AP, XG      -                                    apnic\n"
        );
    }
}
