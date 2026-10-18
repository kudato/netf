//! Terminal output: a table when every selected field fits, cards otherwise.

use super::{Format, column::Column, fields};
use crate::{
    addr::set::AddrSet,
    model::{AsInfo, OrgRef, Rir, Row},
    query::Field,
    text::{terminal_safe, wrap},
};
use unicode_width::UnicodeWidthStr as _;

const MISSING: &str = "not available";
const NO_ROUTE: &str = "not seen in RIPE RIS";
const HEADERS: [&str; 4] = [
    "BGP route",
    "Origin AS",
    "AS organization",
    "Network holder",
];

/// Renders every value without truncation. An empty answer stays empty.
pub(crate) fn render_with_format(
    rows: &[Row],
    fields: &[Column],
    width: usize,
    format: Format,
) -> String {
    if rows.is_empty() {
        return String::new();
    }
    let width = width.max(1);
    let mut extra = Vec::new();
    for field in fields {
        if !matches!(
            field,
            Column::Field(Field::AsAsn | Field::AsOrg) | Column::NetHolder
        ) && !extra.contains(field)
        {
            extra.push(*field);
        }
    }
    let headers: Vec<_> = HEADERS
        .iter()
        .map(|s| (*s).to_owned())
        .chain(extra.iter().map(|field| label(*field)))
        .collect();
    let groups: Vec<Vec<Vec<String>>> = rows
        .iter()
        .map(|row| {
            (0..row.ases.len().max(1))
                .map(|index| {
                    let info = row.ases.get(index);
                    let mut cells = vec![
                        if index == 0 {
                            route(row)
                        } else {
                            String::new()
                        },
                        info.map_or_else(|| MISSING.into(), |info| format!("AS{}", info.asn)),
                        info.map_or_else(|| MISSING.into(), as_org),
                        if index == 0 {
                            holder(row)
                        } else {
                            String::new()
                        },
                    ];
                    cells.extend(extra.iter().map(|field| {
                        if field.is_as() {
                            info.map_or_else(
                                || MISSING.into(),
                                |info| available(fields::as_cell(info, *field)),
                            )
                        } else if index == 0 {
                            available(fields::output_cell(row, *field))
                        } else {
                            String::new()
                        }
                    }));
                    cells.into_iter().map(|cell| terminal_safe(&cell)).collect()
                })
                .collect()
        })
        .collect();
    let widths: Vec<_> = (0..headers.len())
        .map(|column| {
            groups
                .iter()
                .flatten()
                .map(|line| line[column].width())
                .chain([headers[column].width()])
                .max()
                .unwrap_or(0)
        })
        .collect();
    let table = format == Format::Table
        || format == Format::Auto && widths.iter().sum::<usize>() + (widths.len() - 1) * 2 <= width;
    let mut out = String::new();
    if table {
        aligned(&mut out, &headers, &widths);
    }
    for (index, (row, lines)) in rows.iter().zip(&groups).enumerate() {
        if table {
            for line in lines {
                aligned(&mut out, line, &widths);
            }
            context(&mut out, row, &extra, "  ", width);
        } else {
            if index > 0 {
                out.push('\n');
            }
            context_match(&mut out, row, &extra, "", width);
            item(&mut out, "", "BGP route", &route(row), width);
            if row.ases.is_empty() {
                item(&mut out, "", "Origin AS", MISSING, width);
                item(&mut out, "", "AS organization", MISSING, width);
                for field in extra.iter().filter(|field| field.is_as()) {
                    item(&mut out, "  ", &label(*field), MISSING, width);
                }
            }
            for info in &row.ases {
                item(&mut out, "", "Origin AS", &format!("AS{}", info.asn), width);
                item(&mut out, "  ", "AS organization", &as_org(info), width);
                for field in extra.iter().filter(|field| field.is_as()) {
                    item(
                        &mut out,
                        "  ",
                        &label(*field),
                        &available(fields::as_cell(info, *field)),
                        width,
                    );
                }
            }
            item(&mut out, "", "Network holder", &holder(row), width);
            context_registry(&mut out, row, "", width);
            for field in extra
                .iter()
                .filter(|field| !field.is_as() && **field != Column::Match)
            {
                item(
                    &mut out,
                    "",
                    &label(*field),
                    &available(fields::output_cell(row, *field)),
                    width,
                );
            }
        }
    }
    out.push('\n');
    out.push_str(&wrap("Field reference: netf --help=fields", "", width));
    out
}

#[cfg(test)]
fn render(rows: &[Row], fields: &[Column], width: usize) -> String {
    render_with_format(rows, fields, width, Format::Auto)
}

/// Exact fields have no implicit match, registry context, or default columns.
pub(crate) fn exact(rows: &[Row], columns: &[Column], width: usize, format: Format) -> String {
    if rows.is_empty() || columns.is_empty() {
        return String::new();
    }
    let width = width.max(1);
    let headers: Vec<_> = columns.iter().map(|c| exact_label(*c)).collect();
    let has_as = columns.iter().any(|c| c.is_as());
    let groups: Vec<Vec<Vec<String>>> = rows
        .iter()
        .map(|row| {
            let count = if has_as { row.ases.len().max(1) } else { 1 };
            (0..count)
                .map(|index| {
                    columns
                        .iter()
                        .map(|column| {
                            let value = if column.is_as() {
                                row.ases.get(index).map_or_else(
                                    || MISSING.into(),
                                    |info| match column {
                                        Column::Field(Field::AsAsn) => format!("AS{}", info.asn),
                                        Column::Field(Field::AsOrg) => as_org(info),
                                        _ => available(fields::as_cell(info, *column)),
                                    },
                                )
                            } else if index > 0 {
                                String::new()
                            } else {
                                match column {
                                    Column::Field(Field::Route) => route(row),
                                    Column::NetHolder => holder(row),
                                    _ => available(fields::output_cell(row, *column)),
                                }
                            };
                            terminal_safe(&value)
                        })
                        .collect()
                })
                .collect()
        })
        .collect();
    let widths: Vec<_> = headers
        .iter()
        .enumerate()
        .map(|(index, header)| {
            groups
                .iter()
                .flatten()
                .map(|cells| cells[index].width())
                .chain([header.width()])
                .max()
                .unwrap_or(0)
        })
        .collect();
    let table = format == Format::Table
        || format == Format::Auto && widths.iter().sum::<usize>() + (widths.len() - 1) * 2 <= width;
    let mut out = String::new();
    if table {
        aligned(&mut out, &headers, &widths);
    }
    for (group, lines) in groups.iter().enumerate() {
        if !table && group > 0 {
            out.push('\n');
        }
        for (origin, cells) in lines.iter().enumerate() {
            if table {
                aligned(&mut out, cells, &widths);
            } else {
                if origin > 0 {
                    out.push('\n');
                }
                for (header, value) in headers.iter().zip(cells).filter(|(_, v)| !v.is_empty()) {
                    item(&mut out, "", header, value, width);
                }
            }
        }
    }
    out
}

fn exact_label(column: Column) -> String {
    match column {
        Column::Field(Field::Route) => HEADERS[0].into(),
        Column::Field(Field::AsAsn) => HEADERS[1].into(),
        Column::Field(Field::AsOrg) => HEADERS[2].into(),
        Column::NetHolder => HEADERS[3].into(),
        _ => label(column),
    }
}

/// A registration country must not read as the location of an address.
fn label(column: Column) -> String {
    match column {
        Column::Field(Field::NetCountry | Field::AsCountry) => {
            format!("{} (registration)", column.name())
        }
        Column::Match => "Match".into(),
        _ => column.name().into(),
    }
}

fn available(value: String) -> String {
    if value.is_empty() || value == "-" {
        MISSING.into()
    } else {
        value
    }
}

fn route(row: &Row) -> String {
    row.route
        .as_ref()
        .map_or_else(|| NO_ROUTE.into(), |route| route.prefix.to_string())
}

/// An identifier is labeled with its registry, never presented as a name.
fn organization(org: &OrgRef, rir: Rir) -> String {
    if let Some(name) = &org.name
        && !name.trim().is_empty()
    {
        name.clone()
    } else if !org.handle.is_empty() {
        format!("ID {} ({})", org.handle, rir.name())
    } else {
        MISSING.into()
    }
}

fn as_org(info: &AsInfo) -> String {
    if let Some(record) = &info.rdap
        && let Some(org) = &record.org
    {
        return organization(org, record.rir);
    }
    if let Some(block) = &info.block
        && let Some(id) = &block.opaque_id
    {
        return format!("ID {id} ({})", block.rir.name());
    }
    MISSING.into()
}

fn holder(row: &Row) -> String {
    row.chain
        .records
        .last()
        .and_then(|record| record.org.as_ref().map(|org| organization(org, record.rir)))
        .unwrap_or_else(|| MISSING.into())
}

fn context(out: &mut String, row: &Row, fields: &[Column], indent: &str, width: usize) {
    // An explicitly selected Match already has a table column.
    if !fields.contains(&Column::Match) {
        context_match(out, row, fields, indent, width);
    }
    context_registry(out, row, indent, width);
}

fn context_match(out: &mut String, row: &Row, fields: &[Column], indent: &str, width: usize) {
    let same = row.route.as_ref().is_some_and(|route| {
        let mut addresses = AddrSet::new();
        addresses.insert(route.prefix.range());
        row.addresses == addresses
    });
    if !same || fields.contains(&Column::Match) {
        item(
            out,
            indent,
            "Match",
            &available(fields::matched(row)),
            width,
        );
    }
}

fn context_registry(out: &mut String, row: &Row, indent: &str, width: usize) {
    let record = row.chain.records.last();
    if record.is_some_and(|record| {
        row.route
            .as_ref()
            .is_some_and(|route| route.prefix.range() == record.range)
    }) {
        return;
    }
    item(
        out,
        indent,
        "Registry network",
        &record.map_or_else(
            || "not available (no record returned)".into(),
            |record| record.range.to_string(),
        ),
        width,
    );
}

fn item(out: &mut String, indent: &str, label: &str, value: &str, width: usize) {
    let line = format!("{indent}{label}: {}", terminal_safe(value));
    out.push_str(&wrap(&line, &format!("{indent}  "), width));
}

fn aligned(out: &mut String, cells: &[String], widths: &[usize]) {
    let mut line = String::new();
    for (index, cell) in cells.iter().enumerate() {
        if index > 0 {
            line.push_str("  ");
        }
        line.push_str(cell);
        if index + 1 < cells.len() {
            line.extend(std::iter::repeat_n(' ', widths[index] - cell.width()));
        }
    }
    out.push_str(line.trim_end());
    out.push('\n');
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{AsRecord, NetRecord, RecordOrigin, Route};
    use std::sync::Arc;

    fn row() -> Row {
        Row {
            route: Some(Route {
                prefix: "192.0.2.0/24".parse().unwrap(),
                origins: vec![64498],
            }),
            ases: vec![AsInfo {
                asn: 64498,
                entry: None,
                block: None,
                rdap: None,
            }],
            addresses: AddrSet::from("192.0.2.0/24".parse::<crate::addr::Range>().unwrap()),
            ..Row::default()
        }
    }

    #[test]
    fn unavailable_and_identifier_values_do_not_claim_names() {
        let mut row = row();
        let out = render(&[row.clone()], &[], 160);
        assert!(out.contains("Registry network: not available"), "{out}");
        assert_eq!(out.matches(MISSING).count(), 3, "{out}");
        row.ases[0].rdap = Some(Arc::new(AsRecord {
            rir: Rir::Ripencc,
            asn: 64498,
            last: None,
            name: Some("SHORT-NAME".into()),
            org: Some(OrgRef {
                handle: "ORG-EX1-RIPE".into(),
                name: None,
            }),
            mnt: vec![],
            contacts: vec![],
        }));
        let out = render(&[row], &[], 160);
        assert!(out.contains("ID ORG-EX1-RIPE (ripencc)"), "{out}");
        assert!(!out.contains("SHORT-NAME"));
    }

    #[test]
    fn every_disjoint_match_and_different_registry_range_is_visible() {
        let mut row = row();
        row.addresses = ["192.0.2.1", "192.0.2.3"]
            .into_iter()
            .map(|value| value.parse::<crate::addr::Range>().unwrap())
            .collect();
        for range in ["192.0.2.0/25", "192.0.2.0/23"] {
            row.chain.records = vec![Arc::new(NetRecord {
                rir: Rir::Ripencc,
                range: range.parse().unwrap(),
                handle: "NET-EX".into(),
                name: None,
                country: None,
                org: None,
                mnt: vec![],
                contacts: vec![],
                parent_link: None,
                origin: RecordOrigin::Rdap,
            })];
            for width in [45, 80, 120, 160] {
                let out = render(&[row.clone()], &[], width);
                assert!(out.contains("Match: 192.0.2.1, 192.0.2.3"), "{out}");
                assert!(out.contains(&format!("Registry network: {range}")), "{out}");
            }
        }
    }

    #[test]
    fn unicode_columns_and_control_characters_preserve_values() {
        let mut row = row();
        let name = "日本 e\u{301} 👩‍💻 example\u{1b}[31m\nLLC\u{202e}";
        row.ases[0].rdap = Some(Arc::new(AsRecord {
            rir: Rir::Ripencc,
            asn: 64498,
            last: None,
            name: None,
            org: Some(OrgRef {
                handle: "ORG-EX".into(),
                name: Some(name.into()),
            }),
            mnt: vec![],
            contacts: vec![],
        }));
        for width in [45, 80, 120, 160] {
            let out = render(&[row.clone()], &[], width);
            assert!(out.lines().all(|line| line.width() <= width), "{out}");
            assert!(!out.contains(['\u{1b}', '\u{202e}']));
            assert!(out.contains("e\u{301}"));
            assert!(out.contains("👩‍💻"));
            // Wrapping can split the visible escape, but cannot drop its bytes.
            let compact: String = out.chars().filter(|c| !c.is_whitespace()).collect();
            assert!(compact.contains("example\\x1b[31m\\nLLC\\u{202e}"), "{out}");
        }
    }
}
