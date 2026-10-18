//! Enrichment of the rows shown: the network chain, the holder, the abuse
//! contacts, and the `--fields` columns.
//!
//! Only the rows shown are enriched, so RDAP is asked about the holders of
//! those rows alone. For each row, RDAP gives the most specific record of
//! its part or route and the record of each of its AS. The engine enriches
//! `--concurrency` × egresses rows at once. With a `net.*` field, the
//! engine also follows the `up` links of the record to the block from the
//! stats.
//!
//! With `--ripe-emails`, the hidden e-mail of the RIPE persons shown is
//! fetched in one batch, after every row is known. Each person spends at
//! most one query of the RIPE limit.

use std::{collections::HashMap, sync::Arc};

use futures_util::{StreamExt, future::try_join_all, stream};

use super::Engine;
use crate::{
    error::Result,
    model::{Contact, NetChain, Rir, Role, Row},
    output::column::Column,
    plan::eval,
    query::Field,
    rdap,
};

/// Fills the network chain and the AS records of `rows`, then the hidden
/// e-mail of the contacts that the rows show.
///
/// # Errors
///
/// Returns an error if a registry fails.
pub(crate) async fn rows(
    engine: &Engine<'_>,
    rows: &mut Vec<Row>,
    fields: &[Column],
) -> Result<()> {
    if rows.is_empty() {
        return Ok(());
    }
    let chain = fields.iter().any(|field| field.needs_chain());
    let total = u32::try_from(rows.len()).unwrap_or(u32::MAX);
    engine.reporter.activity(Some("reading registry records"));
    engine.reporter.items(0, total, "networks");
    let mut enriched = stream::iter(std::mem::take(rows))
        .map(|row| enrich(engine, row, chain))
        .buffered(engine.window.max(1));
    while let Some(row) = enriched.next().await {
        rows.push(row?);
        engine.reporter.items(
            u32::try_from(rows.len()).unwrap_or(u32::MAX),
            total,
            "networks",
        );
    }
    drop(enriched);
    let handles = hidden(rows, fields);
    if handles.is_empty() {
        return Ok(());
    }
    engine
        .reporter
        .activity(Some("fetching additional contacts"));
    let emails = engine.rdap.ripe_emails(&handles).await?;
    if !emails.is_empty() {
        for row in rows.iter_mut() {
            fill(row, &emails);
        }
    }
    Ok(())
}

/// Fetches the records of one row: the most specific network record of its
/// base, the chain above that record if `chain` is set, and the record of
/// each AS.
async fn enrich(engine: &Engine<'_>, mut row: Row, chain: bool) -> Result<Row> {
    let Some(base) = row.base() else {
        return Ok(row);
    };
    let block = eval::block_of(&row.nets, base).cloned();
    let mut records = Vec::new();
    if let Some(record) = engine.rdap.ip(base).await? {
        if chain {
            records = engine
                .rdap
                .up_chain(&record, block.as_ref().map(|block| &block.range))
                .await?;
        }
        records.push(record);
    }
    row.chain = NetChain { block, records };
    let missing: Vec<usize> = (0..row.ases.len())
        .filter(|index| row.ases[*index].rdap.is_none())
        .collect();
    let found = try_join_all(
        missing
            .iter()
            .map(|index| engine.rdap.autnum(row.ases[*index].asn)),
    )
    .await?;
    for (index, record) in missing.into_iter().zip(found) {
        row.ases[index].rdap = record;
    }
    Ok(row)
}

/// Returns `true` if `contact` has `role`.
///
/// Without a role, any role of [`Role::CONTACT`] matches.
pub(crate) fn in_role(contact: &Contact, role: Option<Role>) -> bool {
    match role {
        Some(role) => contact.roles.contains(&role),
        None => contact
            .roles
            .iter()
            .any(|role| Role::CONTACT.contains(role)),
    }
}

/// Returns the RIPE handles with hidden e-mail among the contacts that
/// `rows` show in the abuse column and in the contact fields.
fn hidden(rows: &[Row], fields: &[Column]) -> Vec<String> {
    let net_roles: Vec<Option<Role>> = fields
        .iter()
        .filter_map(|field| match field {
            Column::Field(Field::NetContact(role)) => Some(*role),
            _ => None,
        })
        .collect();
    let as_roles: Vec<Option<Role>> = fields
        .iter()
        .filter_map(|field| match field {
            Column::Field(Field::AsContact(role)) => Some(*role),
            _ => None,
        })
        .collect();
    let shown = |contact: &Contact, roles: &[Option<Role>], last: bool| {
        contact.rir == Rir::Ripencc
            && ((last && contact.roles.contains(&Role::Abuse))
                || roles.iter().any(|role| in_role(contact, *role)))
    };
    let mut contacts: Vec<&Contact> = Vec::new();
    for row in rows {
        let count = row.chain.records.len();
        for (index, record) in row.chain.records.iter().enumerate() {
            let last = index + 1 == count;
            contacts.extend(
                record
                    .contacts
                    .iter()
                    .filter(|contact| shown(contact, &net_roles, last)),
            );
        }
        for record in row.ases.iter().filter_map(|info| info.rdap.as_ref()) {
            contacts.extend(
                record
                    .contacts
                    .iter()
                    .filter(|contact| shown(contact, &as_roles, true)),
            );
        }
    }
    rdap::hidden_emails(contacts)
}

/// Copies the fetched e-mail into the contacts of `row`.
fn fill(row: &mut Row, emails: &HashMap<String, Vec<String>>) {
    let wanted = |contacts: &[Contact]| {
        contacts
            .iter()
            .any(|contact| contact.emails_hidden && emails.contains_key(&contact.handle))
    };
    for record in &mut row.chain.records {
        if wanted(&record.contacts) {
            rdap::fill_emails(&mut Arc::make_mut(record).contacts, emails);
        }
    }
    for info in &mut row.ases {
        if let Some(record) = &mut info.rdap
            && wanted(&record.contacts)
        {
            rdap::fill_emails(&mut Arc::make_mut(record).contacts, emails);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{EntityKind, NetRecord, RecordOrigin};

    fn contact(handle: &str, role: Role, rir: Rir, hidden: bool) -> Contact {
        Contact {
            handle: handle.to_owned(),
            roles: vec![role],
            kind: EntityKind::Individual,
            name: None,
            address: None,
            phone: None,
            email: Vec::new(),
            rir,
            emails_hidden: hidden,
        }
    }

    fn record(contacts: Vec<Contact>) -> Arc<NetRecord> {
        Arc::new(NetRecord {
            rir: Rir::Ripencc,
            range: "192.0.2.0/24".parse().unwrap(),
            handle: "NET".to_owned(),
            name: None,
            country: None,
            org: None,
            mnt: Vec::new(),
            contacts,
            parent_link: None,
            origin: RecordOrigin::Rdap,
        })
    }

    #[test]
    fn only_shown_ripe_persons_are_fetched() {
        let mut row = Row::default();
        row.chain.records = vec![
            record(vec![
                contact("TOP-RIPE", Role::Administrative, Rir::Ripencc, true),
                contact("TOPABUSE-RIPE", Role::Abuse, Rir::Ripencc, true),
            ]),
            record(vec![
                contact("ABUSE-RIPE", Role::Abuse, Rir::Ripencc, true),
                contact("TECH-RIPE", Role::Technical, Rir::Ripencc, true),
                contact("ARIN", Role::Abuse, Rir::Arin, true),
            ]),
        ];
        let rows = [row];
        assert_eq!(hidden(&rows, &[]), ["ABUSE-RIPE"]);
        assert_eq!(
            hidden(
                &rows,
                &[Field::NetContact(Some(Role::Administrative)).into()]
            ),
            ["TOP-RIPE", "ABUSE-RIPE"]
        );
        let mut row = rows[0].clone();
        let emails = HashMap::from([("ABUSE-RIPE".to_owned(), vec!["a@example.net".to_owned()])]);
        fill(&mut row, &emails);
        assert_eq!(row.chain.records[1].contacts[0].email, ["a@example.net"]);
        assert!(row.chain.records[1].contacts[1].emails_hidden);
    }
}
