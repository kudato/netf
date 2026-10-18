//! Counts and provenance shared by terminal output and the tree.

use crate::{Families, Family, Notice, Reporter, Source, addr::set::AddrSet, model::Row};
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::{Arc, Mutex},
    time::SystemTime,
};

/// Selection counts. A match is a candidate, which can produce several records.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub(crate) struct Selection {
    pub(crate) shown: usize,
    pub(crate) total: Option<usize>,
    pub(crate) unchecked: usize,
}

/// Records evidence while forwarding notices as soon as they arrive.
pub(crate) struct Evidence {
    inner: Arc<dyn Reporter>,
    notices: Mutex<Vec<Notice>>,
    sources: Mutex<BTreeMap<String, Provenance>>,
}

#[derive(Default)]
struct Provenance {
    first: Option<SystemTime>,
    last: Option<SystemTime>,
    unknown: bool,
    modified: BTreeSet<String>,
}

impl Evidence {
    pub(crate) fn new(inner: Arc<dyn Reporter>) -> Self {
        Self {
            inner,
            notices: Mutex::new(Vec::new()),
            sources: Mutex::new(BTreeMap::new()),
        }
    }

    pub(crate) fn limitations(&self) -> Vec<String> {
        let mut lines = Vec::new();
        for notice in self
            .notices
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .iter()
        {
            let line = match notice {
                Notice::Truncated { rir, .. } => format!(
                    "Partial result: {rir} limited its search response. Narrow the query; --limit cannot remove the registry's limit."
                ),
                Notice::SearchNotSupported { rir } => {
                    format!("Partial search: {rir} does not support this search.")
                }
                Notice::RipeLimit { missing, .. } => format!(
                    "Partial contacts: RIPE's daily limit left {missing} e-mails unfetched."
                ),
                _ => continue,
            };
            if !lines.contains(&line) {
                lines.push(line);
            }
        }
        lines
    }

    pub(crate) fn provenance(&self) -> Vec<String> {
        let sources = self.sources.lock().unwrap_or_else(|p| p.into_inner());
        let mut lines = Vec::new();
        for (name, source) in sources
            .iter()
            .filter(|(name, _)| !name.starts_with("bootstrap-"))
        {
            let time = match (source.first, source.last) {
                (Some(first), Some(last)) if first != last => {
                    format!("{} to {}", date(first), date(last))
                }
                (Some(time), _) => date(time),
                _ => "unknown".into(),
            };
            lines.push(format!("Source: {name}; retrieved/revalidated: {time}."));
            if source.unknown && source.first.is_some() {
                lines.push("  Retrieval time is unknown for some responses.".into());
            }
            for date in &source.modified {
                lines.push(format!(
                    "  Source Last-Modified: {}.",
                    crate::text::terminal_safe(date)
                ));
            }
        }
        if !sources.is_empty() {
            lines.push("Source snapshot dates: unknown. Retrieval times and Last-Modified are not snapshot dates.".into());
        }
        lines
    }
}

impl Reporter for Evidence {
    fn notice(&self, notice: &Notice) {
        self.notices
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .push(notice.clone());
        self.inner.notice(notice);
    }
    fn source(&self, source: Source) {
        let mut sources = self.sources.lock().unwrap_or_else(|p| p.into_inner());
        let entry = sources.entry(source.name.clone()).or_default();
        if let Some(time) = source.checked {
            entry.first = Some(entry.first.map_or(time, |first| first.min(time)));
            entry.last = Some(entry.last.map_or(time, |last| last.max(time)));
        } else {
            entry.unknown = true;
        }
        entry.modified.extend(source.last_modified.clone());
        drop(sources);
        self.inner.source(source);
    }
    fn error(&self, message: &str) {
        self.inner.error(message);
    }
    fn progress(&self, done: u32, total: u32, what: &'static str) {
        self.inner.progress(done, total, what);
    }
    fn clear_progress(&self) {
        self.inner.clear_progress();
    }
    fn activity(&self, action: Option<&'static str>) {
        self.inner.activity(action);
    }
    fn items(&self, done: u32, total: u32, unit: &'static str) {
        self.inner.items(done, total, unit);
    }
    fn tick(&self) {
        self.inner.tick();
    }
}

fn date(time: SystemTime) -> String {
    if time
        .duration_since(SystemTime::UNIX_EPOCH)
        .is_ok_and(|d| d.as_secs() < 253_402_300_800)
    {
        httpdate::fmt_http_date(time)
    } else {
        "unknown".into()
    }
}

pub(crate) fn families(families: Families) -> &'static str {
    match (families.v4(), families.v6()) {
        (true, true) => "IPv4, IPv6",
        (false, true) => "IPv6",
        _ => "IPv4",
    }
}

pub(crate) fn count(n: usize, one: &str, many: &str) -> String {
    format!("{n} {}", if n == 1 { one } else { many })
}

/// Counts the union, including the full IPv6 universe plus IPv4, without overflow.
fn address_count(set: &AddrSet) -> String {
    // Five base-10^9 limbs hold every possible IPv4 + IPv6 address count.
    let mut limbs = [0_u64; 5];
    for range in set.pieces() {
        for mut value in [range.last() - range.first(), 1] {
            let mut carry = 0;
            for limb in &mut limbs {
                let sum = *limb + (value % 1_000_000_000) as u64 + carry;
                value /= 1_000_000_000;
                *limb = sum % 1_000_000_000;
                carry = sum / 1_000_000_000;
            }
        }
    }
    let last = limbs.iter().rposition(|n| *n != 0).unwrap_or(0);
    let mut out = limbs[last].to_string();
    for limb in limbs[..last].iter().rev() {
        out.push_str(&format!("{limb:09}"));
    }
    out
}

pub(crate) fn summary(rows: &[Row], selected: &Selection, family: Families) -> Vec<String> {
    let routes: BTreeSet<_> = rows
        .iter()
        .filter_map(|r| r.route.as_ref().map(|r| r.prefix))
        .collect();
    let origins: BTreeSet<_> = rows
        .iter()
        .filter_map(|r| r.route.as_ref())
        .flat_map(|r| &r.origins)
        .collect();
    let addresses: AddrSet = rows.iter().flat_map(|r| r.addresses.pieces()).collect();
    let cidrs: usize = [Family::V4, Family::V6]
        .iter()
        .map(|f| addresses.prefixes(*f).len())
        .sum();
    let n_addresses = address_count(&addresses);
    let mut lines = vec![
        format!(
            "{} · {} · {} · {}",
            count(rows.len(), "record", "records"),
            count(routes.len(), "route", "routes"),
            count(origins.len(), "origin AS", "origin AS"),
            families(family)
        ),
        format!(
            "{n_addresses} unique {} · {} in the selected address set",
            if n_addresses == "1" {
                "address"
            } else {
                "addresses"
            },
            count(cidrs, "CIDR", "CIDRs")
        ),
    ];
    lines.extend(selection_lines(selected));
    lines
}

pub(crate) fn selection_lines(selected: &Selection) -> Vec<String> {
    match selected.total {
        None => vec![
            format!(
                "Showing the first {} matches; {} candidates remain unchecked.",
                selected.shown, selected.unchecked
            ),
            "The total number of matches is unknown. Check all candidates: rerun with --limit 0."
                .into(),
        ],
        Some(total) if selected.shown < total => vec![format!(
            "Showing {} of {total} matches. Show all matches: rerun with --limit 0.",
            selected.shown
        )],
        _ => Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{addr::Range, model::Route};
    #[test]
    fn counts_union_moas_and_the_full_address_space() {
        let all: AddrSet = ["0.0.0.0/0", "::/0"]
            .iter()
            .map(|s| s.parse::<Range>().unwrap())
            .collect();
        assert_eq!(
            address_count(&all),
            "340282366920938463463374607436063178752"
        );
        let row = Row {
            route: Some(Route {
                prefix: "192.0.2.0/24".parse().unwrap(),
                origins: vec![64498, 64499],
            }),
            addresses: AddrSet::from("192.0.2.0/24".parse::<Range>().unwrap()),
            ..Row::default()
        };
        let lines = summary(&[row.clone(), row], &Selection::default(), Families::V4);
        assert_eq!(lines[0], "2 records · 1 route · 2 origin AS · IPv4");
        assert_eq!(
            lines[1],
            "256 unique addresses · 1 CIDR in the selected address set"
        );
    }
}
