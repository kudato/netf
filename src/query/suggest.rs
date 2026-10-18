//! Hints for usage errors in queries.
//!
//! The hints cover the nearest field names, synonyms such as `holder` →
//! `net.org` or `as.org`, the KQL nested groups that netf does not have
//! (`as:{…}` and `net:{…}`), scopes written without a field, and "quote
//! values with spaces".
//!
//! An unknown field is a usage error, never an empty answer, so the message
//! tells the user what they probably meant. The candidates come from two
//! sources, in this order:
//!
//! 1. Synonyms: words people reach for that are not field names, such as
//!    `holder`, `asn`, `prefix`, and `country`.
//! 2. Names within a small edit distance. The distance is optimal string
//!    alignment, so a swap of two neighboring letters costs one. The limit
//!    is 2, or 1 for names of up to three letters. With a limit of 2, a
//!    short name such as `as` or `ip` would match almost anything.

use super::ast::{Field, Selector};

/// Words that are not field names, and the fields they probably mean.
const SYNONYMS: &[(&str, &[&str])] = &[
    ("holder", &["net.org", "as.org"]),
    ("owner", &["net.org", "as.org"]),
    ("org", &["net.org", "as.org"]),
    ("organization", &["net.org", "as.org"]),
    ("organisation", &["net.org", "as.org"]),
    ("asn", &["as.asn"]),
    ("as", &["as.asn"]),
    ("origin", &["as.asn"]),
    ("country", &["net.country", "as.country"]),
    ("cc", &["net.country", "as.country"]),
    ("prefix", &["route"]),
    ("cidr", &["route"]),
    ("network", &["route"]),
    ("net", &["route"]),
    ("maintainer", &["net.mnt", "as.mnt"]),
    ("mnt", &["net.mnt", "as.mnt"]),
    ("mnt-by", &["net.mnt", "as.mnt"]),
    ("contact", &["net.contact", "as.contact"]),
    ("abuse", &["net.contact.abuse", "as.contact.abuse"]),
    ("name", &["as.name"]),
    ("asname", &["as.name"]),
    ("netname", &["net.org"]),
    ("rir", &["net.rir", "as.rir"]),
    ("registry", &["net.rir", "as.rir"]),
    ("address", &["ip"]),
    ("addr", &["ip"]),
    ("host", &["domain"]),
    ("hostname", &["domain"]),
];

/// Returns the names that an unknown field `name` probably meant, best
/// first.
///
/// Returns at most three names, and none if nothing is close.
pub(crate) fn similar_fields(name: &str) -> Vec<&'static str> {
    let name = name.to_ascii_lowercase();
    let mut out: Vec<&'static str> = SYNONYMS
        .iter()
        .find(|(word, _)| *word == name)
        .map(|(_, fields)| fields.to_vec())
        .unwrap_or_default();
    let limit = if name.chars().count() <= 3 { 1 } else { 2 };
    let mut near: Vec<(usize, &'static str)> = Field::ALL
        .iter()
        .map(|field| field.name())
        .chain([Selector::Ip, Selector::Domain, Selector::Set].map(Selector::name))
        .map(|candidate| (distance(&name, candidate), candidate))
        .filter(|(d, _)| *d <= limit)
        .collect();
    // The sort is stable, so equal distances keep the order of `--help`.
    near.sort_by_key(|(d, _)| *d);
    for (_, candidate) in near {
        if !out.contains(&candidate) {
            out.push(candidate);
        }
    }
    out.truncate(3);
    out
}

/// Returns the message and the hint for an unknown field, without the
/// position.
///
/// The hint is `None` if no name is close.
pub(crate) fn unknown_field(name: &str) -> (String, Option<String>) {
    let message = format!("unknown field '{name}'");
    let similar = similar_fields(name);
    let hint = (!similar.is_empty()).then(|| format!("did you mean {}?", similar.join(", ")));
    (message, hint)
}

/// Returns the message for `as` or `net` used as a field name.
pub(crate) fn not_a_field(group: &str) -> String {
    match group {
        "as" => "as is not a field; use as.asn, as.name, …".to_owned(),
        _ => "net is not a field; use route, net.country, net.org, …".to_owned(),
    }
}

/// Returns the message for a KQL nested group: `as:{…}` or `net:{…}`.
///
/// `rewrite` is the query inside the braces, with the group added as a
/// prefix to its fields. If the inside cannot be rewritten that way,
/// `rewrite` is `None` and the message shows a fixed example.
pub(crate) fn nested_group(group: &str, rewrite: Option<String>) -> String {
    match group {
        "as" => format!(
            "as:{{…}} is not supported; conditions on as.* already hold for one AS: {}",
            rewrite
                .as_deref()
                .unwrap_or("as.name: example and as.country: XA")
        ),
        _ => format!(
            "net:{{…}} is not supported; conditions on net.* already hold for one network: {}",
            rewrite
                .as_deref()
                .unwrap_or("net.country: XA and net.rir: ripencc")
        ),
    }
}

/// Returns the hint for a value of several words without quotes:
/// `quote values with spaces: net.org: "EXAMPLE LLC"`.
pub(crate) fn quote_values(field: Option<&str>, words: &[&str]) -> String {
    let value = words.join(" ");
    match field {
        Some(field) => format!("quote values with spaces: {field}: \"{value}\""),
        None => format!("quote values with spaces: \"{value}\""),
    }
}

/// The hint for a scope `{…}` without a field before it.
pub(crate) const SCOPE_NEEDS_FIELD: &str = "for example route: {…} or as.asn: {…}";

/// Returns the edit distance of optimal string alignment.
///
/// An insertion, a deletion, a substitution, and a swap of two neighboring
/// characters each cost one.
fn distance(a: &str, b: &str) -> usize {
    let a: Vec<char> = a.chars().collect();
    let b: Vec<char> = b.chars().collect();
    // The table keeps three rows, because a swap looks two rows back.
    let mut before: Vec<usize> = vec![0; b.len() + 1];
    let mut previous: Vec<usize> = (0..=b.len()).collect();
    let mut current = vec![0; b.len() + 1];
    for i in 1..=a.len() {
        current[0] = i;
        for j in 1..=b.len() {
            let cost = usize::from(a[i - 1] != b[j - 1]);
            let mut best = (previous[j] + 1)
                .min(current[j - 1] + 1)
                .min(previous[j - 1] + cost);
            if i > 1 && j > 1 && a[i - 1] == b[j - 2] && a[i - 2] == b[j - 1] {
                best = best.min(before[j - 2] + 1);
            }
            current[j] = best;
        }
        std::mem::swap(&mut before, &mut previous);
        std::mem::swap(&mut previous, &mut current);
    }
    previous[b.len()]
}

/// Suggests names from an explicit catalog without interpreting or executing them.
pub(crate) fn nearest(name: &str, names: impl Iterator<Item = &'static str>) -> Vec<&'static str> {
    let limit = if name.chars().count() <= 3 { 1 } else { 2 };
    let mut near: Vec<_> = names
        .map(|n| (distance(name, n), n))
        .filter(|(d, _)| *d <= limit)
        .collect();
    near.sort_by_key(|(d, _)| *d);
    near.into_iter().take(3).map(|(_, n)| n).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn near_names() {
        assert_eq!(similar_fields("as.nmae"), ["as.name"]);
        assert_eq!(similar_fields("domian"), ["domain"]);
        assert_eq!(similar_fields("net.contry"), ["net.country"]);
        assert_eq!(similar_fields("rout"), ["route"]);
        assert!(similar_fields("xyzzy").is_empty());
        // Short names match only at distance one.
        assert_eq!(similar_fields("ix"), ["ip"]);
        assert!(similar_fields("ab").is_empty());
    }

    #[test]
    fn messages() {
        assert_eq!(
            unknown_field("holder"),
            (
                "unknown field 'holder'".to_owned(),
                Some("did you mean net.org, as.org?".to_owned())
            )
        );
        assert_eq!(unknown_field("xyzzy").1, None);
        assert_eq!(
            nested_group("as", None),
            "as:{…} is not supported; conditions on as.* already hold for one AS: \
             as.name: example and as.country: XA"
        );
        assert_eq!(
            quote_values(Some("net.org"), &["EXAMPLE", "LLC"]),
            "quote values with spaces: net.org: \"EXAMPLE LLC\""
        );
    }
}
