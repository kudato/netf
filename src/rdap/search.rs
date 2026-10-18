//! Organizations by name and by handle.
//!
//! A search by name asks each registry for `entities?fn=<pattern>` (RFC
//! 9082, section 3.2.3). Of the response, netf keeps only the handle and the
//! name of the entities of kind `org`. Persons and roles that happen to
//! match are dropped. Registries read wildcards in their own way, so the
//! server only narrows the search. netf then filters the response by the
//! pattern of the query, ignoring case. The registries get the pattern as
//! follows:
//!
//! - An exact value goes as is: `fn=Example%20Holdings`. The server reads a
//!   `*` inside it as a wildcard, so such a value goes like a glob.
//! - A glob with only trailing wildcards goes as is: `fn=example*`.
//! - A glob with a wildcard inside goes by its prefix: `example*cloud` asks
//!   for `example*`. RFC 9082 defines only the trailing `*`.
//! - A glob that starts with a wildcard goes as is: `*bank*`. A registry
//!   that refuses the pattern responds with 400 and is skipped, as
//!   [`unsupported`] decides.
//! - An escaped `\*` becomes a wildcard, because RDAP has no literal `*`.
//! - Repeated wildcards collapse into one: `example**` asks for `example*`.
//!
//! The response is cached unfiltered, so `example*` and `example*cloud`
//! share it.

use serde::{Deserialize, Serialize};

use crate::{
    model::{Org, Rir},
    text::Pattern,
};

/// A registry's response to `entities?fn=`, as kept in the response cache.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub(crate) enum Search {
    /// The registry does not search entities by name (400, 501).
    Unsupported,
    /// The organizations found, in the registry's order, and its message
    /// if it truncated them.
    Found {
        hits: Vec<Hit>,
        truncated: Option<String>,
    },
}

impl Search {
    /// Returns a response with nothing found (404).
    pub(crate) fn empty() -> Self {
        Self::Found {
            hits: Vec::new(),
            truncated: None,
        }
    }

    /// Builds the response from the organizations of a search response.
    ///
    /// A repeated handle is kept once, ignoring case.
    pub(crate) fn found(orgs: Vec<(String, String)>, truncated: Option<String>) -> Self {
        let mut hits: Vec<Hit> = Vec::with_capacity(orgs.len());
        for (handle, name) in orgs {
            if !hits
                .iter()
                .any(|hit| hit.handle.eq_ignore_ascii_case(&handle))
            {
                hits.push(Hit { handle, name });
            }
        }
        Self::Found { hits, truncated }
    }

    /// Returns the organizations whose name matches `pattern`.
    pub(crate) fn matching<'a>(&'a self, pattern: &'a Pattern) -> impl Iterator<Item = &'a Hit> {
        let hits: &[Hit] = match self {
            Self::Unsupported => &[],
            Self::Found { hits, .. } => hits,
        };
        hits.iter().filter(|hit| pattern.matches(&hit.name))
    }
}

/// An organization found by a search, as the response gives it.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub(crate) struct Hit {
    /// The handle, for `entity/<handle>`.
    pub(crate) handle: String,
    /// The name (`fn`).
    pub(crate) name: String,
}

impl Hit {
    /// Returns the organization as the search gave it, without resources.
    ///
    /// The method is for a registry that finds the organization but has no
    /// entity by its handle.
    pub(crate) fn to_org(&self, rir: Rir) -> Org {
        Org {
            rir,
            handle: self.handle.clone(),
            name: Some(self.name.clone()),
            networks: Vec::new(),
            autnums: Vec::new(),
            truncated: None,
        }
    }
}

/// Returns `true` if a status of a search response means the registry does
/// not search by name.
///
/// Such a status is 400, when the registry refuses the request or the
/// pattern, or 501 (Not Implemented).
pub(crate) fn unsupported(status: u16) -> bool {
    matches!(status, 400 | 501)
}

/// Returns the path of the search for `pattern`: `entities?fn=…` with the
/// value percent-encoded.
///
/// Returns `None` if there is nothing to search for: `*` alone, an empty
/// value, or wildcards only.
pub(crate) fn path(pattern: &Pattern) -> Option<String> {
    let value = server_pattern(pattern)?;
    Some(format!("entities?fn={}", encode_query(&value)))
}

/// Returns the pattern sent to the registries, by the rules in the module
/// doc.
fn server_pattern(pattern: &Pattern) -> Option<String> {
    let mut value = String::new();
    match pattern {
        Pattern::Any => return None,
        Pattern::Exact(text) => value.push_str(text.trim()),
        Pattern::Glob(glob) => {
            let mut chars = glob.source().trim().chars();
            while let Some(c) = chars.next() {
                match c {
                    '\\' => match chars.next() {
                        Some('\\') => value.push('\\'),
                        // `\*` becomes a wildcard, the same as a lone `*`.
                        Some('*') => value.push('*'),
                        Some(other) => {
                            value.push('\\');
                            value.push(other);
                        }
                        None => value.push('\\'),
                    },
                    _ => value.push(c),
                }
            }
        }
    }
    // The server reads a literal `*` of an exact value as a wildcard too.
    let mut collapsed = String::with_capacity(value.len());
    for c in value.chars() {
        if !(c == '*' && collapsed.ends_with('*')) {
            collapsed.push(c);
        }
    }
    if collapsed.chars().all(|c| c == '*') {
        return None;
    }
    // With a wildcard inside, ask by the prefix.
    let inner = collapsed.trim_end_matches('*').find('*');
    match inner {
        Some(at) if at > 0 => Some(format!("{}*", &collapsed[..at])),
        _ => Some(collapsed),
    }
}

/// Percent-encodes a query value.
///
/// Each UTF-8 byte is encoded, except the unreserved characters and `*`.
fn encode_query(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || b"-._~*".contains(&byte) {
            out.push(char::from(byte));
        } else {
            out.push_str(&format!("%{byte:02X}"));
        }
    }
    out
}

/// Returns the registry that hands out handles with the suffix of
/// `handle`.
///
/// `ORG-EX1-RIPE` is RIPE's, `ORG-EX1-AP` is APNIC's, and `EX1-ARIN` is
/// ARIN's. Returns `None` for a handle without a known suffix, such as an
/// ARIN organization or an opaque-id.
pub(crate) fn rir_of_handle(handle: &str) -> Option<Rir> {
    let (_, suffix) = handle.trim().rsplit_once('-')?;
    match suffix.to_ascii_uppercase().as_str() {
        "RIPE" => Some(Rir::Ripencc),
        "AP" => Some(Rir::Apnic),
        "ARIN" => Some(Rir::Arin),
        "LACNIC" => Some(Rir::Lacnic),
        "AFRINIC" => Some(Rir::Afrinic),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::text::Glob;

    fn glob(source: &str) -> Pattern {
        Pattern::Glob(Glob::new(source))
    }

    #[test]
    fn the_pattern_sent_to_the_registries() {
        let sent = |pattern: &Pattern| path(pattern);
        assert_eq!(
            sent(&Pattern::Exact("Example Holdings".into())).as_deref(),
            Some("entities?fn=Example%20Holdings")
        );
        assert_eq!(
            sent(&glob("example*")).as_deref(),
            Some("entities?fn=example*")
        );
        assert_eq!(
            sent(&glob("example**")).as_deref(),
            Some("entities?fn=example*")
        );
        assert_eq!(sent(&glob("ex*am*ple")).as_deref(), Some("entities?fn=ex*"));
        assert_eq!(sent(&glob("*bank*")).as_deref(), Some("entities?fn=*bank*"));
        assert_eq!(sent(&glob(r"AS\*1*")).as_deref(), Some("entities?fn=AS*"));
        assert_eq!(
            sent(&Pattern::Exact("Δείγμα & Co/1".into())).as_deref(),
            Some("entities?fn=%CE%94%CE%B5%CE%AF%CE%B3%CE%BC%CE%B1%20%26%20Co%2F1")
        );
        assert_eq!(sent(&Pattern::Any), None);
        assert_eq!(sent(&glob("**")), None);
        assert_eq!(sent(&Pattern::Exact("  ".into())), None);
    }

    #[test]
    fn hits_are_unique_and_filtered_by_the_query() {
        let orgs = vec![
            ("ORG-EX1-TEST".to_owned(), "Example Holdings".to_owned()),
            ("org-ex1-test".to_owned(), "Example Holdings".to_owned()),
            ("ORG-EX2-TEST".to_owned(), "Example Cloud".to_owned()),
            ("ORG-OT1-TEST".to_owned(), "Other Example".to_owned()),
        ];
        let search = Search::found(orgs, None);
        let names = |pattern: &Pattern| -> Vec<String> {
            search
                .matching(pattern)
                .map(|hit| hit.name.clone())
                .collect()
        };
        assert_eq!(
            names(&glob("example*")),
            ["Example Holdings", "Example Cloud"]
        );
        assert_eq!(names(&glob("EX*CLOUD")), ["Example Cloud"]);
        assert_eq!(
            names(&Pattern::Exact("example holdings".into())),
            ["Example Holdings"]
        );
        assert!(Search::Unsupported.matching(&Pattern::Any).next().is_none());
        let org = search
            .matching(&Pattern::Any)
            .next()
            .unwrap()
            .to_org(Rir::Arin);
        assert_eq!((org.rir, org.handle.as_str()), (Rir::Arin, "ORG-EX1-TEST"));
        assert!(org.networks.is_empty() && org.truncated.is_none());
    }

    #[test]
    fn registries_by_the_suffix_of_handles() {
        assert_eq!(rir_of_handle("ORG-EX1-RIPE"), Some(Rir::Ripencc));
        assert_eq!(rir_of_handle("org-ex1-ripe"), Some(Rir::Ripencc));
        assert_eq!(rir_of_handle("ORG-EX1-AP"), Some(Rir::Apnic));
        assert_eq!(rir_of_handle("EX1-ARIN"), Some(Rir::Arin));
        assert_eq!(rir_of_handle("XH-EXAM-LACNIC"), Some(Rir::Lacnic));
        assert_eq!(rir_of_handle("ORG-EX1-AFRINIC"), Some(Rir::Afrinic));
        assert_eq!(rir_of_handle("EXAMP"), None);
        assert_eq!(rir_of_handle("ORG-EX1-TEST"), None);
        assert_eq!(rir_of_handle("a1b2c3d4e5f6"), None);
        assert!(unsupported(400) && unsupported(501) && !unsupported(503));
    }
}
