//! The data model: what netf knows about routes, registry networks, and AS.
//!
//! A row of the answer is a **route**: a prefix in BGP, as RIPE RIS sees
//! it. Each route has two kinds of data above it:
//!
//! - The **registry networks**. These are the block that a registry
//!   delegated ([`Block`], from the delegated stats) and the records inside
//!   the block ([`NetRecord`], from RDAP, the RIPE REST API, or the APNIC
//!   and AFRINIC dumps).
//! - The **AS** that announce the route ([`AsInfo`], from `asn.txt`, the
//!   stats, and RDAP on demand).
//!
//! A [`Row`] ties the route, its networks, and its AS together for one line
//! of output.
//!
//! The types are plain data with no I/O. The sources fill them in, the
//! engine matches and enriches them, and the output prints them. The cache
//! stores RDAP and REST responses as [`NetRecord`], [`AsRecord`], and [`Org`],
//! so these types and the types inside them are `serde`-serializable. The
//! cache keeps only the fields of these types.
//!
//! Strings that many records share, such as the opaque ids of stats blocks,
//! are `Arc<str>`. Records that rows share with the RDAP memo are behind an
//! `Arc`.

use std::{cmp::Reverse, fmt, str::FromStr, sync::Arc};

use serde::{Deserialize, Serialize};

use crate::addr::{Family, Prefix, Range, set::AddrSet};

/// An AS number.
pub(crate) type Asn = u32;

/// One of the five regional internet registries.
///
/// The names match the `registry` column of the delegated stats and the
/// values of `net.rir` and `as.rir`: `afrinic`, `apnic`, `arin`, `lacnic`,
/// and `ripencc`.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "lowercase")]
pub(crate) enum Rir {
    /// AFRINIC.
    Afrinic,
    /// APNIC.
    Apnic,
    /// ARIN.
    Arin,
    /// LACNIC.
    Lacnic,
    /// RIPE NCC.
    Ripencc,
}

impl Rir {
    /// All registries, in the order of their names.
    pub(crate) const ALL: [Rir; 5] = [
        Rir::Afrinic,
        Rir::Apnic,
        Rir::Arin,
        Rir::Lacnic,
        Rir::Ripencc,
    ];

    /// Returns the name used in the stats, queries, and messages.
    pub(crate) fn name(self) -> &'static str {
        match self {
            Self::Afrinic => "afrinic",
            Self::Apnic => "apnic",
            Self::Arin => "arin",
            Self::Lacnic => "lacnic",
            Self::Ripencc => "ripencc",
        }
    }
}

impl fmt::Display for Rir {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

/// The error for text that is not a registry name.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct UnknownRir;

impl fmt::Display for UnknownRir {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("expected afrinic, apnic, arin, lacnic or ripencc")
    }
}

/// Parses a registry name, ignoring case.
impl FromStr for Rir {
    type Err = UnknownRir;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Rir::ALL
            .into_iter()
            .find(|rir| rir.name().eq_ignore_ascii_case(s))
            .ok_or(UnknownRir)
    }
}

/// A country code of registration (ISO 3166 alpha-2), in uppercase.
///
/// Countries come from registration, never from geolocation.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub(crate) struct Cc([u8; 2]);

impl Cc {
    /// Returns the code as text: `NL`.
    pub(crate) fn as_str(&self) -> &str {
        // `from_str` stores only ASCII letters, so the fallback never shows.
        std::str::from_utf8(&self.0).unwrap_or("??")
    }
}

/// The error for text that is not a two-letter country code.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct InvalidCc;

impl fmt::Display for InvalidCc {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("expected a two-letter country code")
    }
}

/// Parses two ASCII letters, ignoring case: `nl` is `NL`.
impl FromStr for Cc {
    type Err = InvalidCc;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.as_bytes() {
            &[a, b] if a.is_ascii_alphabetic() && b.is_ascii_alphabetic() => {
                Ok(Cc([a.to_ascii_uppercase(), b.to_ascii_uppercase()]))
            }
            _ => Err(InvalidCc),
        }
    }
}

impl fmt::Display for Cc {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl Serialize for Cc {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for Cc {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let text = <std::borrow::Cow<'de, str>>::deserialize(deserializer)?;
        text.parse().map_err(serde::de::Error::custom)
    }
}

/// A route from RIS: a prefix and every AS that announces it.
///
/// RIS has one line per origin. The lines with the same prefix merge into
/// one route, and every member of an AS set such as `{64496,64497}` is an
/// origin. The order of `origins` is the order of the AS column.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub(crate) struct Route {
    /// The announced prefix.
    pub(crate) prefix: Prefix,
    /// The origin AS, without duplicates.
    pub(crate) origins: Vec<Asn>,
}

/// A block of delegated stats for addresses.
///
/// netf keeps only `allocated` and `assigned` blocks. The registry never
/// delegated `available` and `reserved` blocks, so they have no country or
/// holder. An IPv4 block is a count of addresses, so it is a range and not
/// always one CIDR.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub(crate) struct Block {
    /// The registry that delegated the block.
    pub(crate) rir: Rir,
    /// The addresses of the block.
    pub(crate) range: Range,
    /// The country of registration.
    pub(crate) cc: Cc,
    /// The id of the holder in stats (`opaque-id`), if given.
    pub(crate) opaque_id: Option<Arc<str>>,
}

/// A block of delegated stats for AS numbers.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub(crate) struct AsBlock {
    /// The registry that delegated the numbers.
    pub(crate) rir: Rir,
    /// The first number.
    pub(crate) first: Asn,
    /// The last number, inclusive.
    pub(crate) last: Asn,
    /// The country of registration.
    pub(crate) cc: Cc,
    /// The id of the holder in stats (`opaque-id`), if given.
    pub(crate) opaque_id: Option<Arc<str>>,
}

/// A line of `asn.txt`: `64496 EXAMPLE-NET Example LLC, NL`.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub(crate) struct AsnEntry {
    /// The AS number.
    pub(crate) asn: Asn,
    /// The name (`as.name`): the first word after the number.
    pub(crate) name: String,
    /// The organization text: the rest of the line up to the last comma,
    /// without a leading `- `.
    pub(crate) org_text: String,
    /// The country after the last comma, if it is two letters.
    pub(crate) country: Option<Cc>,
    /// The whole line after the number, for the `no networks` notice.
    pub(crate) raw: String,
}

/// The role of an entity in an RDAP record.
///
/// All five registries use the same roles.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "lowercase")]
pub(crate) enum Role {
    /// The holder of the resource. A registrant of kind individual is a
    /// maintainer.
    Registrant,
    /// The administrative contact.
    Administrative,
    /// The technical contact.
    Technical,
    /// The abuse contact.
    Abuse,
}

impl Role {
    /// The roles that a contact field can name, as in `net.contact.abuse`.
    pub(crate) const CONTACT: [Role; 3] = [Role::Abuse, Role::Administrative, Role::Technical];

    /// Returns the name used in RDAP and in field names.
    pub(crate) fn name(self) -> &'static str {
        match self {
            Self::Registrant => "registrant",
            Self::Administrative => "administrative",
            Self::Technical => "technical",
            Self::Abuse => "abuse",
        }
    }
}

impl fmt::Display for Role {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

/// The error for text that is not a role name.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct UnknownRole;

impl fmt::Display for UnknownRole {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("expected registrant, administrative, technical, or abuse")
    }
}

/// Parses a role name, ignoring case.
impl FromStr for Role {
    type Err = UnknownRole;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        [
            Role::Registrant,
            Role::Administrative,
            Role::Technical,
            Role::Abuse,
        ]
        .into_iter()
        .find(|role| role.name().eq_ignore_ascii_case(s))
        .ok_or(UnknownRole)
    }
}

/// The vCard `kind` of an RDAP entity.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub(crate) enum EntityKind {
    /// An organization.
    Org,
    /// A person. A person who is a registrant is a maintainer.
    Individual,
    /// A group, such as a role object.
    Group,
    /// Not given or not recognized.
    Unknown,
}

/// A contact of a record, as the registry gave it in the response about the
/// network or the AS.
#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub(crate) struct Contact {
    /// The handle: `JD1-RIPE`.
    pub(crate) handle: String,
    /// The roles of the contact in the record. One handle may hold several
    /// roles.
    pub(crate) roles: Vec<Role>,
    /// The vCard kind.
    pub(crate) kind: EntityKind,
    /// The name (`fn`).
    pub(crate) name: Option<String>,
    /// The postal address, on one line.
    pub(crate) address: Option<String>,
    /// The phone number.
    pub(crate) phone: Option<String>,
    /// The e-mail addresses.
    pub(crate) email: Vec<String>,
    /// The registry that gave the contact.
    pub(crate) rir: Rir,
    /// Whether RIPE hid the e-mail of this person. `--ripe-emails` fetches
    /// the hidden e-mail.
    pub(crate) emails_hidden: bool,
}

/// The holder organization of a record: its handle and, if known, its
/// name.
#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub(crate) struct OrgRef {
    /// The handle: `ORG-EX1-RIPE`.
    pub(crate) handle: String,
    /// The name: `EXAMPLE LLC`.
    pub(crate) name: Option<String>,
}

/// Where a record came from.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub(crate) enum RecordOrigin {
    /// The RDAP server of the registry.
    Rdap,
    /// The RIPE database REST API.
    RipeRest,
    /// The APNIC database dump.
    ApnicDb,
    /// The AFRINIC database dump.
    AfrinicDb,
}

/// A registry record about a network: an RDAP `ip network` or a RIPE
/// `inetnum`.
///
/// Records from the dumps and from the REST API know only the handle and
/// the role of each contact.
#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub(crate) struct NetRecord {
    /// The registry that keeps the record.
    pub(crate) rir: Rir,
    /// The addresses of the record.
    pub(crate) range: Range,
    /// The handle of the record.
    pub(crate) handle: String,
    /// The name of the record (`netname`).
    pub(crate) name: Option<String>,
    /// The country of the record.
    pub(crate) country: Option<Cc>,
    /// The holder organization.
    pub(crate) org: Option<OrgRef>,
    /// The maintainers (`net.mnt`).
    pub(crate) mnt: Vec<String>,
    /// The contacts of the record and of its holder.
    pub(crate) contacts: Vec<Contact>,
    /// The URL of the enclosing record (`links[rel=up]`), for the chain up
    /// to the block.
    pub(crate) parent_link: Option<String>,
    /// Where the record came from.
    pub(crate) origin: RecordOrigin,
}

/// A registry record about an AS: an RDAP `autnum` or a RIPE `aut-num`.
#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub(crate) struct AsRecord {
    /// The registry that keeps the record.
    pub(crate) rir: Rir,
    /// The AS number, or the first number of a block of AS.
    pub(crate) asn: Asn,
    /// The last number of a block of AS (`endAutnum`), if the record is a
    /// block. `None` for a single AS.
    #[serde(default)]
    pub(crate) last: Option<Asn>,
    /// The name of the AS.
    pub(crate) name: Option<String>,
    /// The holder organization.
    pub(crate) org: Option<OrgRef>,
    /// The maintainers (`as.mnt`).
    pub(crate) mnt: Vec<String>,
    /// The contacts of the AS and of its holder.
    pub(crate) contacts: Vec<Contact>,
}

impl AsRecord {
    /// Returns the first and the last number of the record. A single AS
    /// gives its number twice.
    pub(crate) fn numbers(&self) -> (Asn, Asn) {
        (self.asn, self.last.unwrap_or(self.asn))
    }
}

/// An organization found in a registry, with the resources that it holds
/// itself.
///
/// netf drops the records that another organization holds, even if this
/// organization is their sponsor.
#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub(crate) struct Org {
    /// The registry.
    pub(crate) rir: Rir,
    /// The handle.
    pub(crate) handle: String,
    /// The name.
    pub(crate) name: Option<String>,
    /// The networks that the organization holds.
    pub(crate) networks: Vec<NetRecord>,
    /// The AS that the organization holds.
    pub(crate) autnums: Vec<AsRecord>,
    /// The message of the registry, if it truncated the response.
    pub(crate) truncated: Option<String>,
}

/// What is known about one AS of a route.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct AsInfo {
    /// The AS number.
    pub(crate) asn: Asn,
    /// The `asn.txt` line, if loaded and present.
    pub(crate) entry: Option<AsnEntry>,
    /// The stats block of the number, if loaded and present.
    pub(crate) block: Option<AsBlock>,
    /// The RDAP record, once fetched.
    pub(crate) rdap: Option<Arc<AsRecord>>,
}

/// A registry network that intersects a row: a stats block or a record.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum NetCandidate {
    /// A block of delegated stats.
    Block(Block),
    /// A record from RDAP, the REST API, or a dump.
    Record(Arc<NetRecord>),
}

impl NetCandidate {
    /// Returns the addresses of the network.
    pub(crate) fn range(&self) -> Range {
        match self {
            Self::Block(block) => block.range,
            Self::Record(record) => record.range,
        }
    }
}

/// The "network" of a row: the chain from the registry block down to the
/// most specific record that covers the part or the route.
///
/// Enrichment fills the chain for the rows that are shown. The `net.*`
/// columns of `--fields` print the whole chain.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub(crate) struct NetChain {
    /// The stats block.
    pub(crate) block: Option<Block>,
    /// The records, from the widest to the most specific.
    pub(crate) records: Vec<Arc<NetRecord>>,
}

/// The highlights (`▶`) of what a row matched, for the tree.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub(crate) struct Marks {
    /// Whether the route or the part itself matched.
    pub(crate) route: bool,
    /// The AS that matched the conditions on `as.*`.
    pub(crate) ases: Vec<Asn>,
}

/// One line of the answer: a route, a part of it, or a registry network
/// without a route.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub(crate) struct Row {
    /// The "part" column: the address or network that `ip:` or `domain:`
    /// chose, or a range that `not ip:` left.
    pub(crate) part: Option<Range>,
    /// The route. `None` prints as `no route`.
    pub(crate) route: Option<Route>,
    /// The AS of the route, in the order of its origins.
    pub(crate) ases: Vec<AsInfo>,
    /// Every registry network that intersects the route or the part.
    pub(crate) nets: Vec<NetCandidate>,
    /// The network column and the holder. Enrichment fills them.
    pub(crate) chain: NetChain,
    /// The addresses of the row, for `--ipset` and the parts.
    pub(crate) addresses: AddrSet,
    /// What matched.
    pub(crate) marks: Marks,
    /// Whether the RDAP records that the predicate looks at were fetched.
    ///
    /// These records are the network of the base with its chain in `nets`,
    /// and the AS in `ases`. Once they are fetched, the conditions on
    /// holders, maintainers, and contacts are known.
    pub(crate) fetched: bool,
}

impl Row {
    /// Returns what the row is about: the part, else the prefix of the
    /// route, else the first network.
    pub(crate) fn base(&self) -> Option<Range> {
        self.part
            .or_else(|| self.route.as_ref().map(|route| route.prefix.range()))
            .or_else(|| self.nets.first().map(NetCandidate::range))
    }

    /// Returns the sort key of the row.
    ///
    /// Rows sort by family, then by first address, then wider before
    /// narrower. [`Prefix`] sorts in the same order.
    pub(crate) fn key(&self) -> Option<(Family, u128, Reverse<u128>)> {
        self.base()
            .map(|range| (range.family(), range.first(), Reverse(range.last())))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rir_names() {
        assert_eq!("RIPENCC".parse::<Rir>(), Ok(Rir::Ripencc));
        assert_eq!(Rir::Arin.to_string(), "arin");
        assert_eq!("ripe".parse::<Rir>(), Err(UnknownRir));
    }

    #[test]
    fn country_codes() {
        assert_eq!("xa".parse::<Cc>().unwrap().to_string(), "XA");
        assert_eq!("NLD".parse::<Cc>(), Err(InvalidCc));
        assert_eq!("R1".parse::<Cc>(), Err(InvalidCc));
    }

    #[test]
    fn roles() {
        assert_eq!("Abuse".parse::<Role>(), Ok(Role::Abuse));
        assert_eq!(Role::Technical.to_string(), "technical");
    }

    #[test]
    fn rows_sort_wider_first() {
        let row = |prefix: &str| Row {
            route: Some(Route {
                prefix: prefix.parse().unwrap(),
                origins: vec![64496],
            }),
            ..Row::default()
        };
        let mut rows = [row("192.0.2.0/25"), row("192.0.2.0/24"), row("10.0.0.0/8")];
        rows.sort_by_key(Row::key);
        let order: Vec<_> = rows
            .iter()
            .map(|r| r.route.as_ref().unwrap().prefix.to_string())
            .collect();
        assert_eq!(order, ["10.0.0.0/8", "192.0.2.0/24", "192.0.2.0/25"]);
    }

    #[test]
    fn records_serialize() {
        let record = NetRecord {
            rir: Rir::Ripencc,
            range: "192.0.2.0/24".parse().unwrap(),
            handle: "192.0.2.0 - 192.0.2.255".into(),
            name: Some("EXAMPLE-NET".into()),
            country: Some("XA".parse().unwrap()),
            org: Some(OrgRef {
                handle: "ORG-EX1-RIPE".into(),
                name: Some("Example LLC".into()),
            }),
            mnt: vec!["EXAMPLE-MNT".into()],
            contacts: Vec::new(),
            parent_link: None,
            origin: RecordOrigin::Rdap,
        };
        let json = serde_json::to_string(&record).unwrap();
        assert!(json.contains("\"rir\":\"ripencc\""));
        assert!(json.contains("\"country\":\"XA\""));
        let back: NetRecord = serde_json::from_str(&json).unwrap();
        assert_eq!(back, record);
    }
}
