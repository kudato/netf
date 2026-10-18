//! A registry database dump as a dataset.
//!
//! The dataset keeps `inetnum`, `inet6num`, `aut-num`, and `organisation`
//! objects. A reverse index leads from maintainer, contact, and
//! organization handles to records.
//!
//! APNIC publishes one dump per class (`apnic.db.inetnum.gz`, …). AFRINIC
//! publishes one dump of everything (`afrinic.db.gz`). Each dump is a
//! separate dataset with its own cache file `whois-<src>`. [`RpslReader`]
//! reads the objects. It keeps only the four classes above, and of them
//! only the attributes netf searches or shows: `mnt-by`, `mnt-lower`,
//! `mnt-routes`, `admin-c`, `tech-c`, `abuse-c`, `org`, `netname`,
//! `as-name`, `org-name`, and `country`. The reader skips `person` and
//! `role` objects without reading them, so nothing personal is stored.
//!
//! A [`WhoisRecord`] is what is left of an object. Its `mnt` is
//! `mnt-by ∪ mnt-lower ∪ mnt-routes`, because AFRINIC puts the holder's
//! maintainer in the last two. The RIPE REST API (`ripe_rest`) gives the
//! same record, so the search logic below serves both.
//!
//! # The index
//!
//! The file has five sections. All numbers are little-endian.
//!
//! | tag | section | record |
//! |---|---|---|
//! | 1 | `records` | 48 bytes: `first u128, last u128, name_off u32, attrs_off u32, name_len u16, attrs_len u16, class u8, cc [u8; 2], pad` |
//! | 2 | `attrs` | 8 bytes: `handle u32, kind u8, pad 3`. The handles of a record are at `attrs_off..+attrs_len`. |
//! | 3 | `handles` | 8 bytes: `off u32, len u16, pad 2` into `strings`, sorted by the handle in ASCII lowercase |
//! | 4 | `by_handle` | 8 bytes: `handle u32, record u32`, sorted, without repeats |
//! | 5 | `strings` | handles and names, each once |
//!
//! Records are in the order of the dump. For an `inetnum` or `inet6num`,
//! `first` and `last` are its first and last addresses. For an `aut-num`,
//! both are its number. The handle of a network or an AS is written from
//! its key (`192.0.2.0 - 192.0.2.255`, `2001:db8::/32`, `AS64496`). The
//! handle of an `organisation` is its attribute of kind `key`.
//!
//! A handle is an index into `handles`, which is sorted so that handles
//! that differ only in case sit next to each other. A search therefore
//! ignores case: one binary search in `handles` finds the handles, and
//! another in `by_handle` finds their records. `kind` is 0 `key`, 1 `mnt`,
//! 2 `admin-c`, 3 `tech-c`, 4 `abuse-c`, or 5 `org`. The search checks the
//! kind on each record found.
//!
//! Every read is checked for bounds, UTF-8, class, key, and kind. A
//! violation is [`Corrupt`], and the caller rebuilds the file.
//!
//! # Searching
//!
//! A [`WhoisRequest`] asks for records by maintainer, by contact (with or
//! without a role), and by holder organization. The answer has one
//! [`WhoisFound`] per condition. The contacts of a record include those of
//! its holder, so a contact search also finds the organizations with that
//! contact, and then the records they hold. `net.contact.abuse` relies on
//! this second search when the abuse contact is on the organization.
//! Holders get their `org-name` and contacts from the `organisation`
//! objects. Every backend takes the same steps:
//!
//! 1. [`org_lookup`] finds organizations by contact. For a stream, it also
//!    asks for the table of every organization (see below).
//! 2. [`record_lookup`] finds records by every condition and by the
//!    organizations from step 1.
//! 3. [`referenced_orgs`] lists the holders of what was found. An index
//!    looks them up by key with [`WhoisIndex::organisations`].
//! 4. [`assemble`] builds [`NetRecord`]s and [`AsRecord`]s per condition.
//!
//! [`WhoisIndex::lookup`] or one pass of [`WhoisStream`] answers a
//! [`Lookup`], which holds classes and handle searches. The `sources`
//! module drives the steps.
//!
//! # Without the cache
//!
//! [`WhoisStream`] answers a [`Lookup`] in one pass. It keeps the object
//! being read, the records found, and, if asked, a table of the
//! organizations. The table holds the handle, name, and contact handles of
//! each organization. Its size follows the number of members of the
//! registry, not the size of the dump. Nothing else of the dump is kept.

use std::{cmp::Ordering, collections::HashMap, sync::Arc};

use serde::{Deserialize, Serialize};

use super::rpsl::{RpslObject, RpslReader};
use crate::{
    addr::{Addr, Families, Family, Range},
    cache::{
        Builder, CacheFile,
        container::{Corrupt, Section, Table, u16_at, u32_at, u128_at},
    },
    error::{Error, Result},
    fetch::lines::{Control, LineSink},
    model::{AsRecord, Asn, Cc, Contact, EntityKind, NetRecord, OrgRef, RecordOrigin, Rir, Role},
};

const RECORDS: u16 = 1;
const ATTRS: u16 = 2;
const HANDLES: u16 = 3;
const BY_HANDLE: u16 = 4;
const STRINGS: u16 = 5;

const RECORD: usize = 48;
const ATTR: usize = 8;
const HANDLE: usize = 8;
const ENTRY: usize = 8;

/// The longest handle kept.
///
/// Longer tokens are not handles.
const MAX_HANDLE: usize = 255;

/// The longest name kept, in bytes.
///
/// A longer name is cut at a character boundary.
const MAX_NAME: usize = 1024;

/// The classes read from a dump.
const CLASSES: &[&str] = &["inetnum", "inet6num", "aut-num", "organisation"];

/// The attributes read from them, besides the class.
const KEPT: &[&str] = &[
    "netname",
    "as-name",
    "org-name",
    "country",
    "mnt-by",
    "mnt-lower",
    "mnt-routes",
    "admin-c",
    "tech-c",
    "abuse-c",
    "org",
];

/// Returns the reader of the objects netf keeps.
pub(crate) fn reader() -> RpslReader {
    RpslReader::new(CLASSES, KEPT)
}

/// Returns the record of an object given as `(name, value)` pairs.
///
/// The RIPE REST API gives objects this way, with the class first.
/// Attributes netf does not keep are dropped before anything is stored.
pub(crate) fn record_of_pairs<'a>(
    pairs: impl IntoIterator<Item = (&'a str, &'a str)>,
) -> Option<WhoisRecord> {
    let mut pairs = pairs.into_iter();
    let (class, key) = pairs.next()?;
    let kept = pairs.filter(|(name, _)| KEPT.iter().any(|k| k.eq_ignore_ascii_case(name)));
    let object = RpslObject::from_pairs(std::iter::once((class, key)).chain(kept));
    WhoisRecord::from_object(&object)
}

/// A class of object netf keeps.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
pub(crate) enum ObjectClass {
    /// An IPv4 network.
    Inetnum,
    /// An IPv6 network.
    Inet6num,
    /// An AS.
    AutNum,
    /// An `organisation`, a holder of networks and AS.
    Organisation,
}

impl ObjectClass {
    /// Every class, in the order of their codes.
    pub(crate) const ALL: [Self; 4] = [
        Self::Inetnum,
        Self::Inet6num,
        Self::AutNum,
        Self::Organisation,
    ];

    /// Returns the RPSL name, such as `inetnum` or `aut-num`.
    pub(crate) fn name(self) -> &'static str {
        match self {
            Self::Inetnum => "inetnum",
            Self::Inet6num => "inet6num",
            Self::AutNum => "aut-num",
            Self::Organisation => "organisation",
        }
    }

    fn from_name(name: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|class| class.name() == name)
    }

    fn code(self) -> u8 {
        self as u8
    }

    fn from_code(code: u8) -> Option<Self> {
        Self::ALL.get(usize::from(code)).copied()
    }
}

/// A set of classes.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct Classes(u8);

impl Classes {
    /// The class `organisation` only.
    pub(crate) const ORGANISATION: Self = Self(1 << 3);

    /// Returns the set of `classes`.
    pub(crate) fn of(classes: impl IntoIterator<Item = ObjectClass>) -> Self {
        Self(classes.into_iter().fold(0, |set, c| set | 1 << c.code()))
    }

    /// Returns `true` if `class` is in the set.
    pub(crate) fn contains(self, class: ObjectClass) -> bool {
        self.0 & 1 << class.code() != 0
    }

    /// Returns the classes of the set.
    pub(crate) fn iter(self) -> impl Iterator<Item = ObjectClass> {
        ObjectClass::ALL
            .into_iter()
            .filter(move |c| self.contains(*c))
    }

    /// Returns `true` for the empty set.
    pub(crate) fn is_empty(self) -> bool {
        self.0 == 0
    }
}

/// What a handle is to a record.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub(crate) enum Attr {
    /// The handle of the object itself (organizations).
    Key,
    /// A maintainer: `mnt-by`, `mnt-lower`, `mnt-routes`.
    Mnt,
    /// `admin-c`.
    Admin,
    /// `tech-c`.
    Tech,
    /// `abuse-c`.
    Abuse,
    /// `org`.
    Org,
}

impl Attr {
    const ALL: [Self; 6] = [
        Self::Key,
        Self::Mnt,
        Self::Admin,
        Self::Tech,
        Self::Abuse,
        Self::Org,
    ];

    fn code(self) -> u8 {
        self as u8
    }

    fn from_code(code: u8) -> Option<Self> {
        Self::ALL.get(usize::from(code)).copied()
    }

    /// Returns the role of a contact attribute, or `None` for another
    /// attribute.
    fn role(self) -> Option<Role> {
        match self {
            Self::Admin => Some(Role::Administrative),
            Self::Tech => Some(Role::Technical),
            Self::Abuse => Some(Role::Abuse),
            Self::Key | Self::Mnt | Self::Org => None,
        }
    }
}

/// A set of [`Attr`]s.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct Attrs(u8);

impl Attrs {
    /// The handle of the object.
    pub(crate) const KEY: Self = Self(1 << 0);
    /// Maintainers.
    pub(crate) const MNT: Self = Self(1 << 1);
    /// The holder organization.
    pub(crate) const ORG: Self = Self(1 << 5);

    /// Returns the contact attributes of `role`.
    ///
    /// Without a role, it returns all three. The registrant has no contact
    /// attribute, so [`Role::Registrant`] gives the empty set.
    pub(crate) fn contact(role: Option<Role>) -> Self {
        let one = |attr: Attr| 1 << attr.code();
        Self(match role {
            None => one(Attr::Admin) | one(Attr::Tech) | one(Attr::Abuse),
            Some(Role::Administrative) => one(Attr::Admin),
            Some(Role::Technical) => one(Attr::Tech),
            Some(Role::Abuse) => one(Attr::Abuse),
            Some(Role::Registrant) => 0,
        })
    }

    /// Returns `true` if `attr` is in the set.
    pub(crate) fn contains(self, attr: Attr) -> bool {
        self.0 & 1 << attr.code() != 0
    }

    /// Returns the attributes of the set.
    pub(crate) fn iter(self) -> impl Iterator<Item = Attr> {
        Attr::ALL.into_iter().filter(move |a| self.contains(*a))
    }
}

/// The primary key of a record.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub(crate) enum WhoisKey {
    /// The addresses of an `inetnum` or `inet6num`.
    Range(Range),
    /// The number of an `aut-num`.
    Asn(Asn),
    /// An `organisation`, whose key is its handle.
    Handle,
}

/// What netf keeps of an RPSL object.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub(crate) struct WhoisRecord {
    /// The class.
    pub(crate) class: ObjectClass,
    /// The key.
    pub(crate) key: WhoisKey,
    /// The handle, such as `192.0.2.0 - 192.0.2.255`, `AS64496`, or
    /// `ORG-EX1-AP`.
    pub(crate) handle: String,
    /// `netname`, `as-name`, or `org-name`.
    pub(crate) name: Option<String>,
    /// `country`.
    pub(crate) country: Option<Cc>,
    /// `mnt-by ∪ mnt-lower ∪ mnt-routes`, in order, without repeats.
    pub(crate) mnt: Vec<String>,
    /// `admin-c`.
    pub(crate) admin: Vec<String>,
    /// `tech-c`.
    pub(crate) tech: Vec<String>,
    /// `abuse-c`.
    pub(crate) abuse: Vec<String>,
    /// `org`.
    pub(crate) org: Option<String>,
}

impl WhoisRecord {
    /// Returns the record of `object`.
    ///
    /// Returns `None` for a class netf does not keep or for a key that does
    /// not parse.
    pub(crate) fn from_object(object: &RpslObject) -> Option<Self> {
        let class = ObjectClass::from_name(object.class()?)?;
        let (_, value) = object.attrs().next()?;
        let (key, handle) = parse_key(class, value)?;
        let name_attr = match class {
            ObjectClass::Inetnum | ObjectClass::Inet6num => "netname",
            ObjectClass::AutNum => "as-name",
            ObjectClass::Organisation => "org-name",
        };
        let name = object
            .values(name_attr)
            .map(|value| match class {
                // The name of a network or an AS is one word and may have a
                // comment. The name of an organization is text, and `#`
                // starts no comment there.
                ObjectClass::Organisation => value.trim(),
                _ => uncomment(value),
            })
            .find(|value| !value.is_empty())
            .map(|value| cut(value, MAX_NAME).to_owned());
        let country = object
            .values("country")
            .find_map(|value| handles(value).next()?.parse::<Cc>().ok());
        let list = |names: &[&str]| {
            let mut out: Vec<String> = Vec::new();
            for name in names {
                for value in object.values(name) {
                    for handle in handles(value) {
                        if !out.iter().any(|known| known.eq_ignore_ascii_case(handle)) {
                            out.push(handle.to_owned());
                        }
                    }
                }
            }
            out
        };
        let org = object.values("org").find_map(|v| handles(v).next());
        Some(Self {
            class,
            key,
            handle,
            name,
            country,
            mnt: list(&["mnt-by", "mnt-lower", "mnt-routes"]),
            admin: list(&["admin-c"]),
            tech: list(&["tech-c"]),
            abuse: list(&["abuse-c"]),
            org: org.map(str::to_owned),
        })
    }

    /// Returns the handles of the record, each with what it is to the
    /// record.
    pub(crate) fn handles(&self) -> impl Iterator<Item = (Attr, &str)> {
        let key = (self.class == ObjectClass::Organisation).then_some((Attr::Key, &*self.handle));
        key.into_iter()
            .chain(self.mnt.iter().map(|h| (Attr::Mnt, h.as_str())))
            .chain(self.admin.iter().map(|h| (Attr::Admin, h.as_str())))
            .chain(self.tech.iter().map(|h| (Attr::Tech, h.as_str())))
            .chain(self.abuse.iter().map(|h| (Attr::Abuse, h.as_str())))
            .chain(self.org.iter().map(|h| (Attr::Org, h.as_str())))
    }

    /// Returns `true` if `handle` is one of `attrs` of the record, ignoring
    /// case.
    pub(crate) fn has(&self, attrs: Attrs, handle: &str) -> bool {
        self.handles()
            .any(|(attr, h)| attrs.contains(attr) && h.eq_ignore_ascii_case(handle))
    }

    /// Returns the record as the table of organizations keeps it, without
    /// maintainers.
    fn as_holder(&self) -> Self {
        Self {
            mnt: Vec::new(),
            ..self.clone()
        }
    }
}

/// Parses the key of a `class` object and returns it with the handle.
fn parse_key(class: ObjectClass, value: &str) -> Option<(WhoisKey, String)> {
    let value = uncomment(value);
    match class {
        ObjectClass::Inetnum => parse_range(value, Family::V4).map(WhoisKey::Range),
        ObjectClass::Inet6num => parse_range(value, Family::V6).map(WhoisKey::Range),
        ObjectClass::AutNum => {
            let digits = value
                .strip_prefix("AS")
                .or_else(|| value.strip_prefix("as"))
                .or_else(|| value.strip_prefix("As"))
                .or_else(|| value.strip_prefix("aS"))?;
            if digits.is_empty() || digits.len() > 10 || !digits.bytes().all(|b| b.is_ascii_digit())
            {
                return None;
            }
            digits.parse::<Asn>().ok().map(WhoisKey::Asn)
        }
        ObjectClass::Organisation => {
            let handle = handles(value).next()?;
            return Some((WhoisKey::Handle, handle.to_owned()));
        }
    }
    .map(|key| {
        let handle = key_handle(&key).unwrap_or_default();
        (key, handle)
    })
}

/// Returns the handle of a network or an AS, written from its key.
///
/// Returns `None` for an organization.
fn key_handle(key: &WhoisKey) -> Option<String> {
    match key {
        WhoisKey::Range(range) => Some(match range.as_prefix() {
            Some(prefix) if range.family() == Family::V6 => prefix.to_string(),
            _ => format!("{} - {}", range.first_addr(), range.last_addr()),
        }),
        WhoisKey::Asn(asn) => Some(format!("AS{asn}")),
        WhoisKey::Handle => None,
    }
}

/// Parses `a - b` or a prefix of `family`.
///
/// The host bits of a prefix are cleared.
fn parse_range(value: &str, family: Family) -> Option<Range> {
    if let Some((first, last)) = value.split_once('-') {
        let first: Addr = first.trim().parse().ok()?;
        let last: Addr = last.trim().parse().ok()?;
        if first.family() != family || last.family() != family {
            return None;
        }
        return Range::new(family, first.bits(), last.bits());
    }
    let (addr, len) = value.split_once('/')?;
    let addr: Addr = addr.trim().parse().ok()?;
    let len = len.trim();
    if addr.family() != family || len.is_empty() || len.len() > 3 {
        return None;
    }
    let len: u32 = len.parse().ok()?;
    let bits = u32::from(family.bits());
    if len > bits {
        return None;
    }
    // `checked_shr` fails on a /128, which shifts out every bit. Its host
    // bits are 0.
    let host = family.max().checked_shr(len).unwrap_or(0);
    let first = addr.bits() & !host & family.max();
    Range::new(family, first, first | host)
}

/// Returns the value without an end-of-line comment, trimmed.
fn uncomment(value: &str) -> &str {
    value.split('#').next().unwrap_or("").trim()
}

/// Returns the handles of a list value.
///
/// Commas or blanks separate the handles, and a comment ends the list.
/// Tokens longer than [`MAX_HANDLE`] are skipped.
fn handles(value: &str) -> impl Iterator<Item = &str> {
    uncomment(value)
        .split(|c: char| c == ',' || c.is_whitespace())
        .filter(|h| !h.is_empty() && h.len() <= MAX_HANDLE)
}

/// Returns `text` cut to at most `max` bytes at a character boundary.
fn cut(text: &str, max: usize) -> &str {
    if text.len() <= max {
        return text;
    }
    let mut end = max;
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    &text[..end]
}

/// Searches of a registry database: by maintainer, by contact, and by
/// holder organization.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub(crate) struct WhoisRequest {
    /// `*.mnt: <handle>`.
    pub(crate) mnt: Vec<String>,
    /// `*.contact: <handle>`, `*.contact.<role>: <handle>`.
    pub(crate) contact: Vec<(Option<Role>, String)>,
    /// Records held by the organization `<handle>`.
    pub(crate) org: Vec<String>,
    /// The networks to search: `inetnum` for IPv4, `inet6num` for IPv6.
    pub(crate) families: Families,
    /// Whether to search the AS (`aut-num`) as well.
    pub(crate) autnums: bool,
}

impl WhoisRequest {
    /// Returns `true` if the request asks for nothing: no condition, or no
    /// class to look in.
    pub(crate) fn is_empty(&self) -> bool {
        (self.mnt.is_empty() && self.contact.is_empty() && self.org.is_empty())
            || self.classes().is_empty()
    }

    /// Returns the classes of the records asked for.
    pub(crate) fn classes(&self) -> Classes {
        let mut classes = Vec::new();
        if self.families.v4() {
            classes.push(ObjectClass::Inetnum);
        }
        if self.families.v6() {
            classes.push(ObjectClass::Inet6num);
        }
        if self.autnums {
            classes.push(ObjectClass::AutNum);
        }
        Classes::of(classes)
    }
}

/// The records of one condition.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub(crate) struct WhoisFound {
    /// Networks, sorted by range, then by registry and handle.
    pub(crate) networks: Vec<Arc<NetRecord>>,
    /// AS, sorted by number, then by registry.
    pub(crate) autnums: Vec<Arc<AsRecord>>,
}

impl WhoisFound {
    /// Returns `true` if nothing was found.
    #[cfg(test)]
    pub(crate) fn is_empty(&self) -> bool {
        self.networks.is_empty() && self.autnums.is_empty()
    }

    fn sort(&mut self) {
        let rank = |rir: Rir| Rir::ALL.iter().position(|r| *r == rir);
        self.networks.sort_by(|a, b| {
            (a.range.first(), a.range.last(), rank(a.rir), &a.handle).cmp(&(
                b.range.first(),
                b.range.last(),
                rank(b.rir),
                &b.handle,
            ))
        });
        self.networks.dedup();
        self.autnums.sort_by_key(|a| (a.asn, rank(a.rir)));
        self.autnums.dedup();
    }
}

/// The answer to a [`WhoisRequest`]: one [`WhoisFound`] per condition, in
/// the order of the request.
///
/// `mnt[i]` answers `request.mnt[i]`, and the other fields work the same
/// way.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub(crate) struct WhoisAnswer {
    /// Per maintainer.
    pub(crate) mnt: Vec<WhoisFound>,
    /// Per contact.
    pub(crate) contact: Vec<WhoisFound>,
    /// Per organization.
    pub(crate) org: Vec<WhoisFound>,
}

impl WhoisAnswer {
    /// Creates an answer with nothing found for each condition of
    /// `request`.
    pub(crate) fn empty(request: &WhoisRequest) -> Self {
        Self {
            mnt: vec![WhoisFound::default(); request.mnt.len()],
            contact: vec![WhoisFound::default(); request.contact.len()],
            org: vec![WhoisFound::default(); request.org.len()],
        }
    }

    /// Joins the answers of several registries to one request.
    pub(crate) fn merge(answers: impl IntoIterator<Item = WhoisAnswer>) -> Self {
        let mut out = Self::default();
        for answer in answers {
            for (into, from) in [
                (&mut out.mnt, answer.mnt),
                (&mut out.contact, answer.contact),
                (&mut out.org, answer.org),
            ] {
                if into.len() < from.len() {
                    into.resize(from.len(), WhoisFound::default());
                }
                for (found, more) in into.iter_mut().zip(from) {
                    found.networks.extend(more.networks);
                    found.autnums.extend(more.autnums);
                }
            }
        }
        for found in out
            .mnt
            .iter_mut()
            .chain(&mut out.contact)
            .chain(&mut out.org)
        {
            found.sort();
        }
        out
    }
}

/// One handle search: records where `handle` is one of `attrs`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct Query {
    /// What the handle may be to the record.
    pub(crate) attrs: Attrs,
    /// The handle. The comparison ignores case.
    pub(crate) handle: String,
}

/// Handle searches over one dataset.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub(crate) struct Lookup {
    /// The classes of the records searched.
    pub(crate) classes: Classes,
    /// The searches.
    pub(crate) queries: Vec<Query>,
    /// Whether to keep every organization seen.
    ///
    /// Only a stream keeps them. An index looks organizations up by key
    /// instead.
    pub(crate) orgs: bool,
}

/// The answer to a [`Lookup`].
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub(crate) struct Found {
    /// Per search, the records found, in the order of the dataset.
    pub(crate) hits: Vec<Vec<WhoisRecord>>,
    /// With [`Lookup::orgs`], every organization, without maintainers.
    pub(crate) orgs: Vec<WhoisRecord>,
}

impl Found {
    /// Creates an answer with no records for each search of `lookup`.
    pub(crate) fn empty(lookup: &Lookup) -> Self {
        Self {
            hits: vec![Vec::new(); lookup.queries.len()],
            orgs: Vec::new(),
        }
    }

    /// Adds the answer of another dataset to the same lookup.
    pub(crate) fn merge(&mut self, other: Found) {
        if self.hits.len() < other.hits.len() {
            self.hits.resize(other.hits.len(), Vec::new());
        }
        for (hits, more) in self.hits.iter_mut().zip(other.hits) {
            hits.extend(more);
        }
        self.orgs.extend(other.orgs);
    }
}

/// Step 1: returns the lookup for the organizations whose contacts are
/// those of the request.
///
/// The lookup has one search per contact. With `table`, a stream also keeps
/// every organization.
pub(crate) fn org_lookup(request: &WhoisRequest, table: bool) -> Lookup {
    Lookup {
        classes: Classes::ORGANISATION,
        queries: request
            .contact
            .iter()
            .map(|(role, handle)| Query {
                attrs: Attrs::contact(*role),
                handle: handle.clone(),
            })
            .collect(),
        orgs: table,
    }
}

/// Step 2: the record searches of a request.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub(crate) struct RecordLookup {
    /// The searches.
    ///
    /// First come the maintainers, the contacts, and the organizations of
    /// the request, in this order. Then comes one search per organization
    /// found by a contact.
    pub(crate) lookup: Lookup,
    /// For each contact, the indexes of the searches of its organizations.
    via: Vec<Vec<usize>>,
}

/// Step 2: returns the searches for the records of every condition of
/// `request`.
///
/// It also searches for the records held by the organizations found for
/// contact `j`. These are `orgs_by_contact[j]`, the hits of
/// [`org_lookup`].
pub(crate) fn record_lookup(
    request: &WhoisRequest,
    orgs_by_contact: &[Vec<WhoisRecord>],
) -> RecordLookup {
    let mut queries: Vec<Query> = Vec::new();
    queries.extend(request.mnt.iter().map(|handle| Query {
        attrs: Attrs::MNT,
        handle: handle.clone(),
    }));
    queries.extend(request.contact.iter().map(|(role, handle)| Query {
        attrs: Attrs::contact(*role),
        handle: handle.clone(),
    }));
    queries.extend(request.org.iter().map(|handle| Query {
        attrs: Attrs::ORG,
        handle: handle.clone(),
    }));
    let mut by_org: HashMap<String, usize> = HashMap::new();
    let mut via = vec![Vec::new(); request.contact.len()];
    for (j, orgs) in orgs_by_contact
        .iter()
        .enumerate()
        .take(request.contact.len())
    {
        for org in orgs {
            if org.class != ObjectClass::Organisation {
                continue;
            }
            let q = *by_org
                .entry(org.handle.to_ascii_lowercase())
                .or_insert_with(|| {
                    queries.push(Query {
                        attrs: Attrs::ORG,
                        handle: org.handle.clone(),
                    });
                    queries.len() - 1
                });
            if !via[j].contains(&q) {
                via[j].push(q);
            }
        }
    }
    RecordLookup {
        lookup: Lookup {
            classes: request.classes(),
            queries,
            orgs: false,
        },
        via,
    }
}

/// Step 3: returns the holders of the records found, each once.
pub(crate) fn referenced_orgs(found: &Found) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for record in found.hits.iter().flatten() {
        if let Some(org) = &record.org
            && !out.iter().any(|known| known.eq_ignore_ascii_case(org))
        {
            out.push(org.clone());
        }
    }
    out
}

/// Step 4: builds the answer from the hits of a [`record_lookup`] and the
/// known organizations `orgs`.
///
/// The answer has one list per condition. The lists hold the records of the
/// classes asked for, with the name and contacts of their holder.
pub(crate) fn assemble(
    request: &WhoisRequest,
    plan: &RecordLookup,
    found: &Found,
    orgs: &[WhoisRecord],
    rir: Rir,
    origin: RecordOrigin,
) -> WhoisAnswer {
    let mut table: HashMap<String, &WhoisRecord> = HashMap::new();
    for org in orgs {
        if org.class == ObjectClass::Organisation {
            table.entry(org.handle.to_ascii_lowercase()).or_insert(org);
        }
    }
    let mut convert = Convert {
        table,
        rir,
        origin,
        classes: request.classes(),
        memo: HashMap::new(),
    };
    let hits = |q: usize| found.hits.get(q).map_or(&[][..], Vec::as_slice);
    let (m, c) = (request.mnt.len(), request.contact.len());
    WhoisAnswer {
        mnt: (0..m).map(|i| convert.found(hits(i).iter())).collect(),
        contact: (0..c)
            .map(|j| {
                let via = plan.via.get(j).into_iter().flatten();
                convert.found(hits(m + j).iter().chain(via.flat_map(|&q| hits(q))))
            })
            .collect(),
        org: (0..request.org.len())
            .map(|k| convert.found(hits(m + c + k).iter()))
            .collect(),
    }
}

/// A converted record, shared between the conditions that found it.
#[derive(Clone)]
enum Converted {
    Net(Arc<NetRecord>),
    As(Arc<AsRecord>),
}

/// Converts records into the model, each record once.
struct Convert<'a> {
    table: HashMap<String, &'a WhoisRecord>,
    rir: Rir,
    origin: RecordOrigin,
    classes: Classes,
    memo: HashMap<(ObjectClass, String), Converted>,
}

impl<'a> Convert<'a> {
    fn found<'r>(&mut self, records: impl Iterator<Item = &'r WhoisRecord>) -> WhoisFound {
        let mut found = WhoisFound::default();
        for record in records {
            if !self.classes.contains(record.class) {
                continue;
            }
            match self.convert(record) {
                Some(Converted::Net(net)) => found.networks.push(net),
                Some(Converted::As(asn)) => found.autnums.push(asn),
                None => {}
            }
        }
        found.sort();
        found
    }

    fn convert(&mut self, record: &WhoisRecord) -> Option<Converted> {
        let key = (record.class, record.handle.to_ascii_lowercase());
        if let Some(known) = self.memo.get(&key) {
            return Some(known.clone());
        }
        let holder = record
            .org
            .as_ref()
            .and_then(|org| self.table.get(&org.to_ascii_lowercase()).copied());
        let org = record.org.as_ref().map(|handle| OrgRef {
            handle: holder.map_or_else(|| handle.clone(), |h| h.handle.clone()),
            name: holder.and_then(|h| h.name.clone()),
        });
        let contacts = contacts(record, holder, self.rir, self.origin);
        let converted = match record.key {
            WhoisKey::Range(range) => Converted::Net(Arc::new(NetRecord {
                rir: self.rir,
                range,
                handle: record.handle.clone(),
                name: record.name.clone(),
                country: record.country,
                org,
                mnt: record.mnt.clone(),
                contacts,
                parent_link: None,
                origin: self.origin,
            })),
            WhoisKey::Asn(asn) => Converted::As(Arc::new(AsRecord {
                rir: self.rir,
                asn,
                last: None,
                name: record.name.clone(),
                org,
                mnt: record.mnt.clone(),
                contacts,
            })),
            WhoisKey::Handle => return None,
        };
        self.memo.insert(key, converted.clone());
        Some(converted)
    }
}

/// Returns the contacts of a record and of its holder by handle, each with
/// every role it holds.
///
/// Only handles and roles are known. RIPE persons may have an e-mail, which
/// `--ripe-emails` fetches.
fn contacts(
    record: &WhoisRecord,
    holder: Option<&WhoisRecord>,
    rir: Rir,
    origin: RecordOrigin,
) -> Vec<Contact> {
    let mut out: Vec<Contact> = Vec::new();
    for source in std::iter::once(record).chain(holder) {
        for (attr, handle) in source.handles() {
            let Some(role) = attr.role() else {
                continue;
            };
            match out
                .iter_mut()
                .find(|c| c.handle.eq_ignore_ascii_case(handle))
            {
                Some(known) => {
                    if !known.roles.contains(&role) {
                        known.roles.push(role);
                    }
                }
                None => out.push(Contact {
                    handle: handle.to_owned(),
                    roles: vec![role],
                    kind: EntityKind::Unknown,
                    name: None,
                    address: None,
                    phone: None,
                    email: Vec::new(),
                    rir,
                    emails_hidden: origin == RecordOrigin::RipeRest,
                }),
            }
        }
    }
    out
}

/// Compares two strings ignoring ASCII case, then by bytes.
fn cmp_handles(a: &[u8], b: &[u8]) -> Ordering {
    cmp_lower(a, b).then_with(|| a.cmp(b))
}

/// Compares two strings in ASCII lowercase.
fn cmp_lower(a: &[u8], b: &[u8]) -> Ordering {
    a.iter()
        .map(u8::to_ascii_lowercase)
        .cmp(b.iter().map(u8::to_ascii_lowercase))
}

/// Builds the sections of a `whois-<src>` file from the lines of a dump.
pub(crate) struct WhoisBuilder {
    reader: RpslReader,
    records: Vec<u8>,
    /// For each attribute, the handle id and the kind.
    ///
    /// Ids follow the order in which the handles first appear.
    attrs: Vec<(u32, u8)>,
    strings: Vec<u8>,
    /// Maps the FNV-1a hash of a string to its place in `strings`.
    interned: HashMap<u64, (u32, u16)>,
    /// Maps the offset of a handle in `strings` to its id.
    ids: HashMap<u32, u32>,
    /// For each handle id, its place in `strings`.
    handles: Vec<(u32, u16)>,
}

impl Default for WhoisBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl WhoisBuilder {
    /// Creates an empty builder.
    pub(crate) fn new() -> Self {
        Self {
            reader: reader(),
            records: Vec::new(),
            attrs: Vec::new(),
            strings: Vec::new(),
            interned: HashMap::new(),
            ids: HashMap::new(),
            handles: Vec::new(),
        }
    }

    fn intern(&mut self, text: &str) -> Result<(u32, u16)> {
        let hash = crate::cache::responses::fnv1a64(text.as_bytes());
        if let Some(&(off, len)) = self.interned.get(&hash)
            && &self.strings[off as usize..off as usize + usize::from(len)] == text.as_bytes()
        {
            return Ok((off, len));
        }
        let off = u32::try_from(self.strings.len()).map_err(|_| too_large())?;
        let len = u16::try_from(text.len()).map_err(|_| too_large())?;
        self.strings.extend_from_slice(text.as_bytes());
        // On a hash collision, the newer string is not interned. It is still
        // stored, as a second copy.
        self.interned.entry(hash).or_insert((off, len));
        Ok((off, len))
    }

    fn handle_id(&mut self, handle: &str) -> Result<u32> {
        let (off, len) = self.intern(handle)?;
        if let Some(&id) = self.ids.get(&off) {
            return Ok(id);
        }
        let id = u32::try_from(self.handles.len()).map_err(|_| too_large())?;
        self.handles.push((off, len));
        self.ids.insert(off, id);
        Ok(id)
    }

    fn add(&mut self, record: &WhoisRecord) -> Result<()> {
        let (first, last) = match record.key {
            WhoisKey::Range(range) => (range.first(), range.last()),
            WhoisKey::Asn(asn) => (u128::from(asn), u128::from(asn)),
            WhoisKey::Handle => (0, 0),
        };
        let (name_off, name_len) = match &record.name {
            Some(name) => self.intern(name)?,
            None => (0, 0),
        };
        let attrs_off = u32::try_from(self.attrs.len()).map_err(|_| too_large())?;
        let mut count: u16 = 0;
        let handles: Vec<(Attr, String)> = record
            .handles()
            .map(|(attr, handle)| (attr, handle.to_owned()))
            .collect();
        for (attr, handle) in handles {
            if count == u16::MAX {
                break;
            }
            let id = self.handle_id(&handle)?;
            self.attrs.push((id, attr.code()));
            count += 1;
        }
        let cc = record.country.map_or([0; 2], |cc| {
            let bytes = cc.as_str().as_bytes();
            [bytes[0], bytes[1]]
        });
        let out = &mut self.records;
        out.extend_from_slice(&first.to_le_bytes());
        out.extend_from_slice(&last.to_le_bytes());
        out.extend_from_slice(&name_off.to_le_bytes());
        out.extend_from_slice(&attrs_off.to_le_bytes());
        out.extend_from_slice(&name_len.to_le_bytes());
        out.extend_from_slice(&count.to_le_bytes());
        out.push(record.class.code());
        out.extend_from_slice(&cc);
        out.push(0);
        if self.records.len() / RECORD > u32::MAX as usize {
            return Err(too_large());
        }
        Ok(())
    }

    fn take(&mut self, record: Option<WhoisRecord>) -> Result<()> {
        match record {
            Some(record) => self.add(&record),
            None => Ok(()),
        }
    }
}

fn too_large() -> Error {
    Error::runtime("the dump is too large for the index")
}

impl LineSink for WhoisBuilder {
    fn line(&mut self, line: &[u8]) -> Result<Control> {
        let record = self.reader.line(line).and_then(WhoisRecord::from_object);
        self.take(record)?;
        Ok(Control::Continue)
    }
}

impl Builder for WhoisBuilder {
    fn finish(mut self) -> Result<Vec<Section>> {
        let record = self.reader.finish().and_then(WhoisRecord::from_object);
        self.take(record)?;
        if self.records.is_empty() {
            return Err(Error::runtime("no records in the dump"));
        }
        // Sorts the handles into the order of the index and notes the rank
        // of each id there.
        let strings = &self.strings;
        let text = |(off, len): (u32, u16)| &strings[off as usize..off as usize + usize::from(len)];
        let mut order: Vec<u32> = (0..self.handles.len() as u32).collect();
        order.sort_unstable_by(|a, b| {
            cmp_handles(
                text(self.handles[*a as usize]),
                text(self.handles[*b as usize]),
            )
        });
        let mut rank = vec![0u32; order.len()];
        let mut handles = Vec::with_capacity(order.len() * HANDLE);
        for (i, id) in order.iter().enumerate() {
            rank[*id as usize] = i as u32;
            let (off, len) = self.handles[*id as usize];
            handles.extend_from_slice(&off.to_le_bytes());
            handles.extend_from_slice(&len.to_le_bytes());
            handles.extend_from_slice(&[0; 2]);
        }
        drop(order);
        let mut attrs = Vec::with_capacity(self.attrs.len() * ATTR);
        for (id, kind) in &self.attrs {
            attrs.extend_from_slice(&rank[*id as usize].to_le_bytes());
            attrs.push(*kind);
            attrs.extend_from_slice(&[0; 3]);
        }
        let mut entries: Vec<(u32, u32)> = Vec::with_capacity(self.attrs.len());
        for (r, record) in self.records.as_chunks::<RECORD>().0.iter().enumerate() {
            let off = u32_at(record, 36) as usize;
            let len = usize::from(u16_at(record, 42));
            for (id, _) in &self.attrs[off..off + len] {
                entries.push((rank[*id as usize], r as u32));
            }
        }
        self.attrs = Vec::new();
        drop(rank);
        entries.sort_unstable();
        entries.dedup();
        let mut by_handle = Vec::with_capacity(entries.len() * ENTRY);
        for (handle, record) in entries {
            by_handle.extend_from_slice(&handle.to_le_bytes());
            by_handle.extend_from_slice(&record.to_le_bytes());
        }
        Ok(vec![
            Section::new(RECORDS, self.records),
            Section::new(ATTRS, attrs),
            Section::new(HANDLES, handles),
            Section::new(BY_HANDLE, by_handle),
            Section::new(STRINGS, self.strings),
        ])
    }
}

/// An open `whois-<src>` file.
#[derive(Debug)]
pub(crate) struct WhoisIndex {
    file: CacheFile,
}

/// The sections of an index, checked for size.
struct View<'a> {
    records: Table<'a, RECORD>,
    attrs: Table<'a, ATTR>,
    handles: Table<'a, HANDLE>,
    by_handle: Table<'a, ENTRY>,
    strings: &'a [u8],
}

impl WhoisIndex {
    /// Opens the index in `file` and checks its sections.
    ///
    /// # Errors
    ///
    /// Returns [`Corrupt`] if a section is missing or has a wrong size.
    pub(crate) fn open(file: CacheFile) -> Result<Self, Corrupt> {
        let index = Self { file };
        index.view()?;
        Ok(index)
    }

    fn view(&self) -> Result<View<'_>, Corrupt> {
        Ok(View {
            records: Table::new(self.file.section(RECORDS)?)?,
            attrs: Table::new(self.file.section(ATTRS)?)?,
            handles: Table::new(self.file.section(HANDLES)?)?,
            by_handle: Table::new(self.file.section(BY_HANDLE)?)?,
            strings: self.file.section(STRINGS)?,
        })
    }

    /// Answers `lookup`.
    ///
    /// [`Lookup::orgs`] is ignored. Use [`WhoisIndex::organisations`]
    /// instead.
    ///
    /// # Errors
    ///
    /// Returns [`Corrupt`] if a read finds the file damaged.
    pub(crate) fn lookup(&self, lookup: &Lookup) -> Result<Found, Corrupt> {
        let view = self.view()?;
        let mut found = Found::empty(lookup);
        for (query, hits) in lookup.queries.iter().zip(&mut found.hits) {
            for record in view.find(&query.handle)? {
                if lookup.classes.contains(record.class) && record.has(query.attrs, &query.handle) {
                    hits.push(record);
                }
            }
        }
        Ok(found)
    }

    /// Returns the organizations with the keys `handles`, without
    /// maintainers.
    ///
    /// # Errors
    ///
    /// Returns [`Corrupt`] if a read finds the file damaged.
    pub(crate) fn organisations(&self, handles: &[String]) -> Result<Vec<WhoisRecord>, Corrupt> {
        let view = self.view()?;
        let mut out = Vec::new();
        for handle in handles {
            for record in view.find(handle)? {
                if record.class == ObjectClass::Organisation && record.has(Attrs::KEY, handle) {
                    out.push(record.as_holder());
                }
            }
        }
        Ok(out)
    }
}

impl View<'_> {
    fn text(&self, off: u32, len: u16) -> Result<&str, Corrupt> {
        let start = off as usize;
        let bytes = self
            .strings
            .get(start..start + usize::from(len))
            .ok_or(Corrupt)?;
        std::str::from_utf8(bytes).map_err(|_| Corrupt)
    }

    fn handle(&self, id: u32) -> Result<&str, Corrupt> {
        let entry = self.handles.get(id as usize)?;
        let text = self.text(u32_at(entry, 0), u16_at(entry, 4))?;
        if text.is_empty() {
            return Err(Corrupt);
        }
        Ok(text)
    }

    /// Returns the records with a handle equal to `handle`, ignoring case,
    /// in the order of the dump.
    fn find(&self, handle: &str) -> Result<Vec<WhoisRecord>, Corrupt> {
        let wanted = handle.as_bytes();
        let n = self.handles.len();
        let mut bad = false;
        let mut below = |entry: &[u8; HANDLE], or_equal: bool| {
            let Ok(text) = self.text(u32_at(entry, 0), u16_at(entry, 4)) else {
                bad = true;
                return false;
            };
            let order = cmp_lower(text.as_bytes(), wanted);
            order == Ordering::Less || (or_equal && order == Ordering::Equal)
        };
        let lo = self.handles.partition_point(0, n, |e| below(e, false))?;
        let hi = self.handles.partition_point(lo, n, |e| below(e, true))?;
        if bad {
            return Err(Corrupt);
        }
        let (lo, hi) = (lo as u32, hi as u32);
        let m = self.by_handle.len();
        let start = self
            .by_handle
            .partition_point(0, m, |e| u32_at(e, 0) < lo)?;
        let end = self
            .by_handle
            .partition_point(start, m, |e| u32_at(e, 0) < hi)?;
        let mut indexes: Vec<u32> = (start..end)
            .map(|i| self.by_handle.get(i).map(|e| u32_at(e, 4)))
            .collect::<Result<_, _>>()?;
        indexes.sort_unstable();
        indexes.dedup();
        indexes.into_iter().map(|r| self.record(r)).collect()
    }

    fn record(&self, index: u32) -> Result<WhoisRecord, Corrupt> {
        let rec = self.records.get(index as usize)?;
        let class = ObjectClass::from_code(rec[44]).ok_or(Corrupt)?;
        let (first, last) = (u128_at(rec, 0), u128_at(rec, 16));
        let name_len = u16_at(rec, 40);
        let name = match name_len {
            0 => None,
            len => Some(self.text(u32_at(rec, 32), len)?.to_owned()),
        };
        let country = match [rec[45], rec[46]] {
            [0, 0] => None,
            cc => Some(
                std::str::from_utf8(&cc)
                    .ok()
                    .and_then(|cc| cc.parse::<Cc>().ok())
                    .ok_or(Corrupt)?,
            ),
        };
        let mut record = WhoisRecord {
            class,
            key: WhoisKey::Handle,
            handle: String::new(),
            name,
            country,
            mnt: Vec::new(),
            admin: Vec::new(),
            tech: Vec::new(),
            abuse: Vec::new(),
            org: None,
        };
        let attrs_off = u32_at(rec, 36) as usize;
        for i in attrs_off..attrs_off + usize::from(u16_at(rec, 42)) {
            let attr = self.attrs.get(i)?;
            let handle = self.handle(u32_at(attr, 0))?.to_owned();
            match Attr::from_code(attr[4]).ok_or(Corrupt)? {
                Attr::Key if class == ObjectClass::Organisation && record.handle.is_empty() => {
                    record.handle = handle;
                }
                Attr::Key => return Err(Corrupt),
                Attr::Mnt => record.mnt.push(handle),
                Attr::Admin => record.admin.push(handle),
                Attr::Tech => record.tech.push(handle),
                Attr::Abuse => record.abuse.push(handle),
                Attr::Org if record.org.is_none() => record.org = Some(handle),
                Attr::Org => return Err(Corrupt),
            }
        }
        record.key = match class {
            ObjectClass::Inetnum => {
                WhoisKey::Range(Range::new(Family::V4, first, last).ok_or(Corrupt)?)
            }
            ObjectClass::Inet6num => {
                WhoisKey::Range(Range::new(Family::V6, first, last).ok_or(Corrupt)?)
            }
            ObjectClass::AutNum if first == last => {
                WhoisKey::Asn(Asn::try_from(first).map_err(|_| Corrupt)?)
            }
            ObjectClass::AutNum => return Err(Corrupt),
            ObjectClass::Organisation if !record.handle.is_empty() => WhoisKey::Handle,
            ObjectClass::Organisation => return Err(Corrupt),
        };
        if let Some(handle) = key_handle(&record.key) {
            record.handle = handle;
        }
        Ok(record)
    }
}

/// Answers a [`Lookup`] in one pass over a dump.
pub(crate) struct WhoisStream<'a> {
    lookup: &'a Lookup,
    reader: RpslReader,
    /// Maps a lowercase handle to its searches.
    queries: HashMap<String, Vec<usize>>,
    found: Found,
    seen: bool,
    key: String,
    matched: Vec<usize>,
}

impl<'a> WhoisStream<'a> {
    /// Creates a pass that answers `lookup`.
    pub(crate) fn new(lookup: &'a Lookup) -> Self {
        let mut queries: HashMap<String, Vec<usize>> = HashMap::new();
        for (i, query) in lookup.queries.iter().enumerate() {
            queries
                .entry(query.handle.to_ascii_lowercase())
                .or_default()
                .push(i);
        }
        Self {
            lookup,
            reader: reader(),
            queries,
            found: Found::empty(lookup),
            seen: false,
            key: String::new(),
            matched: Vec::new(),
        }
    }

    fn take(&mut self, record: Option<WhoisRecord>) {
        let Some(record) = record else {
            return;
        };
        self.seen = true;
        if self.lookup.orgs && record.class == ObjectClass::Organisation {
            self.found.orgs.push(record.as_holder());
        }
        if !self.lookup.classes.contains(record.class) {
            return;
        }
        self.matched.clear();
        for (attr, handle) in record.handles() {
            self.key.clear();
            self.key.push_str(handle);
            self.key.make_ascii_lowercase();
            for &q in self.queries.get(&self.key).into_iter().flatten() {
                if self.lookup.queries[q].attrs.contains(attr) && !self.matched.contains(&q) {
                    self.matched.push(q);
                }
            }
        }
        for &q in &self.matched {
            self.found.hits[q].push(record.clone());
        }
    }

    /// Ends the input and returns what was found.
    ///
    /// # Errors
    ///
    /// Returns an error if the dump has no records.
    pub(crate) fn finish(mut self) -> Result<Found> {
        let record = self.reader.finish().and_then(WhoisRecord::from_object);
        self.take(record);
        if !self.seen {
            return Err(Error::runtime("no records in the dump"));
        }
        Ok(self.found)
    }

    /// Returns the capacity held, in bytes, for the memory tests.
    #[cfg(test)]
    fn held(&self) -> usize {
        let record = std::mem::size_of::<WhoisRecord>() + 64;
        self.reader.held()
            + self.key.capacity()
            + self.found.hits.iter().map(Vec::capacity).sum::<usize>() * record
            + self.found.orgs.capacity() * record
    }
}

impl LineSink for WhoisStream<'_> {
    fn line(&mut self, line: &[u8]) -> Result<Control> {
        let record = self.reader.line(line).and_then(WhoisRecord::from_object);
        self.take(record);
        Ok(Control::Continue)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        cache::{container, mapped::MappedFile},
        fetch::{Validators, gzip::GzipLines, lines::LineSplitter, testing::gzip},
    };

    /// APNIC-like objects of every class, with a person and a role that
    /// must leave no trace.
    const DUMP: &str = "\
% APNIC-like dump, synthetic

inetnum:        192.0.2.0 - 192.0.2.255
netname:        EXAMPLE-NET # the net
descr:          Example network
country:        xd
org:            ORG-EX1-AP
admin-c:        EA1-AP
tech-c:         ET1-AP, EA1-AP
mnt-by:         MAINT-EXAMPLE
mnt-lower:      maint-example
mnt-routes:     MAINT-ROUTES
source:         APNIC

inetnum:        198.51.100.0-198.51.100.127
netname:        CLIENT-NET
mnt-by:         MAINT-OTHER
abuse-c:        AB1-AP
source:         APNIC

inet6num:       2001:db8::/32
netname:        EXAMPLE-V6
org:            org-ex1-ap
mnt-by:         MAINT-EXAMPLE

aut-num:        AS64496
as-name:        EXAMPLE-AS
country:        XD
org:            ORG-EX1-AP
mnt-by:         MAINT-EXAMPLE
admin-c:        EA1-AP

person:         John Doe
address:        1 Example Street
phone:          +1 555 0100
e-mail:         john@example.net
nic-hdl:        EA1-AP
mnt-by:         MAINT-EXAMPLE

role:           Example Abuse
e-mail:         abuse@example.net
nic-hdl:        IRT1-AP
admin-c:        EA1-AP

organisation:   ORG-EX1-AP
org-name:       Example Holding # not a comment for names
abuse-c:        IRT1-AP
admin-c:        EA1-AP
mnt-ref:        MAINT-EXAMPLE
mnt-by:         MAINT-EXAMPLE

inetnum:        not-a-range
mnt-by:         MAINT-EXAMPLE

aut-num:        AS64497
mnt-by:         MAINT-OTHER
org:            ORG-NONE-AP
";

    fn feed(sink: &mut dyn LineSink, text: &[u8]) {
        let mut splitter = LineSplitter::new();
        for chunk in text.chunks(11) {
            splitter.push(chunk, sink).unwrap();
        }
        splitter.finish(sink).unwrap();
    }

    fn sections_of(text: &str) -> Result<Vec<Section>> {
        let mut builder = WhoisBuilder::new();
        feed(&mut builder, text.as_bytes());
        builder.finish()
    }

    fn file_of_sections(sections: &[Section]) -> Vec<u8> {
        let mut bytes = Vec::new();
        container::write(&mut bytes, 0x20, &Validators::default(), "u", sections).unwrap();
        bytes
    }

    fn open(bytes: Vec<u8>) -> Result<WhoisIndex, Corrupt> {
        WhoisIndex::open(CacheFile::new(MappedFile::from_vec(bytes)).map_err(|_| Corrupt)?)
    }

    fn index_of(text: &str) -> WhoisIndex {
        open(file_of_sections(&sections_of(text).unwrap())).unwrap()
    }

    fn stream(text: &str, lookup: &Lookup) -> Result<Found> {
        let mut stream = WhoisStream::new(lookup);
        feed(&mut stream, text.as_bytes());
        stream.finish()
    }

    /// The four steps over one file, with the index or the stream.
    fn search(text: &str, request: &WhoisRequest, indexed: bool) -> WhoisAnswer {
        let index = indexed.then(|| index_of(text));
        let ask = |lookup: &Lookup| match &index {
            Some(index) => index.lookup(lookup).unwrap(),
            None => stream(text, lookup).unwrap(),
        };
        let step1 = ask(&org_lookup(request, true));
        let plan = record_lookup(request, &step1.hits);
        let found = ask(&plan.lookup);
        let orgs = match &index {
            Some(index) => index.organisations(&referenced_orgs(&found)).unwrap(),
            None => step1.orgs,
        };
        assemble(
            request,
            &plan,
            &found,
            &orgs,
            Rir::Apnic,
            RecordOrigin::ApnicDb,
        )
    }

    fn request() -> WhoisRequest {
        WhoisRequest {
            mnt: vec![
                "maint-EXAMPLE".into(),
                "MAINT-ROUTES".into(),
                "NOBODY".into(),
            ],
            contact: vec![
                (Some(Role::Abuse), "irt1-ap".into()),
                (None, "EA1-AP".into()),
                (Some(Role::Technical), "AB1-AP".into()),
            ],
            org: vec!["ORG-EX1-AP".into()],
            families: Families::BOTH,
            autnums: true,
        }
    }

    fn nets(found: &WhoisFound) -> Vec<&str> {
        found.networks.iter().map(|n| n.handle.as_str()).collect()
    }

    fn asns(found: &WhoisFound) -> Vec<Asn> {
        found.autnums.iter().map(|a| a.asn).collect()
    }

    #[test]
    fn records_of_objects() {
        let mut reader = reader();
        let mut records = Vec::new();
        for line in DUMP.lines() {
            if let Some(record) = reader
                .line(line.as_bytes())
                .and_then(WhoisRecord::from_object)
            {
                records.push(record);
            }
        }
        records.extend(reader.finish().and_then(WhoisRecord::from_object));
        let handles: Vec<&str> = records.iter().map(|r| r.handle.as_str()).collect();
        assert_eq!(
            handles,
            [
                "192.0.2.0 - 192.0.2.255",
                "198.51.100.0 - 198.51.100.127",
                "2001:db8::/32",
                "AS64496",
                "ORG-EX1-AP",
                "AS64497"
            ]
        );
        let net = &records[0];
        assert_eq!(net.name.as_deref(), Some("EXAMPLE-NET"));
        assert_eq!(
            net.country.map(|c| c.as_str().to_owned()).as_deref(),
            Some("XD")
        );
        // mnt-by ∪ mnt-lower ∪ mnt-routes, without repeats, ignoring case.
        assert_eq!(net.mnt, ["MAINT-EXAMPLE", "MAINT-ROUTES"]);
        assert_eq!(net.tech, ["ET1-AP", "EA1-AP"]);
        assert_eq!(net.org.as_deref(), Some("ORG-EX1-AP"));
        assert_eq!(
            records[4].name.as_deref(),
            Some("Example Holding # not a comment for names")
        );
        assert_eq!(records[4].key, WhoisKey::Handle);
        assert!(records[4].has(Attrs::KEY, "org-ex1-ap"));
        assert!(records[4].has(Attrs::contact(Some(Role::Abuse)), "IRT1-AP"));
        assert!(!records[4].has(Attrs::contact(Some(Role::Technical)), "IRT1-AP"));
        assert_eq!(records[3].key, WhoisKey::Asn(64496));
        // A prefix with host bits, ranges either way.
        assert_eq!(
            parse_range("192.0.2.77/24", Family::V4),
            Range::new(Family::V4, 0xc000_0200, 0xc000_02ff)
        );
        assert_eq!(parse_range("2001:db8::/129", Family::V6), None);
        assert_eq!(
            parse_range("2001:db8::1/128", Family::V6),
            Range::new(Family::V6, 0x2001_0db8 << 96 | 1, 0x2001_0db8 << 96 | 1)
        );
        assert_eq!(
            parse_range("192.0.2.1/32", Family::V4),
            Range::new(Family::V4, 0xc000_0201, 0xc000_0201)
        );
        assert_eq!(parse_range("192.0.2.9 - 192.0.2.1", Family::V4), None);
        assert_eq!(parse_range("2001:db8:: - 2001:db8::1", Family::V4), None);
    }

    #[test]
    fn nothing_personal_is_kept() {
        let sections = sections_of(DUMP).unwrap();
        let strings = &sections.iter().find(|s| s.tag == STRINGS).unwrap().data;
        let strings = String::from_utf8_lossy(strings);
        for secret in [
            "John",
            "Street",
            "555",
            "example.net",
            "Example Abuse",
            "Example network",
        ] {
            assert!(!strings.contains(secret), "{secret} kept in {strings}");
        }
        // Handles of persons stay: they are what the records name.
        assert!(strings.contains("EA1-AP"));
    }

    #[test]
    fn index_and_stream_agree() {
        let request = request();
        let indexed = search(DUMP, &request, true);
        let streamed = search(DUMP, &request, false);
        assert_eq!(indexed, streamed);
        let answer = indexed;
        // Maintainers: mnt-by, mnt-lower or mnt-routes, ignoring case.
        assert_eq!(
            nets(&answer.mnt[0]),
            ["192.0.2.0 - 192.0.2.255", "2001:db8::/32"]
        );
        assert_eq!(asns(&answer.mnt[0]), [64496]);
        assert_eq!(nets(&answer.mnt[1]), ["192.0.2.0 - 192.0.2.255"]);
        assert!(answer.mnt[2].is_empty());
        // The abuse contact of the holder finds what it holds.
        assert_eq!(
            nets(&answer.contact[0]),
            ["192.0.2.0 - 192.0.2.255", "2001:db8::/32"]
        );
        assert_eq!(asns(&answer.contact[0]), [64496]);
        // Any role: of the record or of its holder.
        assert_eq!(
            nets(&answer.contact[1]),
            ["192.0.2.0 - 192.0.2.255", "2001:db8::/32"]
        );
        // The role must be the one asked.
        assert!(answer.contact[2].is_empty());
        assert_eq!(asns(&answer.org[0]), [64496]);
        // Records come with their holder's name and contacts.
        let net = &answer.mnt[0].networks[0];
        assert_eq!(net.rir, Rir::Apnic);
        assert_eq!(net.origin, RecordOrigin::ApnicDb);
        assert_eq!(
            net.org,
            Some(OrgRef {
                handle: "ORG-EX1-AP".into(),
                name: Some("Example Holding # not a comment for names".into()),
            })
        );
        let roles: Vec<(&str, Vec<Role>)> = net
            .contacts
            .iter()
            .map(|c| (c.handle.as_str(), c.roles.clone()))
            .collect();
        assert_eq!(
            roles,
            [
                ("EA1-AP", vec![Role::Administrative, Role::Technical]),
                ("ET1-AP", vec![Role::Technical]),
                ("IRT1-AP", vec![Role::Abuse]),
            ]
        );
        assert!(
            net.contacts
                .iter()
                .all(|c| !c.emails_hidden && c.email.is_empty())
        );
        // The same record is shared between conditions.
        assert!(Arc::ptr_eq(net, &answer.contact[0].networks[0]));
        // A holder that is not in the dump keeps its handle only.
        let other = WhoisRequest {
            mnt: vec!["MAINT-OTHER".into()],
            families: Families::V4,
            autnums: true,
            ..WhoisRequest::default()
        };
        let answer = search(DUMP, &other, true);
        assert_eq!(nets(&answer.mnt[0]), ["198.51.100.0 - 198.51.100.127"]);
        let org = answer.mnt[0].autnums[0].org.clone().unwrap();
        assert_eq!((org.handle.as_str(), org.name), ("ORG-NONE-AP", None));
        assert_eq!(answer, search(DUMP, &other, false));
    }

    #[test]
    fn an_empty_dump_is_an_error() {
        let html = "<html>\n<body>moved: elsewhere</body>\n";
        let message = sections_of(html).unwrap_err().to_string();
        assert!(message.ends_with("no records in the dump"), "{message}");
        let lookup = Lookup::default();
        let message = stream(html, &lookup).unwrap_err().to_string();
        assert!(message.ends_with("no records in the dump"), "{message}");
        // Only persons: nothing netf keeps.
        assert!(sections_of("person: X\nnic-hdl: X1\n").is_err());
    }

    #[test]
    fn answers_merge_across_registries() {
        let request = WhoisRequest {
            mnt: vec!["MAINT-EXAMPLE".into()],
            families: Families::V4,
            autnums: true,
            ..WhoisRequest::default()
        };
        let apnic = search(DUMP, &request, true);
        let plan = record_lookup(&request, &[]);
        let found = stream(&DUMP.replace("APNIC", "AFRINIC"), &plan.lookup).unwrap();
        let afrinic = assemble(
            &request,
            &plan,
            &found,
            &[],
            Rir::Afrinic,
            RecordOrigin::AfrinicDb,
        );
        let merged = WhoisAnswer::merge([afrinic, apnic.clone()]);
        let rirs: Vec<Rir> = merged.mnt[0].networks.iter().map(|n| n.rir).collect();
        // In the order of Rir::ALL.
        assert_eq!(rirs, [Rir::Afrinic, Rir::Apnic]);
        assert_eq!(merged.mnt[0].autnums.len(), 2);
        assert_eq!(WhoisAnswer::merge([apnic.clone()]), apnic);
        assert_eq!(WhoisAnswer::empty(&request).mnt, [WhoisFound::default()]);
    }

    #[test]
    fn damaged_indexes_are_corrupt_not_panics() {
        let sections = sections_of(DUMP).unwrap();
        let request = request();
        let lookups = [
            org_lookup(&request, false),
            record_lookup(&request, &[]).lookup,
        ];
        // Every byte of every section, flipped one at a time: an answer or
        // Corrupt, never a panic.
        for s in 0..sections.len() {
            for at in 0..sections[s].data.len() {
                let mut damaged = sections.clone();
                damaged[s].data[at] ^= 0xa5;
                if let Ok(index) = open(file_of_sections(&damaged)) {
                    for lookup in &lookups {
                        let _ = index.lookup(lookup);
                    }
                    let _ = index.organisations(&["ORG-EX1-AP".into()]);
                }
            }
        }
        // A missing section or a cut table is Corrupt at open.
        let missing: Vec<Section> = sections
            .iter()
            .filter(|s| s.tag != HANDLES)
            .cloned()
            .collect();
        assert_eq!(open(file_of_sections(&missing)).unwrap_err(), Corrupt);
        let mut cut = sections.clone();
        cut[0].data.pop();
        assert_eq!(open(file_of_sections(&cut)).unwrap_err(), Corrupt);
        // A record pointing past the attributes is Corrupt on use.
        let mut bad = sections;
        bad[0].data[36..40].copy_from_slice(&u32::MAX.to_le_bytes());
        let index = open(file_of_sections(&bad)).unwrap();
        assert_eq!(index.lookup(&lookups[1]).unwrap_err(), Corrupt);
    }

    /// The probe between the decompressor and the stream: it passes the
    /// lines on and keeps the most memory the stream held after any line.
    struct Probe<'a> {
        stream: WhoisStream<'a>,
        peak: usize,
        bytes: usize,
        lines: usize,
    }

    impl LineSink for Probe<'_> {
        fn line(&mut self, line: &[u8]) -> Result<Control> {
            self.bytes += line.len() + 1;
            self.lines += 1;
            let control = self.stream.line(line)?;
            self.peak = self.peak.max(self.stream.held());
            Ok(control)
        }
    }

    #[test]
    fn a_streamed_dump_is_never_held_whole() {
        // The dump above × 1000, every copy with its own addresses, AS and
        // handles, gzipped and read as a download is: the memory of the
        // pass is that of one object and of what was found.
        let mut text = String::new();
        for i in 0..1000u32 {
            let copy = DUMP
                .replace(
                    "192.0.2.0 - 192.0.2.255",
                    &format!(
                        "10.{}.{}.0 - 10.{}.{}.255",
                        i / 256,
                        i % 256,
                        i / 256,
                        i % 256
                    ),
                )
                .replace("2001:db8::/32", &format!("2001:db8:{i:x}::/48"))
                .replace("AS64496", &format!("AS{}", 4_200_000_000_u32 + i))
                .replace("EA1-AP", &format!("EA{i}-AP"))
                .replace("ORG-EX1-AP", &format!("ORG-EX{i}-AP"))
                .replace("org-ex1-ap", &format!("org-ex{i}-ap"));
            text.push_str(&copy);
            text.push('\n');
        }
        let request = WhoisRequest {
            contact: vec![(None, "EA7-AP".into())],
            families: Families::BOTH,
            autnums: true,
            ..WhoisRequest::default()
        };
        let plan = record_lookup(&request, &[]);
        let mut probe = Probe {
            stream: WhoisStream::new(&plan.lookup),
            peak: 0,
            bytes: 0,
            lines: 0,
        };
        let mut gz = GzipLines::new();
        for chunk in gzip(text.as_bytes()).chunks(4096) {
            gz.push(chunk, &mut probe).unwrap();
        }
        gz.finish(&mut probe).unwrap();
        let (peak, bytes, lines) = (probe.peak, probe.bytes, probe.lines);
        let found = probe.stream.finish().unwrap();
        // The network and the AS of copy 7 name the contact themselves.
        assert_eq!(found.hits[0].len(), 2);
        assert!(
            lines > 50_000 && bytes > 1_000_000,
            "{lines} lines, {bytes} bytes"
        );
        // One object and the two records, whatever the size of the input.
        assert!(
            peak < 16 << 10,
            "peak {peak} bytes for {bytes} bytes of input"
        );
        // Without hits the pass holds one object and nothing else.
        let lookup = Lookup {
            classes: Classes::of(ObjectClass::ALL),
            queries: vec![Query {
                attrs: Attrs::MNT,
                handle: "NOBODY".into(),
            }],
            orgs: false,
        };
        let mut probe = Probe {
            stream: WhoisStream::new(&lookup),
            peak: 0,
            bytes: 0,
            lines: 0,
        };
        feed(&mut probe, text.as_bytes());
        assert!(probe.peak < 4 << 10, "peak {} bytes", probe.peak);
    }
}
