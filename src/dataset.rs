//! Datasets: the large files that netf downloads and indexes.
//!
//! A dataset has a source, a line parser, and two backends. The index
//! backend lives in the cache and is built once per download. The stream
//! backend answers a batch of requests in one pass over the file, for
//! `--no-cache`. Both backends answer the same typed batch
//! requests, so the engine does not know which one it uses.
//!
//! Each URL is a separate dataset with its own cache file, so netf downloads
//! again only the files that changed. The four APNIC dumps are therefore four
//! datasets. [`SOURCES`] lists every dataset with its default URL, and the
//! `[sources]` table of the config can replace the URLs through [`Urls`].
//! The `sources` module loads datasets on demand. Tests set the hidden
//! variable `NETF_SOURCE_BASE` to redirect the source URLs to a stub server.
//!
//! The module also holds what the datasets share. [`AsnSet`] is the set of
//! AS numbers that a batch asks for. [`RangeQuery`] answers two questions
//! about a record in `O(log n)`: is it inside one of the ranges, and does it
//! touch one of them. The stream backends need this speed because they check
//! every record of a file against every condition of the request at once.

pub(crate) mod asn;
pub(crate) mod ris;
pub(crate) mod rpsl;
pub(crate) mod stats;
pub(crate) mod whoisdb;

use crate::{
    addr::{Family, Range},
    model::{Asn, Rir},
};

/// The kind of a dataset.
///
/// [`Kind::code`] goes in the header of the cache file of the dataset.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub(crate) enum Kind {
    /// The RIS dump of IPv4 routes.
    RisV4,
    /// The RIS dump of IPv6 routes.
    RisV6,
    /// `asn.txt`, the names of AS numbers.
    Asn,
    /// The delegated stats of a registry.
    Stats(Rir),
    /// `apnic.db.inetnum`.
    ApnicInetnum,
    /// `apnic.db.inet6num`.
    ApnicInet6num,
    /// `apnic.db.aut-num`.
    ApnicAutNum,
    /// `apnic.db.organisation`.
    ApnicOrganisation,
    /// `afrinic.db`.
    AfrinicDb,
    /// The IANA RDAP bootstrap for AS numbers.
    BootstrapAsn,
    /// The IANA RDAP bootstrap for IPv4.
    BootstrapIpv4,
    /// The IANA RDAP bootstrap for IPv6.
    BootstrapIpv6,
}

impl Kind {
    /// Returns the code written in the header of the cache file.
    ///
    /// Codes are part of the file format and never change meaning. A file
    /// whose code does not match its name is corrupt. Codes from `0x100` up
    /// belong to the cache itself: cached responses and the RIPE counter.
    pub(crate) fn code(self) -> u16 {
        match self {
            Self::RisV4 => 0x01,
            Self::RisV6 => 0x02,
            Self::Asn => 0x03,
            Self::Stats(rir) => 0x10 + Rir::ALL.iter().position(|r| *r == rir).unwrap_or(0) as u16,
            Self::ApnicInetnum => 0x20,
            Self::ApnicInet6num => 0x21,
            Self::ApnicAutNum => 0x22,
            Self::ApnicOrganisation => 0x23,
            Self::AfrinicDb => 0x24,
            Self::BootstrapAsn => 0x30,
            Self::BootstrapIpv4 => 0x31,
            Self::BootstrapIpv6 => 0x32,
        }
    }

    /// Returns the RIS dump of `family`.
    pub(crate) fn ris(family: Family) -> Self {
        match family {
            Family::V4 => Self::RisV4,
            Family::V6 => Self::RisV6,
        }
    }

    /// Returns the source of this dataset.
    pub(crate) fn source(self) -> &'static Source {
        SOURCES
            .iter()
            .find(|source| source.kind == self)
            .expect("every kind has a source")
    }
}

/// Where a dataset comes from and what its cache file is called.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct Source {
    /// The kind of the dataset.
    pub(crate) kind: Kind,
    /// The default URL.
    pub(crate) url: &'static str,
    /// The name of the cache file without `.bin`.
    ///
    /// Messages and the `[sources]` table of the config use the same name.
    pub(crate) file: &'static str,
}

/// Every dataset, with its default URL.
pub(crate) const SOURCES: [Source; 16] = [
    source(
        Kind::RisV4,
        "https://www.ris.ripe.net/dumps/riswhoisdump.IPv4.gz",
        "ris-v4",
    ),
    source(
        Kind::RisV6,
        "https://www.ris.ripe.net/dumps/riswhoisdump.IPv6.gz",
        "ris-v6",
    ),
    source(
        Kind::Asn,
        "https://ftp.ripe.net/ripe/asnames/asn.txt",
        "asn",
    ),
    source(
        Kind::Stats(Rir::Ripencc),
        "https://ftp.ripe.net/pub/stats/ripencc/delegated-ripencc-extended-latest",
        "stats-ripencc",
    ),
    source(
        Kind::Stats(Rir::Arin),
        "https://ftp.arin.net/pub/stats/arin/delegated-arin-extended-latest",
        "stats-arin",
    ),
    source(
        Kind::Stats(Rir::Apnic),
        "https://ftp.apnic.net/stats/apnic/delegated-apnic-extended-latest",
        "stats-apnic",
    ),
    source(
        Kind::Stats(Rir::Lacnic),
        "https://ftp.lacnic.net/pub/stats/lacnic/delegated-lacnic-extended-latest",
        "stats-lacnic",
    ),
    source(
        Kind::Stats(Rir::Afrinic),
        "https://ftp.afrinic.net/stats/afrinic/delegated-afrinic-extended-latest",
        "stats-afrinic",
    ),
    source(
        Kind::ApnicInetnum,
        "https://ftp.apnic.net/apnic/whois/apnic.db.inetnum.gz",
        "whois-apnic-inetnum",
    ),
    source(
        Kind::ApnicInet6num,
        "https://ftp.apnic.net/apnic/whois/apnic.db.inet6num.gz",
        "whois-apnic-inet6num",
    ),
    source(
        Kind::ApnicAutNum,
        "https://ftp.apnic.net/apnic/whois/apnic.db.aut-num.gz",
        "whois-apnic-aut-num",
    ),
    source(
        Kind::ApnicOrganisation,
        "https://ftp.apnic.net/apnic/whois/apnic.db.organisation.gz",
        "whois-apnic-organisation",
    ),
    source(
        Kind::AfrinicDb,
        "https://ftp.afrinic.net/dbase/afrinic.db.gz",
        "whois-afrinic-db",
    ),
    source(
        Kind::BootstrapAsn,
        "https://data.iana.org/rdap/asn.json",
        "bootstrap-asn",
    ),
    source(
        Kind::BootstrapIpv4,
        "https://data.iana.org/rdap/ipv4.json",
        "bootstrap-ipv4",
    ),
    source(
        Kind::BootstrapIpv6,
        "https://data.iana.org/rdap/ipv6.json",
        "bootstrap-ipv6",
    ),
];

/// The default base URL of the RIPE database REST API.
///
/// Requests go to `<base>/search.json?…`. The API is not a dataset, but
/// [`Urls`] replaces its URL the same way.
pub(crate) const RIPE_REST_BASE: &str = "https://rest.db.ripe.net";

const fn source(kind: Kind, url: &'static str, file: &'static str) -> Source {
    Source { kind, url, file }
}

/// The name of the RIPE REST API in the `[sources]` table of the config.
pub(crate) const RIPE_REST_NAME: &str = "ripe-rest";

/// The URLs of the sources for one run.
///
/// The defaults come from [`SOURCES`] and [`RIPE_REST_BASE`]. The
/// `[sources]` table of the config replaces them by the name of the dataset.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct Urls {
    /// The URLs of the datasets, in the order of [`SOURCES`].
    datasets: [String; SOURCES.len()],
    ripe_rest: String,
}

impl Default for Urls {
    fn default() -> Self {
        Self {
            datasets: SOURCES.map(|source| source.url.to_owned()),
            ripe_rest: RIPE_REST_BASE.to_owned(),
        }
    }
}

impl Urls {
    /// Returns the URL of the dataset `kind`.
    pub(crate) fn of(&self, kind: Kind) -> &str {
        let at = SOURCES.iter().position(|source| source.kind == kind);
        &self.datasets[at.expect("every kind has a source")]
    }

    /// Returns the base URL of the RIPE REST API.
    pub(crate) fn ripe_rest(&self) -> &str {
        &self.ripe_rest
    }

    /// Replaces the URL of the source `name`.
    ///
    /// `name` is the file name of a dataset, such as `ris-v4`, or
    /// [`RIPE_REST_NAME`]. Returns `false` if the name is unknown.
    pub(crate) fn set(&mut self, name: &str, url: String) -> bool {
        if name == RIPE_REST_NAME {
            self.ripe_rest = url;
            return true;
        }
        match SOURCES.iter().position(|source| source.file == name) {
            Some(at) => {
                self.datasets[at] = url;
                true
            }
            None => false,
        }
    }

    /// Returns the names that [`Urls::set`] accepts, for messages.
    pub(crate) fn names() -> impl Iterator<Item = &'static str> {
        SOURCES
            .iter()
            .map(|source| source.file)
            .chain([RIPE_REST_NAME])
    }
}

/// A set of AS numbers, stored as sorted and merged inclusive ranges.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub(crate) struct AsnSet {
    ranges: Vec<(Asn, Asn)>,
}

impl AsnSet {
    /// Creates an empty set.
    pub(crate) fn new() -> Self {
        Self::default()
    }

    /// Creates the set of every AS number.
    #[cfg(test)]
    pub(crate) fn all() -> Self {
        Self {
            ranges: vec![(0, Asn::MAX)],
        }
    }

    /// Creates the set of the numbers in `ranges`.
    ///
    /// The ranges may come in any order and may overlap. A range whose start
    /// is above its end adds nothing.
    pub(crate) fn from_ranges(ranges: impl IntoIterator<Item = (Asn, Asn)>) -> Self {
        let mut ranges: Vec<(Asn, Asn)> = ranges.into_iter().filter(|(a, b)| a <= b).collect();
        ranges.sort_unstable();
        let mut merged: Vec<(Asn, Asn)> = Vec::with_capacity(ranges.len());
        for (lo, hi) in ranges {
            match merged.last_mut() {
                Some(last) if lo <= last.1.saturating_add(1) => last.1 = last.1.max(hi),
                _ => merged.push((lo, hi)),
            }
        }
        Self { ranges: merged }
    }

    /// Adds `asn` to the set.
    pub(crate) fn insert(&mut self, asn: Asn) {
        if !self.contains(asn) {
            let mut ranges = std::mem::take(&mut self.ranges);
            ranges.push((asn, asn));
            *self = Self::from_ranges(ranges);
        }
    }

    /// Returns `true` if `asn` is in the set.
    pub(crate) fn contains(&self, asn: Asn) -> bool {
        let i = self.ranges.partition_point(|(lo, _)| *lo <= asn);
        i > 0 && self.ranges[i - 1].1 >= asn
    }

    /// Returns `true` if the set is empty.
    pub(crate) fn is_empty(&self) -> bool {
        self.ranges.is_empty()
    }

    /// Returns the ranges: sorted, disjoint, and not adjacent.
    pub(crate) fn ranges(&self) -> &[(Asn, Asn)] {
        &self.ranges
    }
}

/// Address ranges of one family, prepared to answer two questions about a
/// record in `O(log n)`: is it inside one of the ranges, and does it touch
/// one of them.
///
/// The ranges are sorted by first address. For each position in that order,
/// `max_last` holds the largest last address of the ranges up to that
/// position. A record `[a, b]` is inside some range if and only if this
/// maximum over the ranges that start at or before `a` is at least `b`. The
/// record touches some range if and only if the maximum over the ranges that
/// start at or before `b` is at least `a`.
#[derive(Clone, Debug, Default)]
pub(crate) struct RangeQuery {
    firsts: Vec<u128>,
    max_last: Vec<u128>,
}

impl RangeQuery {
    /// Builds the `RangeQuery` from the ranges of `family` in `ranges`.
    ///
    /// It ignores ranges of the other family.
    pub(crate) fn new(family: Family, ranges: &[Range]) -> Self {
        let mut sorted: Vec<(u128, u128)> = ranges
            .iter()
            .filter(|range| range.family() == family)
            .map(|range| (range.first(), range.last()))
            .collect();
        sorted.sort_unstable();
        let mut max = 0;
        let max_last = sorted
            .iter()
            .map(|(_, last)| {
                max = max.max(*last);
                max
            })
            .collect();
        Self {
            firsts: sorted.into_iter().map(|(first, _)| first).collect(),
            max_last,
        }
    }

    /// Returns `true` if `[first, last]` lies inside one of the ranges.
    pub(crate) fn contains(&self, first: u128, last: u128) -> bool {
        self.max_last_from(first).is_some_and(|max| max >= last)
    }

    /// Returns `true` if `[first, last]` shares an address with one of the
    /// ranges.
    pub(crate) fn intersects(&self, first: u128, last: u128) -> bool {
        self.max_last_from(last).is_some_and(|max| max >= first)
    }

    /// Returns the largest last address of the ranges that start at or before
    /// `at`, or `None` if there are no such ranges.
    fn max_last_from(&self, at: u128) -> Option<u128> {
        let i = self.firsts.partition_point(|first| *first <= at);
        i.checked_sub(1).map(|i| self.max_last[i])
    }
}

/// A deterministic random number generator for the property tests of the
/// datasets.
#[cfg(test)]
pub(crate) struct Rng(u64);

#[cfg(test)]
impl Rng {
    pub(crate) fn new(seed: u64) -> Self {
        Self(seed.wrapping_mul(0x9e37_79b9_7f4a_7c15) | 1)
    }

    pub(crate) fn next(&mut self) -> u64 {
        // xorshift64*
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_f491_4f6c_dd1d)
    }

    /// Returns a number in `0..n`, or 0 if `n` is 0.
    pub(crate) fn below(&mut self, n: u64) -> u64 {
        self.next() % n.max(1)
    }
}

/// The source URLs for tests: synthetic hosts with the paths of the default
/// URLs.
#[cfg(test)]
pub(crate) const TEST_URLS: [(&str, &str); SOURCES.len() + 1] = [
    ("ris-v4", "https://ris.ripe.test/dumps/riswhoisdump.IPv4.gz"),
    ("ris-v6", "https://ris.ripe.test/dumps/riswhoisdump.IPv6.gz"),
    ("asn", "https://ftp.ripe.test/ripe/asnames/asn.txt"),
    (
        "stats-ripencc",
        "https://ftp.ripe.test/pub/stats/ripencc/delegated-ripencc-extended-latest",
    ),
    (
        "stats-arin",
        "https://ftp.arin.test/pub/stats/arin/delegated-arin-extended-latest",
    ),
    (
        "stats-apnic",
        "https://ftp.apnic.test/stats/apnic/delegated-apnic-extended-latest",
    ),
    (
        "stats-lacnic",
        "https://ftp.lacnic.test/pub/stats/lacnic/delegated-lacnic-extended-latest",
    ),
    (
        "stats-afrinic",
        "https://ftp.afrinic.test/stats/afrinic/delegated-afrinic-extended-latest",
    ),
    (
        "whois-apnic-inetnum",
        "https://ftp.apnic.test/apnic/whois/apnic.db.inetnum.gz",
    ),
    (
        "whois-apnic-inet6num",
        "https://ftp.apnic.test/apnic/whois/apnic.db.inet6num.gz",
    ),
    (
        "whois-apnic-aut-num",
        "https://ftp.apnic.test/apnic/whois/apnic.db.aut-num.gz",
    ),
    (
        "whois-apnic-organisation",
        "https://ftp.apnic.test/apnic/whois/apnic.db.organisation.gz",
    ),
    (
        "whois-afrinic-db",
        "https://ftp.afrinic.test/dbase/afrinic.db.gz",
    ),
    ("bootstrap-asn", "https://data.iana.test/rdap/asn.json"),
    ("bootstrap-ipv4", "https://data.iana.test/rdap/ipv4.json"),
    ("bootstrap-ipv6", "https://data.iana.test/rdap/ipv6.json"),
    ("ripe-rest", "https://rest.ripe.test"),
];

#[cfg(test)]
impl Urls {
    /// Returns the URLs of [`TEST_URLS`].
    pub(crate) fn test() -> Self {
        let mut urls = Self::default();
        for (name, url) in TEST_URLS {
            assert!(urls.set(name, url.to_owned()), "{name}");
        }
        urls
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kinds_have_distinct_codes_and_sources() {
        let mut codes: Vec<u16> = SOURCES.iter().map(|s| s.kind.code()).collect();
        codes.sort_unstable();
        codes.dedup();
        assert_eq!(codes.len(), SOURCES.len());
        let mut files: Vec<&str> = SOURCES.iter().map(|s| s.file).collect();
        files.sort_unstable();
        files.dedup();
        assert_eq!(files.len(), SOURCES.len());
        assert_eq!(Kind::Stats(Rir::Ripencc).source().file, "stats-ripencc");
        assert!(codes.iter().all(|code| *code < 0x100));
        assert!(Kind::ris(Family::V6).source().url.ends_with("IPv6.gz"));
    }

    #[test]
    fn urls_are_replaced_by_name() {
        let defaults = Urls::default();
        assert_eq!(defaults.of(Kind::Asn), Kind::Asn.source().url);
        assert_eq!(defaults.ripe_rest(), RIPE_REST_BASE);
        let urls = Urls::test();
        assert_eq!(urls.of(Kind::RisV6), TEST_URLS[1].1);
        assert_eq!(urls.ripe_rest(), "https://rest.ripe.test");
        // Every source has a test URL, and every test URL differs from the
        // default.
        assert_eq!(Urls::names().count(), TEST_URLS.len());
        for source in &SOURCES {
            assert_ne!(urls.of(source.kind), defaults.of(source.kind));
        }
        let mut urls = urls;
        assert!(!urls.set("ris", "https://x.test/".to_owned()));
        assert_eq!(urls, Urls::test());
    }

    #[test]
    fn asn_sets() {
        let set = AsnSet::from_ranges([(64500, 64500), (64496, 64499), (64511, 64511)]);
        assert_eq!(set.ranges(), [(64496, 64500), (64511, 64511)]);
        assert!(set.contains(64496) && set.contains(64500) && set.contains(64511));
        assert!(!set.contains(64501) && !set.contains(0) && !set.contains(Asn::MAX));
        let mut set = set;
        set.insert(64501);
        assert_eq!(set.ranges(), [(64496, 64501), (64511, 64511)]);
        assert!(AsnSet::all().contains(Asn::MAX));
        assert!(AsnSet::new().is_empty());
    }

    #[test]
    fn range_queries_match_a_linear_scan() {
        let mut rng = Rng::new(7);
        for _ in 0..200 {
            let ranges: Vec<Range> = (0..rng.below(6))
                .map(|_| {
                    let a = rng.below(64) as u128;
                    let b = a + rng.below(16) as u128;
                    Range::new(Family::V4, a, b).unwrap()
                })
                .collect();
            let query = RangeQuery::new(Family::V4, &ranges);
            for _ in 0..20 {
                let a = rng.below(80) as u128;
                let b = a + rng.below(8) as u128;
                let inside = ranges.iter().any(|r| r.first() <= a && b <= r.last());
                let touches = ranges.iter().any(|r| r.first() <= b && a <= r.last());
                assert_eq!(query.contains(a, b), inside, "{ranges:?} {a}-{b}");
                assert_eq!(query.intersects(a, b), touches, "{ranges:?} {a}-{b}");
            }
        }
    }
}
