//! Parses and indexes the RIPE RIS dumps `riswhoisdump.IPv4` and
//! `riswhoisdump.IPv6`.
//!
//! Each line of a dump holds a prefix and its origin AS. The parser skips
//! `%` comments, reads an AS set `{…}` as several origins, and merges the
//! lines of one prefix into one route.
//!
//! # The format
//!
//! ```text
//! % comments and an empty line or two
//! 64496   192.0.2.0/24    312
//! {64497,64498}   198.51.100.0/24 4
//! ```
//!
//! The columns are the origin, the prefix, and the number of peers that see
//! the prefix. The dump separates the columns with tabs, and the parser
//! also accepts spaces, as in the example. A prefix that several AS
//! announce has one line per origin. Every member of an AS set is an origin.
//!
//! The parser is lenient with lines and strict with the whole body. It skips
//! a line that is not a route of the dump's family, but a body without a
//! single route is an error. A proxy can return an HTML page with status
//! 200, and the cache must not keep that page as an empty dump until the TTL
//! ends.
//!
//! # The index
//!
//! The index has three sections. All numbers are little-endian.
//!
//! | tag | section | record |
//! |---|---|---|
//! | 1 | `routes` | v4, 16 bytes: `first u32, len u8, pad, origins_n u16, origins_off u32, parent u32`. v6, 32 bytes: `first u128`, then the same, padded |
//! | 2 | `origins` | `u32` AS numbers, the lists of the routes |
//! | 3 | `by_asn` | `(asn u32, route u32)`, sorted |
//!
//! Routes are sorted by `(first, len)`, so a network comes before the
//! networks inside it. `parent` is the most specific route that contains
//! the route, or `u32::MAX` if no route does. Two CIDR blocks are either
//! nested or disjoint, so every route that covers an address is an ancestor
//! of the last route that starts at or before the address. One binary
//! search and at most 128 steps up the parents find the most specific
//! covering route.
//!
//! Every read checks bounds and checks that the record makes sense: the
//! length fits the family, the prefix has no host bits, the origins lie
//! inside their section, and the parent comes before its child. A violation
//! returns [`Corrupt`], and the caller rebuilds the file.
//!
//! # Without the cache
//!
//! [`RisStream`] answers a [`RouteRequest`] in one pass over the download.
//! It checks every merged route against every condition at once: a hash set
//! for exact prefixes, [`RangeQuery`] for ranges, and a binary search over
//! the sorted covering ranges. It always reads the dump to the end. Nothing
//! guarantees the order of the lines in a dump, so an early stop could lose
//! routes without an error.

use std::collections::{HashMap, HashSet};

use crate::{
    addr::{Addr, Family, Prefix, Range},
    cache::{
        Builder, CacheFile,
        container::{Corrupt, Section, u16_at, u32_at, u128_at},
    },
    dataset::{AsnSet, RangeQuery},
    error::{Error, Result},
    fetch::lines::{Control, LineSink},
    model::{Asn, Route},
};

/// The tag of the `routes` section.
const ROUTES: u16 = 1;
/// The tag of the `origins` section.
const ORIGINS: u16 = 2;
/// The tag of the `by_asn` section.
const BY_ASN: u16 = 3;

/// The `parent` of a route that has no parent.
const NO_PARENT: u32 = u32::MAX;

/// The size of a `by_asn` record.
const BY_ASN_SIZE: usize = 8;

/// Returns the size of a `routes` record of `family`.
fn record_size(family: Family) -> usize {
    match family {
        Family::V4 => 16,
        Family::V6 => 32,
    }
}

/// Returns the width of `first` in a `routes` record.
fn word(family: Family) -> usize {
    match family {
        Family::V4 => 4,
        Family::V6 => 16,
    }
}

/// Returns the last address of the prefix `first/len`.
fn last_of(family: Family, first: u128, len: u8) -> u128 {
    let host = u32::from(family.bits() - len);
    first
        | (if host == 128 {
            u128::MAX
        } else {
            (1u128 << host) - 1
        })
}

/// A batch of conditions on the routes of one dump, answered in one pass.
///
/// Conditions of the other family are ignored.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub(crate) struct RouteRequest {
    /// Routes with one of these origins.
    pub(crate) by_asn: AsnSet,
    /// Routes of exactly these prefixes.
    pub(crate) exact: Vec<Prefix>,
    /// For each range, the most specific route that contains the whole
    /// range.
    ///
    /// [`RouteAnswer::covering`] holds the answers in the same order.
    pub(crate) covering: Vec<Range>,
    /// Routes inside one of these ranges.
    pub(crate) within: Vec<Range>,
    /// Routes that share an address with one of these ranges.
    pub(crate) intersecting: Vec<Range>,
    /// Every route.
    pub(crate) all: bool,
}

/// The answer to a [`RouteRequest`].
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub(crate) struct RouteAnswer {
    /// The routes that meet `by_asn`, `exact`, `within`, `intersecting`, or
    /// `all`, sorted by prefix and without duplicates.
    pub(crate) routes: Vec<Route>,
    /// For each `covering` range, its most specific route.
    ///
    /// The entry is `None` if no route covers the range or if the range is
    /// of the other family.
    pub(crate) covering: Vec<Option<Route>>,
}

/// One line of the dump.
#[derive(Debug, Eq, PartialEq)]
enum Line {
    /// A route.
    ///
    /// Its origins are in the caller's buffer.
    Route(Prefix),
    /// A comment, an empty line, or a route of the other family.
    Skip,
    /// Not a route line.
    Malformed,
}

/// Parses one line and puts its origins in `origins`, without duplicates.
fn parse_line(line: &[u8], family: Family, origins: &mut Vec<Asn>) -> Line {
    if line.is_empty() || line[0] == b'%' {
        return Line::Skip;
    }
    let mut fields = line
        .split(|b| *b == b'\t' || *b == b' ')
        .filter(|field| !field.is_empty());
    let (Some(origin), Some(prefix)) = (fields.next(), fields.next()) else {
        return if line.iter().all(u8::is_ascii_whitespace) {
            Line::Skip
        } else {
            Line::Malformed
        };
    };
    origins.clear();
    let members = match origin.strip_prefix(b"{") {
        Some(set) => match set.strip_suffix(b"}") {
            Some(set) => set,
            None => return Line::Malformed,
        },
        None => origin,
    };
    for member in members.split(|b| *b == b',') {
        let Some(asn) = parse_asn(member) else {
            return Line::Malformed;
        };
        if !origins.contains(&asn) {
            origins.push(asn);
        }
    }
    let Some(prefix) = std::str::from_utf8(prefix)
        .ok()
        .and_then(|text| text.parse::<Prefix>().ok())
    else {
        return Line::Malformed;
    };
    if prefix.family() != family {
        return Line::Skip;
    }
    Line::Route(prefix)
}

/// Parses a plain decimal AS number.
pub(crate) fn parse_asn(text: &[u8]) -> Option<Asn> {
    let text = text.trim_ascii();
    if text.is_empty() || text.len() > 10 || !text.iter().all(u8::is_ascii_digit) {
        return None;
    }
    std::str::from_utf8(text).ok()?.parse().ok()
}

/// Returns the error for a download without a single route.
fn no_routes() -> Error {
    Error::runtime("no routes in the dump")
}

/// The address type of the builder's entries: `u32` for IPv4 and `u128` for
/// IPv6. With `u32`, an IPv4 entry takes 12 bytes rather than 32.
trait Word: Copy + Ord + Send + 'static {
    fn from_bits(bits: u128) -> Self;
    fn bits(self) -> u128;
}

impl Word for u32 {
    fn from_bits(bits: u128) -> Self {
        bits as u32
    }

    fn bits(self) -> u128 {
        self.into()
    }
}

impl Word for u128 {
    fn from_bits(bits: u128) -> Self {
        bits
    }

    fn bits(self) -> u128 {
        self
    }
}

/// A route as parsed, before sorting.
///
/// Its origins are a slice of a shared buffer.
#[derive(Clone, Copy, Debug)]
struct Entry<W> {
    first: W,
    off: u32,
    n: u16,
    len: u8,
}

/// Builds the index of a dump from its lines.
pub(crate) struct RisBuilder {
    inner: Inner,
}

enum Inner {
    V4(Build<u32>),
    V6(Build<u128>),
}

impl RisBuilder {
    /// Creates a builder for the dump of `family`.
    pub(crate) fn new(family: Family) -> Self {
        let inner = match family {
            Family::V4 => Inner::V4(Build::new(family)),
            Family::V6 => Inner::V6(Build::new(family)),
        };
        Self { inner }
    }
}

impl LineSink for RisBuilder {
    fn line(&mut self, line: &[u8]) -> Result<Control> {
        match &mut self.inner {
            Inner::V4(build) => build.line(line),
            Inner::V6(build) => build.line(line),
        }
        Ok(Control::Continue)
    }
}

impl Builder for RisBuilder {
    fn finish(self) -> Result<Vec<Section>> {
        match self.inner {
            Inner::V4(build) => build.finish(),
            Inner::V6(build) => build.finish(),
        }
    }
}

struct Build<W> {
    family: Family,
    entries: Vec<Entry<W>>,
    origins: Vec<Asn>,
    line: Vec<Asn>,
}

impl<W: Word> Build<W> {
    fn new(family: Family) -> Self {
        Self {
            family,
            entries: Vec::new(),
            origins: Vec::new(),
            line: Vec::new(),
        }
    }

    fn line(&mut self, line: &[u8]) {
        let Line::Route(prefix) = parse_line(line, self.family, &mut self.line) else {
            return;
        };
        let first = W::from_bits(prefix.first());
        let len = prefix.len();
        // The dump keeps the lines of one prefix together. The origins of
        // the last entry end the buffer, so new origins extend them in place.
        if let Some(last) = self.entries.last_mut()
            && last.first == first
            && last.len == len
        {
            for asn in &self.line {
                let own = &self.origins[last.off as usize..];
                if !own.contains(asn) && last.n < u16::MAX {
                    self.origins.push(*asn);
                    last.n += 1;
                }
            }
            return;
        }
        let Ok(off) = u32::try_from(self.origins.len()) else {
            return;
        };
        let n = self.line.len().min(usize::from(u16::MAX));
        self.origins.extend_from_slice(&self.line[..n]);
        self.entries.push(Entry {
            first,
            off,
            n: n as u16,
            len,
        });
    }

    fn finish(self) -> Result<Vec<Section>> {
        let Self {
            family,
            mut entries,
            origins,
            ..
        } = self;
        if entries.is_empty() {
            return Err(no_routes());
        }
        // `off` grows in the order of the dump. Sorting by `off` last keeps
        // the origins of a prefix in dump order without the extra buffer
        // that a stable sort needs.
        entries.sort_unstable_by_key(|e| (e.first, e.len, e.off));
        let size = record_size(family);
        let mut routes = Vec::with_capacity(entries.len() * size);
        let mut merged: Vec<u8> = Vec::with_capacity(origins.len() * 4);
        let mut merged_n: u32 = 0;
        // Routes that may contain the next one: index and last address.
        let mut stack: Vec<(u32, u128)> = Vec::new();
        let mut group: Vec<Asn> = Vec::new();
        let mut count: u32 = 0;
        let mut i = 0;
        while i < entries.len() {
            let head = entries[i];
            group.clear();
            while i < entries.len() && entries[i].first == head.first && entries[i].len == head.len
            {
                let e = entries[i];
                for asn in &origins[e.off as usize..e.off as usize + usize::from(e.n)] {
                    if !group.contains(asn) {
                        group.push(*asn);
                    }
                }
                i += 1;
            }
            group.truncate(usize::from(u16::MAX));
            let first = head.first.bits();
            let last = last_of(family, first, head.len);
            while stack.last().is_some_and(|(_, end)| *end < first) {
                stack.pop();
            }
            let parent = match stack.last() {
                Some((index, end)) if *end >= last => *index,
                _ => NO_PARENT,
            };
            match family {
                Family::V4 => routes.extend_from_slice(&(first as u32).to_le_bytes()),
                Family::V6 => routes.extend_from_slice(&first.to_le_bytes()),
            }
            routes.push(head.len);
            routes.push(0);
            routes.extend_from_slice(&(group.len() as u16).to_le_bytes());
            routes.extend_from_slice(&merged_n.to_le_bytes());
            routes.extend_from_slice(&parent.to_le_bytes());
            routes.resize(routes.len().next_multiple_of(size), 0);
            for asn in &group {
                merged.extend_from_slice(&asn.to_le_bytes());
            }
            merged_n += group.len() as u32;
            stack.push((count, last));
            count += 1;
        }
        drop(entries);
        drop(origins);
        let by_asn = by_asn(family, &routes, &merged);
        Ok(vec![
            Section::new(ROUTES, routes),
            Section::new(ORIGINS, merged),
            Section::new(BY_ASN, by_asn),
        ])
    }
}

/// Builds the `by_asn` section from the `routes` and `origins` sections.
fn by_asn(family: Family, routes: &[u8], origins: &[u8]) -> Vec<u8> {
    let size = record_size(family);
    let at = word(family);
    let mut pairs: Vec<u64> = Vec::with_capacity(origins.len() / 4);
    for (index, record) in routes.chunks_exact(size).enumerate() {
        let n = usize::from(u16_at(record, at + 2));
        let off = u32_at(record, at + 4) as usize;
        for k in off..off + n {
            let asn = u32_at(origins, k * 4);
            pairs.push(u64::from(asn) << 32 | index as u64);
        }
    }
    pairs.sort_unstable();
    let mut out = Vec::with_capacity(pairs.len() * BY_ASN_SIZE);
    for pair in pairs {
        out.extend_from_slice(&((pair >> 32) as u32).to_le_bytes());
        out.extend_from_slice(&(pair as u32).to_le_bytes());
    }
    out
}

/// A decoded `routes` record.
#[derive(Clone, Copy, Debug)]
struct Record {
    first: u128,
    last: u128,
    len: u8,
    n: u16,
    off: u32,
    parent: u32,
}

/// The index of a dump in a cache file.
#[derive(Debug)]
pub(crate) struct RisIndex {
    file: CacheFile,
    family: Family,
}

/// The sections of an index, borrowed for one answer.
struct View<'a> {
    family: Family,
    routes: &'a [u8],
    origins: &'a [u8],
    by_asn: &'a [u8],
}

impl RisIndex {
    /// Checks the sections of `file` and wraps the file in an index.
    ///
    /// # Errors
    ///
    /// Returns [`Corrupt`] if a section is missing, has a wrong size, or
    /// holds no routes.
    pub(crate) fn open(file: CacheFile, family: Family) -> Result<Self, Corrupt> {
        let index = Self { file, family };
        let view = index.view()?;
        if view.len() == 0 {
            return Err(Corrupt);
        }
        Ok(index)
    }

    /// Returns the number of routes.
    #[cfg(test)] // Only tests need the count.
    pub(crate) fn len(&self) -> usize {
        self.view().map_or(0, |view| view.len())
    }

    fn view(&self) -> Result<View<'_>, Corrupt> {
        let view = View {
            family: self.family,
            routes: self.file.section(ROUTES)?,
            origins: self.file.section(ORIGINS)?,
            by_asn: self.file.section(BY_ASN)?,
        };
        if !view.routes.len().is_multiple_of(record_size(self.family))
            || !view.origins.len().is_multiple_of(4)
            || !view.by_asn.len().is_multiple_of(BY_ASN_SIZE)
            || view.len() >= NO_PARENT as usize
        {
            return Err(Corrupt);
        }
        Ok(view)
    }

    /// Answers `request` from the index.
    ///
    /// # Errors
    ///
    /// Returns [`Corrupt`] if a record that the answer reads is damaged.
    pub(crate) fn answer(&self, request: &RouteRequest) -> Result<RouteAnswer, Corrupt> {
        let view = self.view()?;
        let family = self.family;
        let covering = request
            .covering
            .iter()
            .map(|range| {
                if range.family() != family {
                    return Ok(None);
                }
                match view.covering(range.first(), range.last())? {
                    Some(index) => view.route(index).map(Some),
                    None => Ok(None),
                }
            })
            .collect::<Result<Vec<_>, Corrupt>>()?;
        if request.all {
            let routes = (0..view.len())
                .map(|index| view.route(index))
                .collect::<Result<Vec<_>, Corrupt>>()?;
            return Ok(RouteAnswer { routes, covering });
        }
        let mut found: Vec<u32> = Vec::new();
        for &(lo, hi) in request.by_asn.ranges() {
            let start = view.by_asn_partition(|asn| asn < lo)?;
            let end = view.by_asn_partition(|asn| asn <= hi)?;
            for k in start..end {
                let route = view.by_asn_route(k)?;
                found.push(route);
            }
        }
        for prefix in request.exact.iter().filter(|p| p.family() == family) {
            let key = (prefix.first(), prefix.len());
            let index = view.partition(|r| (r.first, r.len) < key)?;
            if index < view.len() {
                let record = view.record(index)?;
                if (record.first, record.len) == key {
                    found.push(index as u32);
                }
            }
        }
        for range in request.within.iter().filter(|r| r.family() == family) {
            let (start, end) = view.starting_in(range.first(), range.last())?;
            for index in start..end {
                if view.record(index)?.last <= range.last() {
                    found.push(index as u32);
                }
            }
        }
        for range in request.intersecting.iter().filter(|r| r.family() == family) {
            let (start, end) = view.starting_in(range.first(), range.last())?;
            found.extend(start as u32..end as u32);
            let mut chain = view.partition(|r| r.first <= range.first())?.checked_sub(1);
            while let Some(index) = chain {
                let record = view.record(index)?;
                if record.last >= range.first() {
                    found.push(index as u32);
                }
                chain = view.parent(index, &record)?;
            }
        }
        found.sort_unstable();
        found.dedup();
        let routes = found
            .into_iter()
            .map(|index| view.route(index as usize))
            .collect::<Result<Vec<_>, Corrupt>>()?;
        Ok(RouteAnswer { routes, covering })
    }
}

impl View<'_> {
    fn len(&self) -> usize {
        self.routes.len() / record_size(self.family)
    }

    fn record(&self, index: usize) -> Result<Record, Corrupt> {
        let size = record_size(self.family);
        let start = index.checked_mul(size).ok_or(Corrupt)?;
        let end = start.checked_add(size).ok_or(Corrupt)?;
        let bytes = self.routes.get(start..end).ok_or(Corrupt)?;
        let at = word(self.family);
        let first = match self.family {
            Family::V4 => u128::from(u32_at(bytes, 0)),
            Family::V6 => u128_at(bytes, 0),
        };
        let len = bytes[at];
        if len > self.family.bits() {
            return Err(Corrupt);
        }
        let host = last_of(self.family, 0, len);
        if first & host != 0 {
            // Host bits set: not a prefix.
            return Err(Corrupt);
        }
        let last = first | host;
        Ok(Record {
            first,
            last,
            len,
            n: u16_at(bytes, at + 2),
            off: u32_at(bytes, at + 4),
            parent: u32_at(bytes, at + 8),
        })
    }

    fn route(&self, index: usize) -> Result<Route, Corrupt> {
        let record = self.record(index)?;
        let start = (record.off as usize).checked_mul(4).ok_or(Corrupt)?;
        let end = start
            .checked_add(usize::from(record.n) * 4)
            .ok_or(Corrupt)?;
        let origins = self.origins.get(start..end).ok_or(Corrupt)?;
        if origins.is_empty() {
            return Err(Corrupt);
        }
        let addr = Addr::new(self.family, record.first).ok_or(Corrupt)?;
        let prefix = Prefix::new(addr, record.len).map_err(|_| Corrupt)?;
        Ok(Route {
            prefix,
            origins: origins
                .as_chunks::<4>()
                .0
                .iter()
                .map(|asn| u32::from_le_bytes(*asn))
                .collect(),
        })
    }

    /// Returns the parent of route `index`, or `None` if the route has no
    /// parent.
    ///
    /// Returns [`Corrupt`] if the parent does not come before the route.
    fn parent(&self, index: usize, record: &Record) -> Result<Option<usize>, Corrupt> {
        match record.parent {
            NO_PARENT => Ok(None),
            parent if (parent as usize) < index => Ok(Some(parent as usize)),
            _ => Err(Corrupt),
        }
    }

    /// Returns the first index for which `pred` is false, like
    /// [`slice::partition_point`].
    fn partition(&self, mut pred: impl FnMut(&Record) -> bool) -> Result<usize, Corrupt> {
        let (mut lo, mut hi) = (0, self.len());
        while lo < hi {
            let mid = lo + (hi - lo) / 2;
            if pred(&self.record(mid)?) {
                lo = mid + 1;
            } else {
                hi = mid;
            }
        }
        Ok(lo)
    }

    /// Returns the index range of the routes whose first address is in
    /// `first..=last`.
    fn starting_in(&self, first: u128, last: u128) -> Result<(usize, usize), Corrupt> {
        let start = self.partition(|r| r.first < first)?;
        let end = self.partition(|r| r.first <= last)?;
        Ok((start, end.max(start)))
    }

    /// Returns the most specific route that contains `first..=last`.
    fn covering(&self, first: u128, last: u128) -> Result<Option<usize>, Corrupt> {
        let mut chain = self.partition(|r| r.first <= first)?.checked_sub(1);
        while let Some(index) = chain {
            let record = self.record(index)?;
            if record.first <= first && record.last >= last {
                return Ok(Some(index));
            }
            chain = self.parent(index, &record)?;
        }
        Ok(None)
    }

    fn by_asn_len(&self) -> usize {
        self.by_asn.len() / BY_ASN_SIZE
    }

    fn by_asn_at(&self, k: usize) -> Result<(Asn, u32), Corrupt> {
        let start = k.checked_mul(BY_ASN_SIZE).ok_or(Corrupt)?;
        let end = start.checked_add(BY_ASN_SIZE).ok_or(Corrupt)?;
        let bytes = self.by_asn.get(start..end).ok_or(Corrupt)?;
        Ok((u32_at(bytes, 0), u32_at(bytes, 4)))
    }

    fn by_asn_partition(&self, mut pred: impl FnMut(Asn) -> bool) -> Result<usize, Corrupt> {
        let (mut lo, mut hi) = (0, self.by_asn_len());
        while lo < hi {
            let mid = lo + (hi - lo) / 2;
            if pred(self.by_asn_at(mid)?.0) {
                lo = mid + 1;
            } else {
                hi = mid;
            }
        }
        Ok(lo)
    }

    fn by_asn_route(&self, k: usize) -> Result<u32, Corrupt> {
        let (_, route) = self.by_asn_at(k)?;
        if route as usize >= self.len() {
            return Err(Corrupt);
        }
        Ok(route)
    }
}

/// Answers a [`RouteRequest`] while the dump downloads, without the cache.
pub(crate) struct RisStream<'a> {
    family: Family,
    request: &'a RouteRequest,
    exact: HashSet<Prefix>,
    within: RangeQuery,
    intersecting: RangeQuery,
    /// The covering ranges of this family, sorted: first address, last
    /// address, and position in the request.
    covering: Vec<(u128, u128, usize)>,
    best: Vec<Option<Route>>,
    found: Vec<Route>,
    positions: HashMap<Prefix, usize>,
    /// The route of the last lines read.
    ///
    /// The next lines of the same prefix add their origins to it.
    current: Option<Route>,
    line: Vec<Asn>,
    seen: bool,
}

impl<'a> RisStream<'a> {
    /// Creates a stream that answers `request` for the dump of `family`.
    pub(crate) fn new(family: Family, request: &'a RouteRequest) -> Self {
        let mut covering: Vec<(u128, u128, usize)> = request
            .covering
            .iter()
            .enumerate()
            .filter(|(_, range)| range.family() == family)
            .map(|(i, range)| (range.first(), range.last(), i))
            .collect();
        covering.sort_unstable();
        Self {
            family,
            request,
            exact: request
                .exact
                .iter()
                .copied()
                .filter(|p| p.family() == family)
                .collect(),
            within: RangeQuery::new(family, &request.within),
            intersecting: RangeQuery::new(family, &request.intersecting),
            covering,
            best: vec![None; request.covering.len()],
            found: Vec::new(),
            positions: HashMap::new(),
            current: None,
            line: Vec::new(),
            seen: false,
        }
    }

    /// Ends the input and returns the answer.
    ///
    /// # Errors
    ///
    /// Returns an error if the dump has no route of the family.
    pub(crate) fn finish(mut self) -> Result<RouteAnswer> {
        if let Some(route) = self.current.take() {
            self.check(route);
        }
        if !self.seen {
            return Err(no_routes());
        }
        let mut routes = self.found;
        routes.sort_unstable_by_key(|route| route.prefix);
        Ok(RouteAnswer {
            routes,
            covering: self.best,
        })
    }

    /// Checks a merged route against every condition.
    fn check(&mut self, route: Route) {
        let prefix = route.prefix;
        let (first, last) = (prefix.first(), prefix.last());
        // A covering range that this route contains starts inside the route.
        let lo = self.covering.partition_point(|(f, _, _)| *f < first);
        let hi = self.covering.partition_point(|(f, _, _)| *f <= last);
        for k in lo..hi.max(lo) {
            let (_, q_last, at) = self.covering[k];
            if q_last > last {
                continue;
            }
            match &mut self.best[at] {
                Some(best) if best.prefix == prefix => merge(&mut best.origins, &route.origins),
                Some(best) if best.prefix.len() >= prefix.len() => {}
                slot => *slot = Some(route.clone()),
            }
        }
        let wanted = self.request.all
            || self.exact.contains(&prefix)
            || self.within.contains(first, last)
            || self.intersecting.intersects(first, last)
            || route
                .origins
                .iter()
                .any(|asn| self.request.by_asn.contains(*asn));
        if wanted {
            match self.positions.get(&prefix) {
                Some(&i) => merge(&mut self.found[i].origins, &route.origins),
                None => {
                    self.positions.insert(prefix, self.found.len());
                    self.found.push(route);
                }
            }
        }
    }
}

/// Appends the origins of `more` that are not in `origins` yet.
fn merge(origins: &mut Vec<Asn>, more: &[Asn]) {
    for asn in more {
        if !origins.contains(asn) {
            origins.push(*asn);
        }
    }
}

impl LineSink for RisStream<'_> {
    fn line(&mut self, line: &[u8]) -> Result<Control> {
        let Line::Route(prefix) = parse_line(line, self.family, &mut self.line) else {
            return Ok(Control::Continue);
        };
        self.seen = true;
        match &mut self.current {
            Some(current) if current.prefix == prefix => merge(&mut current.origins, &self.line),
            _ => {
                let next = Route {
                    prefix,
                    origins: self.line.clone(),
                };
                if let Some(done) = self.current.replace(next) {
                    self.check(done);
                }
            }
        }
        Ok(Control::Continue)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        cache::{container, mapped::MappedFile},
        dataset::Rng,
        fetch::{Validators, lines::LineSplitter},
    };

    const V4: &str = "\
% This is a synthetic dump
%
64496\t192.0.2.0/24\t300
64497\t192.0.2.0/24\t10
64496\t192.0.2.0/24\t1
64496\t192.0.2.0/25\t5
{64498,64499}\t192.0.2.128/26\t3
64500\t198.51.100.0/24\t2
64501\t198.18.0.0/16\t9
64496\t203.0.113.0/24\t1
this is not a route
64502\t2001:db8::/32\t1
64503\t192.0.2.0/33\t1
";

    fn feed(sink: &mut dyn LineSink, text: &[u8]) {
        let mut splitter = LineSplitter::new();
        for chunk in text.chunks(7) {
            splitter.push(chunk, sink).unwrap();
        }
        splitter.finish(sink).unwrap();
    }

    fn file_of(text: &str, family: Family) -> Vec<u8> {
        let mut builder = RisBuilder::new(family);
        feed(&mut builder, text.as_bytes());
        let sections = builder.finish().unwrap();
        let mut bytes = Vec::new();
        container::write(&mut bytes, 1, &Validators::default(), "u", &sections).unwrap();
        bytes
    }

    fn open(bytes: Vec<u8>, family: Family) -> Result<RisIndex, Corrupt> {
        let file = CacheFile::new(MappedFile::from_vec(bytes)).map_err(|_| Corrupt)?;
        RisIndex::open(file, family)
    }

    fn index(text: &str, family: Family) -> RisIndex {
        open(file_of(text, family), family).unwrap()
    }

    fn stream(text: &str, family: Family, request: &RouteRequest) -> Result<RouteAnswer> {
        let mut stream = RisStream::new(family, request);
        feed(&mut stream, text.as_bytes());
        stream.finish()
    }

    /// Answers `request` with the index and with the stream, and checks that
    /// the answers agree.
    fn both(text: &str, family: Family, request: &RouteRequest) -> RouteAnswer {
        let indexed = index(text, family).answer(request).unwrap();
        let streamed = stream(text, family, request).unwrap();
        assert_eq!(indexed, streamed, "{request:?}");
        indexed
    }

    fn p(text: &str) -> Prefix {
        text.parse().unwrap()
    }

    fn r(text: &str) -> Range {
        if text.contains('/') {
            Range::from_prefix(p(text))
        } else {
            Range::from_addr(text.parse().unwrap())
        }
    }

    fn route(prefix: &str, origins: &[Asn]) -> Route {
        Route {
            prefix: p(prefix),
            origins: origins.to_vec(),
        }
    }

    fn prefixes(answer: &RouteAnswer) -> Vec<String> {
        answer.routes.iter().map(|r| r.prefix.to_string()).collect()
    }

    #[test]
    fn parses_lines() {
        let mut origins = Vec::new();
        assert_eq!(parse_line(b"% x", Family::V4, &mut origins), Line::Skip);
        assert_eq!(parse_line(b"", Family::V4, &mut origins), Line::Skip);
        assert_eq!(parse_line(b"  ", Family::V4, &mut origins), Line::Skip);
        assert_eq!(
            parse_line(
                b"{64497,64498,64497}\t198.51.100.0/24\t3",
                Family::V4,
                &mut origins
            ),
            Line::Route(p("198.51.100.0/24"))
        );
        assert_eq!(origins, [64497, 64498]);
        assert_eq!(
            parse_line(b"64496 2001:db8::/32 1", Family::V6, &mut origins),
            Line::Route(p("2001:db8::/32"))
        );
        assert_eq!(
            parse_line(b"64496\t2001:db8::/32", Family::V4, &mut origins),
            Line::Skip
        );
        for bad in [
            &b"64496"[..],
            b"AS64496\t192.0.2.0/24\t1",
            b"+64496\t192.0.2.0/24\t1",
            b"{64496\t192.0.2.0/24\t1",
            b"{}\t192.0.2.0/24\t1",
            b"64496\t192.0.2.0\t1",
            b"4294967296\t192.0.2.0/24\t1",
        ] {
            assert_eq!(
                parse_line(bad, Family::V4, &mut origins),
                Line::Malformed,
                "{}",
                String::from_utf8_lossy(bad)
            );
        }
    }

    #[test]
    fn merges_and_finds_routes() {
        let all = both(
            V4,
            Family::V4,
            &RouteRequest {
                all: true,
                ..RouteRequest::default()
            },
        );
        assert_eq!(
            all.routes,
            [
                route("192.0.2.0/24", &[64496, 64497]),
                route("192.0.2.0/25", &[64496]),
                route("192.0.2.128/26", &[64498, 64499]),
                route("198.18.0.0/16", &[64501]),
                route("198.51.100.0/24", &[64500]),
                route("203.0.113.0/24", &[64496]),
            ]
        );
        assert_eq!(index(V4, Family::V4).len(), 6);
    }

    #[test]
    fn finds_the_covering_route() {
        let request = RouteRequest {
            covering: vec![
                r("192.0.2.130"),
                r("192.0.2.200"),
                r("192.0.2.5"),
                r("198.51.100.7"),
                r("198.18.7.7"),
                r("10.0.0.1"),
                r("192.0.2.0/23"),
                r("192.0.2.128/25"),
                r("2001:db8::1"),
                r("203.0.113.255"),
                r("255.255.255.255"),
            ],
            ..RouteRequest::default()
        };
        let answer = both(V4, Family::V4, &request);
        let covering: Vec<Option<String>> = answer
            .covering
            .iter()
            .map(|r| r.as_ref().map(|r| r.prefix.to_string()))
            .collect();
        let expected = [
            Some("192.0.2.128/26"),
            Some("192.0.2.0/24"),
            Some("192.0.2.0/25"),
            Some("198.51.100.0/24"),
            Some("198.18.0.0/16"),
            None,
            None,
            Some("192.0.2.0/24"),
            None,
            Some("203.0.113.0/24"),
            None,
        ];
        assert_eq!(covering, expected.map(|e| e.map(str::to_owned)).to_vec());
        assert_eq!(answer.covering[1].as_ref().unwrap().origins, [64496, 64497]);
        assert!(answer.routes.is_empty());
    }

    #[test]
    fn within_intersecting_exact_and_by_asn() {
        let within = both(
            V4,
            Family::V4,
            &RouteRequest {
                within: vec![r("192.0.2.0/24"), r("198.51.100.0/24")],
                ..RouteRequest::default()
            },
        );
        assert_eq!(
            prefixes(&within),
            [
                "192.0.2.0/24",
                "192.0.2.0/25",
                "192.0.2.128/26",
                "198.51.100.0/24"
            ]
        );
        let touching = both(
            V4,
            Family::V4,
            &RouteRequest {
                intersecting: vec![r("192.0.2.64/26"), r("198.18.200.0/24")],
                ..RouteRequest::default()
            },
        );
        assert_eq!(
            prefixes(&touching),
            ["192.0.2.0/24", "192.0.2.0/25", "198.18.0.0/16"]
        );
        let exact = both(
            V4,
            Family::V4,
            &RouteRequest {
                exact: vec![
                    p("198.51.100.0/24"),
                    p("198.51.100.0/25"),
                    p("2001:db8::/32"),
                ],
                ..RouteRequest::default()
            },
        );
        assert_eq!(prefixes(&exact), ["198.51.100.0/24"]);
        let by_asn = both(
            V4,
            Family::V4,
            &RouteRequest {
                by_asn: AsnSet::from_ranges([(64496, 64496), (64499, 64499)]),
                ..RouteRequest::default()
            },
        );
        assert_eq!(
            prefixes(&by_asn),
            [
                "192.0.2.0/24",
                "192.0.2.0/25",
                "192.0.2.128/26",
                "203.0.113.0/24"
            ]
        );
        let none = both(V4, Family::V4, &RouteRequest::default());
        assert!(none.routes.is_empty() && none.covering.is_empty());
    }

    #[test]
    fn ipv6() {
        let text = "64510\t2001:db8::/32\t5\n64511\t2001:db8:1::/48\t1\n64496\t192.0.2.0/24\t1\n";
        let answer = both(
            text,
            Family::V6,
            &RouteRequest {
                covering: vec![r("2001:db8:1::5"), r("2001:db8:2::5"), r("192.0.2.1")],
                by_asn: AsnSet::from_ranges([(64510, 64511)]),
                ..RouteRequest::default()
            },
        );
        assert_eq!(prefixes(&answer), ["2001:db8::/32", "2001:db8:1::/48"]);
        assert_eq!(
            answer.covering[0].as_ref().unwrap().prefix,
            p("2001:db8:1::/48")
        );
        assert_eq!(
            answer.covering[1].as_ref().unwrap().prefix,
            p("2001:db8::/32")
        );
        assert_eq!(answer.covering[2], None);
        let root = "64510\t::/0\t1\n";
        let answer = both(
            root,
            Family::V6,
            &RouteRequest {
                covering: vec![r("2001:db8::1")],
                ..RouteRequest::default()
            },
        );
        assert_eq!(answer.covering[0].as_ref().unwrap().prefix, p("::/0"));
    }

    #[test]
    fn a_dump_without_routes_is_an_error() {
        let text = "% only comments\n64502\t2001:db8::/32\t1\n<html>\n";
        let mut builder = RisBuilder::new(Family::V4);
        feed(&mut builder, text.as_bytes());
        assert_eq!(
            builder.finish().unwrap_err().message(),
            "no routes in the dump"
        );
        let error = stream(text, Family::V4, &RouteRequest::default()).unwrap_err();
        assert_eq!(error.message(), "no routes in the dump");
    }

    #[test]
    fn duplicates_apart_are_still_one_route() {
        // The dump keeps the lines of a prefix together. If a dump did not,
        // the index and the stream still return the prefix as one route.
        let text = "64496\t192.0.2.0/24\t1\n64500\t198.51.100.0/24\t1\n64497\t192.0.2.0/24\t1\n";
        let request = RouteRequest {
            within: vec![r("192.0.2.0/24")],
            covering: vec![r("192.0.2.1")],
            ..RouteRequest::default()
        };
        let answer = both(text, Family::V4, &request);
        assert_eq!(answer.routes, [route("192.0.2.0/24", &[64496, 64497])]);
        assert_eq!(
            answer.covering,
            [Some(route("192.0.2.0/24", &[64496, 64497]))]
        );
    }

    #[test]
    fn cache_ranges_are_checked() {
        for (family, prefix) in [(Family::V4, "192.0.2.0/24"), (Family::V6, "2001:db8::/32")] {
            let good = file_of(&format!("64496\t{prefix}\t1\n"), family);
            let layout = container::Layout::parse(&good).unwrap();
            let start =
                layout.section(&good, ROUTES).unwrap().as_ptr() as usize - good.as_ptr() as usize;
            let request = RouteRequest {
                all: true,
                ..RouteRequest::default()
            };
            for (off, n, valid) in [
                (0u32, 1u16, true),
                (1, 0, false), // A route must have an origin.
                (1, 1, false),
                (u32::MAX / 4, 1, false), // The byte offset fits 32 bits, the end does not.
                (u32::MAX / 4 + 1, 1, false),
                (u32::MAX, 1, false),
            ] {
                let mut bytes = good.clone();
                let at = start + word(family);
                bytes[at + 2..at + 4].copy_from_slice(&n.to_le_bytes());
                bytes[at + 4..at + 8].copy_from_slice(&off.to_le_bytes());
                let answer = open(bytes, family).unwrap().answer(&request);
                if valid {
                    assert_eq!(answer.unwrap().routes, [route(prefix, &[64496])]);
                } else {
                    assert_eq!(answer, Err(Corrupt), "{family:?}, off={off}, n={n}");
                }
            }
            let index = open(good, family).unwrap();
            let view = index.view().unwrap();
            for i in [view.len(), usize::MAX / record_size(family), usize::MAX] {
                assert_eq!(view.record(i).err(), Some(Corrupt));
            }
            for i in [view.by_asn_len(), usize::MAX / BY_ASN_SIZE, usize::MAX] {
                assert_eq!(view.by_asn_at(i), Err(Corrupt));
            }
        }
    }

    #[test]
    fn damaged_indexes_are_corrupt_not_panics() {
        let good = file_of(V4, Family::V4);
        let request = RouteRequest {
            by_asn: AsnSet::all(),
            exact: vec![p("192.0.2.0/25")],
            covering: vec![r("192.0.2.130"), r("198.51.100.1")],
            within: vec![r("0.0.0.0/0")],
            intersecting: vec![r("192.0.2.100")],
            all: false,
        };
        let mut rng = Rng::new(1);
        let header = container::Layout::parse(&good).unwrap();
        let start =
            header.section(&good, ROUTES).unwrap().as_ptr() as usize - good.as_ptr() as usize;
        let mut corrupt = 0;
        for _ in 0..3000 {
            let mut damaged = good.clone();
            for _ in 0..1 + rng.below(3) {
                let at = start + rng.below((good.len() - start) as u64) as usize;
                damaged[at] = rng.next() as u8;
            }
            match open(damaged, Family::V4).and_then(|index| index.answer(&request)) {
                Ok(_) => {}
                Err(Corrupt) => corrupt += 1,
            }
        }
        assert!(corrupt > 0);

        // A parent that points at itself would loop forever.
        let mut looped = good.clone();
        let parent_at = start + 16 + 12; // the second route, /25, child of /24
        looped[parent_at..parent_at + 4].copy_from_slice(&1u32.to_le_bytes());
        let index = open(looped, Family::V4).unwrap();
        let request = RouteRequest {
            covering: vec![r("192.0.2.200")],
            ..RouteRequest::default()
        };
        // For 192.0.2.200, the last route that starts before it is the /26
        // at index 2. Its parent is the /24 at index 0, so the search never
        // reaches route 1.
        assert!(index.answer(&request).is_ok());
        let request = RouteRequest {
            covering: vec![r("192.0.2.0/24")],
            ..RouteRequest::default()
        };
        assert_eq!(index.answer(&request), Err(Corrupt));

        // A route with host bits set is not a prefix.
        let mut host = good.clone();
        host[start] = 1; // 192.0.2.0/24 becomes 192.0.2.1/24.
        let answer = open(host, Family::V4).and_then(|index| index.answer(&request));
        assert_eq!(answer, Err(Corrupt));

        // Empty, odd-sized, and missing sections.
        let empty = file_of_sections(vec![
            Section::new(ROUTES, Vec::new()),
            Section::new(ORIGINS, Vec::new()),
            Section::new(BY_ASN, Vec::new()),
        ]);
        assert_eq!(open(empty, Family::V4).unwrap_err(), Corrupt);
        let odd = file_of_sections(vec![
            Section::new(ROUTES, vec![0; 15]),
            Section::new(ORIGINS, Vec::new()),
            Section::new(BY_ASN, Vec::new()),
        ]);
        assert_eq!(open(odd, Family::V4).unwrap_err(), Corrupt);
        let missing = file_of_sections(vec![Section::new(ROUTES, vec![0; 16])]);
        assert_eq!(open(missing, Family::V4).unwrap_err(), Corrupt);
    }

    fn file_of_sections(sections: Vec<Section>) -> Vec<u8> {
        let mut bytes = Vec::new();
        container::write(&mut bytes, 1, &Validators::default(), "u", &sections).unwrap();
        bytes
    }

    /// Returns a random sorted dump over the documentation networks.
    fn random_dump(rng: &mut Rng) -> String {
        let bases = [0xc000_0200u32, 0xc633_6400, 0xcb00_7100];
        let mut prefixes = Vec::new();
        for _ in 0..rng.below(60) {
            let base = bases[rng.below(3) as usize];
            let len = 22 + rng.below(11) as u8;
            let addr = Addr::new(
                Family::V4,
                u128::from(base) + u128::from(rng.below(512) as u32),
            )
            .unwrap();
            prefixes.push(Prefix::new(addr, len).unwrap());
        }
        prefixes.sort();
        // The dump needs at least one route. 10.0.0.0/8 sorts before every
        // generated prefix.
        let mut text = String::from("% random\n64511\t10.0.0.0/8\t1\n");
        for prefix in prefixes {
            for _ in 0..1 + rng.below(2) {
                let asn = 64496 + rng.below(16);
                if rng.below(5) == 0 {
                    text.push_str(&format!(
                        "{{{asn},{}}}\t{prefix}\t1\n",
                        64496 + rng.below(16)
                    ));
                } else {
                    text.push_str(&format!("{asn}\t{prefix}\t1\n"));
                }
            }
        }
        text
    }

    fn random_range(rng: &mut Rng) -> Range {
        let base = [0xc000_0200u128, 0xc633_6400, 0xcb00_7100][rng.below(3) as usize];
        let first = base + u128::from(rng.below(600) as u32);
        let last = first + u128::from(rng.below(300) as u32);
        Range::new(Family::V4, first, last).unwrap()
    }

    #[test]
    fn indexed_and_streaming_agree() {
        let mut rng = Rng::new(42);
        for _ in 0..300 {
            let text = random_dump(&mut rng);
            let mut request = RouteRequest {
                all: rng.below(10) == 0,
                ..RouteRequest::default()
            };
            for _ in 0..rng.below(3) {
                let asn = 64496 + rng.below(16) as u32;
                request.by_asn.insert(asn);
            }
            for _ in 0..rng.below(4) {
                let range = random_range(&mut rng);
                match rng.below(4) {
                    0 => request.covering.push(Range::from_addr(range.first_addr())),
                    1 => request.covering.push(range),
                    2 => request.within.push(range),
                    _ => request.intersecting.push(range),
                }
            }
            if rng.below(2) == 0 {
                let addr = random_range(&mut rng).first_addr();
                request
                    .exact
                    .push(Prefix::new(addr, 22 + rng.below(11) as u8).unwrap());
                request.exact.push(p("192.0.2.0/24"));
            }
            let answer = both(&text, Family::V4, &request);
            // Check the answer against the definitions by brute force over
            // all routes.
            let all = both(
                &text,
                Family::V4,
                &RouteRequest {
                    all: true,
                    ..RouteRequest::default()
                },
            )
            .routes;
            for (range, got) in request.covering.iter().zip(&answer.covering) {
                let best = all
                    .iter()
                    .filter(|route| Range::from_prefix(route.prefix).contains(range))
                    .max_by_key(|route| route.prefix.len());
                assert_eq!(got.as_ref(), best, "covering {range}");
            }
            let expected: Vec<&Route> = all
                .iter()
                .filter(|route| {
                    let range = Range::from_prefix(route.prefix);
                    request.all
                        || request.exact.contains(&route.prefix)
                        || request.within.iter().any(|w| w.contains(&range))
                        || request.intersecting.iter().any(|i| i.intersects(&range))
                        || route.origins.iter().any(|a| request.by_asn.contains(*a))
                })
                .collect();
            assert_eq!(answer.routes.iter().collect::<Vec<_>>(), expected);
        }
    }

    /// Builds the index of a synthetic dump as large as the real IPv4 dump,
    /// 1.1 million lines.
    ///
    /// Measure the peak memory from outside:
    ///
    /// `/usr/bin/time -l target/debug/deps/netf-… peak_memory --ignored`
    ///
    /// The test writes the dump into `target/` once and downloads nothing.
    #[test]
    #[ignore = "builds a 1.1M-line synthetic dump in target/; measure with time -l"]
    fn peak_memory() {
        use std::io::{BufWriter, Read as _, Write as _};

        const LINES: u32 = 1_100_000;
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("target")
            .join("ris-synthetic-v4.txt");
        if !path.exists() {
            let mut out = BufWriter::new(std::fs::File::create(&path).unwrap());
            writeln!(out, "% synthetic RIS dump for the memory test").unwrap();
            let mut rng = Rng::new(3);
            let mut i = 0;
            let mut base: u32 = 0xF000_0000;
            while i < LINES {
                // Mostly /24 routes, with an occasional covering /16 or a
                // more specific /25. Some /24 routes get a second line with
                // an AS set.
                if base & 0xffff == 0 && rng.below(4) == 0 {
                    writeln!(out, "{}\t{}/16\t50", 64496 + rng.below(16), ipv4(base)).unwrap();
                    i += 1;
                }
                let asn = 64496 + rng.below(16);
                writeln!(out, "{asn}\t{}/24\t{}", ipv4(base), rng.below(400)).unwrap();
                i += 1;
                if rng.below(12) == 0 {
                    writeln!(out, "{{{},{}}}\t{}/24\t3", asn + 1, asn + 2, ipv4(base)).unwrap();
                    i += 1;
                }
                if rng.below(8) == 0 {
                    writeln!(out, "{asn}\t{}/25\t7", ipv4(base)).unwrap();
                    i += 1;
                }
                base += 256;
            }
            out.flush().unwrap();
        }
        let mut file = std::fs::File::open(&path).unwrap();
        let mut builder = RisBuilder::new(Family::V4);
        let mut splitter = LineSplitter::new();
        let mut chunk = vec![0; 64 << 10];
        loop {
            let n = file.read(&mut chunk).unwrap();
            if n == 0 {
                break;
            }
            splitter.push(&chunk[..n], &mut builder).unwrap();
        }
        splitter.finish(&mut builder).unwrap();
        let sections = builder.finish().unwrap();
        let size: usize = sections.iter().map(|s| s.data.len()).sum();
        eprintln!(
            "ris-v4 synthetic: {LINES} lines, {} routes, sections {:.1} MB",
            sections[0].data.len() / 16,
            size as f64 / 1e6,
        );
    }

    fn ipv4(bits: u32) -> std::net::Ipv4Addr {
        std::net::Ipv4Addr::from(bits)
    }
}
