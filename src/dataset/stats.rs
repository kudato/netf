//! Parses and indexes the delegated stats files
//! `delegated-<rir>-extended-latest`.
//!
//! A stats file lists blocks of addresses and AS numbers with a country and
//! a holder id. The parser keeps only `allocated` and `assigned` blocks.
//!
//! # The format
//!
//! ```text
//! # comments
//! 2|ripencc|1760745599|128000|19850701|20251017|+0100
//! ripencc|*|ipv4|*|80000|summary
//! ripencc|NL|ipv4|192.0.2.0|384|20100712|allocated|a1b2c3
//! ripencc|NL|ipv6|2001:db8::|32|19990826|allocated|a1b2c3
//! ripencc|NL|asn|64496|4|20020101|assigned|a1b2c3
//! ripencc||ipv4|203.0.113.0|256||available|
//! ```
//!
//! A record has the columns
//! `registry|cc|type|start|value|date|status|opaque-id[|ext…]`. The meaning
//! of `value` depends on `type`:
//!
//! - `ipv4`: a count of addresses. A block is a range and not always one
//!   CIDR, like the 384 addresses above.
//! - `ipv6`: the prefix length. The parser clears the host bits of `start`.
//! - `asn`: a count of AS numbers.
//!
//! The header (`2|…`), the summaries (`…|summary`), and the comments (`#`)
//! are not records. `available` and `reserved` blocks were never delegated
//! and have no holder, so the parser does not keep them, whatever their
//! `cc` column says. The registry of a record is its `registry` column. The
//! country is its `cc` column in uppercase.
//!
//! The parser skips an `allocated` or `assigned` line with a malformed
//! field, but a body without a single record of any status is an error. A
//! proxy can return an HTML page with status 200, and the cache must not
//! keep that page as an empty file until the TTL ends.
//!
//! # The index
//!
//! Each registry has its own cache file, `stats-<rir>`, with the kind code
//! `0x10 + i`, where `i` is the index of the registry in [`Rir::ALL`].
//! The file has five sections. All numbers are little-endian.
//!
//! | tag | section | record |
//! |---|---|---|
//! | 1 | `nets_v4` | 24 bytes: `first u32, last u32, reach u32, opaque_off u32, opaque_len u16, cc [u8; 2], rir u8, pad 3` |
//! | 2 | `nets_v6` | 64 bytes: `first u128, last u128, reach u128`, then the same, padded |
//! | 3 | `asns` | 24 bytes, as `nets_v4` with AS numbers |
//! | 4 | `by_opaque` | 12 bytes: `opaque_off u32, opaque_len u16, table u8, pad, record u32`, sorted by the id in ASCII lowercase, then table and record |
//! | 5 | `strings` | the opaque ids, each once |
//!
//! Records are sorted by `(first, last)`, and records with equal ends keep
//! the order of the file. `reach` is the largest `last` of the record and of
//! all records before it. The blocks of one registry do not overlap, but
//! nothing guarantees that. To find the blocks that cover or touch a range,
//! a binary search finds where the range starts. A walk back from there
//! stops at the first record whose `reach` shows that neither this record
//! nor any earlier one can match. With disjoint blocks the walk takes one
//! step, and with overlapping blocks the answer is still exact.
//!
//! `rir` is the index of the registry in [`Rir::ALL`]. An opaque id of
//! length 0 means that the record has no id.
//!
//! Every read checks bounds and checks that the record makes sense: the
//! ends are in order and inside the family, `reach` is not below `last`,
//! the country has two letters, the registry is known, and the id lies
//! inside `strings`. An id that goes into an answer must also be valid
//! UTF-8. A violation returns [`Corrupt`], and the caller rebuilds the
//! file.
//!
//! # Without the cache
//!
//! [`StatsStream`] answers a [`StatsRequest`] in one pass over the download.
//! Like `RisStream`, it checks every record against every condition at once
//! and reads the file to the end.
//!
//! The engine asks all five registries at once, and [`StatsAnswer::merge`]
//! joins their answers. For each covering range, the merged answer holds
//! the narrowest block of all five. On a tie, the registry that comes first
//! in [`Rir::ALL`] wins.

use std::{borrow::Cow, cmp::Ordering, collections::HashMap, sync::Arc};

use crate::{
    addr::{Addr, Family, Range},
    cache::{
        Builder, CacheFile,
        container::{Corrupt, Section, Table, u16_at, u32_at, u128_at},
    },
    dataset::{AsnSet, RangeQuery},
    error::{Error, Result},
    fetch::lines::{Control, LineSink},
    model::{AsBlock, Asn, Block, Cc, Rir},
};

/// The tag of the `nets_v4` section.
const NETS_V4: u16 = 1;
/// The tag of the `nets_v6` section.
const NETS_V6: u16 = 2;
/// The tag of the `asns` section.
const ASNS: u16 = 3;
/// The tag of the `by_opaque` section.
const BY_OPAQUE: u16 = 4;
/// The tag of the `strings` section.
const STRINGS: u16 = 5;

/// The size of a `by_opaque` record.
const BY_OPAQUE_SIZE: usize = 12;

/// A batch of conditions on the delegated stats, answered in one pass.
///
/// A request can mix IPv4 and IPv6 conditions. Each range is matched only
/// against the blocks of its own family. The answers to `covering` go to
/// [`StatsAnswer::covering`], and the answers to the AS conditions go to
/// [`StatsAnswer::as_blocks`]. The answers to the rest go to
/// [`StatsAnswer::blocks`].
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub(crate) struct StatsRequest {
    /// Ranges, such as an address or a route.
    ///
    /// For each range, the answer holds the narrowest block that contains
    /// the whole range. The blocks go to [`StatsAnswer::covering`] in the
    /// same order.
    pub(crate) covering: Vec<Range>,
    /// Blocks that share an address with one of these ranges.
    pub(crate) intersecting: Vec<Range>,
    /// Blocks of one of these countries (`net.country`).
    pub(crate) by_cc: Vec<Cc>,
    /// Blocks of one of these registries (`net.rir`).
    pub(crate) by_rir: Vec<Rir>,
    /// Blocks with one of these holder ids (`net.org`).
    ///
    /// The comparison ignores ASCII case.
    pub(crate) by_opaque: Vec<Arc<str>>,
    /// Every block (`net.country: *`, `net.rir: *`).
    pub(crate) all_blocks: bool,
    /// AS blocks with a number in this set.
    pub(crate) asn: AsnSet,
    /// AS blocks of one of these countries (`as.country`).
    pub(crate) as_by_cc: Vec<Cc>,
    /// AS blocks of one of these registries (`as.rir`).
    pub(crate) as_by_rir: Vec<Rir>,
    /// AS blocks with one of these holder ids (`as.org`).
    ///
    /// The comparison ignores ASCII case.
    pub(crate) as_by_opaque: Vec<Arc<str>>,
    /// Every AS block (`as.rir: *`).
    pub(crate) all_as: bool,
}

impl StatsRequest {
    /// Returns `true` if the request asks for nothing.
    ///
    /// The answer is then [`StatsAnswer::empty`], and no file needs to be
    /// read.
    pub(crate) fn is_empty(&self) -> bool {
        self.covering.is_empty()
            && self.intersecting.is_empty()
            && self.by_cc.is_empty()
            && self.by_rir.is_empty()
            && self.by_opaque.is_empty()
            && !self.all_blocks
            && self.asn.is_empty()
            && self.as_by_cc.is_empty()
            && self.as_by_rir.is_empty()
            && self.as_by_opaque.is_empty()
            && !self.all_as
    }

    /// Returns `true` if an address block with these fields meets
    /// `all_blocks`, `by_cc`, `by_rir`, or `by_opaque`.
    fn wants_block(&self, cc: Cc, rir: Rir, opaque: &Opaque<'_>) -> bool {
        self.all_blocks
            || self.by_cc.contains(&cc)
            || self.by_rir.contains(&rir)
            || opaque.is_in(&self.by_opaque)
    }

    /// Returns `true` if an AS block with these fields meets `all_as`,
    /// `as_by_cc`, `as_by_rir`, or `as_by_opaque`.
    fn wants_as(&self, cc: Cc, rir: Rir, opaque: &Opaque<'_>) -> bool {
        self.all_as
            || self.as_by_cc.contains(&cc)
            || self.as_by_rir.contains(&rir)
            || opaque.is_in(&self.as_by_opaque)
    }

    /// Returns `true` if a condition needs a pass over all the address
    /// blocks.
    fn scans_blocks(&self) -> bool {
        self.all_blocks || !self.by_cc.is_empty() || !self.by_rir.is_empty()
    }

    /// Returns `true` if a condition needs a pass over all the AS blocks.
    fn scans_as(&self) -> bool {
        self.all_as || !self.as_by_cc.is_empty() || !self.as_by_rir.is_empty()
    }
}

/// The answer to a [`StatsRequest`].
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub(crate) struct StatsAnswer {
    /// The address blocks that meet `intersecting`, `by_cc`, `by_rir`,
    /// `by_opaque`, or `all_blocks`.
    ///
    /// The blocks are sorted by range, IPv4 first, then by registry,
    /// country, and id. There are no duplicates.
    pub(crate) blocks: Vec<Block>,
    /// For each `covering` range, the narrowest block that contains it, or
    /// `None` if no block does.
    pub(crate) covering: Vec<Option<Block>>,
    /// The AS blocks that meet `asn`, `as_by_cc`, `as_by_rir`,
    /// `as_by_opaque`, or `all_as`, sorted like `blocks`.
    pub(crate) as_blocks: Vec<AsBlock>,
}

impl StatsAnswer {
    /// Returns an answer with no blocks and a `None` for each covering range
    /// of `request`.
    pub(crate) fn empty(request: &StatsRequest) -> Self {
        Self {
            covering: vec![None; request.covering.len()],
            ..Self::default()
        }
    }

    /// Joins the answers of several registries to one request.
    ///
    /// The result holds the blocks of all the answers, sorted and without
    /// duplicates. For each covering range, it holds the narrowest block of
    /// all the answers. On a tie, the block of the earlier answer wins.
    pub(crate) fn merge(answers: impl IntoIterator<Item = StatsAnswer>) -> Self {
        let mut merged = Self::default();
        for answer in answers {
            merged.blocks.extend(answer.blocks);
            merged.as_blocks.extend(answer.as_blocks);
            if merged.covering.len() < answer.covering.len() {
                merged.covering.resize(answer.covering.len(), None);
            }
            for (slot, block) in merged.covering.iter_mut().zip(answer.covering) {
                if let Some(block) = block
                    && slot
                        .as_ref()
                        .is_none_or(|best| narrower(&block.range, &best.range))
                {
                    *slot = Some(block);
                }
            }
        }
        merged.normalize();
        merged
    }

    /// Sorts the blocks and removes duplicates.
    fn normalize(&mut self) {
        self.blocks
            .sort_unstable_by(|a, b| block_key(a).cmp(&block_key(b)));
        self.blocks.dedup();
        self.as_blocks
            .sort_unstable_by(|a, b| as_key(a).cmp(&as_key(b)));
        self.as_blocks.dedup();
    }
}

/// Returns the sort key of an address block in an answer.
fn block_key(block: &Block) -> (Range, Rir, Cc, Option<&str>) {
    (block.range, block.rir, block.cc, block.opaque_id.as_deref())
}

/// Returns the sort key of an AS block in an answer.
fn as_key(block: &AsBlock) -> (Asn, Asn, Rir, Cc, Option<&str>) {
    (
        block.first,
        block.last,
        block.rir,
        block.cc,
        block.opaque_id.as_deref(),
    )
}

/// Returns `true` if `a` is a better covering block than `b`.
///
/// The better block has fewer addresses. Of two blocks of the same size, the
/// block with the larger first address is better. Two distinct ranges never
/// tie.
fn narrower(a: &Range, b: &Range) -> bool {
    cover_key(a.first(), a.last()) < cover_key(b.first(), b.last())
}

/// Returns the sort key of a covering block.
///
/// A smaller key means a narrower block.
fn cover_key(first: u128, last: u128) -> (u128, std::cmp::Reverse<u128>) {
    (last - first, std::cmp::Reverse(first))
}

/// Returns `true` if `[first, last]` shares a number with `set`.
fn asn_touches(set: &AsnSet, first: Asn, last: Asn) -> bool {
    let ranges = set.ranges();
    let i = ranges.partition_point(|(lo, _)| *lo <= last);
    i > 0 && ranges[i - 1].1 >= first
}

/// Compares two ids ignoring ASCII case.
fn cmp_ids(a: &[u8], b: &[u8]) -> Ordering {
    a.iter()
        .map(u8::to_ascii_lowercase)
        .cmp(b.iter().map(u8::to_ascii_lowercase))
}

/// The opaque id of a record that is checked against a request.
///
/// The comparison ignores ASCII case.
struct Opaque<'a>(Option<&'a str>);

impl Opaque<'_> {
    fn is_in(&self, ids: &[Arc<str>]) -> bool {
        self.0
            .is_some_and(|id| ids.iter().any(|want| want.eq_ignore_ascii_case(id)))
    }
}

/// Returns the error for a download without a single record.
fn no_records() -> Error {
    Error::runtime("no records in the file")
}

/// What a kept line delegates.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum What {
    /// Addresses.
    Net(Range),
    /// A range of AS numbers, both ends included.
    As(Asn, Asn),
}

/// One line of the file.
#[derive(Debug, Eq, PartialEq)]
enum Line<'a> {
    /// An allocated or assigned block.
    Kept {
        rir: Rir,
        cc: Cc,
        what: What,
        opaque: Option<Cow<'a, str>>,
    },
    /// A well-formed `available` or `reserved` block.
    ///
    /// It counts as a record, but the parser does not keep it.
    Undelegated,
    /// The header, a summary, a comment, an empty line, or a malformed line.
    Other,
}

/// Parses one line.
fn parse_line(line: &[u8]) -> Line<'_> {
    let line = line.trim_ascii();
    if line.is_empty() || line[0] == b'#' {
        return Line::Other;
    }
    let mut fields = line.split(|b| *b == b'|').map(<[u8]>::trim_ascii);
    let (Some(registry), Some(cc), Some(kind), Some(start), Some(value), Some(_date), Some(status)) = (
        fields.next(),
        fields.next(),
        fields.next(),
        fields.next(),
        fields.next(),
        fields.next(),
        fields.next(),
    ) else {
        return Line::Other;
    };
    let Some(rir) = text(registry).and_then(|name| name.parse::<Rir>().ok()) else {
        return Line::Other;
    };
    let Some(what) = parse_what(kind, start, value) else {
        return Line::Other;
    };
    let status = text(status).unwrap_or("");
    if status.eq_ignore_ascii_case("available") || status.eq_ignore_ascii_case("reserved") {
        return Line::Undelegated;
    }
    if !(status.eq_ignore_ascii_case("allocated") || status.eq_ignore_ascii_case("assigned")) {
        return Line::Other;
    }
    let Some(cc) = text(cc).and_then(|cc| cc.parse::<Cc>().ok()) else {
        return Line::Other;
    };
    let opaque = fields
        .next()
        .filter(|id| !id.is_empty())
        .map(String::from_utf8_lossy);
    Line::Kept {
        rir,
        cc,
        what,
        opaque,
    }
}

/// Returns a field as UTF-8 text, or `None` if the field is not valid
/// UTF-8.
fn text(field: &[u8]) -> Option<&str> {
    std::str::from_utf8(field).ok()
}

/// Parses a count or a length.
///
/// Only decimal digits are accepted.
fn number(field: &[u8]) -> Option<u64> {
    if field.is_empty() || field.len() > 20 || !field.iter().all(u8::is_ascii_digit) {
        return None;
    }
    text(field)?.parse().ok()
}

/// Parses `type|start|value` into what the line delegates.
fn parse_what(kind: &[u8], start: &[u8], value: &[u8]) -> Option<What> {
    let value = number(value)?;
    match kind {
        b"ipv4" => {
            let addr = text(start)?.parse::<Addr>().ok()?;
            if addr.family() != Family::V4 || value == 0 {
                return None;
            }
            let last = addr.bits().checked_add(u128::from(value) - 1)?;
            Range::new(Family::V4, addr.bits(), last).map(What::Net)
        }
        b"ipv6" => {
            let addr = text(start)?.parse::<Addr>().ok()?;
            if addr.family() != Family::V6 || value > 128 {
                return None;
            }
            let host = u128::MAX.checked_shr(value as u32).unwrap_or(0);
            let first = addr.bits() & !host;
            Range::new(Family::V6, first, first | host).map(What::Net)
        }
        b"asn" => {
            let first = Asn::try_from(number(start)?).ok()?;
            if value == 0 {
                return None;
            }
            let last = Asn::try_from(u64::from(first).checked_add(value - 1)?).ok()?;
            Some(What::As(first, last))
        }
        _ => None,
    }
}

/// One of the three tables of records.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
enum Tab {
    V4 = 0,
    V6 = 1,
    As = 2,
}

impl Tab {
    const ALL: [Tab; 3] = [Tab::V4, Tab::V6, Tab::As];

    fn of(family: Family) -> Self {
        match family {
            Family::V4 => Self::V4,
            Family::V6 => Self::V6,
        }
    }

    fn from_byte(byte: u8) -> Option<Self> {
        Self::ALL.get(usize::from(byte)).copied()
    }

    fn tag(self) -> u16 {
        match self {
            Self::V4 => NETS_V4,
            Self::V6 => NETS_V6,
            Self::As => ASNS,
        }
    }

    /// Returns the width of an address or a number in bytes.
    fn word(self) -> usize {
        match self {
            Self::V6 => 16,
            Self::V4 | Self::As => 4,
        }
    }

    /// Returns the size of a record in bytes.
    fn size(self) -> usize {
        match self {
            Self::V6 => 64,
            Self::V4 | Self::As => 24,
        }
    }

    /// Returns the largest value that an end can have.
    fn max(self) -> u128 {
        match self {
            Self::V6 => u128::MAX,
            Self::V4 | Self::As => u128::from(u32::MAX),
        }
    }
}

/// Returns the index of a registry in [`Rir::ALL`], as a record stores it.
fn rir_byte(rir: Rir) -> u8 {
    Rir::ALL.iter().position(|r| *r == rir).unwrap_or(0) as u8
}

/// A record as parsed, before sorting.
///
/// `W` is `u32` for IPv4 and AS numbers and `u128` for IPv6. Most records
/// are IPv4 or AS blocks, so most records take 20 bytes.
#[derive(Clone, Copy, Debug)]
struct Ent<W> {
    first: W,
    last: W,
    off: u32,
    len: u16,
    cc: Cc,
    rir: u8,
}

/// Builds the index of one stats file from its lines.
#[derive(Default)]
pub(crate) struct StatsBuilder {
    v4: Vec<Ent<u32>>,
    v6: Vec<Ent<u128>>,
    asns: Vec<Ent<u32>>,
    strings: Vec<u8>,
    /// Every id seen so far, with its offset and length in `strings`.
    ids: HashMap<Box<str>, (u32, u16)>,
    seen: bool,
}

impl StatsBuilder {
    /// Creates an empty builder.
    pub(crate) fn new() -> Self {
        Self::default()
    }

    /// Returns the offset and length of `id` in `strings`, and adds `id` on
    /// first sight.
    ///
    /// # Errors
    ///
    /// Returns an error if `strings` grows past 4 GB.
    fn intern(&mut self, id: &str) -> Result<(u32, u16)> {
        // Real ids are short. An id longer than `u16::MAX` bytes is cut at a
        // char boundary.
        let mut id = id;
        if id.len() > usize::from(u16::MAX) {
            let mut end = usize::from(u16::MAX);
            while !id.is_char_boundary(end) {
                end -= 1;
            }
            id = &id[..end];
        }
        if let Some(&place) = self.ids.get(id) {
            return Ok(place);
        }
        let Ok(off) = u32::try_from(self.strings.len()) else {
            return Err(Error::runtime("stats larger than 4 GB"));
        };
        self.strings.extend_from_slice(id.as_bytes());
        let place = (off, id.len() as u16);
        self.ids.insert(id.into(), place);
        Ok(place)
    }
}

impl LineSink for StatsBuilder {
    fn line(&mut self, line: &[u8]) -> Result<Control> {
        let (rir, cc, what, opaque) = match parse_line(line) {
            Line::Kept {
                rir,
                cc,
                what,
                opaque,
            } => (rir, cc, what, opaque),
            Line::Undelegated => {
                self.seen = true;
                return Ok(Control::Continue);
            }
            Line::Other => return Ok(Control::Continue),
        };
        self.seen = true;
        let (off, len) = match &opaque {
            Some(id) => self.intern(id)?,
            None => (0, 0),
        };
        let rir = rir_byte(rir);
        let ent = |first, last| Ent {
            first,
            last,
            off,
            len,
            cc,
            rir,
        };
        match what {
            What::Net(range) if range.family() == Family::V4 => {
                // `Range` guarantees that the ends fit in IPv4.
                let (first, last) = (range.first() as u32, range.last() as u32);
                self.v4.push(ent(first, last));
            }
            What::Net(range) => self.v6.push(Ent {
                first: range.first(),
                last: range.last(),
                off,
                len,
                cc,
                rir,
            }),
            What::As(first, last) => self.asns.push(ent(first, last)),
        }
        Ok(Control::Continue)
    }
}

impl Builder for StatsBuilder {
    fn finish(self) -> Result<Vec<Section>> {
        if !self.seen {
            return Err(no_records());
        }
        let Self {
            v4,
            v6,
            asns,
            strings,
            ids,
            ..
        } = self;
        drop(ids);
        let mut by_opaque: Vec<(u32, u16, u8, u32)> = Vec::new();
        let mut sections = vec![
            encode(Tab::V4, v4, &mut by_opaque)?,
            encode(Tab::V6, v6, &mut by_opaque)?,
            encode(Tab::As, asns, &mut by_opaque)?,
        ];
        let id = |off: u32, len: u16| &strings[off as usize..off as usize + usize::from(len)];
        by_opaque.sort_unstable_by(|a, b| {
            cmp_ids(id(a.0, a.1), id(b.0, b.1)).then((a.2, a.3).cmp(&(b.2, b.3)))
        });
        let mut index = Vec::with_capacity(by_opaque.len() * BY_OPAQUE_SIZE);
        for (off, len, tab, record) in by_opaque {
            index.extend_from_slice(&off.to_le_bytes());
            index.extend_from_slice(&len.to_le_bytes());
            index.push(tab);
            index.push(0);
            index.extend_from_slice(&record.to_le_bytes());
        }
        sections.push(Section::new(BY_OPAQUE, index));
        sections.push(Section::new(STRINGS, strings));
        Ok(sections)
    }
}

/// Sorts the records of one table by `(first, last)` and encodes them.
///
/// Records with equal ends keep the order of the file. The ids of the
/// records go to `by_opaque`. Fails if the table has `u32::MAX` records or
/// more.
fn encode<W: Copy + Ord + Into<u128>>(
    tab: Tab,
    mut entries: Vec<Ent<W>>,
    by_opaque: &mut Vec<(u32, u16, u8, u32)>,
) -> Result<Section> {
    if entries.len() >= u32::MAX as usize {
        return Err(Error::runtime("too many records in the file"));
    }
    // A stable sort, so equal blocks keep the order of the file.
    entries.sort_by_key(|e| (e.first, e.last));
    let mut out = Vec::with_capacity(entries.len() * tab.size());
    let mut reach = 0;
    for (i, e) in entries.iter().enumerate() {
        let (first, last) = (e.first.into(), e.last.into());
        reach = reach.max(last);
        put_word(&mut out, tab, first);
        put_word(&mut out, tab, last);
        put_word(&mut out, tab, reach);
        out.extend_from_slice(&e.off.to_le_bytes());
        out.extend_from_slice(&e.len.to_le_bytes());
        out.extend_from_slice(e.cc.as_str().as_bytes());
        out.push(e.rir);
        out.resize(out.len().next_multiple_of(tab.size()), 0);
        if e.len > 0 {
            by_opaque.push((e.off, e.len, tab as u8, i as u32));
        }
    }
    Ok(Section::new(tab.tag(), out))
}

/// Appends an address or a number in the width of `tab`.
fn put_word(out: &mut Vec<u8>, tab: Tab, value: u128) {
    match tab {
        Tab::V6 => out.extend_from_slice(&value.to_le_bytes()),
        Tab::V4 | Tab::As => out.extend_from_slice(&(value as u32).to_le_bytes()),
    }
}

/// A decoded record.
#[derive(Clone, Copy, Debug)]
struct Rec {
    first: u128,
    last: u128,
    reach: u128,
    off: u32,
    len: u16,
    cc: Cc,
    rir: Rir,
}

/// The index of one stats file in a cache file.
#[derive(Debug)]
pub(crate) struct StatsIndex {
    file: CacheFile,
}

/// The sections of an index, borrowed for one answer.
struct View<'a> {
    tables: [&'a [u8]; 3],
    by_opaque: Table<'a, BY_OPAQUE_SIZE>,
    strings: &'a [u8],
}

impl StatsIndex {
    /// Checks the sections of `file` and wraps it.
    ///
    /// # Errors
    ///
    /// Returns [`Corrupt`] if a section is missing or has a wrong size.
    pub(crate) fn open(file: CacheFile) -> Result<Self, Corrupt> {
        let index = Self { file };
        index.view()?;
        Ok(index)
    }

    /// Returns the number of kept records: the address blocks and the AS
    /// blocks.
    #[cfg(test)] // Only the tests count the records.
    pub(crate) fn len(&self) -> usize {
        self.view()
            .map_or(0, |view| Tab::ALL.iter().map(|tab| view.len(*tab)).sum())
    }

    fn view(&self) -> Result<View<'_>, Corrupt> {
        let mut tables: [&[u8]; 3] = [&[]; 3];
        for tab in Tab::ALL {
            let bytes = self.file.section(tab.tag())?;
            if !bytes.len().is_multiple_of(tab.size())
                || bytes.len() / tab.size() >= u32::MAX as usize
            {
                return Err(Corrupt);
            }
            tables[tab as usize] = bytes;
        }
        Ok(View {
            tables,
            by_opaque: Table::new(self.file.section(BY_OPAQUE)?)?,
            strings: self.file.section(STRINGS)?,
        })
    }

    /// Answers a batch request.
    ///
    /// # Errors
    ///
    /// Returns [`Corrupt`] if a section or a record that the answer reads is
    /// damaged.
    pub(crate) fn answer(&self, request: &StatsRequest) -> Result<StatsAnswer, Corrupt> {
        let view = self.view()?;
        let mut ids = HashMap::new();
        let mut covering = Vec::with_capacity(request.covering.len());
        for range in &request.covering {
            let found = match view.covering(range)? {
                Some((tab, rec)) => Some(view.block(tab, &rec, &mut ids)?),
                None => None,
            };
            covering.push(found);
        }
        let mut hits: Vec<(Tab, u32)> = Vec::new();
        for range in &request.intersecting {
            view.touching(
                Tab::of(range.family()),
                range.first(),
                range.last(),
                &mut hits,
            )?;
        }
        for &(lo, hi) in request.asn.ranges() {
            view.touching(Tab::As, lo.into(), hi.into(), &mut hits)?;
        }
        if request.scans_blocks() {
            for tab in [Tab::V4, Tab::V6] {
                for i in 0..view.len(tab) {
                    let rec = view.record(tab, i)?;
                    if request.all_blocks
                        || request.by_cc.contains(&rec.cc)
                        || request.by_rir.contains(&rec.rir)
                    {
                        hits.push((tab, i as u32));
                    }
                }
            }
        }
        if request.scans_as() {
            for i in 0..view.len(Tab::As) {
                let rec = view.record(Tab::As, i)?;
                if request.all_as
                    || request.as_by_cc.contains(&rec.cc)
                    || request.as_by_rir.contains(&rec.rir)
                {
                    hits.push((Tab::As, i as u32));
                }
            }
        }
        for id in &request.by_opaque {
            view.by_id(id, |tab| tab != Tab::As, &mut hits)?;
        }
        for id in &request.as_by_opaque {
            view.by_id(id, |tab| tab == Tab::As, &mut hits)?;
        }
        hits.sort_unstable();
        hits.dedup();
        let mut answer = StatsAnswer {
            covering,
            ..StatsAnswer::default()
        };
        for (tab, i) in hits {
            let rec = view.record(tab, i as usize)?;
            match tab {
                Tab::As => answer.as_blocks.push(view.as_block(&rec, &mut ids)?),
                Tab::V4 | Tab::V6 => answer.blocks.push(view.block(tab, &rec, &mut ids)?),
            }
        }
        answer.normalize();
        Ok(answer)
    }
}

impl View<'_> {
    fn len(&self, tab: Tab) -> usize {
        self.tables[tab as usize].len() / tab.size()
    }

    fn record(&self, tab: Tab, index: usize) -> Result<Rec, Corrupt> {
        let size = tab.size();
        let start = index.checked_mul(size).ok_or(Corrupt)?;
        let bytes = self.tables[tab as usize]
            .get(start..start + size)
            .ok_or(Corrupt)?;
        let w = tab.word();
        let word = |at: usize| match tab {
            Tab::V6 => u128_at(bytes, at),
            Tab::V4 | Tab::As => u128::from(u32_at(bytes, at)),
        };
        let (first, last, reach) = (word(0), word(w), word(2 * w));
        if first > last || last > reach || reach > tab.max() {
            return Err(Corrupt);
        }
        let off = u32_at(bytes, 3 * w);
        let len = u16_at(bytes, 3 * w + 4);
        if off as usize + usize::from(len) > self.strings.len() {
            return Err(Corrupt);
        }
        let cc = std::str::from_utf8(&bytes[3 * w + 6..3 * w + 8])
            .ok()
            .and_then(|cc| cc.parse::<Cc>().ok())
            .ok_or(Corrupt)?;
        let rir = *Rir::ALL.get(usize::from(bytes[3 * w + 8])).ok_or(Corrupt)?;
        Ok(Rec {
            first,
            last,
            reach,
            off,
            len,
            cc,
            rir,
        })
    }

    /// Returns the first index for which `pred` is false, like
    /// [`slice::partition_point`].
    fn partition(&self, tab: Tab, mut pred: impl FnMut(&Rec) -> bool) -> Result<usize, Corrupt> {
        let (mut lo, mut hi) = (0, self.len(tab));
        while lo < hi {
            let mid = lo + (hi - lo) / 2;
            if pred(&self.record(tab, mid)?) {
                lo = mid + 1;
            } else {
                hi = mid;
            }
        }
        Ok(lo)
    }

    /// Returns the narrowest block that contains `range`, or `None` if no
    /// block does.
    fn covering(&self, range: &Range) -> Result<Option<(Tab, Rec)>, Corrupt> {
        let tab = Tab::of(range.family());
        let (first, last) = (range.first(), range.last());
        let end = self.partition(tab, |r| r.first <= first)?;
        let mut best: Option<(Rec, (u128, std::cmp::Reverse<u128>))> = None;
        for i in (0..end).rev() {
            let rec = self.record(tab, i)?;
            if rec.reach < last {
                break;
            }
            if rec.first <= first && rec.last >= last {
                let key = cover_key(rec.first, rec.last);
                // The walk goes backward, so with `<=` an equal key earlier in
                // the file wins.
                if best.as_ref().is_none_or(|(_, best)| key <= *best) {
                    best = Some((rec, key));
                }
            }
        }
        Ok(best.map(|(rec, _)| (tab, rec)))
    }

    /// Adds to `hits` the records of `tab` that share a value with
    /// `lo..=hi`.
    fn touching(
        &self,
        tab: Tab,
        lo: u128,
        hi: u128,
        hits: &mut Vec<(Tab, u32)>,
    ) -> Result<(), Corrupt> {
        let start = self.partition(tab, |r| r.first < lo)?;
        let end = self.partition(tab, |r| r.first <= hi)?.max(start);
        hits.extend((start..end).map(|i| (tab, i as u32)));
        for i in (0..start).rev() {
            let rec = self.record(tab, i)?;
            if rec.reach < lo {
                break;
            }
            if rec.last >= lo {
                hits.push((tab, i as u32));
            }
        }
        Ok(())
    }

    /// Adds to `hits` the records with the id `id` whose table passes
    /// `keep`.
    ///
    /// The comparison ignores ASCII case.
    fn by_id(
        &self,
        id: &str,
        keep: impl Fn(Tab) -> bool,
        hits: &mut Vec<(Tab, u32)>,
    ) -> Result<(), Corrupt> {
        let key = id.as_bytes();
        let table = &self.by_opaque;
        let mut failed = false;
        let mut cmp = |record: &[u8; BY_OPAQUE_SIZE]| match self.string(record) {
            Some(text) => cmp_ids(text, key),
            None => {
                failed = true;
                Ordering::Equal
            }
        };
        let start = table.partition_point(0, table.len(), |r| cmp(r) == Ordering::Less)?;
        let end = table.partition_point(start, table.len(), |r| cmp(r) != Ordering::Greater)?;
        if failed {
            return Err(Corrupt);
        }
        for k in start..end {
            let record = table.get(k)?;
            let tab = Tab::from_byte(record[6]).ok_or(Corrupt)?;
            let index = u32_at(record, 8);
            if index as usize >= self.len(tab) {
                return Err(Corrupt);
            }
            if keep(tab) {
                hits.push((tab, index));
            }
        }
        Ok(())
    }

    /// Returns the id of a `by_opaque` record, or `None` if the id lies
    /// outside `strings`.
    fn string(&self, record: &[u8; BY_OPAQUE_SIZE]) -> Option<&[u8]> {
        let off = u32_at(record, 0) as usize;
        let len = usize::from(u16_at(record, 4));
        self.strings.get(off..off + len)
    }

    /// Returns the opaque id of a record.
    ///
    /// The blocks of one answer share one copy of each id.
    fn opaque(
        &self,
        rec: &Rec,
        ids: &mut HashMap<u32, Arc<str>>,
    ) -> Result<Option<Arc<str>>, Corrupt> {
        if rec.len == 0 {
            return Ok(None);
        }
        if let Some(id) = ids.get(&rec.off)
            && id.len() == usize::from(rec.len)
        {
            return Ok(Some(id.clone()));
        }
        let start = rec.off as usize;
        let bytes = self
            .strings
            .get(start..start + usize::from(rec.len))
            .ok_or(Corrupt)?;
        let id: Arc<str> = std::str::from_utf8(bytes).map_err(|_| Corrupt)?.into();
        ids.insert(rec.off, id.clone());
        Ok(Some(id))
    }

    fn block(
        &self,
        tab: Tab,
        rec: &Rec,
        ids: &mut HashMap<u32, Arc<str>>,
    ) -> Result<Block, Corrupt> {
        let family = match tab {
            Tab::V4 => Family::V4,
            Tab::V6 => Family::V6,
            Tab::As => return Err(Corrupt),
        };
        Ok(Block {
            rir: rec.rir,
            range: Range::new(family, rec.first, rec.last).ok_or(Corrupt)?,
            cc: rec.cc,
            opaque_id: self.opaque(rec, ids)?,
        })
    }

    fn as_block(&self, rec: &Rec, ids: &mut HashMap<u32, Arc<str>>) -> Result<AsBlock, Corrupt> {
        Ok(AsBlock {
            rir: rec.rir,
            first: Asn::try_from(rec.first).map_err(|_| Corrupt)?,
            last: Asn::try_from(rec.last).map_err(|_| Corrupt)?,
            cc: rec.cc,
            opaque_id: self.opaque(rec, ids)?,
        })
    }
}

/// Answers a [`StatsRequest`] while one stats file downloads, without the
/// cache.
pub(crate) struct StatsStream<'a> {
    request: &'a StatsRequest,
    /// The `intersecting` ranges, by family.
    intersecting: [RangeQuery; 2],
    /// The covering ranges, by family, sorted.
    ///
    /// Each range is `(first, last, position in the request)`.
    covering: [Vec<(u128, u128, usize)>; 2],
    best: Vec<Option<Block>>,
    blocks: Vec<Block>,
    as_blocks: Vec<AsBlock>,
    /// One shared copy of each id of the kept blocks.
    ids: HashMap<Box<str>, Arc<str>>,
    seen: bool,
}

impl<'a> StatsStream<'a> {
    /// Creates a stream that answers `request`.
    pub(crate) fn new(request: &'a StatsRequest) -> Self {
        let covering = [Family::V4, Family::V6].map(|family| {
            let mut queries: Vec<(u128, u128, usize)> = request
                .covering
                .iter()
                .enumerate()
                .filter(|(_, range)| range.family() == family)
                .map(|(i, range)| (range.first(), range.last(), i))
                .collect();
            queries.sort_unstable();
            queries
        });
        Self {
            request,
            intersecting: [Family::V4, Family::V6]
                .map(|family| RangeQuery::new(family, &request.intersecting)),
            covering,
            best: vec![None; request.covering.len()],
            blocks: Vec::new(),
            as_blocks: Vec::new(),
            ids: HashMap::new(),
            seen: false,
        }
    }

    /// Ends the input and returns the answer.
    ///
    /// # Errors
    ///
    /// Returns an error if the input held no record of any status.
    pub(crate) fn finish(self) -> Result<StatsAnswer> {
        if !self.seen {
            return Err(no_records());
        }
        let mut answer = StatsAnswer {
            blocks: self.blocks,
            covering: self.best,
            as_blocks: self.as_blocks,
        };
        answer.normalize();
        Ok(answer)
    }

    /// Returns the shared copy of `id`, and creates the copy on first sight.
    fn share(&mut self, id: Option<&str>) -> Option<Arc<str>> {
        let id = id?;
        if let Some(shared) = self.ids.get(id) {
            return Some(shared.clone());
        }
        let shared: Arc<str> = id.into();
        self.ids.insert(id.into(), shared.clone());
        Some(shared)
    }

    fn net(&mut self, rir: Rir, cc: Cc, range: Range, opaque: Option<&str>) {
        let fam = Tab::of(range.family()) as usize;
        let (first, last) = (range.first(), range.last());
        let queries = &self.covering[fam];
        // A covering range that this block contains starts inside the block.
        let lo = queries.partition_point(|(f, _, _)| *f < first);
        let hi = queries.partition_point(|(f, _, _)| *f <= last).max(lo);
        let mut block: Option<Block> = None;
        for k in lo..hi {
            let (_, q_last, at) = self.covering[fam][k];
            if q_last > last {
                continue;
            }
            if self.best[at]
                .as_ref()
                .is_some_and(|best| !narrower(&range, &best.range))
            {
                continue;
            }
            if block.is_none() {
                block = Some(Block {
                    rir,
                    range,
                    cc,
                    opaque_id: self.share(opaque),
                });
            }
            self.best[at] = block.clone();
        }
        let wanted = self.request.wants_block(cc, rir, &Opaque(opaque))
            || self.intersecting[fam].intersects(first, last);
        if wanted {
            let block = match block {
                Some(block) => block,
                None => Block {
                    rir,
                    range,
                    cc,
                    opaque_id: self.share(opaque),
                },
            };
            self.blocks.push(block);
        }
    }

    fn asn(&mut self, rir: Rir, cc: Cc, first: Asn, last: Asn, opaque: Option<&str>) {
        if self.request.wants_as(cc, rir, &Opaque(opaque))
            || asn_touches(&self.request.asn, first, last)
        {
            let opaque_id = self.share(opaque);
            self.as_blocks.push(AsBlock {
                rir,
                first,
                last,
                cc,
                opaque_id,
            });
        }
    }
}

impl LineSink for StatsStream<'_> {
    fn line(&mut self, line: &[u8]) -> Result<Control> {
        match parse_line(line) {
            Line::Kept {
                rir,
                cc,
                what,
                opaque,
            } => {
                self.seen = true;
                match what {
                    What::Net(range) => self.net(rir, cc, range, opaque.as_deref()),
                    What::As(first, last) => self.asn(rir, cc, first, last, opaque.as_deref()),
                }
            }
            Line::Undelegated => self.seen = true,
            Line::Other => {}
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

    const TEXT: &str = "\
# synthetic delegated stats
2|ripencc|1760745599|12|19850701|20261017|+0100
ripencc|*|ipv4|*|5|summary
ripencc|*|asn|*|4|summary
ripencc|*|ipv6|*|2|summary
ripencc|XD|ipv4|192.0.2.0|128|20100712|allocated|org-a
ripencc|xd|ipv4|192.0.2.128|64|20100712|ASSIGNED|ORG-B|e-stats
ripencc|XC|ipv4|198.18.0.0|384|20110101|allocated|org-a
ripencc||ipv4|203.0.113.0|256||available|
ripencc|ZZ|ipv4|192.0.2.192|64||reserved|
ripencc|XD|ipv6|2001:db8::|32|19990826|allocated|org-a
ripencc|XJ|ipv6|2001:db8:1::5|48|19990826|assigned|
ripencc|XD|asn|64496|4|20020101|assigned|org-a
ripencc|XC|asn|64500|1|20020101|allocated|org-c
ripencc||asn|64501|10||available|
arin|XE|asn|64511|1|20020101|assigned|ORG-B
ripencc|XD|ipv4|not-an-address|256|20100712|allocated|x
ripencc|XD|ipv4|10.0.0.0|0|20100712|allocated|x
ripencc|XD|ipv4|255.255.255.0|512|20100712|allocated|x
ripencc|XD|ipv6|2001:db8::|129|20100712|allocated|x
ripencc|XD|asn|4294967295|2|20100712|allocated|x
ripencc|N|ipv4|10.0.0.0|256|20100712|allocated|x
ripencc|XD|ipv4|10.0.0.0|256|20100712|transferred|x
nobody|XD|ipv4|10.0.0.0|256|20100712|allocated|x
ripencc|XD|ipv4|10.0.0.0
<html>not stats</html>

";

    fn feed(sink: &mut dyn LineSink, text: &[u8]) {
        let mut splitter = LineSplitter::new();
        for chunk in text.chunks(11) {
            splitter.push(chunk, sink).unwrap();
        }
        splitter.finish(sink).unwrap();
    }

    fn sections_of(text: &str) -> Result<Vec<Section>> {
        let mut builder = StatsBuilder::new();
        feed(&mut builder, text.as_bytes());
        builder.finish()
    }

    fn file_of(text: &str) -> Vec<u8> {
        file_of_sections(&sections_of(text).unwrap())
    }

    fn file_of_sections(sections: &[Section]) -> Vec<u8> {
        let mut bytes = Vec::new();
        container::write(&mut bytes, 0x14, &Validators::default(), "u", sections).unwrap();
        bytes
    }

    fn open(bytes: Vec<u8>) -> Result<StatsIndex, Corrupt> {
        StatsIndex::open(CacheFile::new(MappedFile::from_vec(bytes)).map_err(|_| Corrupt)?)
    }

    fn stream(text: &str, request: &StatsRequest) -> Result<StatsAnswer> {
        let mut stream = StatsStream::new(request);
        feed(&mut stream, text.as_bytes());
        stream.finish()
    }

    /// Answers with the index and the stream, and checks that the answers
    /// agree.
    fn both(text: &str, request: &StatsRequest) -> StatsAnswer {
        let indexed = open(file_of(text)).unwrap().answer(request).unwrap();
        let streamed = stream(text, request).unwrap();
        assert_eq!(indexed, streamed, "{request:?}");
        indexed
    }

    fn r(text: &str) -> Range {
        text.parse().unwrap()
    }

    fn cc(text: &str) -> Cc {
        text.parse().unwrap()
    }

    fn ranges(blocks: &[Block]) -> Vec<String> {
        blocks.iter().map(|b| b.range.to_string()).collect()
    }

    fn all() -> StatsRequest {
        StatsRequest {
            all_blocks: true,
            all_as: true,
            ..StatsRequest::default()
        }
    }

    #[test]
    fn parses_lines() {
        let answer = both(TEXT, &all());
        assert_eq!(
            ranges(&answer.blocks),
            [
                "192.0.2.0/25",
                "192.0.2.128/26",
                "198.18.0.0-198.18.1.127",
                "2001:db8::/32",
                "2001:db8:1::/48",
            ]
        );
        let first = &answer.blocks[0];
        assert_eq!(
            (first.rir, first.cc, first.opaque_id.as_deref()),
            (Rir::Ripencc, cc("XD"), Some("org-a"))
        );
        // The country and the status ignore case, and the id keeps its case.
        // The extensions are ignored, and an empty id is `None`.
        assert_eq!(answer.blocks[1].cc, cc("XD"));
        assert_eq!(answer.blocks[1].opaque_id.as_deref(), Some("ORG-B"));
        assert_eq!(answer.blocks[4].opaque_id, None);
        assert_eq!(answer.blocks[4].cc, cc("XJ"));
        let ases: Vec<(Asn, Asn, Rir)> = answer
            .as_blocks
            .iter()
            .map(|b| (b.first, b.last, b.rir))
            .collect();
        assert_eq!(
            ases,
            [
                (64496, 64499, Rir::Ripencc),
                (64500, 64500, Rir::Ripencc),
                (64511, 64511, Rir::Arin),
            ]
        );
        // One id is stored once and shared by the blocks of an answer.
        assert!(Arc::ptr_eq(
            answer.blocks[0].opaque_id.as_ref().unwrap(),
            answer.as_blocks[0].opaque_id.as_ref().unwrap()
        ));
        assert_eq!(open(file_of(TEXT)).unwrap().len(), 8);
        assert_eq!(
            parse_line(b"ripencc|XD|ipv4|10.0.0.0|256|x|available"),
            Line::Undelegated
        );
        assert_eq!(parse_line(b"2|ripencc|1|2|3|4|+0100"), Line::Other);
    }

    #[test]
    fn covering_blocks() {
        let request = StatsRequest {
            covering: vec![
                r("192.0.2.1"),
                r("192.0.2.128/26"),
                r("192.0.2.0/24"),
                r("198.18.1.100"),
                r("198.18.1.128"),
                r("203.0.113.1"),
                r("2001:db8:1::/64"),
                r("2001:db8:2::1"),
                r("3fff::"),
            ],
            ..StatsRequest::default()
        };
        let answer = both(TEXT, &request);
        let got: Vec<Option<String>> = answer
            .covering
            .iter()
            .map(|b| b.as_ref().map(|b| b.range.to_string()))
            .collect();
        let want = [
            Some("192.0.2.0/25"),
            Some("192.0.2.128/26"),
            None,
            Some("198.18.0.0-198.18.1.127"),
            None,
            None, // An `available` block is not kept.
            Some("2001:db8:1::/48"),
            Some("2001:db8::/32"),
            None,
        ];
        assert_eq!(got, want.map(|w| w.map(str::to_owned)));
        assert!(answer.blocks.is_empty() && answer.as_blocks.is_empty());
    }

    #[test]
    fn requests_by_range_country_registry_and_id() {
        let touching = both(
            TEXT,
            &StatsRequest {
                intersecting: vec![r("192.0.2.100-192.0.2.130"), r("2001:db8:1::/40")],
                ..StatsRequest::default()
            },
        );
        assert_eq!(
            ranges(&touching.blocks),
            [
                "192.0.2.0/25",
                "192.0.2.128/26",
                "2001:db8::/32",
                "2001:db8:1::/48"
            ]
        );
        let by_cc = both(
            TEXT,
            &StatsRequest {
                by_cc: vec![cc("xc"), cc("XJ")],
                as_by_cc: vec![cc("XE")],
                ..StatsRequest::default()
            },
        );
        assert_eq!(
            ranges(&by_cc.blocks),
            ["198.18.0.0-198.18.1.127", "2001:db8:1::/48"]
        );
        assert_eq!(by_cc.as_blocks.len(), 1);
        assert_eq!(by_cc.as_blocks[0].first, 64511);
        let by_rir = both(
            TEXT,
            &StatsRequest {
                by_rir: vec![Rir::Arin],
                as_by_rir: vec![Rir::Arin],
                ..StatsRequest::default()
            },
        );
        assert!(by_rir.blocks.is_empty());
        assert_eq!(by_rir.as_blocks.len(), 1);
        let by_id = both(
            TEXT,
            &StatsRequest {
                by_opaque: vec!["org-b".into(), "nobody".into()],
                as_by_opaque: vec!["ORG-A".into()],
                ..StatsRequest::default()
            },
        );
        assert_eq!(ranges(&by_id.blocks), ["192.0.2.128/26"]);
        assert_eq!(
            (by_id.as_blocks.len(), by_id.as_blocks[0].first),
            (1, 64496)
        );
        let by_asn = both(
            TEXT,
            &StatsRequest {
                asn: AsnSet::from_ranges([(64499, 64499), (64501, 64511)]),
                ..StatsRequest::default()
            },
        );
        let firsts: Vec<Asn> = by_asn.as_blocks.iter().map(|b| b.first).collect();
        assert_eq!(firsts, [64496, 64511]);
        let request = StatsRequest::default();
        assert!(request.is_empty() && !all().is_empty());
        assert_eq!(both(TEXT, &request), StatsAnswer::empty(&request));
    }

    #[test]
    fn a_file_without_records_is_an_error() {
        for text in [
            "",
            "# only a comment\n2|apnic|1|0|2|3|+1000\n",
            "<html>\n</html>\n",
        ] {
            assert_eq!(
                sections_of(text).unwrap_err().message(),
                "no records in the file"
            );
            assert!(stream(text, &all()).is_err());
        }
        // A file with only undelegated blocks is valid and empty.
        let text = "afrinic||ipv4|192.0.2.0|256||available|\n";
        let index = open(file_of(text)).unwrap();
        assert_eq!(index.len(), 0);
        assert_eq!(index.answer(&all()).unwrap(), StatsAnswer::default());
        assert_eq!(stream(text, &all()).unwrap(), StatsAnswer::default());
    }

    #[test]
    fn merges_the_answers_of_registries() {
        let block = |rir, range: &str| Block {
            rir,
            range: r(range),
            cc: cc("XD"),
            opaque_id: None,
        };
        let a = StatsAnswer {
            blocks: vec![block(Rir::Ripencc, "192.0.2.0/24")],
            covering: vec![Some(block(Rir::Ripencc, "192.0.2.0/24")), None],
            as_blocks: Vec::new(),
        };
        let b = StatsAnswer {
            blocks: vec![
                block(Rir::Arin, "10.0.0.0/8"),
                block(Rir::Ripencc, "192.0.2.0/24"),
            ],
            covering: vec![
                Some(block(Rir::Arin, "192.0.2.0/25")),
                Some(block(Rir::Arin, "10.0.0.0/8")),
            ],
            as_blocks: Vec::new(),
        };
        let merged = StatsAnswer::merge([a.clone(), b]);
        assert_eq!(ranges(&merged.blocks), ["10.0.0.0/8", "192.0.2.0/24"]);
        assert_eq!(merged.covering[0].as_ref().unwrap().rir, Rir::Arin);
        assert_eq!(merged.covering[1].as_ref().unwrap().rir, Rir::Arin);
        // A tie goes to the first answer.
        let c = StatsAnswer {
            covering: vec![Some(block(Rir::Apnic, "192.0.2.0/24")), None],
            ..StatsAnswer::default()
        };
        let merged = StatsAnswer::merge([a, c]);
        assert_eq!(merged.covering[0].as_ref().unwrap().rir, Rir::Ripencc);
    }

    #[test]
    fn damaged_indexes_are_corrupt_not_panics() {
        let good = file_of(TEXT);
        let mut requests = vec![
            all(),
            StatsRequest {
                covering: vec![r("192.0.2.130"), r("2001:db8:1::1"), r("198.18.0.0/24")],
                intersecting: vec![r("192.0.2.0/24"), r("2001:db8::/32")],
                by_opaque: vec!["org-a".into(), "ORG-B".into()],
                as_by_opaque: vec!["org-c".into()],
                asn: AsnSet::all(),
                ..StatsRequest::default()
            },
        ];
        requests.push(StatsRequest {
            by_cc: vec![cc("XD")],
            as_by_rir: vec![Rir::Arin],
            ..StatsRequest::default()
        });
        let layout = container::Layout::parse(&good).unwrap();
        let start =
            layout.section(&good, NETS_V4).unwrap().as_ptr() as usize - good.as_ptr() as usize;
        let mut rng = Rng::new(9);
        let mut corrupt = 0;
        for _ in 0..3000 {
            let mut damaged = good.clone();
            for _ in 0..1 + rng.below(3) {
                let at = start + rng.below((good.len() - start) as u64) as usize;
                damaged[at] = rng.next() as u8;
            }
            for request in &requests {
                if open(damaged.clone())
                    .and_then(|index| index.answer(request))
                    .is_err()
                {
                    corrupt += 1;
                }
            }
        }
        assert!(corrupt > 0);

        // Targeted damage: a registry past `Rir::ALL`, an id past the end of
        // `strings`, and `by_opaque` entries that point past their table.
        let nets = layout.section(&good, NETS_V4).unwrap();
        let nets_at = nets.as_ptr() as usize - good.as_ptr() as usize;
        let mut bad_rir = good.clone();
        bad_rir[nets_at + 3 * 4 + 8] = 5;
        assert_eq!(open(bad_rir).unwrap().answer(&all()).unwrap_err(), Corrupt);
        let mut bad_id = good.clone();
        bad_id[nets_at + 12..nets_at + 16].copy_from_slice(&u32::MAX.to_le_bytes());
        assert_eq!(open(bad_id).unwrap().answer(&all()).unwrap_err(), Corrupt);
        let ids = layout.section(&good, BY_OPAQUE).unwrap();
        let ids_at = ids.as_ptr() as usize - good.as_ptr() as usize;
        let mut bad_ref = good.clone();
        for k in 0..ids.len() / BY_OPAQUE_SIZE {
            let at = ids_at + k * BY_OPAQUE_SIZE + 8;
            bad_ref[at..at + 4].copy_from_slice(&1000u32.to_le_bytes());
        }
        let request = StatsRequest {
            by_opaque: vec!["org-a".into()],
            ..StatsRequest::default()
        };
        assert_eq!(
            open(bad_ref).unwrap().answer(&request).unwrap_err(),
            Corrupt
        );

        // A missing section and a section of a wrong size.
        let sections = sections_of(TEXT).unwrap();
        let missing: Vec<Section> = sections
            .iter()
            .filter(|s| s.tag != STRINGS)
            .cloned()
            .collect();
        assert_eq!(open(file_of_sections(&missing)).unwrap_err(), Corrupt);
        let odd: Vec<Section> = sections
            .iter()
            .map(|s| {
                let mut s = s.clone();
                if s.tag == NETS_V6 {
                    s.data.push(0);
                }
                s
            })
            .collect();
        assert_eq!(open(file_of_sections(&odd)).unwrap_err(), Corrupt);
    }

    /// A kept record of a random file, for the brute-force answers.
    #[derive(Clone, Debug)]
    struct Kept {
        rir: Rir,
        cc: Cc,
        what: What,
        opaque: Option<String>,
    }

    const CCS: [&str; 3] = ["XD", "XC", "XE"];
    const IDS: [&str; 4] = ["org-a", "ORG-B", "org-c", "Org-A"];

    /// Returns a random file and its kept records in the order of the file.
    ///
    /// The file covers the documentation networks and has overlaps,
    /// duplicates, undelegated blocks, and garbage lines.
    fn random_file(rng: &mut Rng) -> (String, Vec<Kept>) {
        let bases = [0xc000_0200u128, 0xc633_6400, 0xcb00_7100];
        let mut text = String::from("2|ripencc|1|1|2|3|+0100\n");
        let mut kept = Vec::new();
        for _ in 0..1 + rng.below(40) {
            let rir = [Rir::Ripencc, Rir::Arin][rng.below(2) as usize];
            let cc = CCS[rng.below(3) as usize];
            let opaque = (rng.below(4) != 0).then(|| IDS[rng.below(4) as usize].to_owned());
            let status = ["allocated", "assigned", "available", "reserved"]
                [usize::from(rng.below(8) >= 6) * (2 + rng.below(2) as usize)];
            let (kind, start, value, what) = match rng.below(3) {
                0 => {
                    let first = bases[rng.below(3) as usize] + u128::from(rng.below(512) as u32);
                    let count = 1 + rng.below(300);
                    let addr = Addr::new(Family::V4, first).unwrap();
                    let range =
                        Range::new(Family::V4, first, first + u128::from(count) - 1).unwrap();
                    ("ipv4", addr.to_string(), count, What::Net(range))
                }
                1 => {
                    let len = 32 + rng.below(17) as u32;
                    let first = (0x2001_0db8u128 << 96) | (u128::from(rng.below(64)) << 80);
                    let host = u128::MAX >> len;
                    let first = first & !host;
                    let addr = Addr::new(Family::V6, first).unwrap();
                    let range = Range::new(Family::V6, first, first | host).unwrap();
                    ("ipv6", addr.to_string(), u64::from(len), What::Net(range))
                }
                _ => {
                    let first = 64496 + rng.below(16) as u32;
                    let count = 1 + rng.below(4);
                    let what = What::As(first, first + count as u32 - 1);
                    ("asn", first.to_string(), count, what)
                }
            };
            text.push_str(&format!(
                "{rir}|{cc}|{kind}|{start}|{value}|20200101|{status}|{}\n",
                opaque.as_deref().unwrap_or("")
            ));
            if status.starts_with('a') && status != "available" {
                kept.push(Kept {
                    rir,
                    cc: cc.parse().unwrap(),
                    what,
                    opaque,
                });
            }
            if rng.below(10) == 0 {
                text.push_str("ripencc|*|ipv4|*|3|summary\ngarbage|line\n");
            }
        }
        (text, kept)
    }

    fn random_range(rng: &mut Rng) -> Range {
        if rng.below(4) == 0 {
            let first = (0x2001_0db8u128 << 96) | (u128::from(rng.below(64)) << 80);
            let last = first + (u128::from(rng.below(4)) << 78);
            return Range::new(Family::V6, first, last).unwrap();
        }
        let base = [0xc000_0200u128, 0xc633_6400, 0xcb00_7100][rng.below(3) as usize];
        let first = base + u128::from(rng.below(700) as u32);
        let last = first + u128::from(rng.below(100) as u32);
        Range::new(Family::V4, first, last).unwrap()
    }

    /// Computes the answer from the definitions, by a check of every kept
    /// record.
    fn brute_force(kept: &[Kept], request: &StatsRequest) -> StatsAnswer {
        let block = |k: &Kept, range: Range| Block {
            rir: k.rir,
            range,
            cc: k.cc,
            opaque_id: k.opaque.as_deref().map(Arc::from),
        };
        let has = |ids: &[Arc<str>], k: &Kept| {
            k.opaque
                .as_deref()
                .is_some_and(|id| ids.iter().any(|w| w.eq_ignore_ascii_case(id)))
        };
        let mut answer = StatsAnswer::default();
        for q in &request.covering {
            let mut best: Option<Block> = None;
            for k in kept {
                if let What::Net(range) = k.what
                    && range.contains(q)
                    && best.as_ref().is_none_or(|b| narrower(&range, &b.range))
                {
                    best = Some(block(k, range));
                }
            }
            answer.covering.push(best);
        }
        for k in kept {
            match k.what {
                What::Net(range) => {
                    if request.all_blocks
                        || request.by_cc.contains(&k.cc)
                        || request.by_rir.contains(&k.rir)
                        || has(&request.by_opaque, k)
                        || request.intersecting.iter().any(|i| i.intersects(&range))
                    {
                        answer.blocks.push(block(k, range));
                    }
                }
                What::As(first, last) => {
                    if request.all_as
                        || request.as_by_cc.contains(&k.cc)
                        || request.as_by_rir.contains(&k.rir)
                        || has(&request.as_by_opaque, k)
                        || (first..=last).any(|asn| request.asn.contains(asn))
                    {
                        answer.as_blocks.push(AsBlock {
                            rir: k.rir,
                            first,
                            last,
                            cc: k.cc,
                            opaque_id: k.opaque.as_deref().map(Arc::from),
                        });
                    }
                }
            }
        }
        answer.normalize();
        answer
    }

    #[test]
    fn indexed_streaming_and_brute_force_agree() {
        let mut rng = Rng::new(17);
        let (mut found, mut covered) = (0, 0);
        for _ in 0..400 {
            let (text, kept) = random_file(&mut rng);
            let mut request = StatsRequest {
                all_blocks: rng.below(12) == 0,
                all_as: rng.below(12) == 0,
                ..StatsRequest::default()
            };
            for _ in 0..rng.below(6) {
                let range = random_range(&mut rng);
                match rng.below(3) {
                    0 => request.covering.push(Range::from_addr(range.first_addr())),
                    1 => request.covering.push(range),
                    _ => request.intersecting.push(range),
                }
            }
            for _ in 0..rng.below(3) {
                let lo = 64494 + rng.below(20) as u32;
                let mut ranges = request.asn.ranges().to_vec();
                ranges.push((lo, lo + rng.below(3) as u32));
                request.asn = AsnSet::from_ranges(ranges);
            }
            if rng.below(4) == 0 {
                request
                    .by_cc
                    .push(CCS[rng.below(3) as usize].parse().unwrap());
            }
            if rng.below(4) == 0 {
                request
                    .as_by_cc
                    .push(CCS[rng.below(3) as usize].parse().unwrap());
            }
            if rng.below(6) == 0 {
                request.by_rir.push(Rir::Arin);
            }
            if rng.below(6) == 0 {
                request.as_by_rir.push(Rir::Ripencc);
            }
            if rng.below(3) == 0 {
                request.by_opaque.push(IDS[rng.below(4) as usize].into());
            }
            if rng.below(3) == 0 {
                request.as_by_opaque.push(IDS[rng.below(4) as usize].into());
            }
            let answer = both(&text, &request);
            assert_eq!(answer, brute_force(&kept, &request), "{text}\n{request:?}");
            found += answer.blocks.len() + answer.as_blocks.len();
            covered += answer.covering.iter().flatten().count();
        }
        // The answers are not trivially empty.
        assert!(found > 1000 && covered > 100, "{found} {covered}");
    }

    /// Builds the indexes of synthetic stats, for measuring the peak memory
    /// from outside the process.
    ///
    /// The five synthetic files together have about 250 thousand lines, the
    /// size of the real five. The test holds all five builders at once, as
    /// `prepare` does. Run it with:
    ///
    /// `/usr/bin/time -l target/debug/deps/netf-… stats::tests::peak_memory --ignored`
    ///
    /// The test generates the files into `target/` and downloads nothing.
    #[test]
    #[ignore = "builds 250k lines of synthetic stats in target/; measure with time -l"]
    fn peak_memory() {
        use std::io::{BufWriter, Read as _, Write as _};

        const LINES: [(Rir, u32); 5] = [
            (Rir::Ripencc, 100_000),
            (Rir::Arin, 70_000),
            (Rir::Apnic, 50_000),
            (Rir::Lacnic, 20_000),
            (Rir::Afrinic, 10_000),
        ];
        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("target");
        let mut rng = Rng::new(11);
        let mut base4: u32 = 0xF000_0000;
        let mut base6: u128 = 0xfc00_0000u128 << 96;
        let mut asn: u32 = 4_200_000_000;
        let mut builders = Vec::new();
        for (rir, lines) in LINES {
            let path = dir.join(format!("stats-synthetic-{rir}.txt"));
            {
                let mut out = BufWriter::new(std::fs::File::create(&path).unwrap());
                writeln!(out, "2|{rir}|1|{lines}|19850701|20261017|+0000").unwrap();
                writeln!(out, "{rir}|*|ipv4|*|{}|summary", lines / 2).unwrap();
                for i in 0..lines {
                    let cc = ["XD", "XC", "XE", "XA", "XH", "XK", "XI"][rng.below(7) as usize];
                    // About one holder per three records, with ids of 36
                    // bytes.
                    let id = format!("{:08x}-0000-4000-8000-{:012x}", i / 3, i / 3 * 7919);
                    let status = if rng.below(20) == 0 {
                        "available"
                    } else {
                        ["allocated", "assigned"][rng.below(2) as usize]
                    };
                    match rng.below(20) {
                        0..12 => {
                            let count = [256u32, 512, 1024, 768, 4096][rng.below(5) as usize];
                            let addr = std::net::Ipv4Addr::from(base4);
                            writeln!(out, "{rir}|{cc}|ipv4|{addr}|{count}|20100101|{status}|{id}")
                                .unwrap();
                            base4 += count;
                        }
                        12..15 => {
                            let addr = std::net::Ipv6Addr::from(base6);
                            writeln!(out, "{rir}|{cc}|ipv6|{addr}|32|20100101|{status}|{id}")
                                .unwrap();
                            base6 += 1u128 << 96;
                        }
                        _ => {
                            writeln!(out, "{rir}|{cc}|asn|{asn}|1|20100101|{status}|{id}").unwrap();
                            asn += 1;
                        }
                    }
                }
                out.flush().unwrap();
            }
            let mut file = std::fs::File::open(&path).unwrap();
            let mut builder = StatsBuilder::new();
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
            builders.push(builder);
        }
        let sections: Vec<Vec<Section>> = builders
            .into_iter()
            .map(|builder| builder.finish().unwrap())
            .collect();
        let size: usize = sections.iter().flatten().map(|s| s.data.len()).sum();
        let lines: u32 = LINES.iter().map(|(_, n)| n).sum();
        eprintln!(
            "stats synthetic: {lines} lines, sections {:.1} MB",
            size as f64 / 1e6
        );
    }
}
