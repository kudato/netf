//! The `asn.txt` dataset: AS numbers with their names, organization texts,
//! and countries.
//!
//! # Line format
//!
//! ```text
//! 64496 EXAMPLE-AS Example Networks LLC, NL
//! 64497 DOC-NET - Documentation, Inc., US
//! 64498 NO-COUNTRY-AS
//! ```
//!
//! A line holds the number and then the rest of the line, `raw`, which netf
//! keeps whole for the `no networks` notice. If the text after the last
//! comma is exactly two letters, that text is the country. The name is the
//! first word of `raw`, and the organization text is the text between the
//! name and the country, without a leading `- `. Without a country,
//! everything after the name is the organization text.
//!
//! The file is mostly UTF-8 with some Latin-1, and the parser replaces
//! invalid bytes with U+FFFD. The parser skips a line without a number. A
//! file without a single AS is an error. If a number appears twice, the
//! first line wins.
//!
//! # Index layout
//!
//! | tag | section | record |
//! |---|---|---|
//! | 1 | `entries` | 20 bytes: `asn u32, raw_off u32, raw_len u16, name_len u16, org_start u16, org_len u16, cc [u8; 2], pad 2`, sorted by `asn` |
//! | 2 | `strings` | the `raw` texts, UTF-8 |
//!
//! The name starts the raw text and the organization text lies inside it,
//! so the index stores each line once. A lookup by number uses binary
//! search. A search by name or country reads all 120 thousand entries, which
//! takes a few milliseconds on the mapped file.

use std::{borrow::Cow, collections::HashMap};

use crate::{
    cache::{
        Builder, CacheFile,
        container::{Corrupt, Section, Table, u16_at, u32_at},
    },
    dataset::{AsnSet, ris::parse_asn},
    error::{Error, Result},
    fetch::lines::{Control, LineSink},
    model::{Asn, AsnEntry, Cc},
    text::Pattern,
};

/// The tag of the `entries` section.
const ENTRIES: u16 = 1;
/// The tag of the `strings` section.
const STRINGS: u16 = 2;
/// The size of an `entries` record.
const ENTRY: usize = 20;

/// A batch of conditions on `asn.txt`.
///
/// An entry matches if it meets any one of the conditions.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub(crate) struct AsnRequest {
    /// Entries with these numbers.
    pub(crate) by_asn: AsnSet,
    /// Entries whose name matches one of these patterns (`as.name`).
    pub(crate) name: Vec<Pattern>,
    /// Entries of one of these countries.
    pub(crate) country: Vec<Cc>,
    /// Every entry.
    pub(crate) all: bool,
}

impl AsnRequest {
    fn matches(&self, entry: &AsnEntry) -> bool {
        self.all
            || self.by_asn.contains(entry.asn)
            || entry.country.is_some_and(|cc| self.country.contains(&cc))
            || self.name.iter().any(|pattern| pattern.matches(&entry.name))
    }

    /// Returns `true` if the request holds only numbers, so the index can
    /// answer by binary search alone.
    fn by_asn_only(&self) -> bool {
        !self.all && self.name.is_empty() && self.country.is_empty()
    }
}

/// The answer to an [`AsnRequest`].
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub(crate) struct AsnAnswer {
    /// The matching entries, sorted by number.
    pub(crate) entries: Vec<AsnEntry>,
}

/// The fields of one line, as offsets into `raw`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Parts {
    name_len: usize,
    org_start: usize,
    org_len: usize,
    country: Option<Cc>,
}

/// Splits a line into the number and the rest of the line.
///
/// Returns `None` if the line does not start with a number.
fn split_line(line: &[u8]) -> Option<(Asn, Cow<'_, str>)> {
    let line = line.trim_ascii();
    let end = line
        .iter()
        .position(u8::is_ascii_whitespace)
        .unwrap_or(line.len());
    let asn = parse_asn(&line[..end])?;
    Some((asn, String::from_utf8_lossy(line[end..].trim_ascii())))
}

/// Finds the name, the organization text, and the country in `raw`.
fn parts(raw: &str) -> Parts {
    let (body, country) = match raw.rsplit_once(',') {
        Some((body, tail)) => match tail.trim().parse::<Cc>() {
            Ok(cc) => (body.trim_end(), Some(cc)),
            Err(_) => (raw, None),
        },
        None => (raw, None),
    };
    let name_len = body.find(char::is_whitespace).unwrap_or(body.len());
    let rest = &body[name_len..];
    let trimmed = rest.trim_start();
    let org = trimmed.strip_prefix("- ").unwrap_or(trimmed).trim();
    let org_start = if org.is_empty() {
        name_len
    } else {
        org.as_ptr() as usize - raw.as_ptr() as usize
    };
    Parts {
        name_len,
        org_start,
        org_len: org.len(),
        country,
    }
}

/// Returns the entry of one line.
fn entry(asn: Asn, raw: &str) -> AsnEntry {
    let parts = parts(raw);
    AsnEntry {
        asn,
        name: raw[..parts.name_len].to_owned(),
        org_text: raw[parts.org_start..parts.org_start + parts.org_len].to_owned(),
        country: parts.country,
        raw: raw.to_owned(),
    }
}

/// Returns the error for a file without a single AS.
fn no_entries() -> Error {
    Error::runtime("no AS in the file")
}

/// The builder of the `asn.txt` index.
#[derive(Default)]
pub(crate) struct AsnBuilder {
    /// `(asn, raw_off, raw_len, parts)` in the order of the file.
    records: Vec<(Asn, u32, u16, Parts)>,
    strings: Vec<u8>,
}

impl AsnBuilder {
    /// Creates an empty builder.
    pub(crate) fn new() -> Self {
        Self::default()
    }
}

impl LineSink for AsnBuilder {
    fn line(&mut self, line: &[u8]) -> Result<Control> {
        let Some((asn, raw)) = split_line(line) else {
            return Ok(Control::Continue);
        };
        // Offsets inside a line are u16, so a line longer than `u16::MAX`
        // bytes is cut at a char boundary. No real line is longer than 200
        // bytes.
        let mut raw: &str = &raw;
        if raw.len() > usize::from(u16::MAX) {
            let mut end = usize::from(u16::MAX);
            while !raw.is_char_boundary(end) {
                end -= 1;
            }
            raw = &raw[..end];
        }
        let Ok(off) = u32::try_from(self.strings.len()) else {
            return Err(Error::runtime("asn.txt larger than 4 GB"));
        };
        self.strings.extend_from_slice(raw.as_bytes());
        self.records.push((asn, off, raw.len() as u16, parts(raw)));
        Ok(Control::Continue)
    }
}

impl Builder for AsnBuilder {
    fn finish(self) -> Result<Vec<Section>> {
        let Self {
            mut records,
            strings,
        } = self;
        if records.is_empty() {
            return Err(no_entries());
        }
        // Offsets grow from line to line, so the sort puts the first line of
        // each number first, and `dedup` keeps it.
        records.sort_unstable_by_key(|(asn, off, _, _)| (*asn, *off));
        records.dedup_by_key(|(asn, _, _, _)| *asn);
        let mut entries = Vec::with_capacity(records.len() * ENTRY);
        for (asn, off, len, parts) in records {
            entries.extend_from_slice(&asn.to_le_bytes());
            entries.extend_from_slice(&off.to_le_bytes());
            entries.extend_from_slice(&len.to_le_bytes());
            entries.extend_from_slice(&(parts.name_len as u16).to_le_bytes());
            entries.extend_from_slice(&(parts.org_start as u16).to_le_bytes());
            entries.extend_from_slice(&(parts.org_len as u16).to_le_bytes());
            match parts.country {
                Some(cc) => entries.extend_from_slice(cc.as_str().as_bytes()),
                None => entries.extend_from_slice(&[0, 0]),
            }
            entries.extend_from_slice(&[0, 0]);
        }
        Ok(vec![
            Section::new(ENTRIES, entries),
            Section::new(STRINGS, strings),
        ])
    }
}

/// The index of `asn.txt` in a cache file.
#[derive(Debug)]
pub(crate) struct AsnIndex {
    file: CacheFile,
}

impl AsnIndex {
    /// Checks the sections of `file` and returns the index.
    ///
    /// # Errors
    ///
    /// Returns [`Corrupt`] if a section is missing or damaged, or if the
    /// index has no entries.
    pub(crate) fn open(file: CacheFile) -> Result<Self, Corrupt> {
        let index = Self { file };
        let (entries, _) = index.view()?;
        if entries.is_empty() {
            return Err(Corrupt);
        }
        Ok(index)
    }

    /// Returns the number of entries.
    #[cfg(test)] // Tests of the index count what was built.
    pub(crate) fn len(&self) -> usize {
        self.view().map_or(0, |(entries, _)| entries.len())
    }

    fn view(&self) -> Result<(Table<'_, ENTRY>, &[u8]), Corrupt> {
        let entries = Table::new(self.file.section(ENTRIES)?)?;
        Ok((entries, self.file.section(STRINGS)?))
    }

    /// Answers a batch request.
    ///
    /// # Errors
    ///
    /// Returns [`Corrupt`] if a record points outside the `strings` section
    /// or holds invalid data.
    pub(crate) fn answer(&self, request: &AsnRequest) -> Result<AsnAnswer, Corrupt> {
        let (table, strings) = self.view()?;
        let mut entries = Vec::new();
        if request.by_asn_only() {
            for &(lo, hi) in request.by_asn.ranges() {
                let start = table.partition_point(0, table.len(), |r| u32_at(r, 0) < lo)?;
                let end = table.partition_point(start, table.len(), |r| u32_at(r, 0) <= hi)?;
                for i in start..end {
                    entries.push(decode(table.get(i)?, strings)?);
                }
            }
        } else {
            for i in 0..table.len() {
                let entry = decode(table.get(i)?, strings)?;
                if request.matches(&entry) {
                    entries.push(entry);
                }
            }
        }
        // A damaged file may be unsorted, but the answer must be sorted.
        entries.sort_by_key(|entry| entry.asn);
        entries.dedup_by_key(|entry| entry.asn);
        Ok(AsnAnswer { entries })
    }
}

/// Decodes an `entries` record and checks every offset.
fn decode(record: &[u8; ENTRY], strings: &[u8]) -> Result<AsnEntry, Corrupt> {
    let asn = u32_at(record, 0);
    let off = u32_at(record, 4) as usize;
    let len = usize::from(u16_at(record, 8));
    let name_len = usize::from(u16_at(record, 10));
    let org_start = usize::from(u16_at(record, 12));
    let org_len = usize::from(u16_at(record, 14));
    let end = off.checked_add(len).ok_or(Corrupt)?;
    let raw = strings.get(off..end).ok_or(Corrupt)?;
    let raw = std::str::from_utf8(raw).map_err(|_| Corrupt)?;
    let name = raw.get(..name_len).ok_or(Corrupt)?;
    let org = raw.get(org_start..org_start + org_len).ok_or(Corrupt)?;
    let country = match &record[16..18] {
        [0, 0] => None,
        cc => Some(
            std::str::from_utf8(cc)
                .ok()
                .and_then(|cc| cc.parse::<Cc>().ok())
                .ok_or(Corrupt)?,
        ),
    };
    Ok(AsnEntry {
        asn,
        name: name.to_owned(),
        org_text: org.to_owned(),
        country,
        raw: raw.to_owned(),
    })
}

/// Answers an [`AsnRequest`] while `asn.txt` downloads, without the cache.
pub(crate) struct AsnStream<'a> {
    request: &'a AsnRequest,
    found: HashMap<Asn, AsnEntry>,
    /// Numbers already seen.
    ///
    /// The stream ignores later lines with the same number.
    seen: AsnSet,
    any: bool,
}

impl<'a> AsnStream<'a> {
    /// Creates a stream that answers `request`.
    pub(crate) fn new(request: &'a AsnRequest) -> Self {
        Self {
            request,
            found: HashMap::new(),
            seen: AsnSet::new(),
            any: false,
        }
    }

    /// Ends the input and returns the answer.
    ///
    /// # Errors
    ///
    /// Returns an error if the input held no AS.
    pub(crate) fn finish(self) -> Result<AsnAnswer> {
        if !self.any {
            return Err(no_entries());
        }
        let mut entries: Vec<AsnEntry> = self.found.into_values().collect();
        entries.sort_by_key(|entry| entry.asn);
        Ok(AsnAnswer { entries })
    }
}

impl LineSink for AsnStream<'_> {
    fn line(&mut self, line: &[u8]) -> Result<Control> {
        let Some((asn, raw)) = split_line(line) else {
            return Ok(Control::Continue);
        };
        self.any = true;
        if self.seen.contains(asn) {
            return Ok(Control::Continue);
        }
        self.seen.insert(asn);
        let entry = entry(asn, &raw);
        if self.request.matches(&entry) {
            self.found.insert(asn, entry);
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
        text::Glob,
    };

    const TEXT: &[u8] = b"\
64496 EXAMPLE-AS Example Networks LLC, XD\n\
64497 DOC-NET - Documentation, Inc., XE\r\n\
64498 NO-COUNTRY-AS\n\
64499 TRAILING-AS Some Org, not a country\n\
64500 LATIN-AS Caf\xe9 Net, XJ\n\
64496 SECOND-LINE Ignored, XC\n\
not a number\n\
\n\
64501 -Reserved AS-, ZZ\n\
64502 EXAMPLE-CLOUD Example Cloud, xd\n";

    fn feed(sink: &mut dyn LineSink, text: &[u8]) {
        let mut splitter = LineSplitter::new();
        for chunk in text.chunks(5) {
            splitter.push(chunk, sink).unwrap();
        }
        splitter.finish(sink).unwrap();
    }

    fn file_of(text: &[u8]) -> Vec<u8> {
        let mut builder = AsnBuilder::new();
        feed(&mut builder, text);
        let sections = builder.finish().unwrap();
        let mut bytes = Vec::new();
        container::write(&mut bytes, 3, &Validators::default(), "u", &sections).unwrap();
        bytes
    }

    fn open(bytes: Vec<u8>) -> Result<AsnIndex, Corrupt> {
        AsnIndex::open(CacheFile::new(MappedFile::from_vec(bytes)).map_err(|_| Corrupt)?)
    }

    fn both(text: &[u8], request: &AsnRequest) -> AsnAnswer {
        let indexed = open(file_of(text)).unwrap().answer(request).unwrap();
        let mut stream = AsnStream::new(request);
        feed(&mut stream, text);
        let streamed = stream.finish().unwrap();
        assert_eq!(indexed, streamed, "{request:?}");
        indexed
    }

    fn all() -> Vec<AsnEntry> {
        both(
            TEXT,
            &AsnRequest {
                all: true,
                ..AsnRequest::default()
            },
        )
        .entries
    }

    #[test]
    fn parses_lines() {
        let entries = all();
        let summary: Vec<(Asn, &str, &str, Option<&str>)> = entries
            .iter()
            .map(|e| {
                (
                    e.asn,
                    e.name.as_str(),
                    e.org_text.as_str(),
                    e.country.as_ref().map(Cc::as_str),
                )
            })
            .collect();
        assert_eq!(
            summary,
            [
                (64496, "EXAMPLE-AS", "Example Networks LLC", Some("XD")),
                (64497, "DOC-NET", "Documentation, Inc.", Some("XE")),
                (64498, "NO-COUNTRY-AS", "", None),
                (64499, "TRAILING-AS", "Some Org, not a country", None),
                (64500, "LATIN-AS", "Caf\u{fffd} Net", Some("XJ")),
                (64501, "-Reserved", "AS-", Some("ZZ")),
                (64502, "EXAMPLE-CLOUD", "Example Cloud", Some("XD")),
            ]
        );
        assert_eq!(entries[1].raw, "DOC-NET - Documentation, Inc., XE");
        assert_eq!(open(file_of(TEXT)).unwrap().len(), 7);
    }

    #[test]
    fn answers_requests() {
        let by_asn = both(
            TEXT,
            &AsnRequest {
                by_asn: AsnSet::from_ranges([(64497, 64498), (64510, 64511)]),
                ..AsnRequest::default()
            },
        );
        let numbers: Vec<Asn> = by_asn.entries.iter().map(|e| e.asn).collect();
        assert_eq!(numbers, [64497, 64498]);

        let by_name = both(
            TEXT,
            &AsnRequest {
                name: vec![
                    Pattern::Glob(Glob::new("example*")),
                    Pattern::Exact("doc-net".into()),
                ],
                ..AsnRequest::default()
            },
        );
        let numbers: Vec<Asn> = by_name.entries.iter().map(|e| e.asn).collect();
        assert_eq!(numbers, [64496, 64497, 64502]);

        let by_country = both(
            TEXT,
            &AsnRequest {
                country: vec!["xd".parse().unwrap()],
                by_asn: AsnSet::from_ranges([(64498, 64498)]),
                ..AsnRequest::default()
            },
        );
        let numbers: Vec<Asn> = by_country.entries.iter().map(|e| e.asn).collect();
        assert_eq!(numbers, [64496, 64498, 64502]);

        assert!(both(TEXT, &AsnRequest::default()).entries.is_empty());
    }

    #[test]
    fn a_file_without_numbers_is_an_error() {
        let mut builder = AsnBuilder::new();
        feed(&mut builder, b"<html>\n</html>\n");
        assert_eq!(builder.finish().unwrap_err().message(), "no AS in the file");
        let request = AsnRequest::default();
        let mut stream = AsnStream::new(&request);
        feed(&mut stream, b"");
        assert!(stream.finish().is_err());
    }

    #[test]
    fn cache_ranges_are_checked() {
        let good = file_of(b"64496 A\n");
        let layout = container::Layout::parse(&good).unwrap();
        let start =
            layout.section(&good, ENTRIES).unwrap().as_ptr() as usize - good.as_ptr() as usize;
        let request = AsnRequest {
            all: true,
            ..AsnRequest::default()
        };
        for (off, len, expected) in [
            (0u32, 1u16, Some("A")),
            (1, 0, Some("")),
            (1, 1, None),
            (u32::MAX, 0, None),
            (u32::MAX, 1, None),
            (u32::MAX - 1, 2, None),
        ] {
            let mut bytes = good.clone();
            bytes[start + 4..start + 8].copy_from_slice(&off.to_le_bytes());
            bytes[start + 8..start + 10].copy_from_slice(&len.to_le_bytes());
            // Empty name and organisation ranges also fit an empty string.
            bytes[start + 10..start + 16].fill(0);
            let answer = open(bytes).unwrap().answer(&request);
            match expected {
                Some(raw) => assert_eq!(answer.unwrap().entries[0].raw, raw),
                None => assert_eq!(answer, Err(Corrupt), "off={off}, len={len}"),
            }
        }
    }

    #[test]
    fn damaged_indexes_are_corrupt_not_panics() {
        let good = file_of(TEXT);
        let layout = container::Layout::parse(&good).unwrap();
        let start =
            layout.section(&good, ENTRIES).unwrap().as_ptr() as usize - good.as_ptr() as usize;
        let requests = [
            AsnRequest {
                all: true,
                ..AsnRequest::default()
            },
            AsnRequest {
                by_asn: AsnSet::all(),
                ..AsnRequest::default()
            },
        ];
        let mut rng = Rng::new(5);
        let mut corrupt = 0;
        for _ in 0..3000 {
            let mut damaged = good.clone();
            let at = start + rng.below((good.len() - start) as u64) as usize;
            damaged[at] = rng.next() as u8;
            for request in &requests {
                if open(damaged.clone())
                    .and_then(|i| i.answer(request))
                    .is_err()
                {
                    corrupt += 1;
                }
            }
        }
        assert!(corrupt > 0);
        let mut empty = Vec::new();
        container::write(
            &mut empty,
            3,
            &Validators::default(),
            "u",
            &[
                Section::new(ENTRIES, Vec::new()),
                Section::new(STRINGS, Vec::new()),
            ],
        )
        .unwrap();
        assert!(open(empty).is_err());
    }
}
