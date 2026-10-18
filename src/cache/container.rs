//! The format of a cache file.
//!
//! A file has a header with the version and the validators of the source,
//! then sections. The reader checks every bound, so a truncated or damaged
//! file is [`Corrupt`] and never causes a panic.
//!
//! Every file of the cache uses this format. All numbers are
//! little-endian:
//!
//! ```text
//! magic "NETF"              4
//! format_version            u16    FORMAT_VERSION, else the file is stale
//! kind                      u16    what the file holds (dataset::Kind::code)
//! header_len                u32    up to the end of the section table
//! file_len                  u64    the whole file, so truncation is found
//! etag                      u16 length + bytes
//! last_modified             u16 length + bytes
//! url                       u16 length + bytes
//! section_count             u16
//! sections[]                { tag u16, offset u64, len u64 }
//! payload                   the sections, each starting 8-aligned
//! ```
//!
//! The format has no checksum. Instead, the reader trusts nothing in the
//! file. It parses the header with bounds checks, and every section must
//! lie inside the file. Readers reach records only through [`Table::get`],
//! which returns [`Corrupt`] past the end. If a dataset finds a record that
//! points outside its section, it reports [`Corrupt`], and the cache builds
//! the file again.
//!
//! The parsed [`Layout`] holds byte ranges and not slices, so it can be
//! stored next to the mapping it describes without borrowing from it.

use std::{io, ops::Range};

use crate::fetch::Validators;

/// The first four bytes of every cache file.
pub(crate) const MAGIC: [u8; 4] = *b"NETF";

/// The version of the format and of every section layout in it.
///
/// A file of another version is built again without a notice, because it
/// is old and not damaged.
pub(crate) const FORMAT_VERSION: u16 = 1;

/// The fixed-size start of the header, before the validators.
const FIXED: usize = 4 + 2 + 2 + 4 + 8;

/// One entry of the section table.
const ENTRY: usize = 2 + 8 + 8;

/// The alignment of sections in the payload.
const ALIGN: usize = 8;

/// A file that cannot be used.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Invalid {
    /// The file comes from another version of netf or another URL. The
    /// cache builds it again without a notice.
    Stale,
    /// The file is damaged. The cache removes it, reports it, and builds it
    /// again.
    Corrupt,
}

/// The error for a failed bounds check: the file is damaged.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct Corrupt;

impl From<Corrupt> for Invalid {
    fn from(_: Corrupt) -> Self {
        Self::Corrupt
    }
}

/// A section to write.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct Section {
    /// The tag that the reader finds the section by. Each kind of file
    /// defines its own tags.
    pub(crate) tag: u16,
    /// The bytes.
    pub(crate) data: Vec<u8>,
}

impl Section {
    /// Creates a section.
    pub(crate) fn new(tag: u16, data: Vec<u8>) -> Self {
        Self { tag, data }
    }
}

/// The parsed header of a file: everything except the payload.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct Layout {
    /// The kind of content.
    pub(crate) kind: u16,
    /// The validators of the source the file was built from.
    pub(crate) validators: Validators,
    /// The URL the file was built from.
    pub(crate) url: String,
    /// The sections: the tag and the byte range in the file.
    sections: Vec<(u16, Range<usize>)>,
}

impl Layout {
    /// Parses and checks the header of `bytes`, which hold the whole file.
    ///
    /// This function checks the magic, the length, the header, and the
    /// section table. The reader of each section checks its content.
    ///
    /// # Errors
    ///
    /// Returns [`Invalid::Stale`] for another format version and
    /// [`Invalid::Corrupt`] for any damage.
    pub(crate) fn parse(bytes: &[u8]) -> Result<Self, Invalid> {
        let mut reader = Reader::new(bytes);
        if reader.take(4)? != MAGIC {
            return Err(Invalid::Corrupt);
        }
        if reader.u16()? != FORMAT_VERSION {
            return Err(Invalid::Stale);
        }
        let kind = reader.u16()?;
        let header_len = reader.u32()? as usize;
        let file_len = reader.u64()?;
        if file_len != bytes.len() as u64 || header_len > bytes.len() {
            return Err(Invalid::Corrupt);
        }
        let etag = reader.string()?;
        let last_modified = reader.string()?;
        let url = reader.string()?.unwrap_or_default();
        let count = reader.u16()?;
        let mut sections = Vec::with_capacity(count.into());
        for _ in 0..count {
            let tag = reader.u16()?;
            let offset = usize::try_from(reader.u64()?).map_err(|_| Corrupt)?;
            let len = usize::try_from(reader.u64()?).map_err(|_| Corrupt)?;
            let end = offset.checked_add(len).ok_or(Corrupt)?;
            if offset < header_len || end > bytes.len() || offset % ALIGN != 0 {
                return Err(Invalid::Corrupt);
            }
            if sections.iter().any(|(t, _)| *t == tag) {
                return Err(Invalid::Corrupt);
            }
            sections.push((tag, offset..end));
        }
        if reader.pos != header_len {
            return Err(Invalid::Corrupt);
        }
        Ok(Self {
            kind,
            validators: Validators {
                etag,
                last_modified,
            },
            url,
            sections,
        })
    }

    /// Returns the section `tag` of `bytes`, or `None` if there is no such
    /// section.
    ///
    /// `bytes` must be the file that this layout was parsed from.
    pub(crate) fn section<'a>(&self, bytes: &'a [u8], tag: u16) -> Option<&'a [u8]> {
        let (_, range) = self.sections.iter().find(|(t, _)| *t == tag)?;
        bytes.get(range.clone())
    }
}

/// Writes a whole file: the header, then the sections, each aligned to 8
/// bytes.
///
/// The function writes as it goes and does not copy the sections into one
/// big buffer, so it needs little memory beyond the sections themselves.
///
/// # Errors
///
/// Returns an error if a header string is longer than 64 KB, there are
/// more than 65535 sections, or `out` fails.
pub(crate) fn write(
    out: &mut dyn io::Write,
    kind: u16,
    validators: &Validators,
    url: &str,
    sections: &[Section],
) -> io::Result<()> {
    let strings = [
        validators.etag.as_deref().unwrap_or(""),
        validators.last_modified.as_deref().unwrap_or(""),
        url,
    ];
    for text in strings {
        if text.len() > usize::from(u16::MAX) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "a header field longer than 64 KB",
            ));
        }
    }
    let count = u16::try_from(sections.len())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "too many sections"))?;
    let header_len =
        FIXED + strings.iter().map(|s| 2 + s.len()).sum::<usize>() + 2 + sections.len() * ENTRY;
    let mut offsets = Vec::with_capacity(sections.len());
    let mut end = header_len;
    for section in sections {
        end = end.next_multiple_of(ALIGN);
        offsets.push(end);
        end += section.data.len();
    }
    let mut header = Vec::with_capacity(header_len);
    header.extend_from_slice(&MAGIC);
    header.extend_from_slice(&FORMAT_VERSION.to_le_bytes());
    header.extend_from_slice(&kind.to_le_bytes());
    let header_len32 = u32::try_from(header_len)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "header too long"))?;
    header.extend_from_slice(&header_len32.to_le_bytes());
    header.extend_from_slice(&(end as u64).to_le_bytes());
    for text in strings {
        header.extend_from_slice(&(text.len() as u16).to_le_bytes());
        header.extend_from_slice(text.as_bytes());
    }
    header.extend_from_slice(&count.to_le_bytes());
    for (section, offset) in sections.iter().zip(&offsets) {
        header.extend_from_slice(&section.tag.to_le_bytes());
        header.extend_from_slice(&(*offset as u64).to_le_bytes());
        header.extend_from_slice(&(section.data.len() as u64).to_le_bytes());
    }
    debug_assert_eq!(header.len(), header_len);
    out.write_all(&header)?;
    let mut pos = header_len;
    for (section, offset) in sections.iter().zip(&offsets) {
        out.write_all(&[0; ALIGN][..offset - pos])?;
        out.write_all(&section.data)?;
        pos = offset + section.data.len();
    }
    Ok(())
}

/// A section of fixed-size records, read with bounds checks.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Table<'a, const N: usize> {
    bytes: &'a [u8],
}

impl<'a, const N: usize> Table<'a, N> {
    /// Wraps a section.
    ///
    /// # Errors
    ///
    /// Returns [`Corrupt`] if the length of the section is not a whole
    /// number of records.
    pub(crate) fn new(bytes: &'a [u8]) -> Result<Self, Corrupt> {
        if bytes.len().is_multiple_of(N) {
            Ok(Self { bytes })
        } else {
            Err(Corrupt)
        }
    }

    /// Returns the number of records.
    pub(crate) fn len(&self) -> usize {
        self.bytes.len() / N
    }

    /// Returns `true` if there are no records.
    pub(crate) fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }

    /// Returns the record at `index`.
    ///
    /// # Errors
    ///
    /// Returns [`Corrupt`] if `index` is past the end. Indexes come from
    /// the file itself, so such an index means the file is damaged.
    pub(crate) fn get(&self, index: usize) -> Result<&'a [u8; N], Corrupt> {
        let start = index.checked_mul(N).ok_or(Corrupt)?;
        let end = start.checked_add(N).ok_or(Corrupt)?;
        self.bytes
            .get(start..end)
            .and_then(|record| record.try_into().ok())
            .ok_or(Corrupt)
    }

    /// Returns the first index in `lo..hi` for which `pred` is false, like
    /// [`slice::partition_point`].
    ///
    /// The records must be partitioned: first all records for which `pred`
    /// is true, then all for which it is false. If a damaged file breaks
    /// this order, the result is still some index in the range, and the
    /// function does not panic.
    ///
    /// # Errors
    ///
    /// Returns [`Corrupt`] if a record in the range cannot be read.
    pub(crate) fn partition_point(
        &self,
        mut lo: usize,
        mut hi: usize,
        mut pred: impl FnMut(&'a [u8; N]) -> bool,
    ) -> Result<usize, Corrupt> {
        hi = hi.min(self.len());
        while lo < hi {
            let mid = lo + (hi - lo) / 2;
            if pred(self.get(mid)?) {
                lo = mid + 1;
            } else {
                hi = mid;
            }
        }
        Ok(lo)
    }
}

/// Reads a little-endian `u16` at offset `at` of a record.
///
/// # Panics
///
/// Panics if `bytes` is too short.
pub(crate) fn u16_at(bytes: &[u8], at: usize) -> u16 {
    let mut raw = [0; 2];
    raw.copy_from_slice(&bytes[at..at + 2]);
    u16::from_le_bytes(raw)
}

/// Reads a little-endian `u32` at offset `at` of a record.
///
/// # Panics
///
/// Panics if `bytes` is too short.
pub(crate) fn u32_at(bytes: &[u8], at: usize) -> u32 {
    let mut raw = [0; 4];
    raw.copy_from_slice(&bytes[at..at + 4]);
    u32::from_le_bytes(raw)
}

/// Reads a little-endian `u128` at offset `at` of a record.
///
/// # Panics
///
/// Panics if `bytes` is too short.
pub(crate) fn u128_at(bytes: &[u8], at: usize) -> u128 {
    let mut raw = [0; 16];
    raw.copy_from_slice(&bytes[at..at + 16]);
    u128::from_le_bytes(raw)
}

/// A cursor over the header that fails instead of reading past the end.
struct Reader<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, pos: 0 }
    }

    fn take(&mut self, len: usize) -> Result<&'a [u8], Corrupt> {
        let end = self.pos.checked_add(len).ok_or(Corrupt)?;
        let slice = self.bytes.get(self.pos..end).ok_or(Corrupt)?;
        self.pos = end;
        Ok(slice)
    }

    fn u16(&mut self) -> Result<u16, Corrupt> {
        Ok(u16_at(self.take(2)?, 0))
    }

    fn u32(&mut self) -> Result<u32, Corrupt> {
        Ok(u32_at(self.take(4)?, 0))
    }

    fn u64(&mut self) -> Result<u64, Corrupt> {
        let mut raw = [0; 8];
        raw.copy_from_slice(self.take(8)?);
        Ok(u64::from_le_bytes(raw))
    }

    /// Reads a string with a `u16` length prefix. An empty string means
    /// that the value is absent.
    fn string(&mut self) -> Result<Option<String>, Corrupt> {
        let len = self.u16()?;
        let bytes = self.take(len.into())?;
        let text = std::str::from_utf8(bytes).map_err(|_| Corrupt)?;
        Ok((!text.is_empty()).then(|| text.to_owned()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> Vec<u8> {
        let mut out = Vec::new();
        write(
            &mut out,
            1,
            &Validators {
                etag: Some("\"e1\"".into()),
                last_modified: None,
            },
            "https://ris.ripe.test/dumps/riswhoisdump.IPv4.gz",
            &[
                Section::new(1, vec![1, 2, 3]),
                Section::new(2, Vec::new()),
                Section::new(7, (0..=255).collect()),
            ],
        )
        .unwrap();
        out
    }

    #[test]
    fn round_trip() {
        let bytes = sample();
        let layout = Layout::parse(&bytes).unwrap();
        assert_eq!(layout.kind, 1);
        assert_eq!(layout.validators.etag.as_deref(), Some("\"e1\""));
        assert_eq!(layout.validators.last_modified, None);
        assert!(layout.url.ends_with("IPv4.gz"));
        assert_eq!(layout.section(&bytes, 1).unwrap(), [1, 2, 3]);
        assert_eq!(layout.section(&bytes, 2).unwrap(), [0u8; 0]);
        assert_eq!(layout.section(&bytes, 7).unwrap().len(), 256);
        assert_eq!(layout.section(&bytes, 3), None);
        for (_, range) in &layout.sections {
            assert_eq!(range.start % ALIGN, 0);
        }
    }

    #[test]
    fn every_truncation_is_detected() {
        let bytes = sample();
        for len in 0..bytes.len() {
            assert_eq!(
                Layout::parse(&bytes[..len]),
                Err(Invalid::Corrupt),
                "truncated to {len}"
            );
        }
        let mut longer = bytes.clone();
        longer.push(0);
        assert_eq!(Layout::parse(&longer), Err(Invalid::Corrupt));
    }

    #[test]
    fn damage_in_the_header_never_panics() {
        let bytes = sample();
        let layout = Layout::parse(&bytes).unwrap();
        let header = layout.sections[0].1.start;
        for at in 0..header {
            for value in [0x00, 0xff, 0x80, 0x01] {
                let mut damaged = bytes.clone();
                damaged[at] ^= value;
                // Any result passes if the sections stay in bounds.
                if let Ok(layout) = Layout::parse(&damaged) {
                    for tag in [1, 2, 7] {
                        if let Some(section) = layout.section(&damaged, tag) {
                            assert!(section.len() <= damaged.len());
                        }
                    }
                }
            }
        }
    }

    #[test]
    fn tables_check_bounds() {
        let bytes = [1u8, 0, 0, 0, 2, 0, 0, 0, 3, 0, 0, 0];
        let table = Table::<4>::new(&bytes).unwrap();
        assert_eq!(table.len(), 3);
        assert_eq!(u32_at(table.get(2).unwrap(), 0), 3);
        assert_eq!(table.get(3), Err(Corrupt));
        assert_eq!(table.get(usize::MAX), Err(Corrupt));
        assert_eq!(
            table.partition_point(0, 3, |r| u32_at(r, 0) < 3).unwrap(),
            2
        );
        assert_eq!(table.partition_point(0, 99, |_| true).unwrap(), 3);
        assert!(Table::<4>::new(&bytes[..11]).is_err());
    }
}
