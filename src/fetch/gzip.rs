//! A push decoder for gzip.
//!
//! The decoder takes chunks as they arrive and passes the decoded output
//! on, so netf never holds a whole dump in memory.
//!
//! [`GzipLines`] sits between the body and a [`LineSplitter`]. Compressed
//! chunks go in with [`GzipLines::push`], and the `write::MultiGzDecoder`
//! of `flate2` inflates them into a small buffer. After every step of the
//! decoder, the buffer drains into the splitter, which passes complete
//! lines to the sink. One step of `flate2` produces at most its 32 KB
//! output buffer, so the memory stays at about 100 KB for the inflate
//! window and the buffers, plus the current line, whatever the compression
//! ratio.
//! Several gzip members in a row are one stream, as `gzip -d` reads them.
//!
//! A member that is cut short, as in a truncated download, fails in
//! [`GzipLines::finish`], because its CRC and length trailer is missing.
//! Bytes after the last member that are not another member fail too.

use std::io::{self, Write as _};

use flate2::write::MultiGzDecoder;

use super::lines::{Control, LineSink, LineSplitter};
use crate::error::{Error, Result};

/// The two bytes every gzip member starts with (RFC 1952).
pub(crate) const MAGIC: [u8; 2] = [0x1f, 0x8b];

/// Decompresses pushed chunks and splits the output into lines.
pub(crate) struct GzipLines {
    /// Inflates into a buffer that is drained after every step.
    decoder: MultiGzDecoder<Vec<u8>>,
    splitter: LineSplitter,
}

impl GzipLines {
    /// Creates a decoder with nothing pushed yet.
    pub(crate) fn new() -> Self {
        Self {
            decoder: MultiGzDecoder::new(Vec::new()),
            splitter: LineSplitter::new(),
        }
    }

    /// Decompresses a chunk and passes the lines it completes to `sink`.
    ///
    /// # Errors
    ///
    /// Returns an error if the chunk is not valid gzip, a line is too long,
    /// or the sink fails.
    pub(crate) fn push(&mut self, mut chunk: &[u8], sink: &mut dyn LineSink) -> Result<Control> {
        while !chunk.is_empty() {
            if self.splitter.stopped() {
                return Ok(Control::Stop);
            }
            let used = self.decoder.write(chunk).map_err(gzip_error)?;
            if used == 0 {
                // `flate2` starts a new member by itself, so no progress at
                // all means that the input cannot be decoded.
                return Err(gzip_error(io::ErrorKind::InvalidData.into()));
            }
            chunk = &chunk[used..];
            if self.drain(sink)? == Control::Stop {
                return Ok(Control::Stop);
            }
        }
        Ok(if self.splitter.stopped() {
            Control::Stop
        } else {
            Control::Continue
        })
    }

    /// Ends the stream.
    ///
    /// Checks the trailer of the last member and passes the rest of the
    /// output to `sink`, including a last line without a newline.
    ///
    /// # Errors
    ///
    /// Returns an error if the stream is truncated or damaged, a line is too
    /// long, or the sink fails.
    pub(crate) fn finish(&mut self, sink: &mut dyn LineSink) -> Result<Control> {
        if self.splitter.stopped() {
            return Ok(Control::Stop);
        }
        self.decoder.try_finish().map_err(gzip_error)?;
        if self.drain(sink)? == Control::Stop {
            return Ok(Control::Stop);
        }
        self.splitter.finish(sink)
    }

    /// Passes the inflated bytes so far to the splitter.
    fn drain(&mut self, sink: &mut dyn LineSink) -> Result<Control> {
        let output = self.decoder.get_mut();
        let control = self.splitter.push(output, sink);
        // Keep the capacity, because every step reuses the buffer.
        output.clear();
        control
    }
}

/// Returns the error for a stream that is not valid gzip.
fn gzip_error(error: io::Error) -> Error {
    let cause = match error.kind() {
        io::ErrorKind::InvalidInput | io::ErrorKind::InvalidData => {
            "corrupt or truncated data".to_owned()
        }
        _ => error.to_string(),
    };
    Error::runtime(format!("gzip: {cause}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fetch::testing::gzip;

    #[derive(Default)]
    struct Collect {
        lines: Vec<Vec<u8>>,
        stop_after: Option<usize>,
    }

    impl LineSink for Collect {
        fn line(&mut self, line: &[u8]) -> Result<Control> {
            self.lines.push(line.to_vec());
            Ok(match self.stop_after {
                Some(n) if self.lines.len() >= n => Control::Stop,
                _ => Control::Continue,
            })
        }
    }

    fn decode(chunks: &[&[u8]]) -> Result<Vec<Vec<u8>>> {
        let mut decoder = GzipLines::new();
        let mut sink = Collect::default();
        for chunk in chunks {
            decoder.push(chunk, &mut sink)?;
        }
        decoder.finish(&mut sink)?;
        Ok(sink.lines)
    }

    fn text() -> Vec<u8> {
        let mut text = Vec::new();
        for i in 0..2000u32 {
            writeln!(text, "{}\t192.0.2.{}/32\t{}", 64496 + i % 16, i % 256, i).unwrap();
        }
        text
    }

    #[test]
    fn decodes_at_every_chunk_boundary() {
        let short = b"64496\t192.0.2.0/24\t1\n64497\t198.51.100.0/24\t2";
        let packed = gzip(short);
        let expected = vec![
            b"64496\t192.0.2.0/24\t1".to_vec(),
            b"64497\t198.51.100.0/24\t2".to_vec(),
        ];
        for at in 0..=packed.len() {
            let (a, b) = packed.split_at(at);
            assert_eq!(decode(&[a, b]).unwrap(), expected, "split at {at}");
        }
        let bytes: Vec<&[u8]> = packed.chunks(1).collect();
        assert_eq!(decode(&bytes).unwrap(), expected);
    }

    #[test]
    fn several_members_are_one_stream() {
        let mut packed = gzip(b"a\nb");
        packed.extend(gzip(b"c\n"));
        let lines = decode(&[&packed]).unwrap();
        assert_eq!(lines, [b"a".to_vec(), b"bc".to_vec()]);
    }

    #[test]
    fn truncated_stream_fails() {
        let packed = gzip(&text());
        for cut in [
            1,
            5,
            20,
            packed.len() / 2,
            packed.len() - 4,
            packed.len() - 1,
        ] {
            let error = decode(&[&packed[..cut]]).unwrap_err();
            assert_eq!(
                error.message(),
                "gzip: corrupt or truncated data",
                "cut {cut}"
            );
        }
    }

    #[test]
    fn stop_ends_early() {
        let packed = gzip(&text());
        let mut decoder = GzipLines::new();
        let mut sink = Collect {
            stop_after: Some(3),
            ..Collect::default()
        };
        assert_eq!(decoder.push(&packed, &mut sink).unwrap(), Control::Stop);
        assert_eq!(decoder.finish(&mut sink).unwrap(), Control::Stop);
        assert_eq!(sink.lines.len(), 3);
    }
}
