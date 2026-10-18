//! Splitting a stream into lines.
//!
//! The splitter keeps a line that is cut between chunks until its end
//! arrives. The sink can stop the download early.
//!
//! netf reads datasets line by line as they download, and the only state
//! is the unfinished last line of the previous chunk. Chunk boundaries carry
//! no meaning, and a line can be split anywhere, even inside a `\r\n`. A
//! [`LineSink`] gets each line without its terminator, `\n` or `\r\n`. The
//! last line does not need a newline.
//!
//! A line longer than [`MAX_LINE`] is an error, so the buffer does not
//! grow without end. No source has such lines, and a source that sends
//! one, such as a binary file, must not make netf hold it whole in memory.

use crate::error::{Error, Result};

/// The maximum length of a line, in bytes.
pub(crate) const MAX_LINE: usize = 1 << 20;

/// What a sink wants after a line.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Control {
    /// Go on with the next line.
    Continue,
    /// Stop reading, because the sink has what it needs. The rest of the
    /// body is dropped, and the connection closes.
    Stop,
}

/// Receives the lines of a body.
pub(crate) trait LineSink {
    /// Takes one line, without its terminator.
    ///
    /// # Errors
    ///
    /// An error ends the reading, and the splitter returns it unchanged.
    fn line(&mut self, line: &[u8]) -> Result<Control>;
}

/// Splits chunks into lines.
///
/// Feed chunks with [`push`](Self::push), then call
/// [`finish`](Self::finish) for the last line. After a sink returns
/// [`Control::Stop`], the splitter ignores further input.
#[derive(Debug, Default)]
pub(crate) struct LineSplitter {
    /// The unfinished line from previous chunks.
    partial: Vec<u8>,
    /// Whether a sink has stopped the reading.
    stopped: bool,
}

impl LineSplitter {
    /// Creates a splitter with no pending line.
    pub(crate) fn new() -> Self {
        Self::default()
    }

    /// Returns `true` once a sink has returned [`Control::Stop`].
    pub(crate) fn stopped(&self) -> bool {
        self.stopped
    }

    /// Feeds a chunk and passes every line it completes to `sink`.
    ///
    /// # Errors
    ///
    /// Returns an error if a line is longer than [`MAX_LINE`] or the sink
    /// fails.
    pub(crate) fn push(&mut self, mut chunk: &[u8], sink: &mut dyn LineSink) -> Result<Control> {
        if self.stopped {
            return Ok(Control::Stop);
        }
        while let Some(end) = chunk.iter().position(|&b| b == b'\n') {
            let (head, rest) = chunk.split_at(end);
            chunk = &rest[1..];
            let control = if self.partial.is_empty() {
                sink.line(trim_cr(head))?
            } else {
                self.check_len(head.len())?;
                self.partial.extend_from_slice(head);
                let line = std::mem::take(&mut self.partial);
                let control = sink.line(trim_cr(&line));
                // Keep the allocation for the next split line.
                self.partial = line;
                self.partial.clear();
                control?
            };
            if control == Control::Stop {
                self.stopped = true;
                return Ok(Control::Stop);
            }
        }
        self.check_len(chunk.len())?;
        self.partial.extend_from_slice(chunk);
        Ok(Control::Continue)
    }

    /// Passes the last line, if the body did not end with a newline.
    ///
    /// # Errors
    ///
    /// Returns an error if the sink fails.
    pub(crate) fn finish(&mut self, sink: &mut dyn LineSink) -> Result<Control> {
        if self.stopped {
            return Ok(Control::Stop);
        }
        if self.partial.is_empty() {
            return Ok(Control::Continue);
        }
        let line = std::mem::take(&mut self.partial);
        let control = sink.line(trim_cr(&line))?;
        if control == Control::Stop {
            self.stopped = true;
        }
        Ok(control)
    }

    /// Returns an error if the pending line would grow past [`MAX_LINE`].
    fn check_len(&self, more: usize) -> Result<()> {
        if self.partial.len() + more > MAX_LINE {
            Err(Error::runtime(format!(
                "a line longer than {} MB",
                MAX_LINE >> 20
            )))
        } else {
            Ok(())
        }
    }
}

/// Drops the `\r` of a `\r\n` terminator.
fn trim_cr(line: &[u8]) -> &[u8] {
    line.strip_suffix(b"\r").unwrap_or(line)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Collects lines, and stops after `stop_after` lines if it is set.
    #[derive(Default)]
    struct Collect {
        lines: Vec<String>,
        stop_after: Option<usize>,
    }

    impl LineSink for Collect {
        fn line(&mut self, line: &[u8]) -> Result<Control> {
            self.lines.push(String::from_utf8(line.to_vec()).unwrap());
            Ok(match self.stop_after {
                Some(n) if self.lines.len() >= n => Control::Stop,
                _ => Control::Continue,
            })
        }
    }

    fn split(chunks: &[&[u8]]) -> Vec<String> {
        let mut splitter = LineSplitter::new();
        let mut sink = Collect::default();
        for chunk in chunks {
            splitter.push(chunk, &mut sink).unwrap();
        }
        splitter.finish(&mut sink).unwrap();
        sink.lines
    }

    #[test]
    fn lines_across_chunks() {
        let text = b"64496\t192.0.2.0/24\t300\r\n% comment\n\n64497\t198.51.100.0/24\t1";
        let whole = split(&[text]);
        assert_eq!(
            whole,
            [
                "64496\t192.0.2.0/24\t300",
                "% comment",
                "",
                "64497\t198.51.100.0/24\t1"
            ]
        );
        // Every split point, including between `\r` and `\n`.
        for at in 0..=text.len() {
            let (a, b) = text.split_at(at);
            assert_eq!(split(&[a, b]), whole, "split at {at}");
        }
        // One byte at a time.
        let bytes: Vec<&[u8]> = text.chunks(1).collect();
        assert_eq!(split(&bytes), whole);
    }

    #[test]
    fn trailing_newline_gives_no_empty_line() {
        assert_eq!(split(&[b"a\nb\n"]), ["a", "b"]);
        assert_eq!(split(&[b""]), Vec::<String>::new());
    }

    #[test]
    fn stop_ignores_the_rest() {
        let mut splitter = LineSplitter::new();
        let mut sink = Collect {
            stop_after: Some(2),
            ..Collect::default()
        };
        assert_eq!(
            splitter.push(b"a\nb\nc\n", &mut sink).unwrap(),
            Control::Stop
        );
        assert!(splitter.stopped());
        assert_eq!(splitter.push(b"d\n", &mut sink).unwrap(), Control::Stop);
        assert_eq!(splitter.finish(&mut sink).unwrap(), Control::Stop);
        assert_eq!(sink.lines, ["a", "b"]);
    }

    #[test]
    fn overlong_line_is_an_error() {
        let mut splitter = LineSplitter::new();
        let mut sink = Collect::default();
        let chunk = vec![b'x'; MAX_LINE / 2 + 1];
        splitter.push(&chunk, &mut sink).unwrap();
        let error = splitter.push(&chunk, &mut sink).unwrap_err();
        assert_eq!(error.message(), "a line longer than 1 MB");
    }
}
