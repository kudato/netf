//! Errors that end a run, and the exit codes they map to.
//!
//! netf has one error type for the whole pipeline. An [`Error`] carries a
//! [`Kind`], which decides the exit code, and a message. netf prints the
//! message to stderr as one line with the `netf: ` prefix. The message is
//! complete when the error is created. It names what failed and why, so the
//! caller prints it as is and does not walk a chain of sources. A layer that
//! knows more context prepends it with [`Error::with_prefix`]. For example,
//! the transport reports `connection refused`, and the fetcher turns it into
//! `rdap: arin: connection refused`.
//!
//! netf exits with one of four codes:
//!
//! | Code | Kind | When |
//! |---|---|---|
//! | 0 | none | a result, an empty one included, with any notices |
//! | 1 | [`Kind::Runtime`] | a source did not answer, NXDOMAIN, the cache directory, writing `-f` |
//! | 2 | [`Kind::Usage`] | the options, the query, or the config |
//! | 130 | [`Kind::Interrupted`] | Ctrl+C (128 + SIGINT) |
//!
//! A run gives the whole result or nothing. This module does not enforce
//! that rule. An error propagates to [`run`](crate::run), which discards the
//! result collected so far, so nothing reaches stdout or the `-f` file.

use std::fmt;

/// A [`Result`](std::result::Result) whose error is [`Error`].
pub(crate) type Result<T, E = Error> = std::result::Result<T, E>;

/// The class of an error, which decides the exit code.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub(crate) enum Kind {
    /// The user asked for something that netf cannot do: an unknown or
    /// misplaced option, a query that does not parse, or a bad config. Exit
    /// code 2.
    Usage,
    /// The request was valid, but the run failed: a source did not answer
    /// after the retries, a domain does not exist, or a file cannot be
    /// written. Exit code 1.
    Runtime,
    /// The user interrupted the run, for example with Ctrl+C in the
    /// interactive tree. Exit code 130.
    Interrupted,
}

impl Kind {
    /// Returns the exit code for errors of this kind.
    pub(crate) fn exit_code(self) -> ExitCode {
        match self {
            Self::Usage => ExitCode::Usage,
            Self::Runtime => ExitCode::Runtime,
            Self::Interrupted => ExitCode::Interrupted,
        }
    }
}

/// The exit code of the process.
///
/// The discriminants are the codes themselves. [`ExitCode::code`] converts
/// a code to the `u8` that [`Outcome`](crate::Outcome) carries.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[repr(u8)]
pub(crate) enum ExitCode {
    /// Done. An empty result is a result too.
    #[allow(dead_code)] // `run` returns 0 itself. The variant completes the list of codes.
    Ok = 0,
    /// An error during the run: the network, a source, or NXDOMAIN.
    Runtime = 1,
    /// An error in the options, the query, or the config.
    Usage = 2,
    /// Interrupted by the user: 128 + SIGINT, the shell convention.
    Interrupted = 130,
}

impl ExitCode {
    /// Returns the numeric exit code.
    pub(crate) fn code(self) -> u8 {
        self as u8
    }
}

/// An error that ends a run.
///
/// [`Display`](fmt::Display) prints the line that goes to stderr, with the
/// `netf: ` prefix and without a trailing newline:
/// `netf: domain example.invalid: not found (NXDOMAIN)`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct Error {
    kind: Kind,
    message: String,
    location: Option<Box<Location>>,
    hint: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct Location {
    source: Option<String>,
    span: std::ops::Range<usize>,
}

impl Error {
    /// Creates an error of the given kind.
    pub(crate) fn new(kind: Kind, message: impl Into<String>) -> Self {
        Self {
            kind,
            message: message.into(),
            location: None,
            hint: None,
        }
    }

    /// Creates an error in the options, the query, or the config (code 2).
    pub(crate) fn usage(message: impl Into<String>) -> Self {
        Self::new(Kind::Usage, message)
    }

    /// Creates an error that happened during the run (code 1).
    pub(crate) fn runtime(message: impl Into<String>) -> Self {
        Self::new(Kind::Runtime, message)
    }

    /// Creates the error of an interrupted run (code 130).
    ///
    /// The tree returns this error on Ctrl+C. Outside the tree, `main`
    /// handles Ctrl+C.
    pub(crate) fn interrupted() -> Self {
        Self::new(Kind::Interrupted, "interrupted")
    }

    /// Returns the kind of the error.
    #[cfg(test)] // Tests check the kind of an error.
    pub(crate) fn kind(&self) -> Kind {
        self.kind
    }

    /// Returns the message without the `netf: ` prefix.
    #[cfg(test)] // Tests check the message without the prefix.
    pub(crate) fn message(&self) -> &str {
        &self.message
    }

    /// Returns the exit code for this error.
    pub(crate) fn exit_code(&self) -> ExitCode {
        self.kind.exit_code()
    }

    /// Prepends context to the message: `prefix: message`.
    ///
    /// The layer that knows what the run was doing adds the prefix, so that
    /// the layer below can stay generic. For example, `connection refused`
    /// becomes `rdap: arin: connection refused`.
    #[must_use]
    pub(crate) fn with_prefix(mut self, prefix: impl fmt::Display) -> Self {
        self.message = format!("{prefix}: {}", self.message);
        self
    }

    /// Attaches a byte span without replacing a more specific inner error.
    pub(crate) fn span(mut self, span: std::ops::Range<usize>) -> Self {
        if self.location.is_none() {
            self.location = Some(Box::new(Location { source: None, span }));
        }
        self
    }

    /// Attaches the source of a span, retaining the source of nested set errors.
    pub(crate) fn source(mut self, source: &str) -> Self {
        if let Some(location) = &mut self.location {
            location.source.get_or_insert_with(|| source.to_owned());
        }
        self
    }

    pub(crate) fn hint(mut self, hint: impl Into<String>) -> Self {
        self.hint = Some(hint.into());
        self
    }

    /// The user-facing diagnostic. Display remains a concise error for callers.
    pub(crate) fn render(&self) -> String {
        let Some(location) = &self.location else {
            return self.to_string();
        };
        let Some(source) = &location.source else {
            return self.to_string();
        };
        let mut out = format!("netf: {}", crate::text::terminal_safe(&self.message));
        out.push('\n');
        out.push_str(&excerpt(source, location.span.clone()));
        if let Some(hint) = &self.hint {
            out.push('\n');
            let mut chars = hint.chars();
            if let Some(first) = chars.next() {
                out.extend(first.to_uppercase());
            }
            out.push_str(&crate::text::terminal_safe(chars.as_str()));
        }
        out
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "netf: {}", self.message)?;
        if let Some(hint) = &self.hint {
            write!(f, "; {hint}")?;
        }
        Ok(())
    }
}

/// Shows the affected lines, with Unicode display columns and bounded context.
fn excerpt(source: &str, span: std::ops::Range<usize>) -> String {
    use unicode_segmentation::UnicodeSegmentation as _;
    use unicode_width::UnicodeWidthStr as _;
    let start = source.floor_char_boundary(span.start.min(source.len()));
    let end = source
        .ceil_char_boundary(span.end.min(source.len()))
        .max(start);
    let mut out = String::new();
    let mut offset = 0;
    let mut shown = 0;
    for line in source.split('\n') {
        let last = offset + line.len();
        if last >= start && (offset < end || offset <= start && start <= last) {
            if shown == 3 {
                out.push_str("  …\n");
                break;
            }
            shown += 1;
            let lo = start.saturating_sub(offset).min(line.len());
            let hi = end.saturating_sub(offset).min(line.len());
            let cut = line[..lo]
                .grapheme_indices(true)
                .rev()
                .nth(24)
                .map_or(0, |(i, _)| i);
            let mut visible = String::new();
            let mut before = 0;
            let mut marked = 0;
            if cut > 0 {
                visible.push('…');
                before += 1;
            }
            for (i, g) in line[cut..].grapheme_indices(true) {
                let text = crate::text::terminal_safe(g);
                if visible.width() + text.width() > 76 {
                    visible.push('…');
                    break;
                }
                if cut + i < lo {
                    before += text.width();
                } else if cut + i < hi {
                    marked += text.width();
                }
                visible.push_str(&text);
            }
            out.push_str(&format!(
                "\n  {visible}\n  {}{}\n",
                " ".repeat(before),
                "^".repeat(marked.max(1))
            ));
        }
        offset = last + 1;
    }
    out
}

impl std::error::Error for Error {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn display_has_the_prefix() {
        let error = Error::runtime("domain nx.example.test: not found (NXDOMAIN)");
        assert_eq!(
            error.to_string(),
            "netf: domain nx.example.test: not found (NXDOMAIN)"
        );
        assert_eq!(
            error.message(),
            "domain nx.example.test: not found (NXDOMAIN)"
        );
    }

    #[test]
    fn kinds_map_to_exit_codes() {
        assert_eq!(Error::usage("x").exit_code().code(), 2);
        assert_eq!(Error::runtime("x").exit_code().code(), 1);
        assert_eq!(Error::interrupted().exit_code().code(), 130);
        assert_eq!(ExitCode::Ok.code(), 0);
    }

    #[test]
    fn prefix_adds_context() {
        let error = Error::runtime("connection refused").with_prefix("rdap: arin");
        assert_eq!(error.to_string(), "netf: rdap: arin: connection refused");
        assert_eq!(error.kind(), Kind::Runtime);
    }

    #[test]
    fn interrupted_message() {
        assert_eq!(Error::interrupted().to_string(), "netf: interrupted");
    }
}
