//! Text helpers shared by the query, the engine, and the output.
//!
//! - [`Pattern`] and [`Glob`] compare the values of `as.name`, `as.org`, and
//!   `net.org`, ignoring case. `*` matches any run of characters, and `\*`
//!   is a literal asterisk.
//! - [`fold`] is the case folding for every comparison of names. It works on
//!   `char`s with [`char::to_lowercase`], so non-ASCII names such as
//!   `ΔΕΊΓΜΑ` compare as users expect. It does no Unicode normalization,
//!   because normalization would need Unicode tables in the binary.
//! - [`width`] and [`truncate`] measure text in terminal columns, for the
//!   lines of the tree (`-i`). Wide CJK characters take two columns, and
//!   combining marks take none.
//!
//! The plural forms of messages live in `report.rs`, next to the messages.

/// Folds `text` for a comparison that ignores case.
pub(crate) fn fold(text: &str) -> String {
    text.chars().flat_map(char::to_lowercase).collect()
}

/// Returns the width of `text` in a terminal, in columns.
///
/// Wide characters take two columns: CJK, Hangul, full-width forms, and
/// emoji. Combining marks, zero-width characters, and controls take none.
/// The ranges cover the main blocks of East Asian Width `W` and `F` and of
/// the general category `Mn`, not the whole Unicode table. Registry names
/// are mostly ASCII, and a rare character outside the blocks misaligns a
/// line by one column at worst.
pub(crate) fn width(text: &str) -> usize {
    text.chars().map(char_width).sum()
}

/// Cuts `text` to at most `columns` columns.
///
/// A cut line ends with `…`. If `columns` is 0, the result is empty.
pub(crate) fn truncate(text: &str, columns: usize) -> String {
    if width(text) <= columns {
        return text.to_owned();
    }
    let Some(room) = columns.checked_sub(1) else {
        return String::new();
    };
    let mut out = String::new();
    let mut used = 0;
    for c in text.chars() {
        let w = char_width(c);
        if used + w > room {
            break;
        }
        used += w;
        out.push(c);
    }
    out.push('…');
    out
}

/// Returns the width of one character: 0, 1, or 2 columns.
fn char_width(c: char) -> usize {
    let code = u32::from(c);
    if code < 0x20 || (0x7f..0xa0).contains(&code) {
        return 0;
    }
    if code < 0x300 {
        return 1;
    }
    if ZERO
        .iter()
        .any(|(first, last)| (*first..=*last).contains(&code))
    {
        0
    } else if WIDE
        .iter()
        .any(|(first, last)| (*first..=*last).contains(&code))
    {
        2
    } else {
        1
    }
}

/// The characters of no width: combining marks, zero-width spaces and
/// joiners, and variation selectors.
const ZERO: [(u32, u32); 13] = [
    (0x0300, 0x036f),
    (0x0483, 0x0489),
    (0x0591, 0x05bd),
    (0x0610, 0x061a),
    (0x064b, 0x065f),
    (0x1ab0, 0x1aff),
    (0x1dc0, 0x1dff),
    (0x200b, 0x200f),
    (0x2060, 0x2064),
    (0x20d0, 0x20ff),
    (0xfe00, 0xfe0f),
    (0xfe20, 0xfe2f),
    (0xfeff, 0xfeff),
];

/// The characters two columns wide: Hangul, CJK, Kana, full-width forms,
/// and emoji.
const WIDE: [(u32, u32); 14] = [
    (0x1100, 0x115f),
    (0x2e80, 0x303e),
    (0x3041, 0x33ff),
    (0x3400, 0x4dbf),
    (0x4e00, 0x9fff),
    (0xa000, 0xa4cf),
    (0xac00, 0xd7a3),
    (0xf900, 0xfaff),
    (0xfe30, 0xfe4f),
    (0xff00, 0xff60),
    (0xffe0, 0xffe6),
    (0x1f300, 0x1f64f),
    (0x1f900, 0x1f9ff),
    (0x20000, 0x3fffd),
];

/// Returns `true` if `text` has a `*` that is not escaped as `\*`.
///
/// `text` is a value as the lexer leaves it, so `\*` and `\\` are still
/// escapes. See [`crate::query::ast::Literal`].
pub(crate) fn has_wildcard(text: &str) -> bool {
    let mut chars = text.chars();
    while let Some(c) = chars.next() {
        match c {
            '\\' => {
                chars.next();
            }
            '*' => return true,
            _ => {}
        }
    }
    false
}

/// Resolves the escapes that the lexer keeps, `\*` and `\\`, in a value
/// that is compared as is.
///
/// For example, `as.name: AS\*1` compares with `AS*1`. A backslash before
/// any other character stays, because registry names contain no escapes and
/// `C:\dir` must keep its backslash.
pub(crate) fn unescape(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut chars = text.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\\'
            && let Some(&next @ ('*' | '\\')) = chars.peek()
        {
            out.push(next);
            chars.next();
        } else {
            out.push(c);
        }
    }
    out
}

/// A value with at least one unescaped `*`: `example*`, `*bank*`.
///
/// [`Glob::new`] folds the pattern once. [`Glob::matches`] folds the text
/// and walks both with the classic two-pointer algorithm, which backtracks
/// only to the last `*`. The match takes `O(n·m)` time at worst, with no
/// recursion and no allocation per pattern character.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub(crate) struct Glob {
    /// The pattern as written, with `\*` escapes, for messages and KQL output.
    source: String,
    /// The folded pattern: `Some(c)` is a character, `None` is a wildcard.
    tokens: Vec<Option<char>>,
}

impl Glob {
    /// Builds a glob from the value as written.
    pub(crate) fn new(source: &str) -> Self {
        let mut tokens = Vec::with_capacity(source.len());
        let mut chars = source.chars().peekable();
        while let Some(c) = chars.next() {
            match c {
                '*' => {
                    // `**` is the same as `*`. Collapsing the stars keeps
                    // the backtracking simple.
                    if tokens.last() != Some(&None) {
                        tokens.push(None);
                    }
                }
                '\\' if matches!(chars.peek(), Some('*' | '\\')) => {
                    let literal = chars.next().unwrap_or(c);
                    tokens.push(Some(literal));
                }
                _ => tokens.extend(c.to_lowercase().map(Some)),
            }
        }
        Self {
            source: source.to_owned(),
            tokens,
        }
    }

    /// Returns the pattern as written.
    pub(crate) fn source(&self) -> &str {
        &self.source
    }

    /// Returns `true` if `text` matches, ignoring case.
    ///
    /// The whole text must match: `example*` matches `EXAMPLE-CLOUD`, not
    /// `MY-EXAMPLE`.
    pub(crate) fn matches(&self, text: &str) -> bool {
        let text: Vec<char> = text.chars().flat_map(char::to_lowercase).collect();
        let pattern = &self.tokens;
        let (mut p, mut t) = (0, 0);
        // Where to resume after the last `*`: the pattern position after the
        // star, and the text position up to which the star has matched.
        let mut star: Option<(usize, usize)> = None;
        while t < text.len() {
            match pattern.get(p) {
                Some(Some(c)) if *c == text[t] => {
                    p += 1;
                    t += 1;
                }
                Some(None) => {
                    p += 1;
                    star = Some((p, t));
                }
                _ => match star {
                    // Let the `*` match one more character and retry.
                    Some((after, absorbed)) => {
                        p = after;
                        t = absorbed + 1;
                        star = Some((after, absorbed + 1));
                    }
                    None => return false,
                },
            }
        }
        pattern[p..].iter().all(Option::is_none)
    }
}

impl std::fmt::Display for Glob {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.source)
    }
}

/// A name condition: `as.name: EXAMPLE`, `as.name: example*`, `as.name: *`.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub(crate) enum Pattern {
    /// The whole value. The comparison ignores case.
    Exact(String),
    /// A value with wildcards.
    Glob(Glob),
    /// `*` alone: the field is present.
    Any,
}

impl Pattern {
    /// Returns `true` if `text` matches, ignoring case.
    pub(crate) fn matches(&self, text: &str) -> bool {
        match self {
            Self::Exact(value) => fold(value) == fold(text),
            Self::Glob(glob) => glob.matches(text),
            Self::Any => true,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn folds_non_ascii() {
        assert_eq!(fold("ΔΕΊΓΜΑ LLC"), "δείγμα llc");
        assert!(Pattern::Exact("sample".into()).matches("SAMPLE"));
        assert!(Pattern::Any.matches(""));
    }

    #[test]
    fn globs_match_whole_text_without_case() {
        let glob = Glob::new("sample*");
        assert!(glob.matches("SAMPLE"));
        assert!(glob.matches("Sample-Cloud"));
        assert!(!glob.matches("MY-SAMPLE"));
        assert!(Glob::new("*bank*").matches("Examplebank of Testland"));
        assert!(Glob::new("*bank*").matches("BANK"));
        assert!(!Glob::new("*bank*").matches("BAN K"));
        assert!(Glob::new("Sample Innovation*").matches("sample innovation ltd"));
        assert!(Glob::new("a*b*c").matches("aXXbYYbZZc"));
        assert!(!Glob::new("a*b*c").matches("aXXbYYbZZ"));
        assert!(Glob::new("*").matches(""));
        assert!(Glob::new("**x").matches("x"));
        assert!(Glob::new("ΔΕΊΓΜΑ*").matches("δείγμα δίκτυο"));
        assert!(!Glob::new("").matches("x"));
        assert!(Glob::new("").matches(""));
    }

    #[test]
    fn escaped_star_is_literal() {
        let glob = Glob::new(r"AS\*1*");
        assert!(glob.matches("as*1-net"));
        assert!(!glob.matches("AS01"));
        assert!(Glob::new(r"a\\*").matches(r"a\anything"));
        assert_eq!(glob.source(), r"AS\*1*");
        assert!(has_wildcard("ex*"));
        assert!(!has_wildcard(r"ex\*"));
        assert!(has_wildcard(r"ex\\*"));
        assert_eq!(unescape(r"ex\*\\x\y"), r"ex*\x\y");
    }

    #[test]
    fn widths_are_terminal_columns() {
        assert_eq!(width("AS64510"), 7);
        assert_eq!(width("Δείγμα"), 6);
        assert_eq!(width("├─ ▶ · …"), 8);
        // CJK and Hangul are two columns wide, combining marks none.
        assert_eq!(width("日本語"), 6);
        assert_eq!(width("한국"), 4);
        assert_eq!(width("e\u{301}"), 1);
        assert_eq!(width("a\u{200d}b\tc"), 3);
    }

    #[test]
    fn truncation_counts_columns() {
        assert_eq!(truncate("AS64510 SAMPLE", 20), "AS64510 SAMPLE");
        assert_eq!(truncate("AS64510 SAMPLE", 14), "AS64510 SAMPLE");
        assert_eq!(truncate("AS64510 SAMPLE", 8), "AS64510…");
        // A wide character that does not fit is left out whole.
        assert_eq!(truncate("ab日本", 4), "ab…");
        assert_eq!(width(&truncate("日本語テキスト", 7)), 7);
        assert_eq!(truncate("e\u{301}xyz", 2), "e\u{301}…");
        assert_eq!(truncate("abc", 1), "…");
        assert_eq!(truncate("abc", 0), "");
    }
}
