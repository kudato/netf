//! The lexer of KQL: a cursor over the query text that reads one token at a
//! time, in the mode the parser asks for.
//!
//! KQL cannot be split into tokens up front, because the same characters
//! mean different things on each side of `:`. Before a colon, `as.name` is a
//! field, and after it, `example.com` is a value. `2001:db8::/32` is one
//! value with colons in it. Between terms `and` is an operator, but after
//! `as.name:` it is a word. So the lexer has no token stream. The parser
//! knows its place in the grammar and calls the reader for that place:
//!
//! - [`Lexer::ident_len`] measures a field name: letters, digits, `_`, `.`,
//!   `*`, and also `-` for better messages.
//! - [`Lexer::word`] reads a value up to whitespace, a parenthesis, a brace,
//!   or a quote. Dots, slashes, colons, and `*` belong to the value.
//! - [`Lexer::quoted`] reads a value in double quotes and keeps its spaces.
//! - [`Lexer::keyword`] reads `and`, `or`, or `not`, ignoring case, and
//!   only as a whole word.
//!
//! In a value, `\*` is a literal asterisk. In a word, the lexer resolves
//! every escape except `\*` and `\\`, so `\(` becomes `(`. In quotes, it
//! resolves only `\"`, and every other backslash stays. `\*` and `\\` stay
//! as written because the field decides later whether `*` is a wildcard. Only
//! `as.name`, `as.org`, and `net.org` have wildcards. If the lexer resolved
//! `\\`, then `\\*` (a backslash, then a wildcard) would look like `\*`.
//! [`crate::text::unescape`] and [`crate::text::Glob`] read the kept escapes.
//!
//! Positions are byte offsets into the text. [`column()`] turns an offset
//! into the 1-based column of messages, counted in characters.

use super::ast::Op;

/// A cursor over the query text.
#[derive(Clone, Debug)]
pub(crate) struct Lexer<'a> {
    text: &'a str,
    pos: usize,
}

/// An operator keyword.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Keyword {
    /// `and`.
    And,
    /// `or`.
    Or,
    /// `not`.
    Not,
}

impl Keyword {
    /// Returns the keyword as written in messages.
    pub(crate) fn name(self) -> &'static str {
        match self {
            Self::And => "and",
            Self::Or => "or",
            Self::Not => "not",
        }
    }
}

/// A quoted value without its closing quote.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct Unclosed {
    /// Where the opening quote is.
    pub(crate) at: usize,
}

/// Returns `true` for the characters that end a word: whitespace,
/// parentheses, braces, and the double quote.
pub(crate) fn ends_word(c: char) -> bool {
    c.is_whitespace() || matches!(c, '(' | ')' | '{' | '}' | '"')
}

/// Returns `true` for the characters of a field name.
///
/// No field has a `-`, but reading it lets `mnt-by: X` fail as an unknown
/// field with a hint instead of as a stray word.
fn is_ident(c: char) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | '*' | '-')
}

/// Returns the 1-based column of byte offset `pos`, counted in characters.
pub(crate) fn column(text: &str, pos: usize) -> usize {
    text.get(..pos).map_or(pos, |head| head.chars().count()) + 1
}

impl<'a> Lexer<'a> {
    /// Returns a lexer at the start of `text`.
    pub(crate) fn new(text: &'a str) -> Self {
        Self { text, pos: 0 }
    }

    /// Returns the whole text.
    pub(crate) fn text(&self) -> &'a str {
        self.text
    }

    /// Returns the current byte offset.
    pub(crate) fn pos(&self) -> usize {
        self.pos
    }

    /// Moves to byte offset `pos`.
    ///
    /// The parser moves inside the braces of `as:{…}` or `net:{…}` to
    /// suggest a rewrite.
    pub(crate) fn seek(&mut self, pos: usize) {
        self.pos = pos;
    }

    /// Returns the text from the current position on.
    pub(crate) fn rest(&self) -> &'a str {
        &self.text[self.pos..]
    }

    /// Returns the next character without consuming it.
    pub(crate) fn peek(&self) -> Option<char> {
        self.rest().chars().next()
    }

    /// Returns the character after the next one.
    pub(crate) fn peek_second(&self) -> Option<char> {
        self.rest().chars().nth(1)
    }

    /// Consumes `c` if it is next.
    pub(crate) fn eat(&mut self, c: char) -> bool {
        if self.peek() == Some(c) {
            self.pos += c.len_utf8();
            true
        } else {
            false
        }
    }

    /// Skips whitespace.
    pub(crate) fn skip_ws(&mut self) {
        let rest = self.rest();
        self.pos += rest.len() - rest.trim_start().len();
    }

    /// Returns `true` at the end of the text.
    pub(crate) fn at_end(&self) -> bool {
        self.pos == self.text.len()
    }

    /// Returns the length in bytes of the field name at the current
    /// position, without consuming it.
    ///
    /// Returns 0 if no field name starts here.
    pub(crate) fn ident_len(&self) -> usize {
        self.rest()
            .find(|c: char| !is_ident(c))
            .unwrap_or(self.rest().len())
    }

    /// Returns the length in bytes of the word at the current position,
    /// without consuming it.
    ///
    /// An escaped character belongs to the word, even one that ends words.
    pub(crate) fn word_len(&self) -> usize {
        let mut chars = self.rest().char_indices();
        while let Some((at, c)) = chars.next() {
            if c == '\\' {
                if chars.next().is_none() {
                    return self.rest().len();
                }
            } else if ends_word(c) {
                return at;
            }
        }
        self.rest().len()
    }

    /// Returns the keyword at the current position, without consuming it.
    ///
    /// A keyword is a whole word: `and(` and `not ` are keywords, but
    /// `android` and `not:` are not. The colon makes `not:` a field name.
    pub(crate) fn keyword(&self) -> Option<Keyword> {
        let len = self.ident_len();
        let word = &self.rest()[..len];
        let keyword = [Keyword::And, Keyword::Or, Keyword::Not]
            .into_iter()
            .find(|keyword| keyword.name().eq_ignore_ascii_case(word))?;
        let after = self.rest()[len..].chars().next();
        match after {
            None => Some(keyword),
            Some(c) if c.is_whitespace() || matches!(c, '(' | ')' | '{' | '}' | '"') => {
                Some(keyword)
            }
            Some(_) => None,
        }
    }

    /// Consumes `len` bytes and returns them.
    pub(crate) fn take(&mut self, len: usize) -> &'a str {
        let taken = &self.rest()[..len];
        self.pos += len;
        taken
    }

    /// Reads a word: a value without quotes.
    ///
    /// The module documentation describes which escapes the word keeps.
    pub(crate) fn word(&mut self) -> String {
        let len = self.word_len();
        let raw = self.take(len);
        let mut out = String::with_capacity(raw.len());
        let mut chars = raw.chars();
        while let Some(c) = chars.next() {
            if c == '\\' {
                match chars.next() {
                    Some(next @ ('*' | '\\')) => {
                        out.push('\\');
                        out.push(next);
                    }
                    Some(next) => out.push(next),
                    None => out.push('\\'),
                }
            } else {
                out.push(c);
            }
        }
        out
    }

    /// Reads a value in double quotes, from the opening quote at the current
    /// position.
    ///
    /// # Errors
    ///
    /// Returns [`Unclosed`] if the text ends before the closing quote.
    pub(crate) fn quoted(&mut self) -> Result<String, Unclosed> {
        let at = self.pos;
        self.eat('"');
        let mut out = String::new();
        let mut chars = self.rest().char_indices();
        while let Some((offset, c)) = chars.next() {
            match c {
                '"' => {
                    self.pos += offset + 1;
                    return Ok(out);
                }
                '\\' => match chars.next() {
                    Some((_, '"')) => out.push('"'),
                    Some((_, next)) => {
                        // `\*` and `\\` stay escaped. A backslash before
                        // any other character stays a backslash.
                        out.push('\\');
                        out.push(next);
                    }
                    None => break,
                },
                _ => out.push(c),
            }
        }
        Err(Unclosed { at })
    }

    /// Reads a range operator: `>=`, `>`, `<=`, `<`.
    pub(crate) fn range_op(&mut self) -> Option<Op> {
        let op = match (self.peek(), self.peek_second()) {
            (Some('>'), Some('=')) => Op::Ge,
            (Some('>'), _) => Op::Gt,
            (Some('<'), Some('=')) => Op::Le,
            (Some('<'), _) => Op::Lt,
            _ => return None,
        };
        self.pos += op.symbol().len();
        Some(op)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn words_keep_colons_and_slashes() {
        let mut lexer = Lexer::new("3fff::/32) x");
        assert_eq!(lexer.word(), "3fff::/32");
        assert_eq!(lexer.peek(), Some(')'));
        let mut lexer = Lexer::new(r"AS\*1\ x\(y\\*");
        assert_eq!(lexer.word(), r"AS\*1 x(y\\*");
        assert!(lexer.at_end());
    }

    #[test]
    fn quotes_keep_spaces_and_escapes() {
        let mut lexer = Lexer::new(r#""SAMPLE \"LLC\" \* \\" rest"#);
        assert_eq!(lexer.quoted().unwrap(), r#"SAMPLE "LLC" \* \\"#);
        assert_eq!(lexer.rest(), " rest");
        let mut lexer = Lexer::new(r#"x "open"#);
        lexer.seek(2);
        assert_eq!(lexer.quoted(), Err(Unclosed { at: 2 }));
    }

    #[test]
    fn keywords_are_whole_words() {
        assert_eq!(Lexer::new("AND x").keyword(), Some(Keyword::And));
        assert_eq!(Lexer::new("not(").keyword(), Some(Keyword::Not));
        assert_eq!(Lexer::new("or").keyword(), Some(Keyword::Or));
        assert_eq!(Lexer::new("android").keyword(), None);
        assert_eq!(Lexer::new("not:").keyword(), None);
        assert_eq!(Lexer::new("and.x").keyword(), None);
    }

    #[test]
    fn idents_and_ranges() {
        let mut lexer = Lexer::new("*country: XA");
        assert_eq!(lexer.ident_len(), 8);
        let mut lexer2 = Lexer::new(">= 5");
        assert_eq!(lexer2.range_op(), Some(Op::Ge));
        assert_eq!(lexer2.rest(), " 5");
        lexer.take(8);
        assert_eq!(lexer.range_op(), None);
        assert!(lexer.eat(':'));
        lexer.skip_ws();
        assert_eq!(lexer.pos(), 10);
    }

    #[test]
    fn columns_count_chars() {
        assert_eq!(column("as.asn:", 7), 8);
        assert_eq!(column("λ: x", 2), 2);
    }
}
