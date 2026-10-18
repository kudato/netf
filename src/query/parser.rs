//! The KQL parser: recursive descent over this grammar.
//!
//! ```text
//! query      = or_expr ;
//! or_expr    = and_expr { OR and_expr } ;
//! and_expr   = not_expr { AND not_expr } ;
//! not_expr   = NOT not_expr | primary ;
//! primary    = "(" query ")" | term ;
//! term       = field ":" value | field range_op literal | literal ;
//! value      = "*" | "{" query "}" | "(" value_list ")" | "@" path | literal ;
//! value_list = vl_or ;  vl_or = vl_and { OR vl_and } ;
//! vl_and     = vl_not { AND vl_not } ;
//! vl_not     = NOT vl_not | "(" value_list ")" | "*" | literal ;
//! ```
//!
//! `not` binds tighter than `and`, and `and` binds tighter than `or`. Two
//! operands next to each other without an operator are an error, not an
//! implicit `and`. If the first operand is a name, the hint is to quote the
//! value: `net.org: EXAMPLE LLC` gets `net.org: "EXAMPLE LLC"`.
//!
//! A term starts with a field name only if a `:` or a range operator follows
//! the name. When the colon follows the name directly, the word must also not
//! parse as an address or a network. So `2001:db8::/32` is an operand, and
//! `ip:2001:db8::/32` is a field and a value.
//!
//! The parser checks what it can point at: field names, the selectors that
//! take no `*` or `{…}`, range operators outside `as.asn`, and the KQL nested
//! groups `as:{…}` and `net:{…}`. [`super::expand`] types the values later.
//! Every error is a usage error with exit code 2. The message has the form
//! `query: <what> at column <n>`, and a hint can follow after `; `. The
//! nested-group message is the exception: it has no `query:` prefix and no
//! column.

use super::{
    ast::{Ast, Field, FieldRef, Literal, Op, Selector, Span, Term, Value, ValueList},
    lexer::{Keyword, Lexer, column, ends_word},
    suggest,
};
use crate::{
    addr::Range,
    error::{Error, Result},
    text,
};

/// The deepest nesting of parentheses, braces, and `not`.
///
/// The limit is far beyond any real query and well before the stack runs
/// out.
const MAX_DEPTH: usize = 64;

/// Parses query text into an [`Ast`].
///
/// # Errors
///
/// Returns a usage error if the text is empty or is not a valid query.
pub(crate) fn parse(text: &str) -> Result<Ast> {
    let mut parser = Parser::new(text, false);
    parser.lexer.skip_ws();
    if parser.lexer.at_end() {
        return Err(Error::usage("query: the query is empty"));
    }
    parser.query(Closer::End)
}

/// What ends the query being parsed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Closer {
    /// The end of the text.
    End,
    /// `)` of a group opened at this offset.
    Paren(usize),
    /// `}` of a scope opened at this offset.
    Brace(usize),
}

/// The last operand, if it was an unquoted word that the user may have meant
/// as one value with the words after it: `net.org: EXAMPLE LLC`.
#[derive(Clone, Debug)]
struct OpenWord {
    /// The field as written, or `None` for an operand without a field.
    field: Option<String>,
    /// The word.
    word: String,
}

struct Parser<'a> {
    lexer: Lexer<'a>,
    depth: usize,
    /// If `true`, the parser accepts any field name and records where each
    /// one is. The nested-group message uses this mode to rewrite the inside
    /// of `as:{…}` with prefixed field names.
    lenient: bool,
    /// The byte ranges of the field names seen in lenient mode.
    fields: Vec<(usize, usize)>,
    open_word: Option<OpenWord>,
}

impl<'a> Parser<'a> {
    fn new(text: &'a str, lenient: bool) -> Self {
        Self {
            lexer: Lexer::new(text),
            depth: 0,
            lenient,
            fields: Vec::new(),
            open_word: None,
        }
    }

    /// Returns a usage error at byte offset `at`.
    fn error(&self, at: usize, message: impl std::fmt::Display) -> Error {
        let text = self.lexer.text();
        let rest = &text[at..];
        let len = rest
            .find(|c: char| c.is_whitespace() || matches!(c, ':' | '(' | ')' | '{' | '}' | '"'))
            .unwrap_or(rest.len())
            .max(rest.chars().next().map_or(0, char::len_utf8));
        Error::usage(format!(
            "query: {message} at column {}",
            column(self.lexer.text(), at)
        ))
        .span(at..at + len)
        .source(text)
    }

    /// Returns a usage error at byte offset `at` with a hint after it.
    fn error_hint(&self, at: usize, message: impl std::fmt::Display, hint: &str) -> Error {
        self.error(at, message).hint(hint)
    }

    /// Describes what is at the cursor for a message: `'LLC'`, `')'`, or
    /// `the end of the query`.
    fn describe_next(&self) -> String {
        match self.lexer.peek() {
            None => "the end of the query".to_owned(),
            Some(c) if ends_word(c) => format!("'{c}'"),
            Some(_) => {
                let len = self.lexer.word_len().max(1);
                let word: String = self.lexer.rest()[..len].chars().take(40).collect();
                format!("'{word}'")
            }
        }
    }

    fn enter(&mut self, at: usize) -> Result<()> {
        self.depth += 1;
        if self.depth > MAX_DEPTH {
            return Err(self.error(at, "the query is nested too deeply"));
        }
        Ok(())
    }

    /// Parses `query`, up to and including its closer.
    fn query(&mut self, closer: Closer) -> Result<Ast> {
        let ast = self.or_expr()?;
        self.lexer.skip_ws();
        let at = self.lexer.pos();
        match (closer, self.lexer.peek()) {
            (Closer::End, None) => Ok(ast),
            (Closer::Paren(_), Some(')')) | (Closer::Brace(_), Some('}')) => {
                self.lexer.eat(self.lexer.peek().unwrap_or(')'));
                // A word inside the group cannot continue past the closer.
                self.open_word = None;
                Ok(ast)
            }
            (Closer::Paren(open), None) => Err(self.error(open, "unclosed '('")),
            (Closer::Brace(open), None) => Err(self.error(open, "unclosed '{'")),
            (_, Some(c)) => Err(self.error(at, format!("unexpected '{c}'"))),
        }
    }

    fn or_expr(&mut self) -> Result<Ast> {
        let mut items = vec![self.and_expr()?];
        loop {
            self.lexer.skip_ws();
            if self.lexer.keyword() != Some(Keyword::Or) {
                break;
            }
            self.lexer.take(2);
            items.push(self.and_expr()?);
        }
        Ok(flatten(items, Ast::Or))
    }

    fn and_expr(&mut self) -> Result<Ast> {
        let mut items = vec![self.not_expr()?];
        loop {
            self.lexer.skip_ws();
            match self.lexer.keyword() {
                Some(Keyword::And) => {
                    self.lexer.take(3);
                    items.push(self.not_expr()?);
                }
                Some(Keyword::Or) => break,
                Some(Keyword::Not) | None => match self.lexer.peek() {
                    None | Some(')' | '}') => break,
                    Some(_) => return Err(self.juxtaposed()),
                },
            }
        }
        Ok(flatten(items, Ast::And))
    }

    fn not_expr(&mut self) -> Result<Ast> {
        self.lexer.skip_ws();
        let at = self.lexer.pos();
        if self.lexer.keyword() == Some(Keyword::Not) {
            self.lexer.take(3);
            self.lexer.skip_ws();
            if matches!(self.lexer.peek(), None | Some(')' | '}')) {
                return Err(self.error(self.lexer.pos(), "expected a condition after 'not'"));
            }
            self.enter(at)?;
            let inner = self.not_expr()?;
            self.depth -= 1;
            return Ok(Ast::Not(Box::new(inner)));
        }
        self.primary()
    }

    fn primary(&mut self) -> Result<Ast> {
        self.lexer.skip_ws();
        let at = self.lexer.pos();
        self.open_word = None;
        match self.lexer.peek() {
            None => Err(self.error(at, "expected a condition")),
            Some('(') => {
                self.lexer.eat('(');
                self.enter(at)?;
                let inner = self.query(Closer::Paren(at))?;
                self.depth -= 1;
                Ok(inner)
            }
            Some(c @ (')' | '}')) => Err(self.error(at, format!("unexpected '{c}'"))),
            Some('{') => Err(self.error_hint(
                at,
                "'{' needs a field before it",
                suggest::SCOPE_NEEDS_FIELD,
            )),
            Some(_) => match self.lexer.keyword() {
                Some(keyword @ (Keyword::And | Keyword::Or)) => Err(self.error(
                    at,
                    format!("expected a condition before '{}'", keyword.name()),
                )),
                _ => self.term(),
            },
        }
    }

    /// Returns the error for two operands without an operator between
    /// them.
    fn juxtaposed(&mut self) -> Error {
        let at = self.lexer.pos();
        let found = self.describe_next();
        if let Some(open) = self.open_word.take() {
            // Collect the plain words that follow. The user probably meant
            // them as one value with the open word.
            let mut words = vec![open.word.clone()];
            loop {
                self.lexer.skip_ws();
                if self.lexer.keyword().is_some() {
                    break;
                }
                match self.lexer.peek() {
                    None => break,
                    Some(c) if ends_word(c) => break,
                    Some(_) => {}
                }
                let len = self.lexer.word_len();
                let word = &self.lexer.rest()[..len];
                if word.contains(':') {
                    break;
                }
                words.push(self.lexer.take(len).to_owned());
            }
            if words.len() > 1 {
                let words: Vec<&str> = words.iter().map(String::as_str).collect();
                let hint = suggest::quote_values(open.field.as_deref(), &words);
                return self.error_hint(at, format!("unexpected {found}"), &hint);
            }
        }
        self.error(at, format!("expected 'and' or 'or' before {found}"))
    }

    fn term(&mut self) -> Result<Ast> {
        let start = self.lexer.pos();
        if self.lexer.peek() == Some('"') {
            let literal = self.quoted()?;
            return Ok(self.finish(start, FieldRef::Bare, Op::Is, Value::Literal(literal)));
        }
        let ident = self.lexer.ident_len();
        if ident > 0 && self.is_field(ident) {
            return self.field_term(start, ident);
        }
        let literal = self.word();
        self.open_word = Some(OpenWord {
            field: None,
            word: literal.text.clone(),
        });
        Ok(self.finish(start, FieldRef::Bare, Op::Is, Value::Literal(literal)))
    }

    /// Returns `true` if the name at the cursor, `ident` bytes long, is a
    /// field name.
    fn is_field(&self, ident: usize) -> bool {
        let rest = self.lexer.rest();
        match rest[ident..].chars().next() {
            // `2001:db8::/32` and `::ffff:192.0.2.4` are operands, not fields.
            Some(':') => {
                let word = &rest[..self.lexer.word_len()];
                word.parse::<Range>().is_err()
            }
            _ => {
                let after = rest[ident..].trim_start();
                after.starts_with([':', '<', '>'])
            }
        }
    }

    /// Parses `field ":" value` or `field range_op literal`.
    fn field_term(&mut self, start: usize, ident: usize) -> Result<Ast> {
        let written = self.lexer.take(ident).to_owned();
        let name = written.to_ascii_lowercase();
        self.lexer.skip_ws();
        let op = self.lexer.range_op();
        if op.is_none() {
            self.lexer.eat(':');
        }
        let op = op.unwrap_or(Op::Is);
        let field = self.field_ref(start, &name)?;
        if self.lenient {
            self.fields.push((start, start + ident));
        }
        if op != Op::Is {
            return self.range_term(start, field, &name, op);
        }
        let value = self.value(&name)?;
        if let FieldRef::Selector(selector) = field
            && !self.lenient
        {
            let unsupported = match (&value, selector) {
                (Value::Exists, _) => Some("*"),
                (Value::Scope(_), Selector::Domain | Selector::Set) => Some("{…}"),
                _ => None,
            };
            if let Some(what) = unsupported {
                return Err(self.error(start, format!("{selector}: {what} is not supported")));
            }
        }
        if let Value::Literal(literal) = &value
            && !literal.quoted
            && quote_hint_applies(&field)
        {
            self.open_word = Some(OpenWord {
                field: Some(written.clone()),
                word: literal.text.clone(),
            });
        }
        Ok(self.finish(start, field, op, value))
    }

    /// Resolves a field name, or returns an error with a hint.
    fn field_ref(&mut self, start: usize, name: &str) -> Result<FieldRef> {
        if name.contains('*') {
            return Ok(FieldRef::Glob(name.to_owned()));
        }
        if let Some(selector) = Selector::parse(name) {
            return Ok(FieldRef::Selector(selector));
        }
        if let Some(field) = Field::parse(name) {
            return Ok(FieldRef::Field(field));
        }
        if self.lenient {
            return Ok(FieldRef::Glob(name.to_owned()));
        }
        if name == "as" || name == "net" {
            self.lexer.skip_ws();
            if self.lexer.peek() == Some('{') {
                return Err(self.nested_group(name));
            }
            return Err(self.error(start, suggest::not_a_field(name)));
        }
        let (message, hint) = suggest::unknown_field(name);
        Err(match hint {
            Some(hint) => self.error_hint(start, message, &hint),
            None => self.error(start, message),
        })
    }

    /// Returns the error for `as:{…}` or `net:{…}`, with the cursor at the
    /// brace.
    fn nested_group(&self, group: &str) -> Error {
        let open = self.lexer.pos();
        let mut inner = Parser::new(self.lexer.text(), true);
        inner.lexer.seek(open + 1);
        let rewrite = match inner.query(Closer::Brace(open)) {
            Ok(_) => {
                let close = inner.lexer.pos() - 1;
                rewrite_group(self.lexer.text(), open + 1, close, &inner.fields, group)
            }
            Err(_) => None,
        };
        Error::usage(suggest::nested_group(group, rewrite))
            .span(open.saturating_sub(group.len() + 1)..open + 1)
            .source(self.lexer.text())
    }

    /// Parses `field range_op literal`.
    fn range_term(&mut self, start: usize, field: FieldRef, name: &str, op: Op) -> Result<Ast> {
        match field {
            FieldRef::Field(Field::AsAsn) | FieldRef::Glob(_) => {}
            _ => return Err(self.error(start, "range operators work only in as.asn")),
        }
        self.lexer.skip_ws();
        let at = self.lexer.pos();
        let literal = match self.lexer.peek() {
            Some('"') => self.quoted()?,
            Some(c) if !ends_word(c) && !matches!(c, '*' | '@') => self.word(),
            _ => return Err(self.error(at, format!("expected a number after '{name} {op}'"))),
        };
        Ok(self.finish(start, field, op, Value::Literal(literal)))
    }

    /// Parses `value`, after `field:`.
    fn value(&mut self, name: &str) -> Result<Value> {
        self.lexer.skip_ws();
        let at = self.lexer.pos();
        match self.lexer.peek() {
            None | Some(')' | '}') => {
                Err(self.error(at, format!("expected a value after '{name}:'")))
            }
            Some('*') if self.lexer.peek_second().is_none_or(ends_word) => {
                self.lexer.eat('*');
                Ok(Value::Exists)
            }
            Some('{') => {
                self.lexer.eat('{');
                self.enter(at)?;
                self.lexer.skip_ws();
                if self.lexer.peek() == Some('}') {
                    return Err(self.error(at, "expected a query inside '{…}'"));
                }
                let inner = self.query(Closer::Brace(at))?;
                self.depth -= 1;
                Ok(Value::Scope(Box::new(inner)))
            }
            Some('(') => {
                self.lexer.eat('(');
                self.enter(at)?;
                let list = self.vl_or()?;
                self.lexer.skip_ws();
                if !self.lexer.eat(')') {
                    return Err(self.list_end(at));
                }
                self.depth -= 1;
                Ok(Value::List(list))
            }
            Some('@') => {
                self.lexer.eat('@');
                let path = match self.lexer.peek() {
                    Some('"') => text::unescape(&self.quoted()?.text),
                    Some(c) if !ends_word(c) => text::unescape(&self.word().text),
                    _ => return Err(self.error(at + 1, "expected a path after '@'")),
                };
                Ok(Value::File(path))
            }
            Some('"') => Ok(Value::Literal(self.quoted()?)),
            Some(_) => Ok(Value::Literal(self.word())),
        }
    }

    /// Returns the error for a list of values that does not end with `)`.
    fn list_end(&mut self, open: usize) -> Error {
        if self.lexer.at_end() {
            self.error(open, "unclosed '('")
        } else {
            self.juxtaposed()
        }
    }

    fn vl_or(&mut self) -> Result<ValueList> {
        let mut items = vec![self.vl_and()?];
        loop {
            self.lexer.skip_ws();
            if self.lexer.keyword() != Some(Keyword::Or) {
                break;
            }
            self.lexer.take(2);
            items.push(self.vl_and()?);
        }
        Ok(flatten(items, ValueList::Or))
    }

    fn vl_and(&mut self) -> Result<ValueList> {
        let mut items = vec![self.vl_not()?];
        loop {
            self.lexer.skip_ws();
            if self.lexer.keyword() != Some(Keyword::And) {
                break;
            }
            self.lexer.take(3);
            items.push(self.vl_not()?);
        }
        Ok(flatten(items, ValueList::And))
    }

    fn vl_not(&mut self) -> Result<ValueList> {
        self.lexer.skip_ws();
        let at = self.lexer.pos();
        self.open_word = None;
        match self.lexer.keyword() {
            Some(Keyword::Not) => {
                self.lexer.take(3);
                self.enter(at)?;
                let inner = self.vl_not()?;
                self.depth -= 1;
                return Ok(ValueList::Not(Box::new(inner)));
            }
            Some(keyword) => {
                return Err(self.error(at, format!("expected a value before '{}'", keyword.name())));
            }
            None => {}
        }
        match self.lexer.peek() {
            Some('(') => {
                self.lexer.eat('(');
                self.enter(at)?;
                let inner = self.vl_or()?;
                self.lexer.skip_ws();
                if !self.lexer.eat(')') {
                    return Err(self.list_end(at));
                }
                self.depth -= 1;
                Ok(inner)
            }
            Some('"') => Ok(ValueList::One(self.quoted()?)),
            None | Some(')') => Err(self.error(at, "expected a value")),
            Some(c @ ('{' | '}' | '@')) => {
                Err(self.error(at, format!("'{c}' is not allowed in a list of values")))
            }
            Some(_) => {
                let literal = self.word();
                self.open_word = Some(OpenWord {
                    field: None,
                    word: literal.text.clone(),
                });
                Ok(ValueList::One(literal))
            }
        }
    }

    /// Reads a quoted literal at the cursor.
    fn quoted(&mut self) -> Result<Literal> {
        match self.lexer.quoted() {
            Ok(text) => Ok(literal(text, true)),
            Err(unclosed) => Err(self.error(unclosed.at, "unclosed quote")),
        }
    }

    /// Reads a word literal at the cursor.
    fn word(&mut self) -> Literal {
        literal(self.lexer.word(), false)
    }

    fn finish(&self, start: usize, field: FieldRef, op: Op, value: Value) -> Ast {
        Ast::Term(Term {
            field,
            op,
            value,
            span: Span {
                start,
                end: self.lexer.pos(),
            },
        })
    }
}

fn literal(text: String, quoted: bool) -> Literal {
    let has_wildcard = text::has_wildcard(&text);
    Literal {
        text,
        quoted,
        has_wildcard,
    }
}

/// Returns the one item, or the items joined by `join`.
fn flatten<T>(mut items: Vec<T>, join: fn(Vec<T>) -> T) -> T {
    if items.len() == 1
        && let Some(item) = items.pop()
    {
        item
    } else {
        join(items)
    }
}

/// Returns `true` if a word value of `field` followed by more words is
/// probably a name with spaces.
///
/// The hint applies to the name fields, field globs, and operands without a
/// field.
fn quote_hint_applies(field: &FieldRef) -> bool {
    match field {
        FieldRef::Field(field) => field.allows_glob(),
        FieldRef::Glob(_) | FieldRef::Bare => true,
        FieldRef::Selector(_) => false,
    }
}

/// Rewrites the inside of `as:{…}` or `net:{…}` with the prefix of the
/// group, `as.` or `net.`, before every field name that lacks it.
///
/// `name: example and country: RS` becomes
/// `as.name: example and as.country: RS`. Returns `None` if the inside has no
/// field names, or if a rewritten name is not a field of the group.
fn rewrite_group(
    text: &str,
    start: usize,
    end: usize,
    fields: &[(usize, usize)],
    group: &str,
) -> Option<String> {
    let mut out = String::new();
    let mut at = start;
    for &(from, to) in fields {
        let name = text[from..to].to_ascii_lowercase();
        let full = if name.starts_with(&format!("{group}.")) {
            name
        } else {
            format!("{group}.{name}")
        };
        let field = Field::parse(&full)?;
        if (group == "as") != field.is_as() {
            return None;
        }
        out.push_str(&text[at..from]);
        out.push_str(&full);
        at = to;
    }
    out.push_str(&text[at..end]);
    let out = out.trim();
    (!fields.is_empty()).then(|| out.to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::Role;

    fn term(field: FieldRef, op: Op, value: Value) -> Term {
        Term {
            field,
            op,
            value,
            span: Span::default(),
        }
    }

    fn lit(text: &str) -> Literal {
        literal(text.to_owned(), false)
    }

    fn quoted(text: &str) -> Literal {
        literal(text.to_owned(), true)
    }

    /// Drops spans, so trees can be compared with hand-written ones.
    fn strip(ast: Ast) -> Ast {
        match ast {
            Ast::Or(items) => Ast::Or(items.into_iter().map(strip).collect()),
            Ast::And(items) => Ast::And(items.into_iter().map(strip).collect()),
            Ast::Not(inner) => Ast::Not(Box::new(strip(*inner))),
            Ast::Term(mut t) => {
                t.span = Span::default();
                if let Value::Scope(inner) = t.value {
                    t.value = Value::Scope(Box::new(strip(*inner)));
                }
                Ast::Term(t)
            }
        }
    }

    fn ok(text: &str) -> Ast {
        strip(parse(text).unwrap_or_else(|e| panic!("{text}: {e}")))
    }

    fn err(text: &str) -> String {
        parse(text).expect_err(text).to_string()
    }

    fn field(f: Field, value: Value) -> Ast {
        Ast::Term(term(FieldRef::Field(f), Op::Is, value))
    }

    #[test]
    fn precedence() {
        let a = field(Field::AsAsn, Value::Literal(lit("1")));
        let b = field(Field::AsAsn, Value::Literal(lit("2")));
        let c = field(Field::AsAsn, Value::Literal(lit("3")));
        assert_eq!(
            ok("as.asn: 1 or as.asn: 2 and not as.asn: 3"),
            Ast::Or(vec![
                a.clone(),
                Ast::And(vec![b.clone(), Ast::Not(Box::new(c.clone()))])
            ])
        );
        assert_eq!(
            ok("(as.asn: 1 OR as.asn: 2) AND as.asn: 3"),
            Ast::And(vec![Ast::Or(vec![a.clone(), b.clone()]), c.clone()])
        );
        assert_eq!(
            ok("not not as.asn:1"),
            Ast::Not(Box::new(Ast::Not(Box::new(a))))
        );
    }

    #[test]
    fn values() {
        assert_eq!(
            ok(r#"net.org: "SAMPLE LLC""#),
            field(Field::NetOrg, Value::Literal(quoted("SAMPLE LLC")))
        );
        assert_eq!(ok("net.mnt: *"), field(Field::NetMnt, Value::Exists));
        assert_eq!(
            ok("as.name: sample*"),
            field(Field::AsName, Value::Literal(lit("sample*")))
        );
        assert!(lit("sample*").has_wildcard);
        assert!(!lit(r"x\*").has_wildcard);
        assert_eq!(
            ok("ip: @/tmp/banned.txt"),
            Ast::Term(term(
                FieldRef::Selector(Selector::Ip),
                Op::Is,
                Value::File("/tmp/banned.txt".into())
            ))
        );
        assert_eq!(
            ok("net.contact.abuse: X-RIPE"),
            field(
                Field::NetContact(Some(Role::Abuse)),
                Value::Literal(lit("X-RIPE"))
            )
        );
        // Keywords are words in the position of a value.
        assert_eq!(
            ok("as.name: and"),
            field(Field::AsName, Value::Literal(lit("and")))
        );
        // No spaces around the colon, and colons inside the value. Spaces
        // around the colon and a field name in uppercase work too.
        assert_eq!(
            ok("ip:3fff::/32"),
            Ast::Term(term(
                FieldRef::Selector(Selector::Ip),
                Op::Is,
                Value::Literal(lit("3fff::/32"))
            ))
        );
        assert_eq!(
            ok("AS.ASN : 1"),
            field(Field::AsAsn, Value::Literal(lit("1")))
        );
    }

    #[test]
    fn lists_scopes_and_globs() {
        assert_eq!(
            ok("as.asn: (64510 or 65550)"),
            field(
                Field::AsAsn,
                Value::List(ValueList::Or(vec![
                    ValueList::One(lit("64510")),
                    ValueList::One(lit("65550"))
                ]))
            )
        );
        assert_eq!(
            ok("as.name: (a* and not (ab or \"a c\"))"),
            field(
                Field::AsName,
                Value::List(ValueList::And(vec![
                    ValueList::One(lit("a*")),
                    ValueList::Not(Box::new(ValueList::Or(vec![
                        ValueList::One(lit("ab")),
                        ValueList::One(quoted("a c"))
                    ])))
                ]))
            )
        );
        assert_eq!(
            ok("as.asn: {domain: chat.example.test}"),
            field(
                Field::AsAsn,
                Value::Scope(Box::new(Ast::Term(term(
                    FieldRef::Selector(Selector::Domain),
                    Op::Is,
                    Value::Literal(lit("chat.example.test"))
                ))))
            )
        );
        assert_eq!(
            ok("*country: XA"),
            Ast::Term(term(
                FieldRef::Glob("*country".into()),
                Op::Is,
                Value::Literal(lit("XA"))
            ))
        );
        assert_eq!(
            ok("as.asn >= 64512 and as.asn<=65534"),
            Ast::And(vec![
                Ast::Term(term(
                    FieldRef::Field(Field::AsAsn),
                    Op::Ge,
                    Value::Literal(lit("64512"))
                )),
                Ast::Term(term(
                    FieldRef::Field(Field::AsAsn),
                    Op::Le,
                    Value::Literal(lit("65534"))
                )),
            ])
        );
    }

    #[test]
    fn operands_without_a_field() {
        let bare = |l: Literal| Ast::Term(term(FieldRef::Bare, Op::Is, Value::Literal(l)));
        assert_eq!(ok("sample"), bare(lit("sample")));
        assert_eq!(ok("10.88.55.242"), bare(lit("10.88.55.242")));
        assert_eq!(ok("3fff::/32"), bare(lit("3fff::/32")));
        assert_eq!(ok("::1"), bare(lit("::1")));
        assert_eq!(ok("AS64510"), bare(lit("AS64510")));
        assert_eq!(ok("ORG-SA1-RIPE"), bare(lit("ORG-SA1-RIPE")));
        assert_eq!(ok(r#""SAMPLE LLC""#), bare(quoted("SAMPLE LLC")));
        assert_eq!(
            ok("sample and not 10.88.55.0/24"),
            Ast::And(vec![
                bare(lit("sample")),
                Ast::Not(Box::new(bare(lit("10.88.55.0/24"))))
            ])
        );
    }

    #[test]
    fn errors_point_at_the_text() {
        assert_eq!(
            err("as.asn:"),
            "netf: query: expected a value after 'as.asn:' at column 8"
        );
        assert_eq!(
            err("holder: x"),
            "netf: query: unknown field 'holder' at column 1; did you mean net.org, as.org?"
        );
        assert_eq!(
            err("as.asn: 1 and xyzzy: 2"),
            "netf: query: unknown field 'xyzzy' at column 15"
        );
        assert_eq!(
            err("net.org: SAMPLE LLC"),
            "netf: query: unexpected 'LLC' at column 17; \
             quote values with spaces: net.org: \"SAMPLE LLC\""
        );
        assert_eq!(
            err("sample llc and as.asn: 1"),
            "netf: query: unexpected 'llc' at column 8; quote values with spaces: \"sample llc\""
        );
        assert_eq!(
            err("as.asn: 1 as.name: x"),
            "netf: query: expected 'and' or 'or' before 'as.name:' at column 11"
        );
        assert_eq!(
            err("as.name >= 5"),
            "netf: query: range operators work only in as.asn at column 1"
        );
        assert_eq!(
            err("as.asn >= *"),
            "netf: query: expected a number after 'as.asn >=' at column 11"
        );
        assert_eq!(err("(as.asn: 1"), "netf: query: unclosed '(' at column 1");
        assert_eq!(
            err("as.asn: 1)"),
            "netf: query: unexpected ')' at column 10"
        );
        assert_eq!(
            err("route: {ip: 192.0.2.4"),
            "netf: query: unclosed '{' at column 8"
        );
        assert_eq!(
            err("net.org: \"x"),
            "netf: query: unclosed quote at column 10"
        );
        assert_eq!(
            err("not"),
            "netf: query: expected a condition after 'not' at column 4"
        );
        assert_eq!(
            err("and as.asn: 1"),
            "netf: query: expected a condition before 'and' at column 1"
        );
        assert_eq!(
            err("as.asn: 1 and"),
            "netf: query: expected a condition at column 14"
        );
        assert_eq!(err("   "), "netf: query: the query is empty");
        assert_eq!(
            err("{ip: 192.0.2.4}"),
            "netf: query: '{' needs a field before it at column 1; \
             for example route: {…} or as.asn: {…}"
        );
        assert_eq!(
            err("route: {}"),
            "netf: query: expected a query inside '{…}' at column 8"
        );
        assert_eq!(
            err("as.asn: ()"),
            "netf: query: expected a value at column 10"
        );
        assert_eq!(
            err("as.asn: (1 or {x})"),
            "netf: query: '{' is not allowed in a list of values at column 15"
        );
        assert_eq!(
            err("ip: @"),
            "netf: query: expected a path after '@' at column 6"
        );
    }

    #[test]
    fn selectors_reject_stars_and_scopes() {
        assert_eq!(
            err("domain: {ip: 192.0.2.4}"),
            "netf: query: domain: {…} is not supported at column 1"
        );
        assert_eq!(
            err("set: {ip: 192.0.2.4}"),
            "netf: query: set: {…} is not supported at column 1"
        );
        assert_eq!(
            err("set: *"),
            "netf: query: set: * is not supported at column 1"
        );
        assert_eq!(
            err("ip: *"),
            "netf: query: ip: * is not supported at column 1"
        );
        assert!(parse("ip: {set: banned}").is_ok());
    }

    #[test]
    fn nested_groups() {
        assert_eq!(
            err("as:{name: example and country: XA}"),
            "netf: as:{…} is not supported; conditions on as.* already hold for one AS: \
             as.name: example and as.country: XA"
        );
        assert_eq!(
            err("ip: 192.0.2.1 and net: { country: XA }"),
            "netf: net:{…} is not supported; conditions on net.* already hold for one \
             network: net.country: XA"
        );
        // The inside cannot be rewritten, so the message shows the fixed
        // example.
        assert_eq!(
            err("as:{ip: 192.0.2.1}"),
            "netf: as:{…} is not supported; conditions on as.* already hold for one AS: \
             as.name: example and as.country: XA"
        );
        assert_eq!(
            err("as: 64496"),
            "netf: query: as is not a field; use as.asn, as.name, … at column 1"
        );
    }

    #[test]
    fn deep_nesting_is_an_error() {
        let text = format!("{}as.asn: 1{}", "(".repeat(200), ")".repeat(200));
        assert_eq!(
            err(&text),
            "netf: query: the query is nested too deeply at column 65"
        );
        let text = format!("{}as.asn: 1", "not ".repeat(100));
        assert!(parse(&text).is_err());
    }
}
