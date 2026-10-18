//! [`Ast`] to [`Expr`]: every step of a query that does not need the data.
//!
//! The expansion does the following:
//!
//! - `set: NAME` becomes the query of the named set from the config, parsed and
//!   expanded in place, recursively. An unknown name and a cycle such as
//!   `vpn -> vpn6 -> vpn` are usage errors, and the cycle error shows the
//!   chain of sets. The `ipv4` and `ipv6` keys of a set apply only with
//!   `-s`. The families are fixed for the whole run before expansion, so
//!   `set:` inside a query ignores those keys.
//! - `@path` becomes a list of values: the lines of the file, without `#`
//!   comments and empty lines. `ip: @f` is `ip: (a or b or …)`. A relative
//!   path is resolved against the current directory of the run.
//! - A value list becomes terms: `field: (a or b)` is `field: a or field: b`.
//!   The same holds for `and` and `not`.
//! - A `*field` glob becomes `or` over the data fields whose whole name
//!   matches. Selectors never match. A glob that matches no field is a usage
//!   error.
//! - An operand without a field becomes one of three things. An address, a
//!   network, or a range becomes `ip:`. `AS` with digits becomes `as.asn:`.
//!   Any other word becomes `as.name: w or as.org: w or net.org: w` inside
//!   [`Expr::Bare`], so the engine can report `netf: w: nothing found`.
//! - A `*` inside a value is a wildcard only in `as.name`, `as.org`, and
//!   `net.org`. In other fields, it is a usage error. `field: *` works in
//!   every field.
//! - `ip:` and `route:` addresses of a family that the run does not output
//!   are dropped and counted for the notice
//!   `netf: 1 IPv6 address skipped, use -6`. The leaf becomes
//!   [`Expr::False`].
//! - Values get their types: AS numbers, two-letter country codes, the five
//!   registries, and domains. The expansion checks the syntax of a domain
//!   and then converts the domain to lowercase and punycode.
//!
//! Errors are usage errors that start with `query: `, such as
//! `query: <field>: <value>: <reason>`. The errors of sets differ: a
//! missing set gives `unknown set 'NAME'`, and a set that includes itself
//! gives `set cycle: a -> b -> a`. Inside a set, each level adds the prefix
//! `set <name>: `, so the user can find a broken set in a config.
//!
//! Among the modules of pure data and logic, only this one reads files. It
//! reads `@path` with `std::fs`, because a file of values is part of the
//! query.

use std::path::Path;

use super::{
    ast::{Ast, Field, FieldRef, Literal, Op, Selector, Term, Value, ValueList},
    expr::{AsnMatch, Expr, HandleMatch, Leaf, OrgMatch, RouteMatch},
    parser,
};
use crate::{
    addr::{Addr, Families, Family, Prefix, Range},
    dns::punycode,
    error::{Error, Result},
    model::{Asn, Cc, Rir},
    report::Notice,
    text::{self, Glob, Pattern},
};

/// Expands `ast` like [`expand_in`], with relative `@path` resolved against
/// the current directory of the process.
#[cfg(test)] // `run` always passes a working directory to `expand_in`.
pub(crate) fn expand(
    ast: &Ast,
    sets: &dyn Fn(&str) -> Option<String>,
    families: Families,
) -> Result<(Expr, Vec<Notice>)> {
    expand_in(ast, sets, families, Path::new(""))
}

/// Expands `ast` for the address `families` of the run, with relative
/// `@path` resolved against `cwd`.
///
/// `cwd` is the current directory of the [`Environment`](crate::Environment),
/// so tests that run in process need not change the directory of the test
/// binary. `sets` returns the query text of a named set from the config, or
/// `None` if no set has that name. The notices about skipped addresses come
/// back with the result, and expansion does not report them itself.
///
/// # Errors
///
/// Returns a usage error for an unknown set, a cycle of sets, an unreadable
/// `@path` file, a glob that matches no field, or a bad value.
pub(crate) fn expand_in(
    ast: &Ast,
    sets: &dyn Fn(&str) -> Option<String>,
    families: Families,
    cwd: &Path,
) -> Result<(Expr, Vec<Notice>)> {
    let mut expander = Expander {
        sets,
        families,
        cwd,
        stack: Vec::new(),
        skipped: [0; 2],
        cycle: false,
    };
    let expr = expander.ast(ast)?;
    let notices = [Family::V4, Family::V6]
        .into_iter()
        .zip(expander.skipped)
        .filter(|&(_, count)| count > 0)
        .map(|(family, count)| Notice::Skipped { family, count })
        .collect();
    Ok((expr, notices))
}

struct Expander<'a> {
    sets: &'a dyn Fn(&str) -> Option<String>,
    families: Families,
    cwd: &'a Path,
    /// The sets being expanded, outermost first. A cycle error shows this
    /// chain.
    stack: Vec<String>,
    /// The number of addresses dropped for their family: IPv4, then IPv6.
    skipped: [usize; 2],
    /// `true` if the error being returned is a cycle. The cycle message
    /// already names every set of the chain, so the sets on the way out add
    /// no prefix.
    cycle: bool,
}

/// Returns a usage error about one value:
/// `query: net.country: NLD: expected …`.
fn value_error(field: impl std::fmt::Display, value: &str, reason: &str) -> Error {
    Error::usage(format!("query: {field}: {value}: {reason}"))
}

/// Joins the items with `or`.
///
/// No items give [`Expr::False`]. One item is returned as is.
fn or(mut items: Vec<Expr>) -> Expr {
    match items.len() {
        0 => Expr::False,
        1 => items.pop().unwrap_or(Expr::False),
        _ => Expr::Or(items),
    }
}

/// Joins the items with `and`. One item is returned as is.
fn and(mut items: Vec<Expr>) -> Expr {
    if items.len() == 1
        && let Some(item) = items.pop()
    {
        item
    } else {
        Expr::And(items)
    }
}

impl Expander<'_> {
    fn ast(&mut self, ast: &Ast) -> Result<Expr> {
        Ok(match ast {
            Ast::Or(items) => or(items.iter().map(|a| self.ast(a)).collect::<Result<_>>()?),
            Ast::And(items) => and(items.iter().map(|a| self.ast(a)).collect::<Result<_>>()?),
            Ast::Not(inner) => Expr::Not(Box::new(self.ast(inner)?)),
            Ast::Term(term) => self.term(term)?,
        })
    }

    fn term(&mut self, term: &Term) -> Result<Expr> {
        match &term.field {
            FieldRef::Bare => self.bare(&term.value),
            FieldRef::Field(field) => self.field(*field, term.op, &term.value),
            FieldRef::Glob(glob) => self.glob(glob, term.op, &term.value),
            FieldRef::Selector(selector) => self.selector(*selector, &term.value),
        }
    }

    /// Applies `leaf` to each value in `value`: one literal, a list, or a
    /// file.
    fn values(
        &mut self,
        name: &str,
        value: &Value,
        leaf: &mut dyn FnMut(&mut Self, &Literal) -> Result<Expr>,
    ) -> Result<Expr> {
        match value {
            Value::Literal(literal) => leaf(self, literal),
            Value::List(list) => self.list(list, leaf),
            Value::File(path) => {
                let lines = self.read(name, path)?;
                let items = lines
                    .iter()
                    .map(|literal| leaf(self, literal))
                    .collect::<Result<_>>()?;
                Ok(or(items))
            }
            // Every caller handles these values before it calls
            // `values`.
            Value::Exists | Value::Scope(_) => {
                Err(Error::usage(format!("query: {name}: unexpected value")))
            }
        }
    }

    fn list(
        &mut self,
        list: &ValueList,
        leaf: &mut dyn FnMut(&mut Self, &Literal) -> Result<Expr>,
    ) -> Result<Expr> {
        Ok(match list {
            ValueList::Or(items) => or(items
                .iter()
                .map(|item| self.list(item, leaf))
                .collect::<Result<_>>()?),
            ValueList::And(items) => and(items
                .iter()
                .map(|item| self.list(item, leaf))
                .collect::<Result<_>>()?),
            ValueList::Not(inner) => Expr::Not(Box::new(self.list(inner, leaf)?)),
            ValueList::One(literal) => leaf(self, literal)?,
        })
    }

    /// Reads the values of `@path`, one per line.
    ///
    /// `#` starts a comment that runs to the end of the line. Lines are
    /// trimmed, and empty lines are skipped. A line in double quotes is a
    /// quoted value.
    fn read(&self, name: &str, path: &str) -> Result<Vec<Literal>> {
        let full = self.cwd.join(path);
        let content = std::fs::read_to_string(&full)
            .map_err(|e| value_error(name, &format!("@{path}"), &format!("cannot read: {e}")))?;
        Ok(content
            .lines()
            .map(|line| line.split('#').next().unwrap_or_default().trim())
            .filter(|line| !line.is_empty())
            .map(|line| {
                let (text, quoted) = match line.strip_prefix('"').and_then(|l| l.strip_suffix('"'))
                {
                    Some(inner) => (inner, true),
                    None => (line, false),
                };
                Literal {
                    text: text.to_owned(),
                    quoted,
                    has_wildcard: text::has_wildcard(text),
                }
            })
            .collect())
    }

    fn selector(&mut self, selector: Selector, value: &Value) -> Result<Expr> {
        match (selector, value) {
            (Selector::Ip, Value::Scope(inner)) => {
                Ok(Expr::Leaf(Leaf::IpScope(Box::new(self.ast(inner)?))))
            }
            (_, Value::Exists) => Err(Error::usage(format!(
                "query: {selector}: * is not supported"
            ))),
            (_, Value::Scope(_)) => Err(Error::usage(format!(
                "query: {selector}: {{…}} is not supported"
            ))),
            (Selector::Ip, _) => self.values("ip", value, &mut |this, literal| this.ip(literal)),
            (Selector::Domain, _) => {
                self.values("domain", value, &mut |_, literal| domain(literal))
            }
            (Selector::Set, _) => self.values("set", value, &mut |this, literal| {
                this.set(&text::unescape(&literal.text))
            }),
        }
    }

    /// Expands `set: NAME` in place to the query of the set.
    fn set(&mut self, name: &str) -> Result<Expr> {
        if let Some(at) = self.stack.iter().position(|open| open == name) {
            let mut chain = self.stack[at..].to_vec();
            chain.push(name.to_owned());
            self.cycle = true;
            return Err(Error::usage(format!("set cycle: {}", chain.join(" -> "))));
        }
        let Some(text) = (self.sets)(name) else {
            return Err(Error::usage(format!("unknown set '{name}'")));
        };
        self.stack.push(name.to_owned());
        let result = parser::parse(&text).and_then(|ast| self.ast(&ast));
        self.stack.pop();
        result.map_err(|error| {
            if self.cycle {
                error
            } else {
                error.with_prefix(format!("set {name}"))
            }
        })
    }

    /// Expands `ip: X`, where `X` is an address, a network, or a range.
    fn ip(&mut self, literal: &Literal) -> Result<Expr> {
        if literal.has_wildcard {
            return Err(value_error("ip", &literal.text, "* is not allowed here"));
        }
        let range: Range = literal.text.parse().map_err(|_| {
            value_error(
                "ip",
                &literal.text,
                "expected an address, a network or a range",
            )
        })?;
        Ok(self.keep_family(range.family(), Expr::Leaf(Leaf::Ip(range))))
    }

    /// Returns `expr` if the run outputs `family`.
    ///
    /// Otherwise counts the dropped value for the notice and returns
    /// [`Expr::False`].
    fn keep_family(&mut self, family: Family, expr: Expr) -> Expr {
        if self.families.contains(family) {
            expr
        } else {
            self.skipped[usize::from(family == Family::V6)] += 1;
            Expr::False
        }
    }

    /// Expands an operand without a field.
    fn bare(&mut self, value: &Value) -> Result<Expr> {
        let Value::Literal(literal) = value else {
            return Err(Error::usage("query: expected a field"));
        };
        if !literal.quoted && !literal.has_wildcard {
            if literal.text.parse::<Range>().is_ok() {
                return self.ip(literal);
            }
            // Only a number with `AS` is an AS number. A plain number is a
            // word, as in Kibana.
            let prefixed = literal
                .text
                .get(..2)
                .is_some_and(|prefix| prefix.eq_ignore_ascii_case("as"));
            if prefixed && let Some(asn) = as_number(&literal.text) {
                return Ok(Expr::Leaf(Leaf::Asn(AsnMatch::One(asn))));
            }
        }
        let any = !literal.quoted && literal.text == "*";
        let (name, org) = if any {
            (Pattern::Any, OrgMatch::Any)
        } else {
            (pattern(literal), org(literal))
        };
        Ok(Expr::Bare {
            word: literal.text.clone(),
            inner: Box::new(Expr::Or(vec![
                Expr::Leaf(Leaf::AsName(name)),
                Expr::Leaf(Leaf::AsOrg(org.clone())),
                Expr::Leaf(Leaf::NetOrg(org)),
            ])),
        })
    }

    /// Expands `*field: value` to `or` over every data field that the glob
    /// matches.
    fn glob(&mut self, glob: &str, op: Op, value: &Value) -> Result<Expr> {
        let pattern = Glob::new(glob);
        let fields: Vec<Field> = Field::ALL
            .into_iter()
            .filter(|field| pattern.matches(field.name()))
            .collect();
        if fields.is_empty() {
            return Err(Error::usage(format!("query: no field matches '{glob}'")));
        }
        if op != Op::Is && fields.iter().any(|field| *field != Field::AsAsn) {
            return Err(Error::usage(format!(
                "query: {glob}: range operators work only in as.asn"
            )));
        }
        let items = fields
            .into_iter()
            .map(|field| self.field(field, op, value))
            .collect::<Result<_>>()?;
        Ok(or(items))
    }

    /// Expands `field op value`.
    fn field(&mut self, field: Field, op: Op, value: &Value) -> Result<Expr> {
        match value {
            Value::Exists => Ok(Expr::Leaf(any(field))),
            Value::Scope(inner) => Ok(Expr::Leaf(Leaf::Scope {
                field,
                inner: Box::new(self.ast(inner)?),
            })),
            _ => self.values(field.name(), value, &mut |this, literal| {
                this.typed(field, op, literal)
            }),
        }
    }

    /// Types one value of a data field.
    fn typed(&mut self, field: Field, op: Op, literal: &Literal) -> Result<Expr> {
        let text = &literal.text;
        // In a list of values or a file, `*` means that the field is
        // present.
        if !literal.quoted && text == "*" && op == Op::Is {
            return Ok(Expr::Leaf(any(field)));
        }
        if literal.has_wildcard && !field.allows_glob() {
            return Err(value_error(
                field,
                text,
                "* works only in as.name, as.org and net.org; write \\* for an asterisk",
            ));
        }
        if op != Op::Is && field != Field::AsAsn {
            return Err(value_error(
                field,
                text,
                "range operators work only in as.asn",
            ));
        }
        let leaf = match field {
            Field::Route => return self.route(literal),
            Field::AsAsn => return asn(op, text),
            Field::AsName => Leaf::AsName(pattern(literal)),
            Field::AsOrg => Leaf::AsOrg(org(literal)),
            Field::NetOrg => Leaf::NetOrg(org(literal)),
            Field::AsCountry => Leaf::AsCountry(country(field, text)?),
            Field::NetCountry => Leaf::NetCountry(country(field, text)?),
            Field::AsRir => Leaf::AsRir(rir(field, text)?),
            Field::NetRir => Leaf::NetRir(rir(field, text)?),
            Field::AsMnt => Leaf::AsMnt(handle(literal)),
            Field::NetMnt => Leaf::NetMnt(handle(literal)),
            Field::AsContact(role) => Leaf::AsContact(role, handle(literal)),
            Field::NetContact(role) => Leaf::NetContact(role, handle(literal)),
        };
        Ok(Expr::Leaf(leaf))
    }

    /// Expands `route: P` to exactly the prefix `P`, and `route: A` to the
    /// most specific route covering the address `A`.
    fn route(&mut self, literal: &Literal) -> Result<Expr> {
        let text = &literal.text;
        let invalid = || value_error("route", text, "expected an address or a network");
        let (family, matcher) = if text.contains('/') {
            let prefix: Prefix = text.parse().map_err(|_| invalid())?;
            (prefix.family(), RouteMatch::Exact(prefix))
        } else {
            let addr: Addr = text.parse().map_err(|_| invalid())?;
            (addr.family(), RouteMatch::Covering(addr))
        };
        Ok(self.keep_family(family, Expr::Leaf(Leaf::Route(matcher))))
    }
}

/// Returns the leaf of `field: *`.
fn any(field: Field) -> Leaf {
    match field {
        Field::Route => Leaf::Route(RouteMatch::Any),
        Field::AsAsn => Leaf::Asn(AsnMatch::Any),
        Field::AsName => Leaf::AsName(Pattern::Any),
        Field::AsOrg => Leaf::AsOrg(OrgMatch::Any),
        Field::NetOrg => Leaf::NetOrg(OrgMatch::Any),
        Field::AsMnt => Leaf::AsMnt(HandleMatch::Any),
        Field::NetMnt => Leaf::NetMnt(HandleMatch::Any),
        Field::AsContact(role) => Leaf::AsContact(role, HandleMatch::Any),
        Field::NetContact(role) => Leaf::NetContact(role, HandleMatch::Any),
        Field::AsCountry | Field::NetCountry | Field::AsRir | Field::NetRir => Leaf::Present(field),
    }
}

/// Parses `64496`, `AS64496`, or `as64496`.
fn as_number(text: &str) -> Option<Asn> {
    let digits = match text.get(..2) {
        Some(prefix) if prefix.eq_ignore_ascii_case("as") => &text[2..],
        _ => text,
    };
    // Only plain digits, because `u32::from_str` accepts `+5`.
    if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    digits.parse().ok()
}

/// Expands `as.asn op N`.
///
/// A comparison that no AS number satisfies, such as `as.asn < 0`, gives
/// [`Expr::False`].
fn asn(op: Op, text: &str) -> Result<Expr> {
    let n = as_number(text).ok_or_else(|| value_error("as.asn", text, "expected an AS number"))?;
    let (min, max) = match op {
        Op::Is => return Ok(Expr::Leaf(Leaf::Asn(AsnMatch::One(n)))),
        Op::Gt => match n.checked_add(1) {
            Some(min) => (min, Asn::MAX),
            None => return Ok(Expr::False),
        },
        Op::Ge => (n, Asn::MAX),
        Op::Lt => match n.checked_sub(1) {
            Some(max) => (0, max),
            None => return Ok(Expr::False),
        },
        Op::Le => (0, n),
    };
    Ok(Expr::Leaf(Leaf::Asn(AsnMatch::Range { min, max })))
}

/// Returns the pattern of a name: a glob if the value has a wildcard, or
/// else the exact value.
fn pattern(literal: &Literal) -> Pattern {
    if literal.has_wildcard {
        Pattern::Glob(Glob::new(&literal.text))
    } else {
        Pattern::Exact(text::unescape(&literal.text))
    }
}

/// Returns the condition on a holder.
///
/// A quoted value or a value with a wildcard is a name. Any other value is a
/// word that can be either a handle or a name.
fn org(literal: &Literal) -> OrgMatch {
    if literal.has_wildcard || literal.quoted {
        OrgMatch::Name(pattern(literal))
    } else {
        OrgMatch::HandleOrName(text::unescape(&literal.text))
    }
}

/// Returns the condition on a maintainer or contact handle.
fn handle(literal: &Literal) -> HandleMatch {
    HandleMatch::Handle(text::unescape(&literal.text))
}

fn country(field: Field, text: &str) -> Result<Cc> {
    text.parse()
        .map_err(|_| value_error(field, text, "expected a two-letter country code"))
}

fn rir(field: Field, text: &str) -> Result<Rir> {
    text.parse::<Rir>()
        .map_err(|error| value_error(field, text, &error.to_string()))
}

/// Expands `domain: D`: checks the syntax, then converts the name to lower
/// case and punycode.
///
/// A label holds letters, digits, `-`, `_`, and non-ASCII characters, and it
/// is never empty. After punycode, a label has at most 63 characters, and
/// the name has at most 253. One trailing dot is allowed.
fn domain(literal: &Literal) -> Result<Expr> {
    let text = &literal.text;
    let invalid = || value_error("domain", text, "invalid domain name");
    let name = text.strip_suffix('.').unwrap_or(text);
    let label_ok = |label: &str| {
        !label.is_empty()
            && label
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_') || !c.is_ascii())
    };
    if !name.split('.').all(label_ok) {
        return Err(invalid());
    }
    let ascii = punycode::to_ascii(name).map_err(|_| invalid())?;
    if ascii.len() > 253 || ascii.split('.').any(|label| label.len() > 63) {
        return Err(invalid());
    }
    Ok(Expr::Leaf(Leaf::Domain(ascii)))
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use super::*;
    use crate::{fetch::testing::TempDir, model::Role};

    fn sets(entries: &[(&str, &str)]) -> HashMap<String, String> {
        entries
            .iter()
            .map(|(name, query)| ((*name).to_owned(), (*query).to_owned()))
            .collect()
    }

    fn run_with(
        text: &str,
        sets: &HashMap<String, String>,
        families: Families,
    ) -> Result<(Expr, Vec<Notice>)> {
        let ast = parser::parse(text)?;
        expand(&ast, &|name| sets.get(name).cloned(), families)
    }

    fn ok(text: &str) -> Expr {
        run_with(text, &HashMap::new(), Families::V4)
            .unwrap_or_else(|e| panic!("{text}: {e}"))
            .0
    }

    fn err(text: &str) -> String {
        run_with(text, &HashMap::new(), Families::V4)
            .expect_err(text)
            .to_string()
    }

    fn leaf(leaf: Leaf) -> Expr {
        Expr::Leaf(leaf)
    }

    fn ip(text: &str) -> Expr {
        leaf(Leaf::Ip(text.parse().unwrap()))
    }

    #[test]
    fn typed_values() {
        assert_eq!(ok("as.asn: AS64510"), leaf(Leaf::Asn(AsnMatch::One(64510))));
        assert_eq!(ok("as.asn: as64510"), leaf(Leaf::Asn(AsnMatch::One(64510))));
        assert_eq!(
            ok("net.country: xa"),
            leaf(Leaf::NetCountry("XA".parse().unwrap()))
        );
        assert_eq!(ok("as.rir: RIPENCC"), leaf(Leaf::AsRir(Rir::Ripencc)));
        assert_eq!(
            ok("as.name: sample"),
            leaf(Leaf::AsName(Pattern::Exact("sample".into())))
        );
        assert_eq!(
            ok("as.name: sample*"),
            leaf(Leaf::AsName(Pattern::Glob(Glob::new("sample*"))))
        );
        assert_eq!(
            ok(r"as.name: AS\*1"),
            leaf(Leaf::AsName(Pattern::Exact("AS*1".into())))
        );
        assert_eq!(
            ok(r#"net.org: "SAMPLE LLC""#),
            leaf(Leaf::NetOrg(OrgMatch::Name(Pattern::Exact(
                "SAMPLE LLC".into()
            ))))
        );
        assert_eq!(
            ok(r#"net.org: "Sample Innovation*""#),
            leaf(Leaf::NetOrg(OrgMatch::Name(Pattern::Glob(Glob::new(
                "Sample Innovation*"
            )))))
        );
        assert_eq!(
            ok("as.org: ORG-SA1-RIPE"),
            leaf(Leaf::AsOrg(OrgMatch::HandleOrName("ORG-SA1-RIPE".into())))
        );
        assert_eq!(
            ok("net.contact.abuse: X-RIPE"),
            leaf(Leaf::NetContact(
                Some(Role::Abuse),
                HandleMatch::Handle("X-RIPE".into())
            ))
        );
        assert_eq!(
            ok("route: 10.88.55.242"),
            leaf(Leaf::Route(RouteMatch::Covering(
                "10.88.55.242".parse().unwrap()
            )))
        );
        assert_eq!(
            ok("route: 10.88.55.1/24"),
            leaf(Leaf::Route(RouteMatch::Exact(
                "10.88.55.0/24".parse().unwrap()
            )))
        );
        assert_eq!(ok("ip: 192.0.2.1-192.0.2.9"), ip("192.0.2.1-192.0.2.9"));
        assert_eq!(ok("domain: Ex.TEST."), leaf(Leaf::Domain("ex.test".into())));
        assert_eq!(
            ok("domain: παράδειγμα.δοκιμή"),
            leaf(Leaf::Domain("xn--hxajbheg2az3al.xn--jxalpdlp".into()))
        );
    }

    #[test]
    fn ranges() {
        let range = |min, max| leaf(Leaf::Asn(AsnMatch::Range { min, max }));
        assert_eq!(ok("as.asn >= 64512"), range(64512, u32::MAX));
        assert_eq!(ok("as.asn > 64511"), range(64512, u32::MAX));
        assert_eq!(ok("as.asn <= 65534"), range(0, 65534));
        assert_eq!(ok("as.asn < 65535"), range(0, 65534));
        assert_eq!(ok("as.asn < 0"), Expr::False);
        assert_eq!(ok("as.asn > 4294967295"), Expr::False);
        assert_eq!(ok("*asn >= 5"), range(5, u32::MAX));
        assert_eq!(
            err("*country >= 5"),
            "netf: query: *country: range operators work only in as.asn"
        );
    }

    #[test]
    fn exists_everywhere() {
        assert_eq!(ok("route: *"), leaf(Leaf::Route(RouteMatch::Any)));
        assert_eq!(
            ok("route: * and not net.rir: *"),
            Expr::And(vec![
                leaf(Leaf::Route(RouteMatch::Any)),
                Expr::Not(Box::new(leaf(Leaf::Present(Field::NetRir))))
            ])
        );
        assert_eq!(ok("net.mnt: *"), leaf(Leaf::NetMnt(HandleMatch::Any)));
        assert_eq!(ok("as.org: *"), leaf(Leaf::AsOrg(OrgMatch::Any)));
        // `*` in a list is the same.
        assert_eq!(
            ok("as.asn: (1 or *)"),
            Expr::Or(vec![
                leaf(Leaf::Asn(AsnMatch::One(1))),
                leaf(Leaf::Asn(AsnMatch::Any))
            ])
        );
    }

    #[test]
    fn lists_become_or_and_not() {
        assert_eq!(
            ok("as.asn: (64510 or 65550)"),
            Expr::Or(vec![
                leaf(Leaf::Asn(AsnMatch::One(64510))),
                leaf(Leaf::Asn(AsnMatch::One(65550)))
            ])
        );
        assert_eq!(
            ok("as.name: (y* and not sample)"),
            Expr::And(vec![
                leaf(Leaf::AsName(Pattern::Glob(Glob::new("y*")))),
                Expr::Not(Box::new(leaf(Leaf::AsName(Pattern::Exact(
                    "sample".into()
                )))))
            ])
        );
    }

    #[test]
    fn field_globs() {
        assert_eq!(
            ok("*country: XA"),
            Expr::Or(vec![
                leaf(Leaf::NetCountry("XA".parse().unwrap())),
                leaf(Leaf::AsCountry("XA".parse().unwrap()))
            ])
        );
        assert_eq!(
            ok("*.mnt: *"),
            Expr::Or(vec![
                leaf(Leaf::NetMnt(HandleMatch::Any)),
                leaf(Leaf::AsMnt(HandleMatch::Any))
            ])
        );
        let Expr::Or(contacts) = ok("*contact*: X") else {
            panic!()
        };
        assert_eq!(contacts.len(), 8);
        assert_eq!(err("*xyz: 1"), "netf: query: no field matches '*xyz'");
        assert_eq!(err("*ip: 192.0.2.4"), "netf: query: no field matches '*ip'");
    }

    #[test]
    fn operands_without_a_field() {
        assert_eq!(ok("10.88.55.242"), ip("10.88.55.242"));
        assert_eq!(ok("AS64510"), leaf(Leaf::Asn(AsnMatch::One(64510))));
        assert_eq!(
            ok("sample"),
            Expr::Bare {
                word: "sample".into(),
                inner: Box::new(Expr::Or(vec![
                    leaf(Leaf::AsName(Pattern::Exact("sample".into()))),
                    leaf(Leaf::AsOrg(OrgMatch::HandleOrName("sample".into()))),
                    leaf(Leaf::NetOrg(OrgMatch::HandleOrName("sample".into()))),
                ]))
            }
        );
        let Expr::Bare { word, inner } = ok("\"SAMPLE LLC\"") else {
            panic!()
        };
        assert_eq!(word, "SAMPLE LLC");
        assert!(matches!(*inner, Expr::Or(ref items) if items.len() == 3));
        // A plain number is a word, as in Kibana.
        assert!(matches!(ok("64510"), Expr::Bare { .. }));
    }

    #[test]
    fn scopes() {
        assert_eq!(
            ok("as.asn: {domain: chat.example.test}"),
            leaf(Leaf::Scope {
                field: Field::AsAsn,
                inner: Box::new(leaf(Leaf::Domain("chat.example.test".into())))
            })
        );
        let banned = sets(&[("banned", "ip: 192.0.2.0/24")]);
        assert_eq!(
            run_with("ip: {set: banned}", &banned, Families::V4)
                .unwrap()
                .0,
            leaf(Leaf::IpScope(Box::new(ip("192.0.2.0/24"))))
        );
        assert!(ok("as.contact: {as.org: {domain: x.test}}").has_scope());
    }

    #[test]
    fn wildcards_only_in_names() {
        assert_eq!(
            err("net.mnt: SAMPLE*"),
            "netf: query: net.mnt: SAMPLE*: * works only in as.name, as.org and net.org; \
             write \\* for an asterisk"
        );
        assert_eq!(
            ok(r"net.mnt: A\*B"),
            leaf(Leaf::NetMnt(HandleMatch::Handle("A*B".into())))
        );
        assert!(err("ip: 192.0.2.*").contains("* is not allowed here"));
    }

    #[test]
    fn bad_values() {
        assert_eq!(
            err("net.country: NLD"),
            "netf: query: net.country: NLD: expected a two-letter country code"
        );
        assert_eq!(
            err("as.rir: ripe"),
            "netf: query: as.rir: ripe: expected afrinic, apnic, arin, lacnic or ripencc"
        );
        assert_eq!(
            err("as.asn: AS-SAMPLE"),
            "netf: query: as.asn: AS-SAMPLE: expected an AS number"
        );
        assert_eq!(
            err("as.asn: 4294967296"),
            "netf: query: as.asn: 4294967296: expected an AS number"
        );
        assert_eq!(
            err("ip: 192.0.2"),
            "netf: query: ip: 192.0.2: expected an address, a network or a range"
        );
        assert_eq!(
            err("route: 192.0.2.0/33"),
            "netf: query: route: 192.0.2.0/33: expected an address or a network"
        );
        assert_eq!(
            err("domain: ex..test"),
            "netf: query: domain: ex..test: invalid domain name"
        );
        assert!(err("domain: ex!.test").ends_with("invalid domain name"));
        let long = format!("domain: {}.test", "a".repeat(64));
        assert!(err(&long).ends_with("invalid domain name"));
    }

    #[test]
    fn other_family_is_skipped() {
        let none: HashMap<String, String> = HashMap::new();
        let (expr, notices) = run_with(
            "ip: (192.0.2.1 or 2001:db8::1 or 2001:db8::/32) or route: 2001:db8::/32",
            &none,
            Families::V4,
        )
        .unwrap();
        assert_eq!(
            expr,
            Expr::Or(vec![
                Expr::Or(vec![ip("192.0.2.1"), Expr::False, Expr::False]),
                Expr::False
            ])
        );
        assert_eq!(
            notices,
            [Notice::Skipped {
                family: Family::V6,
                count: 3
            }]
        );
        assert_eq!(
            notices[0].to_string(),
            "netf: 3 IPv6 addresses skipped, use -6"
        );
        let (_, notices) = run_with("192.0.2.1 or 2001:db8::1", &none, Families::V6).unwrap();
        assert_eq!(
            notices,
            [Notice::Skipped {
                family: Family::V4,
                count: 1
            }]
        );
        let (_, notices) = run_with("192.0.2.1 or 2001:db8::1", &none, Families::BOTH).unwrap();
        assert!(notices.is_empty());
    }

    #[test]
    fn sets_expand_recursively() {
        let config = sets(&[
            ("alpha", "as.asn: {domain: chat.example.test}"),
            ("zeta", "as.org: {domain: video.example.test}"),
            ("vpn", "set: alpha or set: zeta"),
            ("vpn6", "set: vpn"),
        ]);
        let (expr, _) = run_with("set: vpn6 and as.country: XF", &config, Families::V4).unwrap();
        let Expr::And(items) = expr else { panic!() };
        let Expr::Or(parts) = &items[0] else { panic!() };
        assert_eq!(parts.len(), 2);
        assert!(items[0].has_scope());
        // A list of sets.
        let (expr, _) = run_with("set: (alpha or zeta)", &config, Families::V4).unwrap();
        assert!(matches!(expr, Expr::Or(ref items) if items.len() == 2));
    }

    #[test]
    fn set_errors() {
        let config = sets(&[
            ("vpn", "set: alpha or set: vpn6"),
            ("vpn6", "set: vpn"),
            ("alpha", "as.asn: 1"),
            ("broken", "as.asn:"),
            ("outer", "set: broken"),
            ("missing", "set: nope"),
        ]);
        let fail = |text| {
            run_with(text, &config, Families::V4)
                .expect_err(text)
                .to_string()
        };
        assert_eq!(fail("set: vpn"), "netf: set cycle: vpn -> vpn6 -> vpn");
        assert_eq!(fail("set: vpn6"), "netf: set cycle: vpn6 -> vpn -> vpn6");
        assert_eq!(fail("set: nope"), "netf: unknown set 'nope'");
        assert_eq!(
            fail("set: missing"),
            "netf: set missing: unknown set 'nope'"
        );
        assert_eq!(
            fail("set: outer"),
            "netf: set outer: set broken: query: expected a value after 'as.asn:' at column 8"
        );
        assert_eq!(err("set: x"), "netf: unknown set 'x'");
    }

    #[test]
    fn files_of_values() {
        let temp = TempDir::new("expand");
        let dir = temp.path();
        std::fs::write(
            dir.join("banned.txt"),
            "# banned\n192.0.2.1\n\n  198.51.100.0/24  # office\n2001:db8::1\n",
        )
        .unwrap();
        std::fs::write(dir.join("orgs.txt"), "\"SAMPLE LLC\"\nORG-SA1-RIPE\n").unwrap();
        std::fs::write(dir.join("empty.txt"), "# nothing\n").unwrap();
        let none: HashMap<String, String> = HashMap::new();
        let expand = |text: &str| {
            let ast = parser::parse(text).unwrap();
            expand_in(&ast, &|name| none.get(name).cloned(), Families::V4, dir)
        };
        let (expr, notices) = expand("ip: @banned.txt").unwrap();
        assert_eq!(
            expr,
            Expr::Or(vec![ip("192.0.2.1"), ip("198.51.100.0/24"), Expr::False])
        );
        assert_eq!(notices.len(), 1);
        let (expr, _) = expand(&format!("net.org: @{}", dir.join("orgs.txt").display())).unwrap();
        assert_eq!(
            expr,
            Expr::Or(vec![
                leaf(Leaf::NetOrg(OrgMatch::Name(Pattern::Exact(
                    "SAMPLE LLC".into()
                )))),
                leaf(Leaf::NetOrg(OrgMatch::HandleOrName("ORG-SA1-RIPE".into()))),
            ])
        );
        assert_eq!(expand("ip: @empty.txt").unwrap().0, Expr::False);
        let error = expand("ip: @missing.txt").unwrap_err().to_string();
        assert!(
            error.starts_with("netf: query: ip: @missing.txt: cannot read: "),
            "{error}"
        );
    }
}
