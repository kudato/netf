//! The syntax tree of a query, as written.
//!
//! The parser builds an [`Ast`] that mirrors the text, with nothing resolved
//! yet:
//!
//! - A field name can still be a glob, such as `*country`.
//! - Selectors, such as `set:` and `ip:`, are not expanded, and neither are
//!   value lists.
//! - An operand can have no field.
//! - Values are untyped [`Literal`]s.
//!
//! [`super::expand`] turns the [`Ast`] into an [`super::Expr`]. Every
//! [`Term`] keeps its [`Span`], so an error found after parsing, such as an
//! unknown named set or a bad country code, can still point at the text.

use std::fmt;

use crate::model::Role;

/// A byte range of the query text, for error messages.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
pub(crate) struct Span {
    /// The first byte.
    pub(crate) start: usize,
    /// One past the last byte.
    pub(crate) end: usize,
}

/// A query as written.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum Ast {
    /// `a or b or …`.
    Or(Vec<Ast>),
    /// `a and b and …`.
    And(Vec<Ast>),
    /// `not a`.
    Not(Box<Ast>),
    /// One condition.
    Term(Term),
}

/// One condition: `field op value`, or a bare operand.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct Term {
    /// What the condition tests.
    pub(crate) field: FieldRef,
    /// The comparison: `:`, or a range operator for `as.asn`.
    pub(crate) op: Op,
    /// The value.
    pub(crate) value: Value,
    /// Where the term is in the text.
    pub(crate) span: Span,
}

/// The left side of a term.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum FieldRef {
    /// A data field.
    Field(Field),
    /// A glob over field names: `*country`.
    Glob(String),
    /// A selector: its value comes from the query, DNS, or the config.
    Selector(Selector),
    /// An operand without a field: `192.0.2.1`, `AS64496`, `example`.
    Bare,
}

/// A data field: a field of a route, its registry network, or its AS.
///
/// `net.contact` and `as.contact` carry the role of the suffix:
/// `net.contact.abuse` is `NetContact(Some(Role::Abuse))`. `net.contact`
/// without a suffix is `NetContact(None)` and means any role.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub(crate) enum Field {
    /// `route`: the announced prefix.
    Route,
    /// `net.country`: the country of registration of the network.
    NetCountry,
    /// `net.org`: the holder of the network.
    NetOrg,
    /// `net.rir`: the registry of the network.
    NetRir,
    /// `net.mnt`: the maintainers of the network.
    NetMnt,
    /// `net.contact`, `net.contact.<role>`.
    NetContact(Option<Role>),
    /// `as.asn`: the AS number.
    AsAsn,
    /// `as.name`: the name of the AS.
    AsName,
    /// `as.org`: the holder of the AS.
    AsOrg,
    /// `as.country`: the country of registration of the AS.
    AsCountry,
    /// `as.rir`: the registry of the AS.
    AsRir,
    /// `as.mnt`: the maintainers of the AS.
    AsMnt,
    /// `as.contact`, `as.contact.<role>`.
    AsContact(Option<Role>),
}

impl Field {
    /// Every field, in the order of `--help`.
    ///
    /// Each contact field appears once for any role and once per role.
    /// `*field` globs and suggestions search these names.
    pub(crate) const ALL: [Field; 19] = [
        Field::Route,
        Field::NetCountry,
        Field::NetOrg,
        Field::NetRir,
        Field::NetMnt,
        Field::NetContact(None),
        Field::NetContact(Some(Role::Abuse)),
        Field::NetContact(Some(Role::Administrative)),
        Field::NetContact(Some(Role::Technical)),
        Field::AsAsn,
        Field::AsName,
        Field::AsOrg,
        Field::AsCountry,
        Field::AsRir,
        Field::AsMnt,
        Field::AsContact(None),
        Field::AsContact(Some(Role::Abuse)),
        Field::AsContact(Some(Role::Administrative)),
        Field::AsContact(Some(Role::Technical)),
    ];

    /// Returns the name as written in queries and `--fields`.
    pub(crate) fn name(self) -> &'static str {
        match self {
            Self::Route => "route",
            Self::NetCountry => "net.country",
            Self::NetOrg => "net.org",
            Self::NetRir => "net.rir",
            Self::NetMnt => "net.mnt",
            Self::NetContact(None) => "net.contact",
            Self::NetContact(Some(Role::Abuse)) => "net.contact.abuse",
            Self::NetContact(Some(Role::Administrative)) => "net.contact.administrative",
            Self::NetContact(Some(Role::Technical)) => "net.contact.technical",
            // A registrant is the holder (`net.org`), not a contact. The
            // parser never builds this field, and `parse` does not know it.
            Self::NetContact(Some(Role::Registrant)) => "net.contact.registrant",
            Self::AsAsn => "as.asn",
            Self::AsName => "as.name",
            Self::AsOrg => "as.org",
            Self::AsCountry => "as.country",
            Self::AsRir => "as.rir",
            Self::AsMnt => "as.mnt",
            Self::AsContact(None) => "as.contact",
            Self::AsContact(Some(Role::Abuse)) => "as.contact.abuse",
            Self::AsContact(Some(Role::Administrative)) => "as.contact.administrative",
            Self::AsContact(Some(Role::Technical)) => "as.contact.technical",
            Self::AsContact(Some(Role::Registrant)) => "as.contact.registrant",
        }
    }

    /// Looks up a field by its exact name.
    ///
    /// Returns `None` for selectors and unknown names. For an unknown name,
    /// the parser then asks [`super::suggest`] for a hint.
    pub(crate) fn parse(name: &str) -> Option<Field> {
        Field::ALL.into_iter().find(|field| field.name() == name)
    }

    /// Returns `true` for the `as.*` fields.
    ///
    /// Conditions on `as.*` fields must hold for one and the same AS of the
    /// route.
    pub(crate) fn is_as(self) -> bool {
        matches!(
            self,
            Self::AsAsn
                | Self::AsName
                | Self::AsOrg
                | Self::AsCountry
                | Self::AsRir
                | Self::AsMnt
                | Self::AsContact(_)
        )
    }

    /// Returns `true` for the `net.*` fields.
    ///
    /// Conditions on `net.*` fields must hold for one and the same network of
    /// the route.
    pub(crate) fn is_net(self) -> bool {
        matches!(
            self,
            Self::NetCountry | Self::NetOrg | Self::NetRir | Self::NetMnt | Self::NetContact(_)
        )
    }

    /// Returns `true` if a `*` inside the value is a wildcard.
    ///
    /// In the other fields, a `*` inside the value is a usage error. A `*`
    /// alone, as in `field: *`, works in every field.
    pub(crate) fn allows_glob(self) -> bool {
        matches!(self, Self::AsName | Self::AsOrg | Self::NetOrg)
    }
}

impl fmt::Display for Field {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

/// A selector: not a field of the data.
///
/// The value of a selector comes from the query, DNS, or the config.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub(crate) enum Selector {
    /// `ip`: an address or a network as is.
    Ip,
    /// `domain`: the addresses of a domain.
    Domain,
    /// `set`: a set from the config.
    Set,
}

impl Selector {
    /// Returns the name as written in queries.
    pub(crate) fn name(self) -> &'static str {
        match self {
            Self::Ip => "ip",
            Self::Domain => "domain",
            Self::Set => "set",
        }
    }

    /// Looks up a selector by its exact name.
    pub(crate) fn parse(name: &str) -> Option<Selector> {
        [Self::Ip, Self::Domain, Self::Set]
            .into_iter()
            .find(|selector| selector.name() == name)
    }
}

impl fmt::Display for Selector {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

/// The comparison of a term.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub(crate) enum Op {
    /// `:`.
    Is,
    /// `>`.
    Gt,
    /// `>=`.
    Ge,
    /// `<`.
    Lt,
    /// `<=`.
    Le,
}

impl Op {
    /// Returns the operator as written.
    pub(crate) fn symbol(self) -> &'static str {
        match self {
            Self::Is => ":",
            Self::Gt => ">",
            Self::Ge => ">=",
            Self::Lt => "<",
            Self::Le => "<=",
        }
    }
}

impl fmt::Display for Op {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.symbol())
    }
}

/// The right side of a term.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum Value {
    /// `*` alone: the field is present.
    Exists,
    /// One value.
    Literal(Literal),
    /// `(a or b)`: a list of values for one field.
    List(ValueList),
    /// `@path`: a file of values, one per line.
    File(String),
    /// `{…}`, a scope: the values of the field among the rows of a
    /// subquery.
    Scope(Box<Ast>),
}

/// A value as written.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub(crate) struct Literal {
    /// The text, without quotes.
    ///
    /// The lexer keeps the escapes `\*` and `\\`, and in quotes every
    /// backslash except the one in `\"`. See [`super::lexer`].
    pub(crate) text: String,
    /// The value was quoted: `"EXAMPLE LLC"`.
    pub(crate) quoted: bool,
    /// The text has an unescaped `*`.
    pub(crate) has_wildcard: bool,
}

/// A list of values: `(a or b)`, `(a and not b)`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum ValueList {
    /// `a or b`.
    Or(Vec<ValueList>),
    /// `a and b`.
    And(Vec<ValueList>),
    /// `not a`.
    Not(Box<ValueList>),
    /// One value.
    One(Literal),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn field_names_round_trip() {
        for field in Field::ALL {
            assert_eq!(Field::parse(field.name()), Some(field), "{field}");
        }
        assert_eq!(Field::parse("ip"), None);
        assert_eq!(Field::parse("holder"), None);
    }

    #[test]
    fn field_groups() {
        assert!(Field::AsContact(None).is_as());
        assert!(Field::NetMnt.is_net());
        assert!(!Field::Route.is_as() && !Field::Route.is_net());
        assert!(Field::NetOrg.allows_glob());
        assert!(!Field::NetCountry.allows_glob());
    }

    #[test]
    fn selectors_and_ops() {
        assert_eq!(Selector::parse("domain"), Some(Selector::Domain));
        assert_eq!(Selector::parse("route"), None);
        assert_eq!(Op::Ge.to_string(), ">=");
    }
}
