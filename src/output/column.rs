//! Output fields. These names do not extend the query language.

use crate::query::Field;

/// A field that `--fields` can add to the answer.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Column {
    /// An existing query field, with its original output semantics.
    Field(Field),
    /// The complete selected address set.
    Match,
    /// The holder of the most specific obtained network record.
    NetHolder,
    /// The ranges of the network records, from parent to child.
    NetRange,
    /// Abuse mailboxes of the most specific network record.
    NetAbuse,
    /// Abuse mailboxes of each origin AS.
    AsAbuse,
}

impl From<Field> for Column {
    fn from(field: Field) -> Self {
        Self::Field(field)
    }
}

impl Column {
    /// Parses a name, keeping output-only names out of KQL.
    pub(crate) fn parse(name: &str) -> Option<Self> {
        match name {
            "match" => Some(Self::Match),
            "net.holder" => Some(Self::NetHolder),
            "net.range" => Some(Self::NetRange),
            "net.abuse" => Some(Self::NetAbuse),
            "as.abuse" => Some(Self::AsAbuse),
            _ => Field::parse(name).map(Self::Field),
        }
    }

    /// Returns the spelling used in `--fields`.
    pub(crate) fn name(self) -> &'static str {
        match self {
            Self::Field(field) => field.name(),
            Self::Match => "match",
            Self::NetHolder => "net.holder",
            Self::NetRange => "net.range",
            Self::NetAbuse => "net.abuse",
            Self::AsAbuse => "as.abuse",
        }
    }

    /// Whether output needs the parent records and the delegated block.
    pub(crate) fn needs_chain(self) -> bool {
        matches!(self, Self::NetRange) || matches!(self, Self::Field(field) if field.is_net())
    }

    /// Whether the values belong to individual origin AS.
    pub(crate) fn is_as(self) -> bool {
        matches!(self, Self::AsAbuse) || matches!(self, Self::Field(field) if field.is_as())
    }
}
