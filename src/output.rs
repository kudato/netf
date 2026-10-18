//! The output: the table of rows or the `--ipset` list.
//!
//! The rendered text goes either into a buffer, which `main` prints only if
//! the run succeeds, or into the `-f` file.

pub(crate) mod column;
pub(crate) mod fields;
pub(crate) mod file;
pub(crate) mod human;
pub(crate) mod ipset;
pub(crate) mod metadata;
pub(crate) mod table;

use crate::{addr::set::AddrSet, model::Row};
use column::Column;

/// How selected fields are laid out. Only explicit formats affect pipes/files.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Format {
    Auto,
    Table,
    Details,
    Plain,
}

impl Format {
    pub(crate) fn parse(value: &str) -> Option<Self> {
        match value {
            "auto" => Some(Self::Auto),
            "table" => Some(Self::Table),
            "details" => Some(Self::Details),
            "plain" => Some(Self::Plain),
            _ => None,
        }
    }
}

/// What the engine answered.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum Answer {
    /// The rows to show, already limited, in address order, with the
    /// columns of `--fields`.
    Rows {
        /// The rows.
        rows: Vec<Row>,
        /// The columns added with `--fields`.
        fields: Vec<Column>,
        /// Counts from selection, before enrichment or MOAS presentation.
        selection: metadata::Selection,
    },
    /// The addresses of all rows, for `--ipset`.
    Ipset(AddrSet),
}

impl Answer {
    /// Renders the answer as the text netf prints.
    pub(crate) fn render(
        &self,
        terminal_width: Option<usize>,
        format: Option<Format>,
        columns: Option<&[Column]>,
    ) -> String {
        match self {
            Self::Rows { rows, fields, .. } => {
                let width = terminal_width.unwrap_or(80);
                if let Some(columns) = columns {
                    human::exact(rows, columns, width, format.unwrap_or(Format::Auto))
                } else if format == Some(Format::Plain)
                    || format.is_none() && terminal_width.is_none()
                {
                    table::render(rows, fields)
                } else {
                    human::render_with_format(rows, fields, width, format.unwrap_or(Format::Auto))
                }
            }
            Self::Ipset(set) => ipset::render(set),
        }
    }
}
