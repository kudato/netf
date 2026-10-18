//! The output: the table of rows or the `--ipset` list.
//!
//! The rendered text goes either into a buffer, which `main` prints only if
//! the run succeeds, or into the `-f` file.

pub(crate) mod column;
pub(crate) mod fields;
pub(crate) mod file;
pub(crate) mod human;
pub(crate) mod ipset;
pub(crate) mod table;

use crate::{addr::set::AddrSet, model::Row};
use column::Column;

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
    },
    /// The addresses of all rows, for `--ipset`.
    Ipset(AddrSet),
}

impl Answer {
    /// Renders the answer as the text netf prints.
    pub(crate) fn render(&self, terminal_width: Option<usize>) -> String {
        match self {
            Self::Rows { rows, fields } => match terminal_width {
                Some(width) => human::render(rows, fields, width),
                None => table::render(rows, fields),
            },
            Self::Ipset(set) => ipset::render(set),
        }
    }
}
