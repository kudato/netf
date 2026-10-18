//! The query language: KQL text to [`Ast`], then to [`Expr`].
//!
//! A query goes through four steps:
//!
//! 1. [`lexer`] reads the text one token at a time. The parser tells it
//!    whether a field name or a value comes next, because the same
//!    characters mean different things on each side of `:`. `as.name` is a
//!    field, and `example.com` is a value.
//! 2. [`parser`] builds the [`Ast`] by recursive descent. Every term keeps
//!    its [`Span`](ast::Span), so errors can point at the text.
//! 3. [`suggest`] turns unknown fields and common mistakes into hints, such
//!    as `holder` → `net.org` or `as.org`, and "quote values with spaces".
//! 4. [`expand`] replaces `set:`, `@path`, value lists, `*field` globs, and
//!    operands without a field, and it types the values. The result is an
//!    [`Expr`] that needs nothing but the data.
//!
//! Every error is a usage error with exit code 2. An unknown construct is
//! an error, never an empty answer.

pub(crate) mod ast;
pub(crate) mod expand;
pub(crate) mod expr;
pub(crate) mod lexer;
pub(crate) mod parser;
pub(crate) mod suggest;

pub(crate) use ast::{Ast, Field};
pub(crate) use expr::Expr;

use crate::error::Result;

/// Parses the query text: the words of the command line, joined with
/// spaces.
///
/// # Errors
///
/// Returns a usage error if the text is not a valid query.
pub(crate) fn parse(text: &str) -> Result<Ast> {
    parser::parse(text)
}
