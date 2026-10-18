//! The expanded query: what the plan and the engine work on.
//!
//! An [`Expr`] has no named sets, files, value lists, or field globs,
//! because [`super::expand`] has replaced them. An operand without a field
//! is left only as [`Expr::Bare`], around its expansion. What is
//! left are data fields with typed values ([`Leaf`]), the selectors `ip:`
//! and `domain:`, and scopes `field: {…}` that need the data to resolve.
//!
//! Two nodes do not come from the text as written:
//!
//! - [`Expr::Bare`] wraps the expansion of an operand without a field:
//!   `as.name: w or as.org: w or net.org: w`. Evaluation looks through it.
//!   The node exists so that the engine can report `netf: w: nothing found`
//!   when the operand matched nothing.
//! - [`Expr::False`] matches nothing. It replaces an `ip:` or `route:` whose
//!   addresses all belong to the other family, an empty `@path` file, and an
//!   `as.asn` comparison that no number satisfies.

use super::ast::Field;
use crate::{
    addr::{Addr, Prefix, Range},
    model::{Asn, Cc, Rir, Role},
    text::Pattern,
};

/// An expanded query.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum Expr {
    /// `a or b or …`.
    Or(Vec<Expr>),
    /// `a and b and …`.
    And(Vec<Expr>),
    /// `not a`.
    Not(Box<Expr>),
    /// One condition.
    Leaf(Leaf),
    /// Matches nothing.
    False,
    /// The expansion of an operand without a field.
    Bare {
        /// The word as written, for `netf: <word>: nothing found`.
        word: String,
        /// What the word expanded to.
        inner: Box<Expr>,
    },
}

/// One typed condition.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum Leaf {
    /// `route: …`.
    Route(RouteMatch),
    /// `as.asn: …`, `as.asn >= …`.
    Asn(AsnMatch),
    /// `as.name: …`.
    AsName(Pattern),
    /// `as.org: …`.
    AsOrg(OrgMatch),
    /// `as.country: …`.
    AsCountry(Cc),
    /// `as.rir: …`.
    AsRir(Rir),
    /// `as.mnt: …`.
    AsMnt(HandleMatch),
    /// `as.contact: …`, `as.contact.<role>: …`.
    AsContact(Option<Role>, HandleMatch),
    /// `net.country: …`.
    NetCountry(Cc),
    /// `net.org: …`.
    NetOrg(OrgMatch),
    /// `net.rir: …`.
    NetRir(Rir),
    /// `net.mnt: …`.
    NetMnt(HandleMatch),
    /// `net.contact: …`, `net.contact.<role>: …`.
    NetContact(Option<Role>, HandleMatch),
    /// `ip: …`: an address, a network, or a range of a family that the run
    /// outputs.
    Ip(Range),
    /// `domain: …`, already in punycode and lowercase.
    Domain(String),
    /// `field: {…}`, a scope: the values of `field` among the rows of
    /// `inner`.
    Scope {
        /// The field whose values are collected and then matched.
        field: Field,
        /// The subquery.
        inner: Box<Expr>,
    },
    /// `ip: {…}`: the addresses of the rows of the subquery.
    IpScope(Box<Expr>),
    /// `field: *` for the fields whose condition has no "any" form.
    ///
    /// These fields are `net.country`, `net.rir`, `as.country`, and
    /// `as.rir`. For example, `route: * and not net.rir: *` finds routes to
    /// addresses that no registry delegated. The other fields use their own
    /// `Any`, such as [`RouteMatch::Any`] and [`Pattern::Any`].
    Present(Field),
}

/// A condition on `route`.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub(crate) enum RouteMatch {
    /// `route: 192.0.2.0/24`: exactly this prefix.
    Exact(Prefix),
    /// `route: 192.0.2.1`: the most specific route covering the address.
    Covering(Addr),
    /// `route: *`: any announced route.
    Any,
}

/// A condition on `as.asn`.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub(crate) enum AsnMatch {
    /// One number: `as.asn: 64496`.
    One(Asn),
    /// An inclusive range from a comparison: `as.asn >= 64512` is
    /// `Range { min: 64512, max: u32::MAX }`.
    Range {
        /// The smallest number.
        min: Asn,
        /// The largest number.
        max: Asn,
    },
    /// `as.asn: *`.
    Any,
}

/// A condition on `as.org` or `net.org`.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub(crate) enum OrgMatch {
    /// A quoted name or a name with wildcards: `"EXAMPLE LLC"`, `example*`.
    Name(Pattern),
    /// A word that can be either a handle or a name: `ORG-EX1-RIPE`,
    /// `example`.
    HandleOrName(String),
    /// `*`: the record has a holder.
    Any,
}

/// A condition on maintainers or contacts, by handle.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub(crate) enum HandleMatch {
    /// One handle, such as `EXAMPLE-MNT`. The comparison ignores case.
    Handle(String),
    /// `*`: the record has the field.
    Any,
}

impl Expr {
    /// Returns `true` if the expression has a scope anywhere.
    #[cfg(test)]
    pub(crate) fn has_scope(&self) -> bool {
        match self {
            Self::Or(items) | Self::And(items) => items.iter().any(Expr::has_scope),
            Self::Not(inner) | Self::Bare { inner, .. } => inner.has_scope(),
            Self::Leaf(Leaf::Scope { .. } | Leaf::IpScope(_)) => true,
            Self::Leaf(_) | Self::False => false,
        }
    }

    /// Visits every leaf, including those inside scopes.
    pub(crate) fn for_each_leaf(&self, visit: &mut dyn FnMut(&Leaf)) {
        match self {
            Self::Or(items) | Self::And(items) => {
                for item in items {
                    item.for_each_leaf(visit);
                }
            }
            Self::Not(inner) | Self::Bare { inner, .. } => inner.for_each_leaf(visit),
            Self::Leaf(leaf) => {
                visit(leaf);
                if let Leaf::Scope { inner, .. } | Leaf::IpScope(inner) = leaf {
                    inner.for_each_leaf(visit);
                }
            }
            Self::False => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn walks_into_scopes() {
        let inner = Expr::Leaf(Leaf::Domain("ex.test".into()));
        let expr = Expr::And(vec![
            Expr::Leaf(Leaf::Asn(AsnMatch::Any)),
            Expr::Not(Box::new(Expr::Leaf(Leaf::Scope {
                field: Field::AsAsn,
                inner: Box::new(inner),
            }))),
        ]);
        assert!(expr.has_scope());
        let mut count = 0;
        expr.for_each_leaf(&mut |_| count += 1);
        assert_eq!(count, 3);
        assert!(!Expr::False.has_scope());
    }
}
