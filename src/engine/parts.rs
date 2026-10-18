//! The addresses of rows.
//!
//! `not ip:` and `not domain:` cut addresses out of a row, and each
//! remaining part becomes a row with the same route. `--ipset` prints the
//! union of the addresses of all rows.
//!
//! A row keeps the addresses where the predicate surely holds, its
//! [`Part`]. The whole base stays one row with the part of the candidate,
//! and a route has no part. Otherwise the addresses are split by the `ip:`
//! they came from:
//!
//! - An `ip: X` kept whole is one row with the part `X`, such as an
//!   address of `domain: example.com`.
//! - The rest is one row per CIDR, such as the parts left by `not ip:`.

use crate::{
    addr::{Families, Family, Range, set::AddrSet},
    model::{Asn, Marks, Row},
    plan::eval::Part,
    query::{Expr, expr::Leaf},
};

/// Returns the prefixes of the positive `ip:` leaves of `expr`, in address
/// order and wider first.
///
/// These are the prefixes that a row is split by.
pub(crate) fn atoms(expr: &Expr) -> Vec<Range> {
    fn walk(expr: &Expr, positive: bool, out: &mut Vec<Range>) {
        match expr {
            Expr::Or(items) | Expr::And(items) => {
                items.iter().for_each(|item| walk(item, positive, out));
            }
            Expr::Not(inner) => walk(inner, !positive, out),
            Expr::Bare { inner, .. } => walk(inner, positive, out),
            Expr::Leaf(Leaf::Ip(range)) if positive => {
                out.extend(range.prefixes().map(Range::from));
            }
            Expr::Leaf(_) | Expr::False => {}
        }
    }
    let mut atoms = Vec::new();
    walk(expr, true, &mut atoms);
    atoms.sort_by_key(|range| super::candidates::key(*range));
    atoms.dedup();
    atoms
}

/// Returns the rows of a matching candidate, one row per part that `sure`
/// splits into.
///
/// `sure` holds the addresses of the candidate where the predicate surely
/// holds.
pub(crate) fn split(
    candidate: &Row,
    base: Range,
    sure: &Part,
    atoms: &[Range],
    ases: Vec<Asn>,
) -> Vec<Row> {
    let marks = Marks { route: true, ases };
    let row = |part: Option<Range>, addresses: AddrSet| Row {
        part,
        addresses,
        marks: marks.clone(),
        ..candidate.clone()
    };
    let mut rest = match sure {
        Part::Empty => return Vec::new(),
        // The whole base keeps the part of the candidate: none for a route,
        // and its own part for an address or a network without a route.
        Part::Full => {
            let part = candidate.part;
            return vec![row(part, AddrSet::from(base))];
        }
        Part::Some(set) => set.clone(),
    };
    let mut pieces: Vec<Range> = Vec::new();
    for atom in atoms.iter().filter(|atom| base.contains(atom)) {
        let whole = AddrSet::from(*atom);
        let piece = rest.intersect(&whole);
        if piece.is_empty() {
            continue;
        }
        if piece == whole {
            pieces.push(*atom);
        } else {
            pieces.extend(cidrs(&piece));
        }
        rest = rest.subtract(&piece);
    }
    pieces.extend(cidrs(&rest));
    pieces.sort_by_key(|range| super::candidates::key(*range));
    pieces
        .into_iter()
        .map(|piece| row(Some(piece), AddrSet::from(piece)))
        .collect()
}

/// Returns the CIDR prefixes of `set`, in address order.
fn cidrs(set: &AddrSet) -> Vec<Range> {
    set.pieces()
        .flat_map(|range| range.prefixes().map(Range::from).collect::<Vec<_>>())
        .collect()
}

/// Returns the addresses of `expr` in `families`.
///
/// `expr` has only `ip:` leaves, as in `--ipset 'ip: … and not ip: …'`, so
/// no dataset is needed.
pub(crate) fn addresses(expr: &Expr, families: Families) -> AddrSet {
    let universe: AddrSet = families
        .iter()
        .filter_map(|family: Family| Range::new(family, 0, family.max()))
        .collect();
    let mut set = algebra(expr, &universe);
    set.retain_family(families);
    set
}

/// Returns the addresses of an address expression.
///
/// `not` is the complement in `universe`.
fn algebra(expr: &Expr, universe: &AddrSet) -> AddrSet {
    match expr {
        Expr::Or(items) => items.iter().fold(AddrSet::new(), |set, item| {
            set.union(&algebra(item, universe))
        }),
        Expr::And(items) => items.iter().fold(universe.clone(), |set, item| {
            set.intersect(&algebra(item, universe))
        }),
        Expr::Not(inner) => universe.subtract(&algebra(inner, universe)),
        Expr::Bare { inner, .. } => algebra(inner, universe),
        Expr::Leaf(Leaf::Ip(range)) => AddrSet::from(*range),
        // The plan sends anything else to the datasets.
        Expr::Leaf(_) | Expr::False => AddrSet::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::Route;

    fn range(text: &str) -> Range {
        text.parse().unwrap()
    }

    fn ip(text: &str) -> Expr {
        Expr::Leaf(Leaf::Ip(range(text)))
    }

    fn route_row(prefix: &str) -> Row {
        Row {
            route: Some(Route {
                prefix: prefix.parse().unwrap(),
                origins: vec![64496],
            }),
            ..Row::default()
        }
    }

    fn parts(rows: &[Row]) -> Vec<String> {
        rows.iter()
            .map(|row| row.part.map_or("-".to_owned(), |part| part.to_string()))
            .collect()
    }

    #[test]
    fn atoms_are_positive_prefixes_wider_first() {
        let expr = Expr::And(vec![
            Expr::Or(vec![ip("192.0.2.1"), ip("192.0.2.0/24"), ip("192.0.2.1")]),
            Expr::Not(Box::new(ip("192.0.2.128/25"))),
        ]);
        let atoms: Vec<String> = atoms(&expr).iter().map(ToString::to_string).collect();
        assert_eq!(atoms, ["192.0.2.0/24", "192.0.2.1/32"]);
    }

    #[test]
    fn full_value_is_one_row() {
        let row = route_row("192.0.2.0/24");
        let base = range("192.0.2.0/24");
        let rows = split(&row, base, &Part::Full, &[], vec![64496]);
        assert_eq!(parts(&rows), ["-"]);
        assert_eq!(rows[0].addresses, AddrSet::from(base));
        assert!(rows[0].marks.route);
        assert_eq!(rows[0].marks.ases, [64496]);
        // Without a route, the part stays.
        let unrouted = Row {
            part: Some(base),
            ..Row::default()
        };
        assert_eq!(
            parts(&split(&unrouted, base, &Part::Full, &[], vec![])),
            ["192.0.2.0/24"]
        );
        assert!(split(&row, base, &Part::Empty, &[], vec![]).is_empty());
    }

    #[test]
    fn addresses_of_ip_are_parts() {
        let row = route_row("192.0.2.0/24");
        let base = range("192.0.2.0/24");
        let atoms = [range("192.0.2.1"), range("192.0.2.9")];
        let set: AddrSet = atoms.iter().copied().collect();
        let rows = split(&row, base, &Part::Some(set), &atoms, vec![]);
        assert_eq!(parts(&rows), ["192.0.2.1/32", "192.0.2.9/32"]);
        // A `Part` with a hole is split into CIDRs.
        let wide = [range("192.0.2.0/25")];
        let set = AddrSet::from(wide[0]).subtract(&AddrSet::from(range("192.0.2.0")));
        let rows = split(&row, base, &Part::Some(set), &wide, vec![]);
        assert_eq!(rows.len(), 7);
        assert_eq!(rows[0].part, Some(range("192.0.2.1")));
    }

    #[test]
    fn pure_address_algebra() {
        let expr = Expr::And(vec![
            Expr::Or(vec![ip("10.0.0.0/8"), ip("2001:db8::/32")]),
            Expr::Not(Box::new(ip("10.0.0.0/9"))),
        ]);
        let set = addresses(&expr, Families::V4);
        assert_eq!(set.prefixes(Family::V4), ["10.128.0.0/9".parse().unwrap()]);
        assert!(set.prefixes(Family::V6).is_empty());
        let both = addresses(&expr, Families::BOTH);
        assert_eq!(
            both.prefixes(Family::V6),
            ["2001:db8::/32".parse().unwrap()]
        );
    }
}
