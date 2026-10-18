//! Expensive filters: RDAP checks of the candidates in address order.
//!
//! If the generator did not look up a record, a condition on the holder,
//! the maintainers, or the contacts of that record is known only from the
//! RDAP record of the row, so the cheap conditions leave the candidate
//! undecided. [`check`] fetches the records of the undecided candidates in
//! address order, `--concurrency` × egresses at once, and shows progress as
//! `rdap: done/total`. With a limit, the check stops as soon as the limit
//! is filled. If some of the remaining candidates need RDAP, the check
//! counts all of them as not checked, and the `LimitUnchecked` notice
//! reports them. `--ipset` and scopes check every candidate.

use futures_util::{StreamExt, future::try_join_all, stream};

use super::Engine;
use crate::{
    error::Result,
    model::{Asn, NetCandidate, Row},
    plan::eval::{self, Facts, Truth, Value},
    query::{Expr, expr::Leaf},
};

/// The records that the expensive leaves of an expression read.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct Wants {
    /// The network record and its chain: `net.org`, `net.mnt`,
    /// `net.contact`.
    net: bool,
    /// The AS records: `as.org`, `as.mnt`, `as.contact`.
    asn: bool,
}

impl Wants {
    fn of(expr: &Expr) -> Self {
        let mut wants = Self::default();
        expr.for_each_leaf(&mut |leaf| match leaf {
            Leaf::NetOrg(_) | Leaf::NetMnt(_) | Leaf::NetContact(..) => wants.net = true,
            Leaf::AsOrg(_) | Leaf::AsMnt(_) | Leaf::AsContact(..) => wants.asn = true,
            _ => {}
        });
        wants
    }
}

/// Returns `true` if `expr` has leaves that RDAP may have to decide.
pub(crate) fn has_leaves(expr: &Expr) -> bool {
    Wants::of(expr) != Wants::default()
}

/// The result of [`check`].
#[derive(Debug, Default)]
pub(crate) struct Checked {
    /// The matching candidates, in order, with their value and the AS that
    /// matched.
    pub(crate) matches: Vec<(Row, Value, Vec<Asn>)>,
    /// The number of candidates after the limit that surely match.
    /// They count in the total.
    pub(crate) more: usize,
    /// The number of candidates after the limit, if some of them needed
    /// RDAP. The total is then unknown.
    pub(crate) unchecked: Option<usize>,
}

/// Checks `pending`: the candidates that the cheap conditions did not
/// reject, each with its cheap outcome.
///
/// Stops after `limit` matches.
///
/// # Errors
///
/// Returns an error if a registry fails.
pub(crate) async fn check(
    engine: &Engine<'_>,
    expr: &Expr,
    facts: &Facts,
    pending: Vec<(Row, Truth)>,
    limit: Option<usize>,
) -> Result<Checked> {
    let wants = Wants::of(expr);
    let truths: Vec<Truth> = pending.iter().map(|(_, truth)| *truth).collect();
    let total =
        u32::try_from(truths.iter().filter(|t| **t == Truth::Unknown).count()).unwrap_or(u32::MAX);
    let mut checks = stream::iter(pending)
        .map(|(row, truth)| async move {
            if truth == Truth::Unknown {
                fetch(engine, row, wants).await.map(|row| (row, true))
            } else {
                Ok((row, false))
            }
        })
        .buffered(engine.window.max(1));
    let mut checked = Checked::default();
    let mut consumed = 0;
    let mut done = 0;
    engine.reporter.items(0, total, "networks");
    while let Some(next) = checks.next().await {
        let (row, fetched) = match next {
            Ok(next) => next,
            Err(error) => {
                engine.reporter.clear_progress();
                return Err(error);
            }
        };
        consumed += 1;
        if fetched {
            done += 1;
            engine.reporter.progress(done, total, "rdap");
        }
        let Some(base) = row.base() else {
            continue;
        };
        let (value, marks) = eval::eval_row(expr, &row, base, facts);
        if value.sure.is_empty() {
            continue;
        }
        checked.matches.push((row, value, marks));
        if limit.is_some_and(|limit| checked.matches.len() >= limit) {
            break;
        }
    }
    drop(checks);
    engine.reporter.clear_progress();
    let rest = &truths[consumed..];
    if rest.contains(&Truth::Unknown) {
        checked.unchecked = Some(rest.len());
    } else {
        checked.more = rest.len();
    }
    Ok(checked)
}

/// Fetches the RDAP records of `row` that `wants` names.
///
/// These are the most specific network record of the row's base with the
/// chain up to its block, and the records of the row's AS.
async fn fetch(engine: &Engine<'_>, mut row: Row, wants: Wants) -> Result<Row> {
    if wants.net
        && let Some(base) = row.base()
        && let Some(record) = engine.rdap.ip(base).await?
    {
        let block = eval::block_of(&row.nets, base).map(|block| block.range);
        let chain = engine.rdap.up_chain(&record, block.as_ref()).await?;
        for record in chain.into_iter().chain([record]) {
            let known = row.nets.iter().any(|net| match net {
                NetCandidate::Record(other) => {
                    other.range == record.range && other.handle == record.handle
                }
                NetCandidate::Block(_) => false,
            });
            if !known {
                row.nets.push(NetCandidate::Record(record));
            }
        }
    }
    if wants.asn {
        let missing: Vec<usize> = (0..row.ases.len())
            .filter(|index| row.ases[*index].rdap.is_none())
            .collect();
        let records = try_join_all(
            missing
                .iter()
                .map(|index| engine.rdap.autnum(row.ases[*index].asn)),
        )
        .await?;
        for (index, record) in missing.into_iter().zip(records) {
            row.ases[index].rdap = record;
        }
    }
    row.fetched = true;
    Ok(row)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::query::expr::{HandleMatch, OrgMatch};

    #[test]
    fn rdap_leaves_are_expensive() {
        let leaf = |leaf| Expr::Leaf(leaf);
        assert!(!has_leaves(&leaf(Leaf::Route(
            crate::query::expr::RouteMatch::Any
        ))));
        let net = leaf(Leaf::NetOrg(OrgMatch::Any));
        assert_eq!(
            Wants::of(&net),
            Wants {
                net: true,
                asn: false
            }
        );
        let both = Expr::And(vec![net, leaf(Leaf::AsMnt(HandleMatch::Any))]);
        assert_eq!(
            Wants::of(&both),
            Wants {
                net: true,
                asn: true
            }
        );
        assert!(has_leaves(&both));
    }
}
