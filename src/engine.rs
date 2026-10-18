//! The engine: runs a plan and returns the rows.
//!
//! A run takes these steps in order:
//!
//! 1. [`scope`] resolves domains and scopes `{…}`.
//! 2. [`candidates`] generates the candidates in address order.
//! 3. [`eval`] evaluates the predicate on every candidate.
//! 4. [`expensive`] runs the expensive filters, one RDAP request per row,
//!    in a window that stops at the limit.
//! 5. [`parts`] splits a matching row into parts by the addresses it
//!    keeps after `not ip:`.
//! 6. [`enrich`] adds the network, holder, and abuse columns to the shown
//!    rows.
//!
//! The engine reports notices, such as the limit or an organization not
//! found, as soon as it finds them. The answer is all or nothing: if a
//! source fails, the run returns an error and no rows.

pub(crate) mod candidates;
pub(crate) mod enrich;
pub(crate) mod expensive;
pub(crate) mod intervals;
pub(crate) mod parts;
pub(crate) mod scope;
pub(crate) mod stats;

use std::{
    collections::{HashMap, HashSet},
    sync::{Mutex, PoisonError},
};

use crate::{
    addr::{Families, set::AddrSet},
    dns::{Resolved, Resolver},
    error::{Error, Result},
    model::Row,
    output::Answer,
    plan::{
        Mode, OrgSide, Plan,
        eval::{self, Facts, Truth, Value},
    },
    query::{Expr, expr::OrgMatch},
    rdap::RdapClient,
    report::{Notice, Reporter},
    ripe_rest::RipeRest,
    sources::Sources,
};

/// What a run of the engine works with.
pub(crate) struct Context<'a> {
    /// The datasets.
    pub(crate) sources: &'a Sources,
    /// RDAP of the registries.
    pub(crate) rdap: &'a RdapClient,
    /// The RIPE database REST API, for reverse searches and for RIPE
    /// organizations by name.
    pub(crate) rest: &'a RipeRest,
    /// DNS, for `domain:`.
    pub(crate) resolver: &'a dyn Resolver,
    /// Where notices go.
    pub(crate) reporter: &'a dyn Reporter,
    /// `--concurrency`, the number of requests at once per egress.
    pub(crate) concurrency: usize,
}

/// Runs `plan` and returns the answer: the rows to show, limited, or the
/// addresses of all rows for `--ipset`.
///
/// # Errors
///
/// Returns an error if a source, a registry, or a domain lookup fails.
pub(crate) async fn run(plan: &Plan, context: &Context<'_>) -> Result<Answer> {
    let sources = context.sources;
    context.reporter.activity(Some("loading network data"));
    sources.prepare(&plan.needs).await?;
    // Without a cache, datasets stream during matching instead of prepare.
    context.reporter.activity(Some("finding matches"));
    let egresses = sources.transport().egresses().len().max(1);
    let engine = Engine {
        sources,
        rdap: context.rdap,
        rest: context.rest,
        resolver: context.resolver,
        reporter: context.reporter,
        families: plan.families,
        rows_mode: matches!(plan.mode, Mode::Rows { .. }),
        need_stats: plan.needs.stats,
        window: context.concurrency.max(1) * egresses,
        stats: stats::Stats::default(),
        domains: Mutex::new(HashMap::new()),
        reported: Mutex::new(Vec::new()),
        quiet: Mutex::new(HashSet::new()),
    };
    let expr = scope::resolve(&engine, &plan.root).await?;
    match &plan.mode {
        // A query of addresses only, such as `--ipset 'ip: …'`, needs no
        // dataset at all.
        Mode::Ipset if plan.needs.ris.is_empty() => {
            Ok(Answer::Ipset(parts::addresses(&expr, plan.families)))
        }
        Mode::Ipset => {
            let selection = engine
                .select(&expr, plan.needs.asn, false, Collect::Addresses)
                .await?;
            Ok(Answer::Ipset(selection.addresses))
        }
        Mode::Rows { limit, fields } => {
            let mut selection = engine
                .select(&expr, true, false, Collect::Rows { limit: *limit })
                .await?;
            if let Some(unchecked) = selection.unchecked {
                engine.notice(Notice::LimitUnchecked {
                    shown: limit.unwrap_or(selection.total),
                    unchecked,
                });
            } else if let Some(shown) = limit.filter(|shown| *shown < selection.total) {
                engine.notice(Notice::Limit {
                    shown,
                    total: selection.total,
                });
            }
            enrich::rows(&engine, &mut selection.rows, fields).await?;
            Ok(Answer::Rows {
                rows: selection.rows,
                fields: fields.clone(),
                selection: crate::output::metadata::Selection {
                    shown: limit.map_or(selection.total, |n| n.min(selection.total)),
                    total: selection.unchecked.is_none().then_some(selection.total),
                    unchecked: selection.unchecked.unwrap_or(0),
                },
            })
        }
    }
}

/// What a selection keeps of the matching rows.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Collect {
    /// The rows of the first `limit` routes, or of all routes with `None`,
    /// and the number of matching routes.
    Rows {
        /// The limit, in routes. The parts of one route stay together.
        limit: Option<usize>,
    },
    /// Only the addresses of all rows, for `--ipset` and `ip: {…}`.
    Addresses,
}

/// The result of a selection.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub(crate) struct Selection {
    /// The rows kept, in the order of their routes. The parts of one route
    /// stay together.
    pub(crate) rows: Vec<Row>,
    /// The number of matching routes and addresses without a route: the
    /// units of the limit.
    pub(crate) total: usize,
    /// The addresses of all matching rows, with [`Collect::Addresses`].
    pub(crate) addresses: AddrSet,
    /// The number of candidates that RDAP did not check because the limit
    /// filled first. With `Some`, `total` is not known.
    pub(crate) unchecked: Option<usize>,
}

impl Selection {
    /// Counts a matching candidate and keeps what `collect` asks of it.
    fn accept(
        &mut self,
        collect: Collect,
        candidate: &Row,
        base: crate::addr::Range,
        value: &Value,
        marks: Vec<crate::model::Asn>,
        atoms: &[crate::addr::Range],
    ) {
        self.total += 1;
        match collect {
            Collect::Addresses => {
                for piece in value.sure.addresses(base).pieces() {
                    self.addresses.insert(piece);
                }
            }
            Collect::Rows { limit } => {
                if limit.is_none_or(|limit| self.total <= limit) {
                    self.rows
                        .extend(parts::split(candidate, base, &value.sure, atoms, marks));
                }
            }
        }
    }
}

/// The state of one run of the engine.
pub(crate) struct Engine<'a> {
    /// The datasets.
    pub(crate) sources: &'a Sources,
    /// RDAP of the registries.
    pub(crate) rdap: &'a RdapClient,
    /// The RIPE database REST API.
    pub(crate) rest: &'a RipeRest,
    /// DNS, for `domain:`.
    resolver: &'a dyn Resolver,
    /// Where notices go.
    pub(crate) reporter: &'a dyn Reporter,
    /// The families of the run.
    pub(crate) families: Families,
    /// `true` if the answer is rows. Notices then name the AS with its
    /// asn.txt line.
    pub(crate) rows_mode: bool,
    /// `true` if the rows carry their stats blocks and AS blocks. The plan
    /// needs the stats for `net.*`, `as.rir`, and `--fields net.*`.
    pub(crate) need_stats: bool,
    /// The number of RDAP requests at once: `--concurrency` times the
    /// number of egresses.
    pub(crate) window: usize,
    /// The delegated stats.
    pub(crate) stats: stats::Stats,
    /// The domains resolved so far. Each domain is resolved once per run.
    domains: Mutex<HashMap<String, Resolved>>,
    /// The notices reported so far, so a scope that runs twice does not
    /// repeat them.
    reported: Mutex<Vec<Notice>>,
    /// The organization conditions that a scope produced from the records
    /// of its rows. The engine does not report an empty answer for them.
    quiet: Mutex<HashSet<(OrgSide, OrgMatch)>>,
}

impl Engine<'_> {
    /// Reports `notice` unless it was reported already.
    pub(crate) fn notice(&self, notice: Notice) {
        let mut reported = self.reported.lock().unwrap_or_else(PoisonError::into_inner);
        if !reported.contains(&notice) {
            self.reporter.notice(&notice);
            reported.push(notice);
        }
    }

    /// Records an organization condition that a scope produced, so the
    /// engine does not report it as not found or empty.
    pub(crate) fn quiet(&self, side: OrgSide, matcher: OrgMatch) {
        self.quiet
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .insert((side, matcher));
    }

    /// Returns `true` if a scope produced the condition `matcher` on
    /// `side`, as recorded by [`quiet`](Self::quiet).
    pub(crate) fn is_quiet(&self, side: OrgSide, matcher: &OrgMatch) -> bool {
        self.quiet
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .contains(&(side, matcher.clone()))
    }

    /// Resolves `name` in the families of the run, once per run.
    ///
    /// The flag is `true` on the first resolution of `name` and `false`
    /// when the answer comes from earlier in the run.
    ///
    /// # Errors
    ///
    /// Returns an error if the resolver fails.
    pub(crate) async fn resolve_domain(&self, name: &str) -> Result<(Resolved, bool)> {
        let known = self
            .domains
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get(name)
            .cloned();
        if let Some(resolved) = known {
            return Ok((resolved, false));
        }
        let resolved = self
            .resolver
            .resolve(name, self.families)
            .await
            .map_err(|error| Error::runtime(format!("domain {name}: {error}")))?;
        self.domains
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(name.to_owned(), resolved.clone());
        Ok((resolved, true))
    }

    /// Selects the rows of `expr` in the order of their routes, one row per
    /// part.
    ///
    /// `expr` is resolved, so it has no domains and no scopes. With `asn`,
    /// the engine loads asn.txt for the AS of the rows. With `scope`, it
    /// evaluates the inside of a scope, where `ip: X` takes only the
    /// covering route.
    ///
    /// # Errors
    ///
    /// Returns an error if a source or a registry fails.
    pub(crate) async fn select(
        &self,
        expr: &Expr,
        asn: bool,
        scope: bool,
        collect: Collect,
    ) -> Result<Selection> {
        let mut found = candidates::find(self, expr, asn).await?;
        let facts = Facts {
            cover: std::mem::take(&mut found.cover),
            scope,
            orgs: std::mem::take(&mut found.orgs),
            names: std::mem::take(&mut found.org_names),
            handles: std::mem::take(&mut found.handles),
        };
        let atoms = parts::atoms(expr);
        let mut bare = candidates::bare(expr);
        let expensive = expensive::has_leaves(expr);
        let mut selection = Selection::default();
        // With an expensive filter, these candidates wait for RDAP to
        // decide.
        let mut pending: Vec<(Row, Truth)> = Vec::new();
        for candidate in found.candidates() {
            let Some(base) = candidate.base() else {
                continue;
            };
            for bare in &mut bare {
                if !bare.found {
                    bare.found = eval::eval_row(bare.inner, &candidate, base, &facts)
                        .0
                        .truth()
                        != Truth::False;
                }
            }
            let (value, marks) = eval::eval_row(expr, &candidate, base, &facts);
            if expensive {
                let truth = value.truth();
                if truth != Truth::False {
                    pending.push((candidate, truth));
                }
                continue;
            }
            if value.sure.is_empty() {
                continue;
            }
            selection.accept(collect, &candidate, base, &value, marks, &atoms);
        }
        if expensive {
            let limit = match collect {
                Collect::Rows { limit } => limit,
                Collect::Addresses => None,
            };
            let checked = expensive::check(self, expr, &facts, pending, limit).await?;
            for (candidate, value, marks) in checked.matches {
                if let Some(base) = candidate.base() {
                    selection.accept(collect, &candidate, base, &value, marks, &atoms);
                }
            }
            selection.total += checked.more;
            selection.unchecked = checked.unchecked;
        }
        found.report(self, &bare);
        Ok(selection)
    }
}
