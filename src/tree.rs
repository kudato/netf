//! The interactive tree of `-i`.
//!
//! Every query gets a tree of the same shape:
//!
//! ```text
//! AS organization
//! └─ AS
//!    └─ route · network holder · also AS…
//!       └─ part
//! no route
//! └─ network · holder
//! ```
//!
//! [`build`] makes the tree from the rows of the engine. The rows are
//! already limited and carry the holder of each route and the RDAP record
//! of each AS. The organization of an AS is the registrant of its
//! `autnum`, so each AS appears once, under its organization. A route with
//! several origins appears under each AS it matched for, with `also AS…`.
//!
//! The `▶` sign shows what the query matched. If the query took only parts
//! of a route, the parts get `▶`. Otherwise the route gets `▶` when the
//! query has conditions on addresses, routes, or networks. The AS gets `▶`
//! when the query has conditions on `as.*`.
//!
//! One request to RIS counts the routes of every AS in the tree
//! ([`Sources::routes_of`](crate::sources::Sources::routes_of)). A
//! `· N routes` node stands for the routes that are not shown. Expanding
//! that node loads the next page of routes, `--limit` at a time, with their
//! holders from RDAP. So netf asks the registries only about what the user
//! expands. An AS of `as.asn: N` without any route appears with
//! `· 0 routes`.
//!
//! [`Tree::query`] turns the marked nodes back into KQL. [`render`] draws
//! the lines without a terminal. [`tui`] handles the keys and the screen.

pub(crate) mod render;
pub(crate) mod tui;

use std::{
    collections::{HashMap, HashSet},
    sync::{Arc, Mutex, PoisonError},
};

use futures_util::{StreamExt as _, stream};

use crate::{
    addr::{Prefix, Range},
    dataset::{AsnSet, asn::AsnRequest},
    engine::Context,
    error::{Error, Result},
    model::{AsInfo, Asn, NetRecord, Route, Row},
    plan::{Mode, Plan},
    query::{
        Expr, Field,
        expr::{AsnMatch, Leaf},
    },
    report::{Notice, Reporter},
};

/// The tree of one query.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub(crate) struct Tree {
    /// The first line: the query.
    pub(crate) header: String,
    /// A registry truncated a response for the query. The header shows `*`.
    pub(crate) truncated: bool,
    /// The organizations of AS, then `no route`.
    pub(crate) roots: Vec<Node>,
}

/// A node of the tree.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct Node {
    /// What the node stands for.
    pub(crate) kind: NodeKind,
    /// The text after the signs: `AS64496 EXAMPLE-NET`.
    pub(crate) label: String,
    /// The children, in order.
    pub(crate) children: Vec<Node>,
    /// The query matched the node. The node shows `▶`.
    pub(crate) matched: bool,
    /// The user marked the node. Its KQL is printed on exit.
    pub(crate) marked: bool,
    /// The children are shown.
    pub(crate) expanded: bool,
    /// For an organization or an AS, the number of its routes in RIS,
    /// shown or not. A collapsed node shows this number as its size.
    pub(crate) routes: usize,
}

/// What a node stands for.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum NodeKind {
    /// An organization of AS, with its KQL form.
    Org(OrgQuery),
    /// An AS.
    As(Asn),
    /// A route under one of its AS.
    Route(Prefix),
    /// The part of a route the query took.
    Part(Range),
    /// The root of the networks without a route.
    NoRoute,
    /// A registry network without a route.
    Net(Range),
    /// The routes of an AS not shown yet: `· N routes`.
    More {
        /// The AS.
        asn: Asn,
        /// The routes, in address order.
        rest: Vec<Route>,
    },
}

/// How an organization is written in KQL.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum OrgQuery {
    /// By name: `as.org: "Example Networks LLC"`.
    Name(String),
    /// By handle, or by the opaque-id from the delegated stats:
    /// `as.org: ORG-EN1-RIPE`.
    Handle(String),
    /// An organization that the registries do not know. The KQL lists its
    /// AS: `as.asn: N or …`.
    Ases,
}

impl Node {
    /// Creates an expanded node without children.
    fn new(kind: NodeKind, label: String) -> Self {
        Self {
            kind,
            label,
            children: Vec::new(),
            matched: false,
            marked: false,
            expanded: true,
            routes: 0,
        }
    }

    /// Returns `true` if the user can mark the node.
    ///
    /// The user can mark every node except `no route` and `· N routes`,
    /// which have no KQL form.
    pub(crate) fn markable(&self) -> bool {
        !matches!(self.kind, NodeKind::NoRoute | NodeKind::More { .. })
    }

    /// Returns the KQL of this node alone.
    ///
    /// Returns `None` for `no route`, for `· N routes`, and for an
    /// [`OrgQuery::Ases`] organization without AS children.
    pub(crate) fn kql(&self) -> Option<String> {
        Some(match &self.kind {
            NodeKind::Org(OrgQuery::Name(name)) => format!("as.org: \"{}\"", quote(name)),
            NodeKind::Org(OrgQuery::Handle(handle)) => format!("as.org: {handle}"),
            NodeKind::Org(OrgQuery::Ases) => {
                let ases: Vec<String> = self
                    .children
                    .iter()
                    .filter_map(|child| match child.kind {
                        NodeKind::As(asn) => Some(format!("as.asn: {asn}")),
                        _ => None,
                    })
                    .collect();
                if ases.is_empty() {
                    return None;
                }
                ases.join(" or ")
            }
            NodeKind::As(asn) => format!("as.asn: {asn}"),
            NodeKind::Route(prefix) => format!("route: {prefix}"),
            NodeKind::Part(range) | NodeKind::Net(range) => format!("ip: {}", part(*range)),
            NodeKind::NoRoute | NodeKind::More { .. } => return None,
        })
    }
}

impl Tree {
    /// Returns `true` if the tree has nothing to show.
    pub(crate) fn is_empty(&self) -> bool {
        self.roots.is_empty()
    }

    /// Returns the node at `path`, a list of child indexes from the roots
    /// down.
    pub(crate) fn node(&self, path: &[usize]) -> Option<&Node> {
        let (first, rest) = path.split_first()?;
        let mut node = self.roots.get(*first)?;
        for index in rest {
            node = node.children.get(*index)?;
        }
        Some(node)
    }

    /// Returns the node at `path` as a mutable reference.
    pub(crate) fn node_mut(&mut self, path: &[usize]) -> Option<&mut Node> {
        let (first, rest) = path.split_first()?;
        let mut node = self.roots.get_mut(*first)?;
        for index in rest {
            node = node.children.get_mut(*index)?;
        }
        Some(node)
    }

    /// Returns the KQL of the marked nodes, joined by ` or `.
    ///
    /// The nodes come in tree order, and each KQL appears once. The string
    /// is empty if no node is marked.
    pub(crate) fn query(&self) -> String {
        fn walk(node: &Node, seen: &mut HashSet<String>, out: &mut Vec<String>) {
            if node.marked
                && let Some(kql) = node.kql()
                && seen.insert(kql.clone())
            {
                out.push(kql);
            }
            for child in &node.children {
                walk(child, seen, out);
            }
        }
        let (mut seen, mut out) = (HashSet::new(), Vec::new());
        for root in &self.roots {
            walk(root, &mut seen, &mut out);
        }
        out.join(" or ")
    }

    /// Returns the next routes of the `· N routes` node at `path`.
    ///
    /// Returns at most `page` routes, or all of them if `page` is `None`.
    /// Returns `None` if the node at `path` is not a `· N routes` node.
    pub(crate) fn page(&self, path: &[usize], page: Option<usize>) -> Option<Vec<Route>> {
        match &self.node(path)?.kind {
            NodeKind::More { rest, .. } => {
                let count = page.map_or(rest.len(), |page| page.clamp(1, rest.len()));
                Some(rest[..count].to_vec())
            }
            _ => None,
        }
    }

    /// Shows the next routes of the `· N routes` node at `path`.
    ///
    /// Inserts one route node per entry of `holders` before the
    /// `· N routes` node. Removes the `· N routes` node when no route is
    /// left.
    pub(crate) fn show_page(&mut self, path: &[usize], holders: &[Option<String>]) {
        let Some((index, parent)) = path.split_last() else {
            return;
        };
        let siblings = if parent.is_empty() {
            &mut self.roots
        } else {
            match self.node_mut(parent) {
                Some(node) => &mut node.children,
                None => return,
            }
        };
        let Some(more) = siblings.get_mut(*index) else {
            return;
        };
        let NodeKind::More { asn, rest } = &mut more.kind else {
            return;
        };
        let asn = *asn;
        let count = holders.len().min(rest.len());
        let routes: Vec<Route> = rest.drain(..count).collect();
        let empty = rest.is_empty();
        more.label = format!("· {}", self::count(rest.len(), "route", "routes"));
        let nodes = routes
            .iter()
            .zip(holders)
            .map(|(route, holder)| route_node(route, asn, holder.as_deref(), false, Vec::new()));
        siblings.splice(*index..*index, nodes);
        if empty {
            siblings.remove(index + count);
        }
    }
}

/// The levels of the tree that get `▶`.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct Levels {
    /// The query has conditions on `as.*`. The AS it matched get `▶`.
    pub(crate) ases: bool,
    /// The query has conditions on addresses, routes, or networks. The
    /// routes get `▶`, or their parts if the query took only parts.
    pub(crate) routes: bool,
}

impl Levels {
    /// Returns the levels of the positive conditions of `expr`.
    ///
    /// A condition is positive under an even number of `not`. If `expr`
    /// has no positive condition on `as.*`, the routes get `▶`.
    pub(crate) fn of(expr: &Expr) -> Self {
        fn walk(expr: &Expr, positive: bool, levels: &mut Levels) {
            match expr {
                Expr::Or(items) | Expr::And(items) => {
                    items.iter().for_each(|item| walk(item, positive, levels));
                }
                Expr::Not(inner) => walk(inner, !positive, levels),
                Expr::Bare { inner, .. } => walk(inner, positive, levels),
                Expr::Leaf(leaf) if positive => {
                    if leaf_is_as(leaf) {
                        levels.ases = true;
                    } else {
                        levels.routes = true;
                    }
                }
                Expr::Leaf(_) | Expr::False => {}
            }
        }
        let mut levels = Self::default();
        walk(expr, true, &mut levels);
        if !levels.ases {
            levels.routes = true;
        }
        levels
    }
}

/// Returns `true` if `leaf` is a condition on the AS of a route.
fn leaf_is_as(leaf: &Leaf) -> bool {
    match leaf {
        Leaf::Asn(_)
        | Leaf::AsName(_)
        | Leaf::AsOrg(_)
        | Leaf::AsCountry(_)
        | Leaf::AsRir(_)
        | Leaf::AsMnt(_)
        | Leaf::AsContact(..) => true,
        Leaf::Scope { field, .. } | Leaf::Present(field) => matches!(
            field,
            Field::AsAsn
                | Field::AsName
                | Field::AsOrg
                | Field::AsCountry
                | Field::AsRir
                | Field::AsMnt
                | Field::AsContact(_)
        ),
        _ => false,
    }
}

/// Returns the AS numbers of the positive `as.asn: N` conditions of `expr`.
///
/// These AS appear in the tree even without a route, with `· 0 routes`.
fn named_ases(expr: &Expr) -> Vec<Asn> {
    fn walk(expr: &Expr, positive: bool, out: &mut Vec<Asn>) {
        match expr {
            Expr::Or(items) | Expr::And(items) => {
                items.iter().for_each(|item| walk(item, positive, out));
            }
            Expr::Not(inner) => walk(inner, !positive, out),
            Expr::Bare { inner, .. } => walk(inner, positive, out),
            Expr::Leaf(Leaf::Asn(AsnMatch::One(asn))) if positive => {
                if !out.contains(asn) {
                    out.push(*asn);
                }
            }
            Expr::Leaf(_) | Expr::False => {}
        }
    }
    let mut out = Vec::new();
    walk(expr, true, &mut out);
    out
}

/// What the tree is made of, gathered by [`build`].
#[derive(Clone, Debug, Default)]
pub(crate) struct Inputs<'a> {
    /// The query, for the header.
    pub(crate) header: String,
    /// A registry truncated a response.
    pub(crate) truncated: bool,
    /// What the query is about.
    pub(crate) levels: Levels,
    /// The rows of the engine, in order.
    pub(crate) rows: &'a [Row],
    /// The holders of the routes whose rows all have parts. The records in
    /// those rows belong to the parts, not to the route.
    pub(crate) holders: HashMap<Prefix, Option<String>>,
    /// Every route of every AS in the tree.
    pub(crate) routes: &'a [Route],
    /// The AS of `as.asn: N` that have no route.
    pub(crate) quiet: &'a [AsInfo],
}

/// The rows of one route, consecutive in the answer.
struct Group<'a> {
    route: &'a Route,
    rows: Vec<&'a Row>,
}

/// Splits `rows` into groups of consecutive rows of one route, and the rows
/// without a route.
fn groups(rows: &[Row]) -> (Vec<Group<'_>>, Vec<&Row>) {
    let (mut groups, mut unrouted): (Vec<Group<'_>>, Vec<&Row>) = (Vec::new(), Vec::new());
    for row in rows {
        match &row.route {
            Some(route) => match groups.last_mut() {
                Some(group) if group.route.prefix == route.prefix => group.rows.push(row),
                _ => groups.push(Group {
                    route,
                    rows: vec![row],
                }),
            },
            None => unrouted.push(row),
        }
    }
    (groups, unrouted)
}

impl Group<'_> {
    /// Returns the AS the route appears under: the AS it matched for, or
    /// all its origins if it matched for none.
    fn ases(&self) -> Vec<Asn> {
        let matched: Vec<Asn> = self
            .route
            .origins
            .iter()
            .copied()
            .filter(|asn| self.rows.iter().any(|row| row.marks.ases.contains(asn)))
            .collect();
        if matched.is_empty() {
            self.route.origins.clone()
        } else {
            matched
        }
    }

    /// Returns the parts the query took. The list is empty if the query
    /// took the whole route.
    fn parts(&self) -> Vec<Range> {
        self.rows.iter().filter_map(|row| row.part).collect()
    }

    /// Returns the holder of the route from a row without a part.
    ///
    /// Returns `None` if every row has a part, and `Some(None)` if the
    /// record of that row has no holder.
    fn holder(&self) -> Option<Option<String>> {
        self.rows
            .iter()
            .find(|row| row.part.is_none())
            .map(|row| row.chain.records.last().and_then(|record| holder(record)))
    }

    /// Returns what the rows know about `asn`.
    fn info(&self, asn: Asn) -> Option<&AsInfo> {
        self.rows
            .iter()
            .flat_map(|row| &row.ases)
            .find(|info| info.asn == asn)
    }
}

/// An organization being assembled.
struct OrgDraft {
    key: String,
    label: String,
    query: OrgQuery,
    ases: Vec<AsDraft>,
}

/// An AS being assembled.
struct AsDraft {
    asn: Asn,
    label: String,
    matched: bool,
    routes: Vec<Node>,
}

/// Builds the tree from `inputs`.
///
/// The function does no I/O, so tests call it directly.
pub(crate) fn assemble(inputs: &Inputs<'_>) -> Tree {
    let (groups, unrouted) = groups(inputs.rows);
    let mut orgs: Vec<OrgDraft> = Vec::new();
    for group in &groups {
        let parts = group.parts();
        let holder = group
            .holder()
            .or_else(|| inputs.holders.get(&group.route.prefix).cloned())
            .flatten();
        let children: Vec<Node> = parts
            .iter()
            .map(|range| Node {
                matched: true,
                ..Node::new(NodeKind::Part(*range), part(*range))
            })
            .collect();
        let matched = inputs.levels.routes && parts.is_empty();
        for asn in group.ases() {
            let fallback = AsInfo {
                asn,
                entry: None,
                block: None,
                rdap: None,
            };
            let info = group.info(asn).unwrap_or(&fallback);
            let (org, index) = place(&mut orgs, info);
            let draft = &mut orgs[org].ases[index];
            draft.matched |=
                inputs.levels.ases && group.rows.iter().any(|row| row.marks.ases.contains(&asn));
            draft.routes.push(route_node(
                group.route,
                asn,
                holder.as_deref(),
                matched,
                children.clone(),
            ));
        }
    }
    for info in inputs.quiet {
        let (org, index) = place(&mut orgs, info);
        orgs[org].ases[index].matched |= inputs.levels.ases;
    }
    // `all` maps each AS to every route it originates, for the counts and
    // `· N routes`.
    let mut all: HashMap<Asn, Vec<&Route>> = HashMap::new();
    for route in inputs.routes {
        for asn in &route.origins {
            all.entry(*asn).or_default().push(route);
        }
    }
    let mut roots: Vec<Node> = orgs
        .into_iter()
        .map(|org| {
            let ases: Vec<Node> = org
                .ases
                .into_iter()
                .map(|draft| {
                    let routes = all.get(&draft.asn);
                    as_node(draft, routes)
                })
                .collect();
            let mut node = Node::new(NodeKind::Org(org.query), org.label);
            node.routes = ases.iter().map(|node| node.routes).sum();
            node.children = ases;
            node
        })
        .collect();
    if !unrouted.is_empty() {
        let mut node = Node::new(NodeKind::NoRoute, "no route".to_owned());
        node.children = unrouted
            .iter()
            .filter_map(|row| {
                let range = row.base()?;
                let label = match row.chain.records.last().and_then(|record| holder(record)) {
                    Some(holder) => format!("{} · {holder}", part(range)),
                    None => part(range),
                };
                Some(Node {
                    matched: true,
                    ..Node::new(NodeKind::Net(range), label)
                })
            })
            .collect();
        roots.push(node);
    }
    Tree {
        header: inputs.header.clone(),
        truncated: inputs.truncated,
        roots,
    }
}

/// Returns the indexes of the organization and the AS of `info` in `orgs`.
///
/// Adds the organization, the AS, or both if they are new.
fn place(orgs: &mut Vec<OrgDraft>, info: &AsInfo) -> (usize, usize) {
    let (key, label, query) = org_of(info);
    let org = match orgs.iter().position(|org| org.key == key) {
        Some(index) => index,
        None => {
            orgs.push(OrgDraft {
                key,
                label,
                query,
                ases: Vec::new(),
            });
            orgs.len() - 1
        }
    };
    let ases = &mut orgs[org].ases;
    let index = match ases.iter().position(|draft| draft.asn == info.asn) {
        Some(index) => index,
        None => {
            ases.push(AsDraft {
                asn: info.asn,
                label: as_label(info),
                matched: false,
                routes: Vec::new(),
            });
            ases.len() - 1
        }
    };
    (org, index)
}

/// Returns the node of an AS.
///
/// The node holds the routes of `draft`, then a `· N routes` node for the
/// rest of `all`, the routes of the AS in RIS.
fn as_node(draft: AsDraft, all: Option<&Vec<&Route>>) -> Node {
    let all = all.map_or(&[][..], Vec::as_slice);
    let shown: HashSet<Prefix> = draft
        .routes
        .iter()
        .filter_map(|node| match node.kind {
            NodeKind::Route(prefix) => Some(prefix),
            _ => None,
        })
        .collect();
    let rest: Vec<Route> = all
        .iter()
        .filter(|route| !shown.contains(&route.prefix))
        .map(|route| (*route).clone())
        .collect();
    let mut node = Node::new(NodeKind::As(draft.asn), draft.label);
    node.matched = draft.matched;
    node.routes = shown.len() + rest.len();
    node.children = draft.routes;
    if !rest.is_empty() {
        let label = count(rest.len(), "route", "routes");
        node.children.push(Node::new(
            NodeKind::More {
                asn: draft.asn,
                rest,
            },
            format!("· {label}"),
        ));
    }
    node
}

/// Returns the node of `route` under `asn`, labeled
/// `prefix · holder · also AS…`.
fn route_node(
    route: &Route,
    asn: Asn,
    holder: Option<&str>,
    matched: bool,
    children: Vec<Node>,
) -> Node {
    let mut label = route.prefix.to_string();
    if let Some(holder) = holder {
        label.push_str(" · ");
        label.push_str(holder);
    }
    let also: Vec<String> = route
        .origins
        .iter()
        .filter(|origin| **origin != asn)
        .map(|origin| format!("AS{origin}"))
        .collect();
    if !also.is_empty() {
        label.push_str(" · also ");
        label.push_str(&also.join(", "));
    }
    Node {
        matched,
        children,
        ..Node::new(NodeKind::Route(route.prefix), label)
    }
}

/// Returns the organization of an AS: a key that groups its AS, the label,
/// and the KQL.
///
/// The organization is the registrant of the `autnum` in RDAP. Without a
/// registrant, it is the opaque-id from the delegated stats, then the
/// organization text of asn.txt, then `unknown organization`.
fn org_of(info: &AsInfo) -> (String, String, OrgQuery) {
    let cc = info
        .entry
        .as_ref()
        .and_then(|entry| entry.country)
        .or_else(|| info.block.as_ref().map(|block| block.cc));
    let with_cc = |name: &str| match cc {
        Some(cc) => format!("{name}, {cc}"),
        None => name.to_owned(),
    };
    if let Some(org) = info.rdap.as_ref().and_then(|record| record.org.as_ref()) {
        let key = format!("org {}", crate::text::fold(&org.handle));
        return match &org.name {
            Some(name) => (key, with_cc(name), OrgQuery::Name(name.clone())),
            None => (
                key,
                with_cc(&org.handle),
                OrgQuery::Handle(org.handle.clone()),
            ),
        };
    }
    if let Some(id) = info
        .block
        .as_ref()
        .and_then(|block| block.opaque_id.as_deref())
    {
        return (
            format!("org {}", crate::text::fold(id)),
            with_cc(id),
            OrgQuery::Handle(id.to_owned()),
        );
    }
    match info.entry.as_ref().map(|entry| entry.org_text.as_str()) {
        Some(text) if !text.is_empty() => (
            format!("text {}", crate::text::fold(text)),
            with_cc(text),
            OrgQuery::Ases,
        ),
        _ => (
            format!("as {}", info.asn),
            with_cc("unknown organization"),
            OrgQuery::Ases,
        ),
    }
}

/// Returns the label of an AS, such as `AS64496 EXAMPLE-NET`.
///
/// The name comes from asn.txt, or from RDAP if asn.txt has none.
fn as_label(info: &AsInfo) -> String {
    let name = info
        .entry
        .as_ref()
        .map(|entry| entry.name.clone())
        .filter(|name| !name.is_empty())
        .or_else(|| info.rdap.as_ref().and_then(|record| record.name.clone()));
    match name {
        Some(name) => format!("AS{} {name}", info.asn),
        None => format!("AS{}", info.asn),
    }
}

/// Returns the holder of a network as the table prints it: `Name, CC`.
fn holder(record: &NetRecord) -> Option<String> {
    let org = record.org.as_ref()?;
    let name = org.name.as_deref().unwrap_or(&org.handle);
    Some(match record.country {
        Some(cc) => format!("{name}, {cc}"),
        None => name.to_owned(),
    })
}

/// Returns a part as the table prints it. A single address has no prefix
/// length.
fn part(range: Range) -> String {
    if range.first() == range.last() {
        range.first_addr().to_string()
    } else {
        range.to_string()
    }
}

/// Formats `n` with `one` or `many`: `1 route`, `3 routes`.
pub(crate) fn count(n: usize, one: &str, many: &str) -> String {
    format!("{n} {}", if n == 1 { one } else { many })
}

/// Escapes `\`, `"`, and `*` in `text` for a quoted KQL value.
fn quote(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        if matches!(c, '\\' | '"' | '*') {
            out.push('\\');
        }
        out.push(c);
    }
    out
}

/// Returns the holders of `ranges` from RDAP, in order.
///
/// Up to `--concurrency` requests per egress run at once. `progress` gets
/// `done` and `total` after each response.
///
/// # Errors
///
/// Returns the error of the first RDAP request that fails.
pub(crate) async fn holders(
    context: &Context<'_>,
    ranges: &[Range],
    progress: &dyn Fn(usize, usize),
) -> Result<Vec<Option<String>>> {
    let window = context.sources.transport().egresses().len().max(1) * context.concurrency.max(1);
    let total = ranges.len();
    let mut answers = stream::iter(ranges.iter().copied())
        .map(|range| context.rdap.ip(range))
        .buffered(window);
    let mut out = Vec::with_capacity(total);
    while let Some(record) = answers.next().await {
        out.push(record?.as_deref().and_then(holder));
        progress(out.len(), total);
    }
    Ok(out)
}

/// Builds the tree of `rows`, the answer of `plan` to `query`.
///
/// First the function gathers what the rows lack: the holders of routes
/// shown only by parts, the routes of every AS, and the AS of `as.asn: N`
/// without routes. Then [`assemble`] builds the tree.
///
/// # Errors
///
/// Returns the error of a source or of an RDAP request.
pub(crate) async fn build(
    context: &Context<'_>,
    plan: &Plan,
    query: &str,
    rows: &[Row],
    truncated: bool,
) -> Result<Tree> {
    let levels = Levels::of(&plan.root);
    let (groups, _) = groups(rows);
    let reporter = context.reporter;
    // A route whose rows all have parts needs its own holder. The records
    // in those rows belong to the parts.
    let bare: Vec<Prefix> = groups
        .iter()
        .filter(|group| group.holder().is_none())
        .map(|group| group.route.prefix)
        .collect();
    let ranges: Vec<Range> = bare.iter().map(|prefix| prefix.range()).collect();
    let found = holders(context, &ranges, &|done, total| {
        reporter.progress(narrow(done), narrow(total), "rdap");
    })
    .await?;
    if !ranges.is_empty() {
        reporter.clear_progress();
    }
    let holders: HashMap<Prefix, Option<String>> = bare.into_iter().zip(found).collect();
    let placed: HashSet<Asn> = groups.iter().flat_map(Group::ases).collect();
    let named: Vec<Asn> = named_ases(&plan.root)
        .into_iter()
        .filter(|asn| !placed.contains(asn))
        .collect();
    let mut asns = AsnSet::new();
    placed
        .iter()
        .chain(&named)
        .for_each(|asn| asns.insert(*asn));
    let routes = context.sources.routes_of(plan.families, &asns).await?;
    let routed: HashSet<Asn> = routes
        .iter()
        .flat_map(|route| route.origins.iter().copied())
        .collect();
    let quiet = quiet_ases(context, &named, &routed).await?;
    Ok(assemble(&Inputs {
        header: query.to_owned(),
        truncated,
        levels,
        rows,
        holders,
        routes: &routes,
        quiet: &quiet,
    }))
}

/// Returns the AS of `named` that have no route in `routed`, with their
/// asn.txt entries and RDAP records.
///
/// The tree shows these AS with `· 0 routes`.
///
/// # Errors
///
/// Returns the error of asn.txt or of an RDAP request.
async fn quiet_ases(
    context: &Context<'_>,
    named: &[Asn],
    routed: &HashSet<Asn>,
) -> Result<Vec<AsInfo>> {
    let quiet: Vec<Asn> = named
        .iter()
        .copied()
        .filter(|asn| !routed.contains(asn))
        .collect();
    if quiet.is_empty() {
        return Ok(Vec::new());
    }
    let mut by_asn = AsnSet::new();
    quiet.iter().for_each(|asn| by_asn.insert(*asn));
    let entries = context
        .sources
        .asns(&AsnRequest {
            by_asn,
            ..AsnRequest::default()
        })
        .await?
        .entries;
    let mut out = Vec::with_capacity(quiet.len());
    for asn in quiet {
        let entry = entries.iter().find(|entry| entry.asn == asn).cloned();
        let rdap = context.rdap.autnum(asn).await?;
        // A number neither asn.txt nor RDAP knows is not an AS.
        if entry.is_some() || rdap.is_some() {
            out.push(AsInfo {
                asn,
                entry,
                block: None,
                rdap,
            });
        }
    }
    Ok(out)
}

/// Converts `n` to `u32` for the progress line. Values above `u32::MAX`
/// become `u32::MAX`.
fn narrow(n: usize) -> u32 {
    u32::try_from(n).unwrap_or(u32::MAX)
}

/// The reporter of a run with `-i`.
///
/// The relay remembers when a registry truncated a response, for the `*` in
/// the header. While the tree is on screen, the relay keeps notices for the
/// status line and drops progress. Output to stderr would break the screen.
pub(crate) struct Relay {
    inner: Arc<dyn Reporter>,
    state: Mutex<RelayState>,
}

/// The state of a [`Relay`].
#[derive(Default)]
struct RelayState {
    /// The tree is on screen.
    captured: bool,
    /// A registry truncated a response.
    truncated: bool,
    /// The notices that came while the tree was on screen.
    notices: Vec<String>,
}

impl Relay {
    /// Creates a relay that forwards to `inner`.
    pub(crate) fn new(inner: Arc<dyn Reporter>) -> Self {
        Self {
            inner,
            state: Mutex::new(RelayState::default()),
        }
    }

    fn state(&self) -> std::sync::MutexGuard<'_, RelayState> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Returns `true` once a registry has truncated a response.
    pub(crate) fn truncated(&self) -> bool {
        self.state().truncated
    }

    /// Keeps notices and progress off stderr while `captured` is `true`.
    pub(crate) fn capture(&self, captured: bool) {
        self.state().captured = captured;
    }

    /// Returns the notices kept since the last call and forgets them.
    pub(crate) fn take_notices(&self) -> Vec<String> {
        std::mem::take(&mut self.state().notices)
    }
}

impl Reporter for Relay {
    fn source(&self, source: crate::Source) {
        self.inner.source(source);
    }
    fn notice(&self, notice: &Notice) {
        let mut state = self.state();
        if matches!(notice, Notice::Truncated { .. }) {
            state.truncated = true;
        }
        if state.captured {
            state.notices.push(notice.to_string());
        } else {
            drop(state);
            self.inner.notice(notice);
        }
    }

    fn error(&self, message: &str) {
        self.inner.error(message);
    }

    fn progress(&self, done: u32, total: u32, what: &'static str) {
        if !self.state().captured {
            self.inner.progress(done, total, what);
        }
    }

    fn clear_progress(&self) {
        if !self.state().captured {
            self.inner.clear_progress();
        }
    }

    fn activity(&self, action: Option<&'static str>) {
        if !self.state().captured {
            self.inner.activity(action);
        }
    }

    fn items(&self, done: u32, total: u32, unit: &'static str) {
        if !self.state().captured {
            self.inner.items(done, total, unit);
        }
    }
}

/// Runs `-i` and returns the output for stdout.
///
/// Builds the tree of `rows` and shows it on `terminal`, or on the terminal
/// of the process if `terminal` is `None`. On exit, returns the KQL of the
/// marked nodes with a newline, or nothing if no node is marked.
///
/// If the query found nothing, there is no tree. The screen does not open,
/// and stdout stays empty. The notices of the engine have already told the
/// user.
///
/// # Errors
///
/// Returns the error of an interrupted run, exit code 130, if the user
/// presses Ctrl+C in the tree. The terminal is restored first. Also returns
/// the errors of the sources and of the terminal.
pub(crate) async fn run(
    context: &Context<'_>,
    plan: &Plan,
    query: &str,
    rows: &[Row],
    relay: &Relay,
    terminal: Option<&mut dyn tui::Terminal>,
) -> Result<Vec<u8>> {
    context.reporter.activity(Some("reading registry records"));
    let mut tree = build(context, plan, query, rows, relay.truncated()).await?;
    context.reporter.activity(None);
    context.reporter.clear_progress();
    if tree.is_empty() {
        return Ok(Vec::new());
    }
    let page = match &plan.mode {
        Mode::Rows { limit, .. } => *limit,
        Mode::Ipset => None,
    };
    let loader = tui::Loader {
        context,
        relay,
        page,
    };
    relay.capture(true);
    let exit = match terminal {
        Some(terminal) => tui::run(&mut tree, terminal, &loader).await,
        None => match tui::Screen::open() {
            // Dropping `screen` at the end of this arm restores the
            // terminal before anything is printed.
            Ok(mut screen) => tui::run(&mut tree, &mut screen, &loader).await,
            Err(error) => Err(error),
        },
    };
    relay.capture(false);
    match exit.map_err(|error| Error::runtime(format!("terminal: {error}")))? {
        tui::Exit::Done => {
            let mut query = tree.query();
            if !query.is_empty() {
                query.push('\n');
            }
            Ok(query.into_bytes())
        }
        tui::Exit::Interrupted => Err(Error::interrupted()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{AsnEntry, Marks, OrgRef};

    fn prefix(text: &str) -> Prefix {
        text.parse().unwrap()
    }

    fn range(text: &str) -> Range {
        text.parse().unwrap()
    }

    fn route(text: &str, origins: &[Asn]) -> Route {
        Route {
            prefix: prefix(text),
            origins: origins.to_vec(),
        }
    }

    fn info(asn: Asn, name: &str, org: Option<&str>) -> AsInfo {
        AsInfo {
            asn,
            entry: Some(AsnEntry {
                asn,
                name: name.to_owned(),
                org_text: format!("{name} Org"),
                country: "XA".parse().ok(),
                raw: String::new(),
            }),
            block: None,
            rdap: org.map(|org| {
                Arc::new(crate::model::AsRecord {
                    rir: crate::model::Rir::Ripencc,
                    asn,
                    last: None,
                    name: None,
                    org: Some(OrgRef {
                        handle: format!("ORG-{asn}"),
                        name: Some(org.to_owned()),
                    }),
                    mnt: Vec::new(),
                    contacts: Vec::new(),
                })
            }),
        }
    }

    fn row(route: &Route, part: Option<&str>, ases: Vec<AsInfo>, marks: &[Asn]) -> Row {
        Row {
            part: part.map(range),
            route: Some(route.clone()),
            ases,
            marks: Marks {
                route: true,
                ases: marks.to_vec(),
            },
            ..Row::default()
        }
    }

    fn labels(tree: &Tree) -> Vec<String> {
        render::lines(tree)
            .into_iter()
            .map(|line| line.text)
            .collect()
    }

    #[test]
    fn multi_origin_route_stands_under_each_as() {
        let both = route("192.0.2.128/27", &[64499, 64500]);
        let rows = [row(
            &both,
            Some("192.0.2.130"),
            vec![
                info(64499, "SETONE", Some("Set One")),
                info(64500, "SETTWO", None),
            ],
            &[64499, 64500],
        )];
        let routes = [both.clone()];
        let holders = HashMap::from([(both.prefix, Some("Tenant, XC".to_owned()))]);
        // The rows have only parts, so the holder of the route comes from
        // `holders`.
        let tree = assemble(&Inputs {
            header: "ip: 192.0.2.130".into(),
            levels: Levels {
                ases: false,
                routes: true,
            },
            rows: &rows,
            holders,
            routes: &routes,
            ..Inputs::default()
        });
        assert_eq!(
            labels(&tree),
            [
                "Set One, XA",
                "└─ AS64499 SETONE",
                "   └─ 192.0.2.128/27 · Tenant, XC · also AS64500",
                "      └─ ▶ 192.0.2.130",
                "SETTWO Org, XA",
                "└─ AS64500 SETTWO",
                "   └─ 192.0.2.128/27 · Tenant, XC · also AS64499",
                "      └─ ▶ 192.0.2.130",
            ]
        );
        assert!(matches!(tree.roots[1].kind, NodeKind::Org(OrgQuery::Ases)));
    }

    #[test]
    fn rest_of_the_routes_waits_behind_a_count() {
        let first = route("203.0.113.0/28", &[64503]);
        let rows = [row(
            &first,
            None,
            vec![info(64503, "CDN", Some("CDN Ltd"))],
            &[64503],
        )];
        let routes = [
            first.clone(),
            route("203.0.113.16/28", &[64503]),
            route("203.0.113.32/28", &[64503]),
        ];
        let mut tree = assemble(&Inputs {
            header: "as.asn: 64503".into(),
            levels: Levels::of(&Expr::Leaf(Leaf::Asn(AsnMatch::One(64503)))),
            rows: &rows,
            routes: &routes,
            ..Inputs::default()
        });
        assert_eq!(
            labels(&tree),
            [
                "CDN Ltd, XA",
                "└─ ▶ AS64503 CDN",
                "   ├─ 203.0.113.0/28",
                "   └─ · 2 routes",
            ]
        );
        assert_eq!(tree.roots[0].routes, 3);
        let more = [0, 0, 1];
        let page = tree.page(&more, Some(1)).unwrap();
        assert_eq!(page, [route("203.0.113.16/28", &[64503])]);
        tree.show_page(&more, &[Some("Customer, XG".into())]);
        assert_eq!(
            labels(&tree)[3..],
            ["   ├─ 203.0.113.16/28 · Customer, XG", "   └─ · 1 route"]
        );
        let more = [0, 0, 2];
        assert_eq!(tree.page(&more, None).unwrap().len(), 1);
        tree.show_page(&more, &[None]);
        assert_eq!(labels(&tree)[4..], ["   └─ 203.0.113.32/28"]);
        assert_eq!(tree.page(&[0, 0, 2], None), None);
    }

    #[test]
    fn quiet_as_and_networks_without_route() {
        let rows = [Row {
            part: Some(range("203.0.113.192/27")),
            ..Row::default()
        }];
        let quiet = [info(64505, "QUIET-AS", None)];
        let tree = assemble(&Inputs {
            header: "q".into(),
            levels: Levels {
                ases: true,
                routes: true,
            },
            rows: &rows,
            quiet: &quiet,
            ..Inputs::default()
        });
        assert_eq!(
            labels(&tree),
            [
                "QUIET-AS Org, XA",
                "└─ ▶ AS64505 QUIET-AS · 0 routes",
                "no route",
                "└─ ▶ 203.0.113.192/27",
            ]
        );
    }

    #[test]
    fn marked_nodes_are_kql() {
        let both = route("192.0.2.128/27", &[64499, 64500]);
        let rows = [row(
            &both,
            Some("192.0.2.130"),
            vec![
                info(64499, "SETONE", Some("Set \"One\" *")),
                info(64500, "SETTWO", None),
            ],
            &[],
        )];
        let mut tree = assemble(&Inputs {
            rows: &rows,
            levels: Levels::default(),
            ..Inputs::default()
        });
        assert_eq!(tree.query(), "");
        for path in [
            &[0][..],
            &[0, 0],
            &[0, 0, 0],
            &[0, 0, 0, 0],
            &[1],
            &[1, 0, 0],
        ] {
            tree.node_mut(path).unwrap().marked = true;
        }
        assert_eq!(
            tree.query(),
            r#"as.org: "Set \"One\" \*" or as.asn: 64499 or route: 192.0.2.128/27 or ip: 192.0.2.130 or as.asn: 64500"#
        );
        let handle = Node::new(
            NodeKind::Org(OrgQuery::Handle("ORG-EN1-RIPE".into())),
            String::new(),
        );
        assert_eq!(handle.kql().unwrap(), "as.org: ORG-EN1-RIPE");
        assert_eq!(Node::new(NodeKind::NoRoute, String::new()).kql(), None);
        assert_eq!(
            Node::new(
                NodeKind::Net(range("203.0.113.0-203.0.113.95")),
                String::new()
            )
            .kql()
            .unwrap(),
            "ip: 203.0.113.0-203.0.113.95"
        );
    }

    #[test]
    fn levels_follow_positive_conditions() {
        let asn = Expr::Leaf(Leaf::Asn(AsnMatch::One(64496)));
        let ip = Expr::Leaf(Leaf::Ip(range("192.0.2.0/24")));
        assert_eq!(
            Levels::of(&asn),
            Levels {
                ases: true,
                routes: false
            }
        );
        assert_eq!(
            Levels::of(&Expr::And(vec![
                ip.clone(),
                Expr::Not(Box::new(asn.clone()))
            ])),
            Levels {
                ases: false,
                routes: true
            }
        );
        assert_eq!(
            Levels::of(&Expr::Or(vec![ip, asn.clone()])),
            Levels {
                ases: true,
                routes: true
            }
        );
        assert_eq!(named_ases(&Expr::Or(vec![asn.clone(), asn])), [64496]);
    }

    #[test]
    fn relay_keeps_notices_while_captured() {
        struct Count(Mutex<Vec<String>>);
        impl Reporter for Count {
            fn notice(&self, notice: &Notice) {
                self.0.lock().unwrap().push(notice.to_string());
            }
            fn error(&self, _: &str) {}
            fn progress(&self, _: u32, _: u32, _: &'static str) {}
            fn clear_progress(&self) {}
        }
        let inner = Arc::new(Count(Mutex::new(Vec::new())));
        let relay = Relay::new(inner.clone());
        let truncated = Notice::Truncated {
            rir: "ripencc".into(),
            message: "limited search results to 100 maximum".into(),
        };
        relay.notice(&truncated);
        assert!(relay.truncated());
        relay.capture(true);
        relay.notice(&truncated);
        assert_eq!(inner.0.lock().unwrap().len(), 1);
        assert_eq!(
            relay.take_notices(),
            ["netf: ripencc: limited search results to 100 maximum"]
        );
        assert!(relay.take_notices().is_empty());
    }
}
