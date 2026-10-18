//! The lines of the tree: the branches `├─ └─ │`, the `✓` and `▶` signs,
//! and the sizes such as `· 45 routes`.
//!
//! The functions do no I/O, so tests check them without a terminal.
//! [`lines`] returns every visible node with its path. [`render`] returns
//! the lines of a screen: the query, a blank line, and a window of the
//! tree. [`crate::text::truncate`] cuts each line to the width of the
//! screen in display columns.
//!
//! A line is `<branches><✓ ><▶ ><label><size>`. `✓` shows a node the user
//! marked, and `▶` shows a node the query matched. A collapsed node and an
//! AS without routes end with their size, such as `· 45 routes`.

use super::{Node, NodeKind, Tree, count};
use crate::text;

/// A visible node: where it is and its text.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct Line {
    /// The indexes from the roots down to the node.
    pub(crate) path: Vec<usize>,
    /// The line, with the branches.
    pub(crate) text: String,
}

/// What a screen shows of the tree.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct View {
    /// The width of the screen in columns.
    pub(crate) width: usize,
    /// The number of tree lines below the header.
    pub(crate) rows: usize,
    /// The index of the first visible node on the screen.
    pub(crate) offset: usize,
}

/// Returns every visible node in order. A node is visible if all its
/// ancestors are expanded.
pub(crate) fn lines(tree: &Tree) -> Vec<Line> {
    let mut out = Vec::new();
    for (index, root) in tree.roots.iter().enumerate() {
        walk(root, vec![index], "", "", &mut out);
    }
    out
}

/// Adds `node` to `out` after the prefix `branch`, then its visible
/// children indented by `indent`.
fn walk(node: &Node, path: Vec<usize>, branch: &str, indent: &str, out: &mut Vec<Line>) {
    out.push(Line {
        path: path.clone(),
        text: format!("{branch}{}", text_of(node)),
    });
    if !node.expanded {
        return;
    }
    let last = node.children.len().saturating_sub(1);
    for (index, child) in node.children.iter().enumerate() {
        let (fork, rest) = if index == last {
            ("└─ ", "   ")
        } else {
            ("├─ ", "│  ")
        };
        let mut child_path = path.clone();
        child_path.push(index);
        walk(
            child,
            child_path,
            &format!("{indent}{fork}"),
            &format!("{indent}{rest}"),
            out,
        );
    }
}

/// Returns the text of a node without its branches.
fn text_of(node: &Node) -> String {
    let mut out = String::new();
    if node.marked {
        out.push_str("[x] ");
    }
    if node.matched {
        out.push_str("▶ ");
    }
    out.push_str(&text::terminal_safe(&node.label));
    if let Some(size) = size(node) {
        out.push_str(" · ");
        out.push_str(&size);
    }
    out
}

/// Returns the size of a collapsed node or of an AS without routes.
fn size(node: &Node) -> Option<String> {
    let collapsed = !node.expanded && !node.children.is_empty();
    match node.kind {
        NodeKind::As(_) if node.routes == 0 => Some(count(0, "route", "routes")),
        _ if !collapsed => None,
        NodeKind::Org(_) | NodeKind::As(_) => Some(count(node.routes, "route", "routes")),
        NodeKind::Route(_) => Some(count(node.children.len(), "part", "parts")),
        NodeKind::NoRoute => Some(count(node.children.len(), "network", "networks")),
        NodeKind::Part(_) | NodeKind::Net(_) | NodeKind::More { .. } => None,
    }
}

/// Returns the lines of a screen.
///
/// The first line is the query, with `*` if a registry truncated a
/// response. A blank line and `view.rows` nodes from `view.offset` follow.
/// Each line is cut to `view.width` columns.
pub(crate) fn render(tree: &Tree, view: View) -> Vec<String> {
    let header = if tree.truncated {
        format!("{} *", tree.header)
    } else {
        tree.header.clone()
    };
    let mut out = vec![text::truncate(&header, view.width), String::new()];
    out.extend(
        lines(tree)
            .into_iter()
            .skip(view.offset)
            .take(view.rows)
            .map(|line| text::truncate(&line.text, view.width)),
    );
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tree::OrgQuery;

    fn node(kind: NodeKind, label: &str, children: Vec<Node>) -> Node {
        Node {
            children,
            ..Node::new(kind, label.to_owned())
        }
    }

    /// Returns the tree of `net.org: "SAMPLE LLC"`: an organization with
    /// one AS, and a network without a route.
    ///
    /// The only AS of an organization is drawn with `└─`.
    fn sample() -> Tree {
        let route = |text: &str| {
            let prefix = text.parse().unwrap();
            NodeKind::Route(prefix)
        };
        let mut matched = node(
            route("10.45.192.0/18"),
            "10.45.192.0/18 · SAMPLE LLC, XA",
            vec![],
        );
        matched.matched = true;
        let more = node(
            NodeKind::More {
                asn: 64510,
                rest: vec![],
            },
            "· 120 routes",
            vec![],
        );
        let mut asn = node(NodeKind::As(64510), "AS64510 SAMPLE", vec![matched, more]);
        asn.routes = 121;
        let mut org = node(
            NodeKind::Org(OrgQuery::Name("SAMPLE LLC".into())),
            "SAMPLE LLC, XA",
            vec![asn],
        );
        org.routes = 121;
        let mut net = node(
            NodeKind::Net("10.250.128.0/17".parse().unwrap()),
            "10.250.128.0/17 · SAMPLE LLC, XA",
            vec![],
        );
        net.matched = true;
        Tree {
            header: "net.org: \"SAMPLE LLC\"".into(),
            truncated: false,
            roots: vec![org, node(NodeKind::NoRoute, "no route", vec![net])],
        }
    }

    fn wide() -> View {
        View {
            width: 200,
            rows: 100,
            offset: 0,
        }
    }

    #[test]
    fn renders_the_sample_tree_with_line_paths() {
        assert_eq!(
            render(&sample(), wide()),
            [
                "net.org: \"SAMPLE LLC\"",
                "",
                "SAMPLE LLC, XA",
                "└─ AS64510 SAMPLE",
                "   ├─ ▶ 10.45.192.0/18 · SAMPLE LLC, XA",
                "   └─ · 120 routes",
                "no route",
                "└─ ▶ 10.250.128.0/17 · SAMPLE LLC, XA",
            ]
        );
        let paths: Vec<Vec<usize>> = lines(&sample()).into_iter().map(|line| line.path).collect();
        assert_eq!(
            paths,
            [
                vec![0],
                vec![0, 0],
                vec![0, 0, 0],
                vec![0, 0, 1],
                vec![1],
                vec![1, 0]
            ]
        );
    }

    #[test]
    fn collapsed_nodes_show_their_size() {
        let mut tree = sample();
        tree.roots[0].children[0].expanded = false;
        tree.roots[1].expanded = false;
        tree.roots[1].children[0].marked = true;
        tree.truncated = true;
        assert_eq!(
            render(&tree, wide()),
            [
                "net.org: \"SAMPLE LLC\" *",
                "",
                "SAMPLE LLC, XA",
                "└─ AS64510 SAMPLE · 121 routes",
                "no route · 1 network",
            ]
        );
        tree.roots[1].expanded = true;
        tree.roots[0].expanded = false;
        assert_eq!(
            render(&tree, wide())[2..],
            [
                "SAMPLE LLC, XA · 121 routes",
                "no route",
                "└─ [x] ▶ 10.250.128.0/17 · SAMPLE LLC, XA",
            ]
        );
    }

    #[test]
    fn window_and_width() {
        let view = View {
            width: 12,
            rows: 2,
            offset: 1,
        };
        assert_eq!(
            render(&sample(), view),
            ["net.org: \"S…", "", "└─ AS64510 …", "   ├─ ▶ 10.…"]
        );
    }
}
