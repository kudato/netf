//! Tests of the interactive tree, `-i`. They check what the tree draws on the
//! fixtures, the KQL of the marked nodes, the pages of routes that load on
//! demand, `Ctrl+C`, and the errors of `-i` without a terminal.
//!
//! The tree runs on a fake [`netf::Terminal`] that plays scripted keys and
//! records the frames. No test touches a real terminal.

mod common;

use common::World;
use netf::{Frame, Key, Outcome, Terminal};
use std::collections::VecDeque;
use std::io;

/// A fake terminal that plays scripted keys and records the frames.
///
/// While a page loads, the terminal holds the keys back, as a user would
/// wait. When the script ends, it presses `Ctrl+C`, so a test that
/// forgets `q` still ends.
struct Fake<'w> {
    world: &'w World,
    keys: VecDeque<Key>,
    frames: Vec<Frame>,
    /// For each frame, the number of RDAP requests for networks made
    /// before the frame was drawn.
    ips: Vec<usize>,
    size: (u16, u16),
}

impl Terminal for Fake<'_> {
    fn size(&mut self) -> io::Result<(u16, u16)> {
        Ok(self.size)
    }

    fn key(&mut self) -> io::Result<Option<Key>> {
        if self.frames.last().is_some_and(|frame| frame.loading) {
            return Ok(None);
        }
        Ok(Some(self.keys.pop_front().unwrap_or(Key::Interrupt)))
    }

    fn draw(&mut self, frame: &Frame) -> io::Result<()> {
        self.frames.push(frame.clone());
        self.ips.push(ip_requests(self.world));
        Ok(())
    }
}

fn ip_requests(world: &World) -> usize {
    world
        .rdap_calls()
        .iter()
        .filter(|call| call.kind == "ip")
        .count()
}

/// The result of a run of the tree: the outcome, stderr, the frames, and
/// the request counts.
struct Run {
    outcome: Outcome,
    stderr: Vec<String>,
    frames: Vec<Frame>,
    ips: Vec<usize>,
}

impl Run {
    fn stdout(&self) -> String {
        String::from_utf8(self.outcome.stdout.clone()).expect("UTF-8 stdout")
    }

    /// Returns the lines of the last frame below the query and the blank
    /// line.
    fn tree(&self) -> Vec<String> {
        self.frames.last().expect("a frame").lines[2..].to_vec()
    }
}

fn tree(world: &World, args: &[&str], keys: &[Key]) -> Run {
    tree_sized(world, args, keys, (100, 40))
}

fn tree_sized(world: &World, args: &[&str], keys: &[Key], size: (u16, u16)) -> Run {
    let mut all = vec!["-i"];
    all.extend(args);
    let (invocation, reporter) = world.invocation(&all);
    let mut terminal = Fake {
        world,
        keys: keys.iter().copied().collect(),
        frames: Vec::new(),
        ips: Vec::new(),
        size,
    };
    let outcome = common::runtime().block_on(netf::run_with_terminal(invocation, &mut terminal));
    Run {
        outcome,
        stderr: reporter.lines(),
        frames: terminal.frames,
        ips: terminal.ips,
    }
}

/// An AS with more routes than `--limit` shows one page and a
/// `· N routes` node.
///
/// netf asks RDAP for the next page only when the user expands that node.
#[test]
fn the_rest_loads_on_expand() {
    let world = World::standard();
    let keys = [Key::End, Key::Right, Key::Right, Key::Char('q')];
    let run = tree(&world, &["--limit", "2", "as.asn: 64503"], &keys);
    assert_eq!(run.outcome.code, 0, "{:?}", run.stderr);
    assert_eq!(
        run.stderr,
        ["netf: showing 2 of 8 matches; refine the query or use --limit 0"]
    );
    assert_eq!(
        run.frames[0].lines[2..],
        [
            "Example CDN Ltd, XF",
            "└─ ▶ AS64503 EXAMPLE-CDN",
            "   ├─ 203.0.113.0/28 · Example CDN Ltd, XG",
            "   ├─ 203.0.113.16/28 · CDN Customer Pty Ltd, XG",
            "   └─ · 6 routes",
        ]
    );
    let before = run.ips[0];
    assert_eq!(run.ips[1], before, "moving to `· 6 routes` asks nothing");
    let loading = run
        .frames
        .iter()
        .position(|frame| frame.loading)
        .expect("a load");
    assert!(
        run.frames[loading]
            .footer
            .iter()
            .any(|line| line.starts_with("rdap: ")),
        "{:?}",
        run.frames[loading].status
    );
    assert_eq!(
        *run.ips.last().unwrap(),
        before + 4,
        "two pages of two routes"
    );
    assert_eq!(
        run.tree(),
        [
            "Example CDN Ltd, XF",
            "└─ ▶ AS64503 EXAMPLE-CDN",
            "   ├─ 203.0.113.0/28 · Example CDN Ltd, XG",
            "   ├─ 203.0.113.16/28 · CDN Customer Pty Ltd, XG",
            "   ├─ 203.0.113.32/28 · Example CDN Ltd, XG",
            "   ├─ 203.0.113.48/28 · Example CDN Ltd, XG",
            "   ├─ 203.0.113.64/28 · Example CDN Ltd, XG",
            "   ├─ 203.0.113.80/28 · Example CDN Ltd, XG",
            "   └─ · 2 routes",
        ]
    );
    let middle = &run.frames[run.frames.len() - 3..];
    assert!(
        middle
            .iter()
            .any(|frame| frame.lines.last().unwrap() == "   └─ · 4 routes"),
        "the count follows the pages"
    );
}

/// Networks without a route appear under `no route`.
#[test]
fn networks_without_route() {
    let world = World::standard();
    let run = tree(&world, &["net.org: L3C0FFEE"], &[Key::Esc]);
    assert_eq!(run.outcome.code, 0, "{:?}", run.stderr);
    assert_eq!(
        run.tree(),
        [
            "Rede Exemplo Ltda, XH",
            "└─ AS64507 REDE-EXEMPLO",
            "   └─ ▶ 203.0.113.128/27 · Rede Exemplo Ltda, XH",
            "No Country Org, XH",
            "└─ AS64504 NOCOUNTRY-AS",
            "   └─ ▶ 203.0.113.160/27 · Provedor Exemplo Ltda, XH",
            "no route",
            "└─ ▶ 203.0.113.192/27 · Ilha Exemplo Ltda, XH",
        ]
    );
    assert_eq!(run.frames[0].cursor, Some(4));
}

/// An AS that the query names but that announces nothing shows
/// `· 0 routes`.
#[test]
fn a_quiet_as_has_zero_routes() {
    let world = World::standard();
    let run = tree(&world, &["as.asn: 64505"], &[Key::Char('q')]);
    assert_eq!(run.outcome.code, 0, "{:?}", run.stderr);
    assert_eq!(
        run.tree(),
        [
            "Quiet Networks, Inc., XE",
            "└─ ▶ AS64505 QUIET-AS · 0 routes"
        ]
    );
}

/// When a registry truncates its answer, the query line ends with `*`.
#[test]
fn a_truncated_answer_marks_the_query() {
    let world = World::standard();
    world.serve_search();
    let run = tree(&world, &["net.org: ORG-EN1-RIPE"], &[Key::Char('q')]);
    assert_eq!(run.outcome.code, 0, "{:?}", run.stderr);
    assert_eq!(run.frames[0].lines[0], "net.org: ORG-EN1-RIPE");
    assert!(
        run.frames[0]
            .footer
            .iter()
            .any(|line| line.contains("Partial result"))
    );
    assert_eq!(
        run.stderr,
        ["netf: ripencc: limited search results to 100 maximum"]
    );
}

/// `Space` marks a node, and `q` prints the marked nodes as one KQL
/// query, in the order of the tree.
#[test]
fn marked_nodes_are_printed_as_kql() {
    let world = World::standard();
    let keys = [
        Key::Space,
        Key::Up,
        Key::Char('k'),
        Key::Space,
        Key::Down,
        Key::Space,
        Key::Space,
        Key::End,
        Key::Up,
        Key::Space,
        Key::Char('q'),
    ];
    let run = tree(&world, &["ip: 192.0.2.130"], &keys);
    assert_eq!(run.outcome.code, 0, "{:?}", run.stderr);
    assert_eq!(
        run.stdout(),
        "as.asn: 64499 or ip: 192.0.2.130 or route: 192.0.2.128/27\n"
    );
    let last = run.frames.last().unwrap();
    assert!(
        last.lines[1].starts_with("Selected nodes: 3"),
        "{:?}",
        last.lines
    );
    assert_eq!(last.status, "q/Esc export KQL  Ctrl+C cancel");
    assert_eq!(
        last.lines[8],
        "   └─ [x] 192.0.2.128/27 · Tenant One GmbH, XC · also AS64499"
    );
}

/// `←` collapses a node, and the collapsed node shows its size.
#[test]
fn collapsed_nodes_show_their_size() {
    let world = World::standard();
    let keys = [Key::Left, Key::Left, Key::Left, Key::Char('q')];
    let run = tree(&world, &["ip: 192.0.2.130"], &keys);
    assert_eq!(run.outcome.code, 0, "{:?}", run.stderr);
    assert_eq!(
        run.tree()[..3],
        [
            "Set One GmbH, XC",
            "└─ AS64499 SETONE",
            "   └─ 192.0.2.128/27 · Tenant One GmbH, XC · also AS64500 · 1 part",
        ]
    );
}

/// `Ctrl+C` cancels the run with code 130 and an empty stdout.
#[test]
fn ctrl_c_is_130() {
    let world = World::standard();
    let run = tree(&world, &["ip: 192.0.2.130"], &[Key::Space, Key::Interrupt]);
    assert_eq!(run.outcome.code, 130);
    assert!(run.outcome.stdout.is_empty());
    assert_eq!(run.stderr, ["netf: interrupted"]);
}

/// When the query finds nothing, netf draws no tree and prints nothing.
#[test]
fn nothing_to_show() {
    let world = World::standard();
    let run = tree(&world, &["as.asn: 64511"], &[]);
    assert_eq!(run.outcome.code, 0, "{:?}", run.stderr);
    assert!(run.outcome.stdout.is_empty());
    assert!(run.frames.is_empty());
}

/// Without a terminal on stdin and stdout, `-i` fails before any
/// request.
#[test]
fn no_terminal_is_code_2() {
    let world = World::standard();
    let (code, stderr) = world.fail(&["-i", "ip: 192.0.2.130"]);
    assert_eq!(code, 2);
    assert_eq!(
        stderr,
        ["netf: -i: the interactive tree needs a terminal on stdin and stdout"]
    );
    assert!(world.transport.requests().is_empty());
}

/// `-i` cannot be combined with `--ipset`, `-s`, or `-f`.
#[test]
fn interactive_takes_one_query() {
    let world = World::standard();
    let path = world.home.path().join("out.txt");
    let file = path.to_str().unwrap();
    for (args, error) in [
        (
            &["-i", "--ipset", "ip: 192.0.2.130"][..],
            "netf: -i cannot be combined with --ipset",
        ),
        (
            &["-i", "-s", "example"],
            "netf: -i cannot be combined with -s",
        ),
        (
            &["-i", "-f", file, "ip: 192.0.2.130"],
            "netf: -i cannot be combined with -f",
        ),
    ] {
        let (code, stderr) = world.fail(args);
        assert_eq!((code, stderr), (2, vec![error.to_owned()]), "{args:?}");
    }
    assert!(!path.exists());
    assert!(world.transport.requests().is_empty());
}

#[test]
fn help_and_details_preserve_selection_and_exit_keys_at_each_size() {
    let world = World::standard();
    for size in [(80, 24), (45, 24), (32, 10)] {
        let run = tree_sized(
            &world,
            &["as.asn: 64498"],
            &[
                Key::Space,
                Key::Char('?'),
                Key::PageDown,
                Key::Home,
                Key::Backspace,
                Key::Char('d'),
                Key::Esc,
            ],
            size,
        );
        assert_eq!(run.outcome.code, 0, "{:?}", run.stderr);
        assert_eq!(run.stdout(), "as.asn: 64498\n");
        assert!(run.frames.iter().any(|f| f.lines[0] == "Help"));
        assert!(run.frames.iter().any(|f| f.lines[0] == "Node details"));
        for frame in &run.frames {
            assert_eq!(frame.status, "q/Esc export KQL  Ctrl+C cancel");
            assert!(
                frame.lines.len() + frame.footer.len() < usize::from(size.1),
                "{frame:?}"
            );
            for line in frame
                .lines
                .iter()
                .chain(&frame.footer)
                .chain([&frame.status])
            {
                assert!(
                    unicode_width::UnicodeWidthStr::width(line.as_str()) <= usize::from(size.0),
                    "{line}"
                );
            }
        }
    }
    let run = tree_sized(&world, &["as.asn: 64498"], &[Key::Interrupt], (20, 8));
    assert_eq!(run.outcome.code, 130);
    assert!(run.outcome.stdout.is_empty());
    assert_eq!(run.frames[0].footer, ["q/Esc: export KQL"]);
    assert_eq!(run.frames[0].status, "Ctrl+C: cancel");
}
