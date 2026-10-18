//! The terminal UI of the tree: the keys, the cursor, the loading of route
//! pages, and the screen through crossterm.
//!
//! The loop draws a [`Frame`] on a [`Terminal`]. A frame holds the lines
//! of [`render`], the line of the cursor, and a status line. The loop reads
//! keys without waiting, so the screen can show the progress of a page of
//! routes while the page loads: `rdap: 3/12`.
//!
//! [`Screen`] is the terminal of the process: the alternate screen in raw
//! mode. Its `Drop` restores the terminal on every return, errors included.
//! Tests implement [`Terminal`] with scripted keys and pass it to
//! [`run_with_terminal`](crate::run_with_terminal).
//!
//! The tree reads these keys:
//!
//! - `↑`, `↓`, `k`, and `j` move the cursor. `PgUp`, `PgDn`, `Home` or
//!   `g`, and `End` or `G` jump.
//! - `→`, `l`, and `Enter` expand a node. On `· N routes`, they load the
//!   next page of routes with their holders from RDAP. A page holds as many
//!   routes as the limit of the run.
//! - `←` and `h` collapse a node or move to its parent.
//! - `Space` marks a node.
//! - `q` and `Esc` exit and print the KQL of the marked nodes.
//! - `Ctrl+C` exits without printing, with exit code 130.
//!
//! While a page loads, the loop ignores every key except `q`, `Esc`, and
//! `Ctrl+C`, so the tree does not change under the cursor.

use std::{
    cell::Cell,
    io::{self, Write as _},
    pin::pin,
    time::Duration,
};

use crossterm::{
    cursor::{Hide, MoveTo, Show},
    event::{self, Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers},
    execute, queue,
    style::{Attribute, Print, SetAttribute},
    terminal::{self, Clear, ClearType, EnterAlternateScreen, LeaveAlternateScreen},
};

use super::{
    Node, NodeKind, Relay, Tree, holders,
    render::{self, View},
};
use crate::{addr::Range, engine::Context, text};

/// How long the loop sleeps when there is no key.
const TICK: Duration = Duration::from_millis(20);

/// The status line when there is no message and no progress.
const EXIT_KEYS: &str = "q/Esc export KQL  Ctrl+C cancel";
const HELP: &str = "▶ query match. [x] selected for KQL export.\nSpace selects or deselects the current node.\nSelecting a parent exports that parent's condition. It does not select its children. Separately selected children also contribute to the exported query.\n↑↓ or j/k move. →, Enter or l expand. ← or h collapse or move to the parent.\nPgUp/PgDn scroll. Home/End jump.\n? opens or closes help. d opens or closes full node details. Backspace closes either panel.\nIn a panel, ↑↓ and PgUp/PgDn scroll.\nq or Esc exports the selected KQL, including from a panel. Ctrl+C cancels with empty stdout and exit code 130.\nWhile routes load, q, Esc and Ctrl+C remain available.\nCountry codes describe registration, not geolocation.\nCounters describe matching candidates, not input file lines.";

/// A terminal the tree is drawn on.
///
/// netf uses the terminal of the process. Tests pass their own terminal
/// with scripted keys to [`run_with_terminal`](crate::run_with_terminal).
pub trait Terminal {
    /// Returns the size as columns, then lines.
    fn size(&mut self) -> io::Result<(u16, u16)>;

    /// Returns the next key pressed, if any, without waiting.
    fn key(&mut self) -> io::Result<Option<Key>>;

    /// Shows `frame`, replacing what was shown.
    fn draw(&mut self, frame: &Frame) -> io::Result<()>;
}

/// A key the tree understands.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum Key {
    /// `↑`.
    Up,
    /// `↓`.
    Down,
    /// `←`.
    Left,
    /// `→`.
    Right,
    /// `PgUp`.
    PageUp,
    /// `PgDn`.
    PageDown,
    /// `Home`.
    Home,
    /// `End`.
    End,
    /// `Enter`.
    Enter,
    /// `Space`.
    Space,
    /// `Backspace`: close help or details.
    Backspace,
    /// `Esc`.
    Esc,
    /// `Ctrl+C`.
    Interrupt,
    /// Any other character.
    Char(char),
}

/// What the screen shows.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Frame {
    /// The lines from the top: the query, a blank line, and the tree. Each
    /// line fits the width.
    pub lines: Vec<String>,
    /// The line of the cursor, an index into `lines`.
    pub cursor: Option<usize>,
    /// The status line, at the bottom: the keys, a notice, an error, or
    /// the progress of a load.
    pub status: String,
    /// Persistent key hints and status above the exit keys.
    pub footer: Vec<String>,
    /// A page of routes is loading. Until the load ends, the tree ignores
    /// every key except `q`, `Esc`, and `Ctrl+C`.
    pub loading: bool,
}

/// How the user left the tree.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Exit {
    /// `q` or `Esc`: print the marked nodes.
    Done,
    /// `Ctrl+C`: print nothing, exit code 130.
    Interrupted,
}

/// What the loop needs to load a page of routes.
pub(crate) struct Loader<'a, 'c> {
    /// The sources and RDAP of the run.
    pub(crate) context: &'a Context<'c>,
    /// The reporter of the run, which keeps notices for the status line.
    pub(crate) relay: &'a Relay,
    /// Routes per page, the limit of the run. `None` loads all routes.
    pub(crate) page: Option<usize>,
    /// Family, completeness, and source information for this query.
    pub(crate) information: &'a dyn Fn() -> Vec<String>,
}

/// What a key asks of the loop.
#[derive(Clone, Debug, Eq, PartialEq)]
enum Action {
    /// Redraw only.
    Stay,
    /// Load the next page of the `· N routes` node at this path.
    Load(Vec<usize>),
    /// Leave the tree.
    Exit(Exit),
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum Panel {
    Help,
    Details,
}

/// The tree on screen, with the cursor and the scroll position.
struct App<'t> {
    tree: &'t mut Tree,
    /// The index of the visible node under the cursor.
    cursor: usize,
    /// The index of the first visible node on screen.
    offset: usize,
    /// The number of tree lines on screen, for `PgUp` and `PgDn`.
    rows: usize,
    /// A message for the status line until the next key.
    status: Option<String>,
    information: Vec<String>,
    panel: Option<Panel>,
    panel_offset: usize,
}

impl<'t> App<'t> {
    /// Creates the app with the cursor on the first node the query matched.
    fn new(tree: &'t mut Tree) -> Self {
        let cursor = render::lines(tree)
            .iter()
            .position(|line| tree.node(&line.path).is_some_and(|node| node.matched))
            .unwrap_or(0);
        Self {
            tree,
            cursor,
            offset: 0,
            rows: 1,
            status: None,
            information: Vec::new(),
            panel: None,
            panel_offset: 0,
        }
    }

    /// Returns the frame for a terminal of `columns` by `height`.
    ///
    /// Scrolls the tree to keep the cursor on screen. `loading` is the
    /// progress of a load as done and total.
    fn frame(&mut self, (columns, height): (u16, u16), loading: Option<(usize, usize)>) -> Frame {
        let width = usize::from(columns).max(1);
        let height = usize::from(height);
        if width < 32 || height < 10 {
            let status = if width >= 14 {
                "Ctrl+C: cancel"
            } else {
                "^C:cancel"
            };
            let export = if width >= 17 {
                "q/Esc: export KQL"
            } else {
                "q/Esc:KQL"
            };
            return Frame {
                lines: vec![text::truncate("Resize to at least 32 × 10", width)],
                cursor: None,
                footer: vec![text::truncate(export, width)],
                status: text::truncate(status, width),
                loading: loading.is_some(),
            };
        }
        let mut footer = Vec::new();
        if self.tree.truncated
            || self
                .information
                .iter()
                .any(|line| line.starts_with("Partial") || line.starts_with("Showing"))
        {
            footer.push(
                if width < 45 {
                    "Partial result · ? for details"
                } else {
                    "Partial result · ? for limits and sources"
                }
                .into(),
            );
        }
        if let Some((done, total)) = loading {
            footer.push(format!("rdap: {done}/{total}"));
        } else if let Some(status) = &self.status {
            footer.push(text::truncate(&text::terminal_safe(status), width));
        }
        if self.panel.is_some() {
            footer.push("↑↓ scroll  Backspace close  ? help  d details".into());
        } else {
            footer.push(
                if width < 45 {
                    "▶ match  [x] selected"
                } else {
                    "▶ query match  [x] selected for KQL"
                }
                .into(),
            );
            footer.push("Space select/deselect  ? help  d details".into());
            footer.push("↑↓ move  → expand  ← collapse".into());
        }
        let footer: Vec<_> = footer
            .iter()
            .flat_map(|line| {
                text::wrap(line, "", width)
                    .lines()
                    .map(str::to_owned)
                    .collect::<Vec<_>>()
            })
            .collect();
        // Reserve the header and every key hint before allocating tree rows.
        self.rows = height.saturating_sub(3 + footer.len()).max(1);
        let total = render::lines(self.tree).len();
        self.cursor = self.cursor.min(total.saturating_sub(1));
        if self.cursor < self.offset {
            self.offset = self.cursor;
        } else if self.cursor >= self.offset + self.rows {
            self.offset = self.cursor + 1 - self.rows;
        }
        self.offset = self.offset.min(total.saturating_sub(self.rows));
        let mut lines = render::render(
            self.tree,
            View {
                width,
                rows: self.rows,
                offset: self.offset,
            },
        );
        lines[0] = text::truncate(&text::terminal_safe(&self.tree.header), width);
        lines[1] = text::truncate(
            &format!(
                "Selected nodes: {} · {}",
                marked(&self.tree.roots),
                self.information
                    .first()
                    .map_or("Family: IPv4", String::as_str)
            ),
            width,
        );
        let mut cursor = Some(2 + self.cursor - self.offset);
        if let Some(panel) = self.panel {
            let help = panel == Panel::Help;
            let content = if help {
                format!("{HELP}\n\n{}", self.information.join("\n"))
            } else {
                let visible = render::lines(self.tree);
                visible
                    .get(self.cursor)
                    .and_then(|line| self.tree.node(&line.path))
                    .map_or_else(|| "No node selected.".into(), details)
            };
            let content: Vec<_> = content
                .lines()
                .flat_map(|line| {
                    text::wrap(&text::terminal_safe(line), "", width)
                        .lines()
                        .map(str::to_owned)
                        .collect::<Vec<_>>()
                })
                .collect();
            self.panel_offset = self
                .panel_offset
                .min(content.len().saturating_sub(self.rows));
            lines = vec![
                if help { "Help" } else { "Node details" }.into(),
                String::new(),
            ];
            lines.extend(content.into_iter().skip(self.panel_offset).take(self.rows));
            cursor = None;
        }
        Frame {
            cursor,
            lines,
            footer,
            status: EXIT_KEYS.into(),
            loading: loading.is_some(),
        }
    }

    /// Handles `key` and returns what the loop does next.
    fn key(&mut self, key: Key) -> Action {
        self.status = None;
        match key {
            Key::Esc | Key::Char('q') => return Action::Exit(Exit::Done),
            Key::Interrupt => return Action::Exit(Exit::Interrupted),
            Key::Char('?') | Key::Char('d') => {
                let panel = if key == Key::Char('?') {
                    Panel::Help
                } else {
                    Panel::Details
                };
                self.panel = if self.panel == Some(panel) {
                    None
                } else {
                    Some(panel)
                };
                self.panel_offset = 0;
                return Action::Stay;
            }
            Key::Backspace => {
                self.panel = None;
                return Action::Stay;
            }
            _ => {}
        }
        if self.panel.is_some() {
            match key {
                Key::Up | Key::Char('k') => self.panel_offset = self.panel_offset.saturating_sub(1),
                Key::Down | Key::Char('j') => {
                    self.panel_offset = self.panel_offset.saturating_add(1)
                }
                Key::PageUp => self.panel_offset = self.panel_offset.saturating_sub(self.rows),
                Key::PageDown => self.panel_offset = self.panel_offset.saturating_add(self.rows),
                Key::Home => self.panel_offset = 0,
                Key::End => self.panel_offset = usize::MAX,
                _ => {}
            }
            return Action::Stay;
        }
        let lines = render::lines(self.tree);
        let last = lines.len().saturating_sub(1);
        let path = match lines.get(self.cursor) {
            Some(line) => line.path.clone(),
            None => Vec::new(),
        };
        match key {
            Key::Up | Key::Char('k') => self.cursor = self.cursor.saturating_sub(1),
            Key::Down | Key::Char('j') => self.cursor = (self.cursor + 1).min(last),
            Key::PageUp => self.cursor = self.cursor.saturating_sub(self.rows),
            Key::PageDown => self.cursor = (self.cursor + self.rows).min(last),
            Key::Home | Key::Char('g') => self.cursor = 0,
            Key::End | Key::Char('G') => self.cursor = last,
            Key::Right | Key::Enter | Key::Char('l') => {
                if let Some(node) = self.tree.node_mut(&path) {
                    if matches!(node.kind, NodeKind::More { .. }) {
                        return Action::Load(path);
                    }
                    node.expanded = true;
                }
            }
            Key::Left | Key::Char('h') => match self.tree.node_mut(&path) {
                Some(node) if node.expanded && !node.children.is_empty() => {
                    node.expanded = false;
                }
                _ if path.len() > 1 => {
                    let parent = &path[..path.len() - 1];
                    if let Some(index) = lines.iter().position(|line| line.path == parent) {
                        self.cursor = index;
                    }
                }
                _ => {}
            },
            Key::Space | Key::Char(' ') => {
                if let Some(node) = self.tree.node_mut(&path)
                    && node.markable()
                {
                    node.marked = !node.marked;
                }
            }
            Key::Esc | Key::Char('q') => return Action::Exit(Exit::Done),
            Key::Interrupt => return Action::Exit(Exit::Interrupted),
            Key::Char(_) | Key::Backspace => {}
        }
        Action::Stay
    }
}

fn details(node: &Node) -> String {
    let kind = match &node.kind {
        NodeKind::Org(_) => format!(
            "Organization; {} in RIPE RIS",
            super::count(node.routes, "route", "routes")
        ),
        NodeKind::As(_) => format!(
            "Origin AS; {} in RIPE RIS",
            super::count(node.routes, "route", "routes")
        ),
        NodeKind::Route(_) => "BGP route seen in RIPE RIS".into(),
        NodeKind::Part(_) => "Selected part of a BGP route".into(),
        NodeKind::Net(_) => "Registry network".into(),
        NodeKind::NoRoute => "Networks not seen in RIPE RIS".into(),
        NodeKind::More { rest, .. } => format!("{} routes remain to be loaded", rest.len()),
    };
    format!(
        "{}\n\n{kind}\nQuery match: {}\nSelected for export: {}\nKQL: {}",
        text::terminal_safe(&node.label),
        node.matched,
        node.marked,
        node.kql().map_or_else(
            || "this node cannot be selected".into(),
            |q| text::terminal_safe(&q)
        )
    )
}

/// Returns the number of marked nodes in `nodes` and their descendants.
fn marked(nodes: &[Node]) -> usize {
    nodes
        .iter()
        .map(|node| usize::from(node.marked) + marked(&node.children))
        .sum()
}

/// Draws `frame` unless the same frame is already on screen.
fn show(terminal: &mut dyn Terminal, frame: Frame, shown: &mut Option<Frame>) -> io::Result<()> {
    if shown.as_ref() != Some(&frame) {
        terminal.draw(&frame)?;
        *shown = Some(frame);
    }
    Ok(())
}

/// Shows `tree` on `terminal` until the user leaves.
///
/// # Errors
///
/// Returns the I/O errors of `terminal`.
pub(crate) async fn run(
    tree: &mut Tree,
    terminal: &mut dyn Terminal,
    loader: &Loader<'_, '_>,
) -> io::Result<Exit> {
    let mut app = App::new(tree);
    app.information = (loader.information)();
    let mut shown = None;
    loop {
        let frame = app.frame(terminal.size()?, None);
        show(terminal, frame, &mut shown)?;
        let Some(key) = terminal.key()? else {
            tokio::time::sleep(TICK).await;
            continue;
        };
        match app.key(key) {
            Action::Stay => {}
            Action::Exit(exit) => return Ok(exit),
            Action::Load(path) => {
                if let Some(exit) = load(&mut app, terminal, loader, &path, &mut shown).await? {
                    return Ok(exit);
                }
            }
        }
    }
}

/// Loads the next page of the `· N routes` node at `path` and shows the
/// progress.
///
/// Returns `Some` if the user left the tree during the load. A failed load
/// leaves the node as it was and shows the error in the status line. The
/// user can try again.
///
/// # Errors
///
/// Returns the I/O errors of `terminal`.
async fn load(
    app: &mut App<'_>,
    terminal: &mut dyn Terminal,
    loader: &Loader<'_, '_>,
    path: &[usize],
    shown: &mut Option<Frame>,
) -> io::Result<Option<Exit>> {
    let Some(routes) = app.tree.page(path, loader.page) else {
        return Ok(None);
    };
    let ranges: Vec<Range> = routes.iter().map(|route| route.prefix.range()).collect();
    let progress = Cell::new((0, ranges.len()));
    let report = |done, total| progress.set((done, total));
    let mut work = pin!(holders(loader.context, &ranges, &report));
    let result = loop {
        let frame = app.frame(terminal.size()?, Some(progress.get()));
        show(terminal, frame, shown)?;
        match terminal.key()? {
            Some(Key::Interrupt) => return Ok(Some(Exit::Interrupted)),
            Some(Key::Esc | Key::Char('q')) => return Ok(Some(Exit::Done)),
            _ => {}
        }
        tokio::select! {
            result = &mut work => break result,
            () = tokio::time::sleep(TICK) => {}
        }
    };
    let notices = loader.relay.take_notices();
    app.information = (loader.information)();
    for notice in &notices {
        app.information.push(notice.clone());
    }
    app.tree.truncated |= loader.relay.truncated();
    match result {
        Ok(found) => {
            app.tree.show_page(path, &found);
            // The cursor stays on `· N routes` for the next page. When no
            // route is left, the cursor moves to the last route shown.
            let mut more = path.to_vec();
            if let Some(index) = more.last_mut() {
                *index += found.len();
            }
            let left = app
                .tree
                .node(&more)
                .is_some_and(|node| matches!(node.kind, NodeKind::More { .. }));
            app.cursor += found.len() - usize::from(!left && !found.is_empty());
            app.status = notices.last().cloned();
        }
        Err(error) => app.status = Some(error.to_string()),
    }
    Ok(None)
}

/// The terminal of the process: the alternate screen in raw mode.
///
/// Dropping the screen restores the terminal.
pub(crate) struct Screen {
    out: io::Stdout,
}

impl Screen {
    /// Switches the terminal to raw mode and the alternate screen.
    ///
    /// # Errors
    ///
    /// Returns the error of the terminal.
    pub(crate) fn open() -> io::Result<Self> {
        terminal::enable_raw_mode()?;
        // From here on, `Drop` restores the terminal, even if the rest
        // fails.
        let mut screen = Self { out: io::stdout() };
        execute!(screen.out, EnterAlternateScreen, Hide)?;
        Ok(screen)
    }
}

impl Drop for Screen {
    fn drop(&mut self) {
        // `drop` cannot return an error, so a failure here is ignored.
        let _ = execute!(self.out, Show, LeaveAlternateScreen);
        let _ = terminal::disable_raw_mode();
    }
}

impl Terminal for Screen {
    fn size(&mut self) -> io::Result<(u16, u16)> {
        terminal::size()
    }

    fn key(&mut self) -> io::Result<Option<Key>> {
        while event::poll(Duration::ZERO)? {
            if let Event::Key(key) = event::read()?
                && key.kind != KeyEventKind::Release
                && let Some(key) = key_of(key)
            {
                return Ok(Some(key));
            }
            // The loop sees a resize through `size` at the next frame.
        }
        Ok(None)
    }

    fn draw(&mut self, frame: &Frame) -> io::Result<()> {
        let (_, height) = terminal::size()?;
        let last = height.saturating_sub(1);
        let footer_start = last.saturating_sub(u16::try_from(frame.footer.len()).unwrap_or(last));
        for (row, line) in (0..footer_start).zip(&frame.lines) {
            queue!(self.out, MoveTo(0, row), Clear(ClearType::CurrentLine))?;
            if frame.cursor == Some(usize::from(row)) {
                queue!(
                    self.out,
                    SetAttribute(Attribute::Reverse),
                    Print(line),
                    SetAttribute(Attribute::Reset)
                )?;
            } else {
                queue!(self.out, Print(line))?;
            }
        }
        let used = u16::try_from(frame.lines.len())
            .unwrap_or(u16::MAX)
            .min(footer_start);
        queue!(self.out, MoveTo(0, used), Clear(ClearType::FromCursorDown),)?;
        for (row, line) in (footer_start..last).zip(&frame.footer) {
            queue!(self.out, MoveTo(0, row), Print(line))?;
        }
        queue!(
            self.out,
            MoveTo(0, last),
            SetAttribute(Attribute::Dim),
            Print(&frame.status),
            SetAttribute(Attribute::Reset)
        )?;
        self.out.flush()
    }
}

/// Returns the key of a crossterm event, or `None` for a key the tree does
/// not use.
fn key_of(event: KeyEvent) -> Option<Key> {
    Some(match event.code {
        KeyCode::Char('c') if event.modifiers.contains(KeyModifiers::CONTROL) => Key::Interrupt,
        KeyCode::Char(' ') => Key::Space,
        KeyCode::Char(c) => Key::Char(c),
        KeyCode::Up => Key::Up,
        KeyCode::Down => Key::Down,
        KeyCode::Left => Key::Left,
        KeyCode::Right => Key::Right,
        KeyCode::PageUp => Key::PageUp,
        KeyCode::PageDown => Key::PageDown,
        KeyCode::Home => Key::Home,
        KeyCode::End => Key::End,
        KeyCode::Enter => Key::Enter,
        KeyCode::Esc => Key::Esc,
        KeyCode::Backspace => Key::Backspace,
        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tree::OrgQuery;

    fn leaf(kind: NodeKind, label: &str, matched: bool) -> Node {
        Node {
            matched,
            ..Node::new(kind, label.to_owned())
        }
    }

    /// Returns an organization with two AS. The second AS has a matched
    /// route.
    fn tree() -> Tree {
        let route = leaf(
            NodeKind::Route("192.0.2.0/24".parse().unwrap()),
            "192.0.2.0/24",
            true,
        );
        let mut first = leaf(NodeKind::As(64496), "AS64496 EXAMPLE-NET", false);
        first.routes = 3;
        let mut second = leaf(NodeKind::As(64497), "AS64497 TELE-EDGE", false);
        second.children = vec![route];
        second.routes = 1;
        let mut org = leaf(
            NodeKind::Org(OrgQuery::Handle("ORG-EN1-RIPE".into())),
            "Example Networks LLC, XA",
            false,
        );
        org.children = vec![first, second];
        Tree {
            header: "route: 192.0.2.0/24".into(),
            truncated: false,
            roots: vec![org],
        }
    }

    #[test]
    fn keys_move_collapse_and_mark() {
        let mut tree = tree();
        let mut app = App::new(&mut tree);
        assert_eq!(app.key(Key::Left), Action::Stay);
        // On a leaf, `←` moves to the parent. The next `←` collapses the AS.
        assert_eq!(app.cursor, 2);
        app.key(Key::Left);
        assert!(!app.tree.roots[0].children[1].expanded);
        assert_eq!(
            app.frame((80, 24), None).lines[4],
            "└─ AS64497 TELE-EDGE · 1 route"
        );
        app.key(Key::Right);
        assert!(app.tree.roots[0].children[1].expanded);
        app.key(Key::Home);
        app.key(Key::Space);
        app.key(Key::Char('j'));
        app.key(Key::Space);
        assert_eq!(app.tree.query(), "as.org: ORG-EN1-RIPE or as.asn: 64496");
        let frame = app.frame((80, 24), None);
        assert_eq!(frame.lines[2], "[x] Example Networks LLC, XA");
        assert!(frame.lines[1].starts_with("Selected nodes: 2"));
        assert_eq!(frame.status, EXIT_KEYS);
        app.key(Key::Space);
        app.key(Key::End);
        assert_eq!(app.cursor, 3);
        app.key(Key::Down);
        assert_eq!(app.cursor, 3);
        assert_eq!(app.key(Key::Char('q')), Action::Exit(Exit::Done));
        assert_eq!(app.key(Key::Esc), Action::Exit(Exit::Done));
        assert_eq!(app.key(Key::Interrupt), Action::Exit(Exit::Interrupted));
    }

    #[test]
    fn the_window_follows_the_cursor() {
        let mut tree = tree();
        let mut app = App::new(&mut tree);
        app.key(Key::Home);
        let frame = app.frame((45, 10), None);
        assert_eq!(frame.cursor, Some(2));
        app.key(Key::End);
        let frame = app.frame((45, 10), None);
        assert_eq!(frame.cursor, Some(frame.lines.len() - 1));
        assert!(frame.lines.len() + frame.footer.len() < 10);
        assert_eq!(frame.status, EXIT_KEYS);
        let frame = app.frame((10, 5), Some((3, 12)));
        assert_eq!(frame.footer, ["q/Esc:KQL"]);
        assert_eq!(frame.status, "^C:cancel");
        assert!(frame.loading);
    }

    #[test]
    fn crossterm_keys() {
        let key = |code, modifiers| key_of(KeyEvent::new(code, modifiers));
        assert_eq!(
            key(KeyCode::Char('c'), KeyModifiers::CONTROL),
            Some(Key::Interrupt)
        );
        assert_eq!(
            key(KeyCode::Char('c'), KeyModifiers::NONE),
            Some(Key::Char('c'))
        );
        assert_eq!(
            key(KeyCode::Char(' '), KeyModifiers::NONE),
            Some(Key::Space)
        );
        assert_eq!(key(KeyCode::Up, KeyModifiers::NONE), Some(Key::Up));
        assert_eq!(key(KeyCode::F(1), KeyModifiers::NONE), None);
    }

    #[test]
    fn details_scroll_through_full_unicode_names() {
        let mut tree = tree();
        tree.roots[0].label = format!("START {} END", "日本 e\u{301} 👩‍💻 ".repeat(70));
        let mut app = App::new(&mut tree);
        app.key(Key::Home);
        app.key(Key::Char('d'));
        let mut seen = String::new();
        for _ in 0..30 {
            let frame = app.frame((45, 24), None);
            assert_eq!(frame.status, EXIT_KEYS);
            for line in &frame.lines {
                assert!(text::width(line) <= 45, "{line}");
                assert!(!line.contains('…'));
            }
            seen.push_str(&frame.lines.join("\n"));
            app.key(Key::PageDown);
        }
        assert!(seen.contains("START") && seen.contains("END") && seen.contains("👩‍💻"));
        assert!(seen.contains("KQL: as.org: ORG-EN1-RIPE"));
    }
}
