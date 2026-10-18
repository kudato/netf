//! Everything netf says on stderr: the catalogue of notices and the
//! [`Reporter`] that prints them.
//!
//! A run that ends with exit code 0 may still print notices. Examples are an
//! AS without networks, an organization that the registries don't know, or
//! the row limit. Each notice is a variant of [`Notice`]. Its
//! [`Display`](fmt::Display) implementation is the only place that forms
//! the text, so tests compare texts against one catalogue.
//!
//! Notices are one line that starts with `netf: `. Errors that end the
//! run are not notices. They are [`Error`](crate::error::Error)s, and
//! [`Reporter::error`] prints the error once, at the end.
//! The no-argument usage screen is a multiline usage error.
//!
//! # Ordering
//!
//! Notices are printed as they happen. The result goes to stdout only at
//! the end, so everything on stderr appears before stdout. Progress
//! (`netf: rdap: 37/120`) shares the terminal with notices. The reporter
//! erases the progress line before it prints a notice, so the two never
//! mix.

use std::{
    fmt,
    io::{self, Write as _},
    sync::{Mutex, PoisonError},
    time::Duration,
};
use tokio::time::Instant;

use crate::{addr::Family, transport::Class};

/// When a source used by this run was retrieved or revalidated.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Source {
    /// The dataset or registry name, without a request URL.
    pub name: String,
    /// Retrieval or revalidation time. This is not the source's snapshot date.
    pub checked: Option<std::time::SystemTime>,
    /// The source's HTTP Last-Modified value, if available.
    pub last_modified: Option<String>,
}

impl Source {
    pub(crate) fn new(
        class: Class,
        checked: Option<std::time::SystemTime>,
        last_modified: Option<String>,
    ) -> Self {
        let name = match class {
            Class::Dataset(name @ ("ris-v4" | "ris-v6")) => format!("RIPE RIS ({name})"),
            Class::Dataset("asn") => "RIPE NCC asn.txt".into(),
            other => other.to_string(),
        };
        Self {
            name,
            checked,
            last_modified,
        }
    }
}

/// Receives what netf has to say on stderr.
///
/// [`StderrReporter`] prints to the stderr of the process. Tests collect the
/// lines instead. Concurrent requests share one reporter, so implementations
/// must be thread-safe.
pub trait Reporter: Send + Sync {
    /// Reports a notice: something the user should know that does not stop
    /// the run (exit code 0).
    fn notice(&self, notice: &Notice);

    /// Reports the error that ends the run.
    ///
    /// `message` is the full line, `netf: …`, without a newline.
    fn error(&self, message: &str);

    /// Reports how far a long check has got: `done` of `total` items of
    /// `what`, such as `rdap`.
    ///
    /// Callers may call this method often. The reporter decides how often
    /// to show the progress.
    fn progress(&self, done: u32, total: u32, what: &'static str);

    /// Removes the progress line, if one is shown, at the end of the check.
    fn clear_progress(&self);

    /// Starts a terminal activity, or ends it with `None`.
    /// This does not add log lines for nonterminal reporters.
    fn activity(&self, _action: Option<&'static str>) {}

    /// Updates a known terminal count. `unit` names the objects counted.
    fn items(&self, _done: u32, _total: u32, _unit: &'static str) {}

    /// Redraws a slow activity, including while no request has completed.
    fn tick(&self) {}

    /// Records source provenance without printing a progress message.
    fn source(&self, _source: Source) {}
}

/// Drives progress independently of results arriving from the network.
/// Dropping this future clears the activity, including on cancellation.
pub(crate) async fn drive<T>(reporter: &dyn Reporter, work: impl Future<Output = T>) -> T {
    struct Guard<'a>(&'a dyn Reporter);
    impl Drop for Guard<'_> {
        fn drop(&mut self) {
            self.0.activity(None);
            self.0.clear_progress();
        }
    }
    let _guard = Guard(reporter);
    tokio::pin!(work);
    // Ticks only inspect state. The reporter limits actual writes to 2/s.
    let mut timer = tokio::time::interval(Duration::from_millis(100));
    timer.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        tokio::select! {
            biased;
            result = &mut work => return result,
            _ = timer.tick() => reporter.tick(),
        }
    }
}

/// A message on stderr that does not stop the run.
///
/// [`Display`](fmt::Display) gives the whole line, with the `netf: ` prefix
/// and without a newline.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Notice {
    /// A completion message, emitted only when stderr is a terminal.
    Completion(String),
    /// `as.asn: N` gave no networks. `N` is a single number, not a range.
    ///
    /// In rows: `netf: AS64505 QUIET-AS - Quiet Networks, Inc., XE: no
    /// networks`. With `--ipset`, netf does not load `asn.txt`, so the line
    /// is `netf: AS64505: no networks`.
    NoNetworks {
        /// The AS number.
        asn: u32,
        /// The `asn.txt` line after the number, or `None` with `--ipset`.
        entry: Option<String>,
    },
    /// `as.asn: N` gave no networks, and `asn.txt` has no such AS:
    /// `netf: AS64512: unknown AS, no networks`.
    UnknownAs {
        /// The AS number.
        asn: u32,
    },
    /// An `as.name` pattern matched no AS: `netf: as.name: exampl*: no AS`.
    NoAs {
        /// The pattern as written in the query.
        pattern: String,
    },
    /// The registries know no such organization:
    /// `netf: net.org: xyz: not found`.
    OrgNotFound {
        /// The field: `net.org` or `as.org`.
        field: &'static str,
        /// The value, ready to print.
        value: String,
    },
    /// The organization holds no networks: `netf: net.org: xyz: no networks`.
    OrgNoNetworks {
        /// The value, ready to print.
        value: String,
    },
    /// The organization holds no AS: `netf: as.org: xyz: no AS`.
    OrgNoAs {
        /// The value, ready to print.
        value: String,
    },
    /// A bare word found nothing: `netf: exampl: nothing found`.
    NothingFound {
        /// The word as written in the query.
        word: String,
    },
    /// The query dropped addresses of a family that the run does not output:
    /// `netf: 1 IPv6 address skipped, use -6`.
    Skipped {
        /// The family of the dropped addresses.
        family: Family,
        /// The number of dropped addresses.
        count: usize,
    },
    /// A domain has no address of a requested family:
    /// `netf: domain example.com: no IPv6 address`.
    NoAddress {
        /// The domain, in punycode.
        domain: String,
        /// The family without addresses.
        family: Family,
    },
    /// The limit cut the rows, and the total is known:
    /// `netf: showing 100 of 25325 matches; refine the query or use --limit 0`.
    Limit {
        /// The number of routes shown.
        shown: usize,
        /// The number of routes that matched.
        total: usize,
    },
    /// The limit cut the rows during a check of a condition on the holder,
    /// so the total is unknown:
    /// `netf: showing first 100 matches; 2400 candidates not checked; use --limit 0`.
    LimitUnchecked {
        /// The number of routes shown.
        shown: usize,
        /// The number of candidate routes that were not checked.
        unchecked: usize,
    },
    /// A server responded with 429, and the requests through that egress wait:
    /// `netf: rdap: lacnic: rate limited, waiting 60s`.
    RateLimited {
        /// The class of the request.
        class: Class,
        /// How long the requests wait.
        wait: Duration,
    },
    /// A registry said that it truncated a search result:
    /// `netf: ripencc: limited search results to 100 maximum`.
    Truncated {
        /// The registry, such as `ripencc` or `arin`.
        rir: String,
        /// The message of the registry, on one line.
        message: String,
    },
    /// A registry does not support RDAP search by name, so netf skipped it:
    /// `netf: rdap: lacnic: search not supported`.
    SearchNotSupported {
        /// The registry, such as `ripencc` or `arin`.
        rir: String,
    },
    /// The RIPE limit ran out on every egress:
    /// `netf: ripe: daily limit reached on 3 of 3 IPs; 40 e-mails not fetched`.
    RipeLimit {
        /// The number of egresses whose limit is exhausted.
        exhausted: usize,
        /// The number of all egresses.
        total: usize,
        /// The number of e-mails left unfetched.
        missing: usize,
    },
    /// A cache file failed the checks, and the cache deleted it:
    /// `netf: cache: ris-v4: corrupt, downloading again`.
    CacheCorrupt {
        /// The name of the dataset: `ris-v4`.
        file: String,
    },
    /// The run was interrupted with Ctrl+C: `netf: interrupted`.
    Interrupted,
}

impl fmt::Display for Notice {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("netf: ")?;
        match self {
            Self::Completion(message) => f.write_str(message),
            Self::NoNetworks {
                asn,
                entry: Some(entry),
            } => write!(f, "AS{asn} {entry}: no networks"),
            Self::NoNetworks { asn, entry: None } => write!(f, "AS{asn}: no networks"),
            Self::UnknownAs { asn } => write!(f, "AS{asn}: unknown AS, no networks"),
            Self::NoAs { pattern } => write!(f, "as.name: {pattern}: no AS"),
            Self::OrgNotFound { field, value } => write!(f, "{field}: {value}: not found"),
            Self::OrgNoNetworks { value } => write!(f, "net.org: {value}: no networks"),
            Self::OrgNoAs { value } => write!(f, "as.org: {value}: no AS"),
            Self::NothingFound { word } => write!(f, "{word}: nothing found"),
            Self::Skipped { family, count } => write!(
                f,
                "{count} {family} {} skipped, use {}",
                plural(*count, "address", "addresses"),
                family.flag()
            ),
            Self::NoAddress { domain, family } => {
                write!(f, "domain {domain}: no {family} address")
            }
            Self::Limit { shown, total } => write!(
                f,
                "showing {shown} of {total} {}; refine the query or use --limit 0",
                plural(*total, "match", "matches")
            ),
            Self::LimitUnchecked { shown, unchecked } => write!(
                f,
                "showing first {shown} {}; {unchecked} {} not checked; use --limit 0",
                plural(*shown, "match", "matches"),
                plural(*unchecked, "candidate", "candidates")
            ),
            Self::RateLimited { class, wait } => {
                write!(f, "{class}: rate limited, waiting {}", duration(*wait))
            }
            Self::Truncated { rir, message } => write!(f, "{rir}: {message}"),
            Self::SearchNotSupported { rir } => write!(f, "rdap: {rir}: search not supported"),
            Self::RipeLimit {
                exhausted,
                total,
                missing,
            } => write!(
                f,
                // "IPs" stays plural even for one egress ("on 1 of 1 IPs"),
                // because the word names the set of all egresses.
                "ripe: daily limit reached on {exhausted} of {total} IPs; {missing} {} not fetched",
                plural(*missing, "e-mail", "e-mails")
            ),
            Self::CacheCorrupt { file } => write!(f, "cache: {file}: corrupt, downloading again"),
            Self::Interrupted => f.write_str("interrupted"),
        }
    }
}

/// Chooses the singular or the plural form for `count`.
fn plural(count: usize, one: &'static str, many: &'static str) -> &'static str {
    if count == 1 { one } else { many }
}

/// Formats a pause for messages, in the units of `--ttl`.
///
/// A pause under an hour is shown in seconds, as `Retry-After` gives it:
/// `waiting 60s`. A longer pause is shown in whole hours or minutes if it
/// divides evenly (`2h`, `90m`), and in seconds otherwise. Fractions of a
/// second round up, so a pause never looks shorter than it is.
pub(crate) fn duration(wait: Duration) -> String {
    let seconds = wait.as_secs() + u64::from(wait.subsec_nanos() > 0);
    if seconds >= 3600 && seconds.is_multiple_of(3600) {
        format!("{}h", seconds / 3600)
    } else if seconds >= 3600 && seconds.is_multiple_of(60) {
        format!("{}m", seconds / 60)
    } else {
        format!("{seconds}s")
    }
}

/// How often a progress line is redrawn on a terminal: twice a second.
const REDRAW: Duration = Duration::from_millis(500);

/// The smallest number of items for which a check shows progress.
const MIN_PROGRESS: u32 = 10;

/// Erases the current terminal line.
const ERASE_LINE: &str = "\r\x1b[K";

/// A reporter that redraws slow activities on stderr terminals.
/// Nonterminals retain the existing progress log at each tenth.
#[derive(Debug)]
pub struct StderrReporter {
    terminal: bool,
    dumb: bool,
    columns: usize,
    state: Mutex<ProgressState>,
}

/// One activity and the output emitted for it.
#[derive(Debug, Default)]
struct ProgressState {
    shown: bool,
    drawn_at: Option<Instant>,
    tenth: u64,
    activity: Option<Activity>,
}

#[derive(Debug)]
struct Activity {
    action: &'static str,
    started: Instant,
    count: Option<(u32, u32, &'static str)>,
    static_shown: bool,
}

impl ProgressState {
    /// Computes one redraw from a supplied time, without doing I/O.
    fn draw(&mut self, now: Instant, dumb: bool, columns: usize) -> Option<String> {
        let activity = self.activity.as_mut()?;
        let elapsed = now.duration_since(activity.started);
        if elapsed < REDRAW
            || self
                .drawn_at
                .is_some_and(|at| now.duration_since(at) < REDRAW)
            || (dumb && activity.static_shown)
        {
            return None;
        }
        let mut line = format!("netf: {}", activity.action);
        if let Some((done, total, unit)) = activity.count {
            line.push_str(&format!(" · {done} of {total} {unit}"));
        }
        line.push_str(&format!(" · elapsed {}s", elapsed.as_secs()));
        if crate::text::width(&line) > columns {
            let action = match activity.action {
                "reading registry records" => "registry records",
                "fetching additional contacts" => "additional contacts",
                action => action,
            };
            line = format!("netf: {action}");
            if let Some((done, total, unit)) = activity.count {
                line.push_str(&format!(" · {done}/{total} {unit}"));
            }
            line.push_str(&format!(" · {}s", elapsed.as_secs()));
            line = crate::text::truncate(&line, columns);
        }
        self.drawn_at = Some(now);
        activity.static_shown = true;
        self.shown = !dumb;
        Some(if dumb {
            format!("{line}\n")
        } else {
            format!("{ERASE_LINE}{line}")
        })
    }
}

impl StderrReporter {
    /// Creates a reporter for stderr. Use `with_terminal` to honor TERM=dumb.
    pub fn new(terminal: bool) -> Self {
        Self::with_terminal(terminal, false)
    }

    /// Creates a reporter with plain, static progress for a dumb terminal.
    pub fn with_terminal(terminal: bool, dumb: bool) -> Self {
        Self {
            terminal,
            dumb,
            columns: 80,
            state: Mutex::new(ProgressState::default()),
        }
    }

    /// Limits progress to one physical line on stderr.
    pub fn with_columns(mut self, columns: usize) -> Self {
        self.columns = columns.max(1);
        self
    }

    /// Removes a transient line before a notice, error, or new stage.
    fn erase(state: &mut ProgressState, stderr: &mut impl io::Write) {
        if state.shown {
            let _ = stderr.write_all(ERASE_LINE.as_bytes());
            let _ = stderr.flush();
            state.shown = false;
        }
    }

    fn line(&self, text: &str) {
        let mut state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        let mut stderr = io::stderr().lock();
        Self::erase(&mut state, &mut stderr);
        let _ = writeln!(stderr, "{text}");
    }
}

impl Reporter for StderrReporter {
    fn notice(&self, notice: &Notice) {
        self.line(&notice.to_string());
    }

    fn error(&self, message: &str) {
        self.line(message);
    }

    fn progress(&self, done: u32, total: u32, what: &'static str) {
        if self.terminal {
            // Existing RDAP checks count candidates, not HTTP requests.
            self.items(done, total, "networks");
        } else if total >= MIN_PROGRESS {
            let mut state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
            let tenth = u64::from(done) * 10 / u64::from(total);
            if tenth > state.tenth {
                state.tenth = tenth;
                let _ = writeln!(io::stderr().lock(), "netf: {what}: {done}/{total}");
            }
        }
    }

    fn clear_progress(&self) {
        let mut state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        Self::erase(&mut state, &mut io::stderr().lock());
        state.tenth = 0;
        if let Some(activity) = &mut state.activity {
            activity.count = None;
        }
    }

    fn activity(&self, action: Option<&'static str>) {
        if !self.terminal {
            return;
        }
        let mut state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        Self::erase(&mut state, &mut io::stderr().lock());
        state.activity = action.map(|action| Activity {
            action,
            started: Instant::now(),
            count: None,
            static_shown: false,
        });
    }

    fn items(&self, done: u32, total: u32, unit: &'static str) {
        let mut state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        if let Some(activity) = &mut state.activity {
            activity.count = Some((done, total, unit));
        }
    }

    fn tick(&self) {
        if !self.terminal {
            return;
        }
        let mut state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        if let Some(line) = state.draw(Instant::now(), self.dumb, self.columns) {
            let mut stderr = io::stderr().lock();
            let _ = stderr.write_all(line.as_bytes());
            let _ = stderr.flush();
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;

    fn activity_at(started: Instant, count: Option<(u32, u32, &'static str)>) -> ProgressState {
        ProgressState {
            activity: Some(Activity {
                action: "reading registry records",
                started,
                count,
                static_shown: false,
            }),
            ..ProgressState::default()
        }
    }

    #[test]
    fn progress_waits_half_a_second_even_for_one_object() {
        let start = Instant::now();
        let mut state = activity_at(start, Some((0, 1, "networks")));
        assert!(
            state
                .draw(start + Duration::from_millis(499), false, 80)
                .is_none()
        );
        let line = state.draw(start + REDRAW, false, 80).unwrap();
        assert!(line.contains("0 of 1 networks"));
        assert!(
            state
                .draw(start + Duration::from_millis(999), false, 80)
                .is_none()
        );
        state.activity.as_mut().unwrap().count = Some((1, 1, "networks"));
        assert!(
            state
                .draw(start + Duration::from_secs(1), false, 80)
                .unwrap()
                .contains("1 of 1 networks")
        );
    }

    #[test]
    fn unknown_total_has_elapsed_time_and_dumb_terminal_has_one_plain_line() {
        let start = Instant::now();
        let mut state = activity_at(start, None);
        let line = state
            .draw(start + Duration::from_secs(2), true, 80)
            .unwrap();
        assert_eq!(line, "netf: reading registry records · elapsed 2s\n");
        assert!(!line.contains(['\r', '\u{1b}']));
        assert!(
            state
                .draw(start + Duration::from_secs(20), true, 80)
                .is_none()
        );
        assert!(!state.shown);
    }

    #[test]
    fn progress_fits_a_narrow_stderr_without_leaving_wrapped_lines() {
        let start = Instant::now();
        let mut state = activity_at(start, Some((1, 3, "networks")));
        let line = state
            .draw(start + Duration::from_secs(4), false, 45)
            .unwrap();
        assert!(crate::text::width(line.strip_prefix(ERASE_LINE).unwrap()) <= 45);
        assert!(line.contains("1/3 networks"), "{line}");
        assert!(line.contains("registry records"));
        assert!(line.ends_with("4s"));
    }

    #[test]
    fn notice_cleanup_erases_only_transient_output() {
        let start = Instant::now();
        let mut state = activity_at(start, None);
        state.draw(start + REDRAW, false, 80).unwrap();
        let mut bytes = Vec::new();
        StderrReporter::erase(&mut state, &mut bytes);
        assert_eq!(bytes, ERASE_LINE.as_bytes());
        StderrReporter::erase(&mut state, &mut bytes);
        assert_eq!(bytes, ERASE_LINE.as_bytes());
        let mut dumb = activity_at(start, None);
        dumb.draw(start + REDRAW, true, 80).unwrap();
        let mut bytes = Vec::new();
        StderrReporter::erase(&mut dumb, &mut bytes);
        assert!(bytes.is_empty());
    }

    /// Runs the real drawing state and timer against a captured output stream.
    #[derive(Default)]
    struct Capture {
        state: Mutex<ProgressState>,
        lines: Mutex<Vec<String>>,
    }

    impl Reporter for Capture {
        fn notice(&self, _: &Notice) {}
        fn error(&self, _: &str) {}
        fn progress(&self, _: u32, _: u32, _: &'static str) {}
        fn clear_progress(&self) {}
        fn activity(&self, action: Option<&'static str>) {
            self.state.lock().unwrap().activity = action.map(|action| Activity {
                action,
                started: Instant::now(),
                count: None,
                static_shown: false,
            });
        }
        fn tick(&self) {
            if let Some(line) = self.state.lock().unwrap().draw(Instant::now(), false, 80) {
                self.lines.lock().unwrap().push(line);
            }
        }
    }

    #[tokio::test(start_paused = true)]
    async fn timer_reports_pending_work_and_stops_on_success_error_and_drop() {
        for fail in [false, true] {
            let reporter = Capture::default();
            let result = drive(&reporter, async {
                reporter.activity(Some("loading network data"));
                tokio::time::sleep(Duration::from_millis(1100)).await;
                if fail { Err("failed") } else { Ok(()) }
            })
            .await;
            assert_eq!(result.is_err(), fail);
            assert_eq!(reporter.lines.lock().unwrap().len(), 2);
            assert!(reporter.state.lock().unwrap().activity.is_none());
        }
        let reporter = Capture::default();
        let result = tokio::time::timeout(
            Duration::from_millis(1100),
            drive(&reporter, async {
                reporter.activity(Some("loading network data"));
                std::future::pending::<()>().await;
            }),
        )
        .await;
        assert!(result.is_err());
        assert_eq!(reporter.lines.lock().unwrap().len(), 2);
        assert!(reporter.state.lock().unwrap().activity.is_none());
        tokio::time::sleep(Duration::from_secs(2)).await;
        assert_eq!(reporter.lines.lock().unwrap().len(), 2);
    }

    #[tokio::test(start_paused = true)]
    async fn fast_work_is_silent() {
        let reporter = Capture::default();
        drive(&reporter, async {
            reporter.activity(Some("finding matches"));
            tokio::time::sleep(Duration::from_millis(499)).await;
        })
        .await;
        assert!(reporter.lines.lock().unwrap().is_empty());
        assert!(reporter.state.lock().unwrap().activity.is_none());
    }

    fn text(notice: Notice) -> String {
        notice.to_string()
    }

    #[test]
    fn as_notices() {
        assert_eq!(
            text(Notice::NoNetworks {
                asn: 64505,
                entry: Some("QUIET-AS - Quiet Networks, Inc., XE".into()),
            }),
            "netf: AS64505 QUIET-AS - Quiet Networks, Inc., XE: no networks"
        );
        assert_eq!(
            text(Notice::NoNetworks {
                asn: 64505,
                entry: None
            }),
            "netf: AS64505: no networks"
        );
        assert_eq!(
            text(Notice::UnknownAs { asn: 64512 }),
            "netf: AS64512: unknown AS, no networks"
        );
        assert_eq!(
            text(Notice::NoAs {
                pattern: "sampl*".into()
            }),
            "netf: as.name: sampl*: no AS"
        );
    }

    #[test]
    fn org_and_word_notices() {
        assert_eq!(
            text(Notice::OrgNotFound {
                field: "net.org",
                value: "xyz".into()
            }),
            "netf: net.org: xyz: not found"
        );
        assert_eq!(
            text(Notice::OrgNoNetworks {
                value: "xyz".into()
            }),
            "netf: net.org: xyz: no networks"
        );
        assert_eq!(
            text(Notice::OrgNoAs {
                value: "xyz".into()
            }),
            "netf: as.org: xyz: no AS"
        );
        assert_eq!(
            text(Notice::NothingFound {
                word: "sampl".into()
            }),
            "netf: sampl: nothing found"
        );
    }

    #[test]
    fn family_notices() {
        assert_eq!(
            text(Notice::Skipped {
                family: Family::V6,
                count: 1
            }),
            "netf: 1 IPv6 address skipped, use -6"
        );
        assert_eq!(
            text(Notice::Skipped {
                family: Family::V4,
                count: 3
            }),
            "netf: 3 IPv4 addresses skipped, use -4"
        );
        assert_eq!(
            text(Notice::NoAddress {
                domain: "ex.test".into(),
                family: Family::V6
            }),
            "netf: domain ex.test: no IPv6 address"
        );
    }

    #[test]
    fn limit_notices() {
        assert_eq!(
            text(Notice::Limit {
                shown: 100,
                total: 25325
            }),
            "netf: showing 100 of 25325 matches; refine the query or use --limit 0"
        );
        assert_eq!(
            text(Notice::LimitUnchecked {
                shown: 100,
                unchecked: 2400
            }),
            "netf: showing first 100 matches; 2400 candidates not checked; use --limit 0"
        );
        assert_eq!(
            text(Notice::LimitUnchecked {
                shown: 1,
                unchecked: 1
            }),
            "netf: showing first 1 match; 1 candidate not checked; use --limit 0"
        );
    }

    #[test]
    fn network_notices() {
        assert_eq!(
            text(Notice::RateLimited {
                class: Class::Rdap(Arc::from("lacnic")),
                wait: Duration::from_secs(60)
            }),
            "netf: rdap: lacnic: rate limited, waiting 60s"
        );
        assert_eq!(
            text(Notice::RateLimited {
                class: Class::Dataset("ris-v4"),
                wait: Duration::from_secs(90)
            }),
            "netf: ris-v4: rate limited, waiting 90s"
        );
        assert_eq!(
            text(Notice::Truncated {
                rir: "ripencc".into(),
                message: "limited search results to 100 maximum".into()
            }),
            "netf: ripencc: limited search results to 100 maximum"
        );
        assert_eq!(
            text(Notice::SearchNotSupported {
                rir: "lacnic".into()
            }),
            "netf: rdap: lacnic: search not supported"
        );
        assert_eq!(
            text(Notice::RipeLimit {
                exhausted: 3,
                total: 3,
                missing: 40
            }),
            "netf: ripe: daily limit reached on 3 of 3 IPs; 40 e-mails not fetched"
        );
        assert_eq!(
            text(Notice::RipeLimit {
                exhausted: 1,
                total: 1,
                missing: 1
            }),
            "netf: ripe: daily limit reached on 1 of 1 IPs; 1 e-mail not fetched"
        );
    }

    #[test]
    fn cache_and_interrupt_notices() {
        assert_eq!(
            text(Notice::CacheCorrupt {
                file: "ris-v4".into()
            }),
            "netf: cache: ris-v4: corrupt, downloading again"
        );
        assert_eq!(text(Notice::Interrupted), "netf: interrupted");
    }

    #[test]
    fn durations() {
        assert_eq!(duration(Duration::from_secs(0)), "0s");
        assert_eq!(duration(Duration::from_secs(45)), "45s");
        assert_eq!(duration(Duration::from_millis(1500)), "2s");
        assert_eq!(duration(Duration::from_secs(90)), "90s");
        assert_eq!(duration(Duration::from_secs(300)), "300s");
        assert_eq!(duration(Duration::from_secs(3661)), "3661s");
        assert_eq!(duration(Duration::from_secs(7200)), "2h");
        assert_eq!(duration(Duration::from_secs(5400)), "90m");
    }
}
