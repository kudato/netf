//! netf: networks of the internet from BGP routes, registries, and DNS,
//! queried with KQL.
//!
//! netf answers a query such as `as.name: example* and not ip: 192.0.2.0/26`
//! with the routes that RIPE RIS sees in BGP, the registry networks that the
//! routes belong to, and the AS that announce them. With `--ipset`, netf
//! instead prints the addresses of the result as a collapsed CIDR list. The
//! data comes from public sources: the RIS dumps, `asn.txt`, the delegated
//! stats, RDAP, the RIPE database REST API, and the APNIC and AFRINIC
//! database dumps. netf downloads each source on demand and caches it under
//! `~/.netf`.
//!
//! # The library
//!
//! The crate is a binary. The library exists so that integration tests can
//! run the whole pipeline in process, with the network, DNS, the clock, and
//! stderr replaced. Its surface is small on purpose and **not stable**:
//!
//! - [`run`] takes an [`Invocation`] and returns an [`Outcome`]. The
//!   invocation holds the arguments, the [`Environment`], and the
//!   [`Transport`], [`Resolver`], [`Clock`], and [`Reporter`] to use. The
//!   outcome holds the exit code and the bytes to print on stdout.
//! - The traits and the types they exchange are public, so that tests can
//!   implement them. Everything else is `pub(crate)`.
//! - [`run_with_terminal`] runs `-i` on a [`Terminal`] that the caller
//!   supplies. Tests drive the tree with
//!   scripted keys and read the [`Frame`]s that it draws.
//!
//! [`run`] never prints to stdout. It returns the whole result, and `main`
//! prints it at the end, so a failed run prints nothing. Notices and the
//! final error go to the [`Reporter`] as they happen.
//!
//! # Layers
//!
//! Each layer can be tested without the layers above it. From the bottom:
//!
//! 1. Pure data and logic: `addr`, `model`, `text`, `query`, `plan`,
//!    `report`, and `error`.
//! 2. I/O primitives: `transport`, `cache`, `fetch`, and `dns`.
//! 3. Sources: `dataset`, `rdap`, `ripe_rest`, and `sources`.
//! 4. Evaluation and output: `engine`, `output`, and `tree`.
//! 5. The application: `cli`, `config`, `http`, and this file.
//!
//! Only this file names `http`, the real network.

mod addr;
mod cache;
mod cli;
mod config;
mod dataset;
mod dns;
mod engine;
mod error;
mod fetch;
mod http;
mod model;
mod output;
mod plan;
mod query;
mod rdap;
mod report;
mod ripe_rest;
mod sources;
mod text;
mod transport;
mod tree;

use std::{
    collections::HashMap, ffi::OsString, io::IsTerminal as _, path::PathBuf, sync::Arc,
    time::SystemTime,
};

pub use addr::{Families, Family};
pub use dns::{DnsError, Resolved, Resolver};
pub use http::{HttpOptions, HttpTransport, ProxyError};
pub use report::{Notice, Reporter, Source, StderrReporter};
pub use transport::{
    BodyStream, BoxFuture, Class, EgressId, Method, Request, Response, Transport, TransportError,
};
pub use tree::tui::{Frame, Key, Terminal};

use crate::{
    cli::Command,
    config::Settings,
    error::{Error, Result},
};

/// A source of the current time.
///
/// The cache uses it for the TTL, and the RIPE limit uses it for the UTC
/// day. Tests use a clock that they can advance instead of waiting.
pub trait Clock: Send + Sync {
    /// Returns the current time.
    fn now(&self) -> SystemTime;
}

/// The clock of the system.
#[derive(Clone, Copy, Debug, Default)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> SystemTime {
        SystemTime::now()
    }
}

/// What netf reads from the process besides the arguments.
///
/// [`Environment::from_process`] reads it once. No other code reads the
/// process environment, so tests control all of it.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Environment {
    /// The home directory, which holds `~/.netf`. `None` if unknown.
    pub home: Option<PathBuf>,
    /// The current directory. Relative paths in `-c`, `-f`, and `@path`
    /// resolve against it.
    pub cwd: PathBuf,
    /// The environment variables that are valid UTF-8.
    pub vars: HashMap<String, String>,
    /// Whether stdin is a terminal.
    pub stdin_is_terminal: bool,
    /// Whether stdout is a terminal.
    pub stdout_is_terminal: bool,
    /// Whether stderr is a terminal. If it is, progress is redrawn in
    /// place.
    pub stderr_is_terminal: bool,
    /// The width of stdout in terminal columns, or `None` if unknown.
    pub stdout_columns: Option<usize>,
    /// The width of stderr in terminal columns, or `None` if unknown.
    pub stderr_columns: Option<usize>,
}

impl Environment {
    /// Reads the environment of the current process.
    pub fn from_process() -> Self {
        Self {
            home: std::env::home_dir(),
            // An unreadable current directory matters only for relative
            // paths. Those paths then fail with their own error.
            cwd: std::env::current_dir().unwrap_or_default(),
            vars: std::env::vars_os()
                .filter_map(|(name, value)| {
                    Some((name.into_string().ok()?, value.into_string().ok()?))
                })
                .collect(),
            stdin_is_terminal: std::io::stdin().is_terminal(),
            stdout_is_terminal: std::io::stdout().is_terminal(),
            stderr_is_terminal: std::io::stderr().is_terminal(),
            stdout_columns: terminal_columns(true),
            stderr_columns: terminal_columns(false),
        }
    }

    /// Returns the variable `name`, if set.
    pub fn var(&self, name: &str) -> Option<&str> {
        self.vars.get(name).map(String::as_str)
    }
}

/// Reads the chosen output stream, independent of the controlling terminal.
fn terminal_columns(stdout: bool) -> Option<usize> {
    let is_terminal = if stdout {
        std::io::stdout().is_terminal()
    } else {
        std::io::stderr().is_terminal()
    };
    if !is_terminal {
        return None;
    }
    #[cfg(unix)]
    {
        use std::os::fd::AsRawFd as _;
        let mut size = libc::winsize {
            ws_row: 0,
            ws_col: 0,
            ws_xpixel: 0,
            ws_ypixel: 0,
        };
        let fd = if stdout {
            std::io::stdout().as_raw_fd()
        } else {
            std::io::stderr().as_raw_fd()
        };
        // SAFETY: fd is a live descriptor and size is writable for the ioctl.
        #[allow(unsafe_code)]
        let result = unsafe { libc::ioctl(fd, libc::TIOCGWINSZ, &mut size) };
        (result == 0 && size.ws_col > 0).then_some(usize::from(size.ws_col))
    }
    #[cfg(not(unix))]
    {
        crossterm::terminal::size()
            .ok()
            .map(|(width, _)| usize::from(width))
            .filter(|width| *width > 0)
    }
}

/// Everything a run depends on.
pub struct Invocation {
    /// The arguments, without `argv[0]`.
    pub args: Vec<OsString>,
    /// The environment.
    pub env: Environment,
    /// The network. `None` selects the real network, [`HttpTransport`].
    pub transport: Option<Arc<dyn Transport>>,
    /// DNS. `None` selects the system resolver, or DNS over HTTPS if a
    /// proxy is set.
    pub resolver: Option<Arc<dyn Resolver>>,
    /// The clock.
    pub clock: Arc<dyn Clock>,
    /// Where notices, progress, and the final error go.
    pub reporter: Arc<dyn Reporter>,
}

impl Invocation {
    /// Builds the invocation of the current process.
    ///
    /// The invocation takes the arguments and the environment of the
    /// process. It uses the real network, DNS, and clock, and it reports to
    /// stderr.
    pub fn from_process() -> Self {
        let env = Environment::from_process();
        let reporter = Arc::new(
            StderrReporter::with_terminal(env.stderr_is_terminal, env.var("TERM") == Some("dumb"))
                .with_columns(env.stderr_columns.unwrap_or(80)),
        );
        Self {
            args: std::env::args_os().skip(1).collect(),
            env,
            transport: None,
            resolver: None,
            clock: Arc::new(SystemClock),
            reporter,
        }
    }
}

/// The result of a run.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Outcome {
    /// The exit code: 0 for a result, 1 for a runtime error, 2 for a usage
    /// error, or 130 for an interrupted run.
    pub code: u8,
    /// The bytes to print on stdout. Empty unless `code` is 0.
    pub stdout: Vec<u8>,
}

/// Runs netf.
///
/// On failure, the reporter has already received the error, and `stdout`
/// is empty.
pub async fn run(invocation: Invocation) -> Outcome {
    let result = report::drive(invocation.reporter.as_ref(), execute(&invocation, None)).await;
    finish(&invocation, result)
}

/// Runs netf like [`run`], but draws the `-i` tree on `terminal`.
///
/// The process then needs no terminal of its own. Without `-i`, the
/// function behaves like [`run`].
pub async fn run_with_terminal(invocation: Invocation, terminal: &mut dyn Terminal) -> Outcome {
    let result = report::drive(
        invocation.reporter.as_ref(),
        execute(&invocation, Some(terminal)),
    )
    .await;
    finish(&invocation, result)
}

/// The terminal that `-i` draws on: the caller's, or `None` for the
/// terminal of the process.
type TerminalArg<'a> = Option<&'a mut dyn Terminal>;

/// Turns the result of a run into an [`Outcome`] and passes an error to the
/// reporter.
fn finish(invocation: &Invocation, result: Result<Vec<u8>>) -> Outcome {
    match result {
        Ok(stdout) => Outcome { code: 0, stdout },
        Err(error) => {
            invocation.reporter.error(&error.render());
            Outcome {
                code: error.exit_code().code(),
                stdout: Vec::new(),
            }
        }
    }
}

/// Does the work of [`run`] and returns the bytes for stdout.
///
/// The steps run in this order, so that each error appears before the work
/// that it would waste:
///
/// 1. Parse the command line. `--help` and `--version` return here: they
///    need neither `~/.netf` nor the config.
/// 2. Build the [`Settings`]. A bad option, config, or home directory fails
///    here.
/// 3. Parse, expand, and plan the query. A bad query fails before the `-f`
///    file exists and before any download.
/// 4. Run the engine over the sources.
/// 5. Write the answer to stdout or to the `-f` file. With `-i`, the tree
///    takes the answer instead and returns the marked nodes.
async fn execute(invocation: &Invocation, terminal: TerminalArg<'_>) -> Result<Vec<u8>> {
    let cli = match cli::parse(&invocation.args)? {
        Command::Help(topic) => return Ok(cli::help::help(topic).into_bytes()),
        Command::Version => return Ok(cli::help::version().into_bytes()),
        Command::Run(cli) => cli,
    };
    let settings: Settings = config::load(&cli, &invocation.env)?;
    // The tree reads keys from stdin and draws on stdout. Without a
    // terminal on both, fail before the cache and the network are touched.
    let env = &invocation.env;
    if settings.interactive
        && terminal.is_none()
        && !(env.stdin_is_terminal && env.stdout_is_terminal)
    {
        return Err(Error::usage(
            "-i: the interactive tree needs a terminal on stdin and stdout",
        ));
    }
    let ast = query::parse(&settings.query)?;
    let (expr, notices) = query::expand::expand_in(
        &ast,
        &|name| settings.sets.query(name),
        settings.families,
        &invocation.env.cwd,
    )
    .map_err(|error| error.source(&settings.query))?;
    let plan = plan::build(expr, settings.mode.clone(), settings.families)?;
    // Create the output before the work, so that an unwritable directory
    // fails at once.
    let output = settings
        .file
        .as_deref()
        .map(output::file::Output::create)
        .transpose()?;
    // With `-i`, notices pass through the relay. The relay notes whether a
    // registry truncated a response, for the `*` sign. It also keeps notices
    // off the screen of the tree.
    let relay = settings
        .interactive
        .then(|| Arc::new(tree::Relay::new(Arc::clone(&invocation.reporter))));
    let inner: Arc<dyn Reporter> = match &relay {
        Some(relay) => Arc::clone(relay) as Arc<dyn Reporter>,
        None => Arc::clone(&invocation.reporter),
    };
    let evidence = Arc::new(output::metadata::Evidence::new(inner));
    let reporter: &Arc<dyn Reporter> = &(Arc::clone(&evidence) as Arc<dyn Reporter>);
    for notice in &notices {
        reporter.notice(notice);
    }
    let transport: Arc<dyn Transport> = match &invocation.transport {
        Some(transport) => Arc::clone(transport),
        None => Arc::new(HttpTransport::new(
            HttpOptions {
                proxies: settings.proxies.clone(),
                concurrency: settings.concurrency,
                ..HttpOptions::default()
            },
            Arc::clone(reporter),
        )?),
    };
    let resolver: Arc<dyn Resolver> = match &invocation.resolver {
        Some(resolver) => Arc::clone(resolver),
        None => dns::select(!settings.proxies.is_empty(), &settings.doh, &transport),
    };
    let cache = settings.cache.then(|| {
        cache::Cache::new(
            settings.cache_dir.clone(),
            settings.ttl,
            Arc::clone(&invocation.clock),
            Arc::clone(reporter),
        )
    });
    let base = sources::source_base(&invocation.env);
    // Building the client sends no request. The client fetches the
    // bootstrap on first use.
    let rdap = rdap::RdapClient::new(
        rdap::RdapSettings {
            cache_dir: settings.cache_dir.clone(),
            cache: settings.cache,
            ttl: settings.ttl,
            ripe_emails: settings.ripe_emails,
            base: base.clone(),
            sources: settings.sources.clone(),
        },
        Arc::clone(&transport),
        Arc::clone(&invocation.clock),
        Arc::clone(reporter),
    );
    // The RIPE REST API keeps its responses in the cache of RDAP, so the run
    // sweeps the directory once.
    let rest = ripe_rest::RipeRest::new(
        Arc::clone(&transport),
        rdap.responses(),
        settings.sources.ripe_rest(),
        base.clone(),
        Arc::clone(reporter),
    );
    let sources = sources::Sources::new(transport, cache, base, settings.sources.clone())
        .with_reporting(Arc::clone(reporter), Arc::clone(&invocation.clock));
    let context = engine::Context {
        sources: &sources,
        rdap: &rdap,
        rest: &rest,
        resolver: resolver.as_ref(),
        reporter: reporter.as_ref(),
        concurrency: settings.concurrency,
    };
    let answer = engine::run(&plan, &context).await?;
    if let (
        Some(relay),
        output::Answer::Rows {
            rows, selection, ..
        },
    ) = (&relay, &answer)
    {
        let information = || {
            std::iter::once(format!(
                "Family: {}",
                output::metadata::families(plan.families)
            ))
            .chain(output::metadata::selection_lines(selection))
            .chain(evidence.limitations())
            .chain(evidence.provenance())
            .collect()
        };
        let result = tree::run(
            &context,
            &plan,
            &settings.query,
            rows,
            relay,
            terminal,
            &information,
        )
        .await?;
        if result.is_none() && env.stderr_is_terminal {
            reporter.notice(&Notice::Completion(format!(
                "no matches ({}).",
                output::metadata::families(plan.families)
            )));
        }
        return Ok(result.unwrap_or_default());
    }
    let width =
        (env.stdout_is_terminal && output.is_none()).then_some(env.stdout_columns.unwrap_or(80));
    let mut text = answer.render(width, cli.format, cli.columns.as_deref());
    let (written, empty) = match &answer {
        output::Answer::Rows {
            rows, selection, ..
        } => {
            if let Some(width) =
                width.filter(|_| !rows.is_empty() && cli.format != Some(output::Format::Plain))
            {
                text.push('\n');
                for line in output::metadata::summary(rows, selection, plan.families)
                    .into_iter()
                    .chain(evidence.limitations())
                    .chain(evidence.provenance())
                {
                    text.push_str(&text::wrap(&line, "", width));
                }
            }
            (
                output::metadata::count(rows.len(), "record", "records"),
                rows.is_empty(),
            )
        }
        output::Answer::Ipset(set) => (
            output::metadata::count(text.lines().count(), "CIDR", "CIDRs"),
            set.is_empty(),
        ),
    };
    let text = text.into_bytes();
    reporter.activity(None);
    reporter.clear_progress();
    match output {
        Some(output) => {
            output.commit(&text)?;
            if env.stderr_is_terminal {
                reporter.notice(&Notice::Completion(format!(
                    "saved {written} to {} ({}).",
                    text::terminal_safe(
                        &cli.file
                            .as_ref()
                            .expect("output path")
                            .display()
                            .to_string()
                    ),
                    output::metadata::families(plan.families)
                )));
            }
            Ok(Vec::new())
        }
        None => {
            if empty && env.stderr_is_terminal {
                reporter.notice(&Notice::Completion(format!(
                    "no matches ({}).",
                    output::metadata::families(plan.families)
                )));
            }
            Ok(text)
        }
    }
}
