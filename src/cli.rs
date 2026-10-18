//! The command line: options and query words.
//!
//! `lexopt` yields the arguments one at a time, so the parser sees where the
//! query starts and ends. The query is the run of arguments that starts at
//! the first argument that is neither an option nor an option's value. The
//! run ends at the next argument that starts with a minus. The parser joins
//! the query words with single spaces, and the text is parsed later as one
//! KQL query.
//!
//! Options may come before or after the query, but not inside it. In
//! `netf as.asn: -4 64496`, the `-4` is more likely a mistake than intent,
//! so the parser returns a usage error (code 2) instead of a guess. A query
//! word that starts with a minus is quoted inside KQL (`'as.name: "-x"'`)
//! or follows `--`. Every argument after `--` is a query word.
//!
//! This module checks the option values, so an error names the option:
//! `--limit ten`, `--ttl 5x`, `--fields holder`. What depends on the config
//! is decided by [`config::load`](crate::config::load): the address family,
//! the defaults, and whether `-s` names a set.

pub(crate) mod help;

use std::{ffi::OsString, path::PathBuf, time::Duration};

use lexopt::{Arg, Parser};

use crate::{
    config::{DURATION_HINT, parse_duration, parse_field},
    error::{Error, Result},
    output::column::Column,
};

/// What the command line asks for.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum Command {
    /// `-h`, `--help`.
    Help(help::Topic),
    /// `-V`, `--version`.
    Version,
    /// A query or `-s`.
    Run(Box<Cli>),
}

/// The options and the query of a run, as given.
///
/// `None` and `false` mean that the option is not given, so the config or
/// the default decides.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub(crate) struct Cli {
    /// The query words joined with spaces. `None` with `-s`.
    pub(crate) query: Option<String>,
    /// `-s`, `--set`.
    pub(crate) set: Option<String>,
    /// `-c`, `--config`, as given. A relative path is not yet resolved
    /// against the current directory.
    pub(crate) config: Option<PathBuf>,
    /// `--ipset`.
    pub(crate) ipset: bool,
    /// `-4`.
    pub(crate) v4: bool,
    /// `-6`.
    pub(crate) v6: bool,
    /// `-f`, `--file`, as given.
    pub(crate) file: Option<PathBuf>,
    /// `--fields`.
    pub(crate) fields: Option<Vec<Column>>,
    /// `--limit`. `Some(0)` shows all networks.
    pub(crate) limit: Option<usize>,
    /// `--ttl`.
    pub(crate) ttl: Option<Duration>,
    /// `--cache-dir`, as given.
    pub(crate) cache_dir: Option<PathBuf>,
    /// `--no-cache`.
    pub(crate) no_cache: bool,
    /// `--proxy`, in the given order. Each repeat adds a proxy to the pool.
    pub(crate) proxies: Vec<String>,
    /// `--concurrency`, at least 1.
    pub(crate) concurrency: Option<usize>,
    /// `--ripe-emails`.
    pub(crate) ripe_emails: bool,
    /// `--doh`.
    pub(crate) doh: Option<String>,
    /// `-i`: the interactive tree.
    pub(crate) interactive: bool,
}

/// Where the parser is relative to the query.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Place {
    /// No query word yet.
    Before,
    /// Inside the query.
    Query,
    /// After the query: options only.
    After,
}

/// Parses the arguments, without `argv[0]`.
///
/// `--help` and `--version` stop the parsing where they stand. The
/// arguments after them are ignored, but an error before them is reported.
///
/// # Errors
///
/// Returns a usage error in these cases:
///
/// - An option is unknown, inside the query, or not available in this
///   build.
/// - An option that takes a value is repeated. Only `--proxy` may repeat.
/// - A value is missing, invalid, or not UTF-8, or an option that takes no
///   value has one.
/// - A query word is not UTF-8.
/// - The query is missing, or `-s` comes with a query.
/// - Two options cannot be combined.
pub(crate) fn parse(args: &[OsString]) -> Result<Command> {
    if args.is_empty() {
        return Err(Error::usage(help::FIRST_RUN));
    }
    let mut parser = Parser::from_args(args.iter().cloned());
    let mut cli = Cli::default();
    let mut words: Vec<String> = Vec::new();
    let mut place = Place::Before;
    // The first option after the query. The error names it if a query word
    // follows.
    let mut after: Option<String> = None;

    while let Some(arg) = parser.next().map_err(lexopt_error)? {
        let name = match &arg {
            Arg::Value(word) => {
                if place == Place::After {
                    let option = after.unwrap_or_default();
                    return Err(Error::usage(format!(
                        "{option}: option inside the query; put options before or after the query"
                    )));
                }
                place = Place::Query;
                let word = word
                    .to_str()
                    .ok_or_else(|| Error::usage(format!("query word {word:?}: not valid UTF-8")))?;
                words.push(word.to_owned());
                continue;
            }
            Arg::Short(c) => format!("-{c}"),
            Arg::Long(long) => format!("--{long}"),
        };
        if place == Place::Query {
            place = Place::After;
            after = Some(name.clone());
        }
        match arg {
            Arg::Short('h') | Arg::Long("help") => {
                let topic = match parser.optional_value() {
                    Some(value) => help::Topic::parse(
                        value
                            .to_str()
                            .ok_or_else(|| Error::usage("--help: topic is not valid UTF-8"))?,
                    )?,
                    None => help::Topic::Main,
                };
                return Ok(Command::Help(topic));
            }
            Arg::Short('V') | Arg::Long("version") => return Ok(Command::Version),
            Arg::Short('s') | Arg::Long("set") => {
                let value = text(&name, &mut parser)?;
                if cli.set.is_some() {
                    return Err(Error::usage(format!(
                        "{name}: only one set; combine sets in a query: 'set: a or set: b'"
                    )));
                }
                cli.set = Some(value);
            }
            Arg::Short('c') | Arg::Long("config") => {
                let value = path(&mut parser)?;
                once(&name, &mut cli.config, value)?;
            }
            Arg::Long("ipset") => cli.ipset = true,
            Arg::Short('4') => cli.v4 = true,
            Arg::Short('6') => cli.v6 = true,
            Arg::Short('f') | Arg::Long("file") => {
                let value = path(&mut parser)?;
                once(&name, &mut cli.file, value)?;
            }
            Arg::Long("fields") => {
                let value = text(&name, &mut parser)?;
                let fields = output_fields(&name, &value)?;
                once(&name, &mut cli.fields, fields)?;
            }
            Arg::Long("limit") => {
                let value = text(&name, &mut parser)?;
                let limit = number(&value)
                    .ok_or_else(|| invalid_value(&name, &value, "expected a number"))?;
                once(&name, &mut cli.limit, limit)?;
            }
            Arg::Long("ttl") => {
                let value = text(&name, &mut parser)?;
                let ttl = parse_duration(&value)
                    .ok_or_else(|| invalid_value(&name, &value, DURATION_HINT))?;
                once(&name, &mut cli.ttl, ttl)?;
            }
            Arg::Long("cache-dir") => {
                let value = path(&mut parser)?;
                once(&name, &mut cli.cache_dir, value)?;
            }
            Arg::Long("no-cache") => cli.no_cache = true,
            Arg::Long("proxy") => cli.proxies.push(text(&name, &mut parser)?),
            Arg::Long("concurrency") => {
                let value = text(&name, &mut parser)?;
                let concurrency = number(&value)
                    .filter(|&n| n > 0)
                    .ok_or_else(|| invalid_value(&name, &value, "expected a number, at least 1"))?;
                once(&name, &mut cli.concurrency, concurrency)?;
            }
            Arg::Long("ripe-emails") => cli.ripe_emails = true,
            Arg::Long("doh") => {
                let value = text(&name, &mut parser)?;
                once(&name, &mut cli.doh, value)?;
            }
            Arg::Short('i') => cli.interactive = true,
            _ => {
                let near = crate::query::suggest::nearest(&name, OPTIONS.iter().copied());
                let mut error = Error::usage(format!("{name}: unknown option; see netf --help"))
                    .span(0..name.len())
                    .source(&name);
                if !near.is_empty() {
                    error = error.hint(format!("did you mean {}?", near.join(", ")));
                }
                return Err(error);
            }
        }
    }

    let query = words.join(" ");
    let query = (!query.trim().is_empty()).then_some(query);
    match (&cli.set, &query) {
        (Some(set), Some(_)) => {
            return Err(Error::usage(format!(
                "-s {set}: a set takes no query; use the query 'set: {set} and …' instead"
            )));
        }
        (None, None) => return Err(Error::usage("no query; see netf --help")),
        _ => {}
    }
    cli.query = query;

    let ipset = if cli.ipset {
        Some("--ipset")
    } else if cli.set.is_some() {
        Some("-s")
    } else {
        None
    };
    if let Some(ipset) = ipset {
        if cli.fields.is_some() {
            return Err(Error::usage(format!(
                "--fields cannot be combined with {ipset}: the list has no columns"
            )));
        }
        if cli.interactive {
            return Err(Error::usage(format!("-i cannot be combined with {ipset}")));
        }
    }
    if cli.interactive && cli.file.is_some() {
        return Err(Error::usage("-i cannot be combined with -f"));
    }
    Ok(Command::Run(Box::new(cli)))
}

const OPTIONS: &[&str] = &[
    "--help",
    "--version",
    "--set",
    "--config",
    "--ipset",
    "--file",
    "--fields",
    "--limit",
    "--ttl",
    "--cache-dir",
    "--no-cache",
    "--proxy",
    "--concurrency",
    "--ripe-emails",
    "--doh",
];

fn invalid_value(name: &str, value: &str, reason: &str) -> Error {
    let source = format!("{name} {value}");
    Error::usage(format!("{source}: {reason}"))
        .span(name.len() + 1..source.len())
        .source(&source)
}

fn output_fields(name: &str, value: &str) -> Result<Vec<Column>> {
    let source = format!("{name} {value}");
    let mut offset = name.len() + 1;
    let mut fields = Vec::new();
    for item in value.split(',') {
        let word = item.trim();
        let parsed = parse_field(word);
        let field = parsed.map_err(|reason| {
            let at = offset + item.len() - item.trim_start().len();
            let mut error = Error::usage(format!("{name}: {reason}"))
                .span(at..at + word.len())
                .source(&source);
            let near = crate::query::suggest::nearest(word, Column::names());
            if Column::parse(word).is_none() && !near.is_empty() {
                error = error.hint(format!("did you mean {}?", near.join(", ")));
            }
            error
        })?;
        fields.push(field);
        offset += item.len() + 1;
    }
    Ok(fields)
}

/// Stores the value of an option that may be given only once.
fn once<T>(name: &str, slot: &mut Option<T>, value: T) -> Result<()> {
    if slot.is_some() {
        return Err(Error::usage(format!("{name}: given twice")));
    }
    *slot = Some(value);
    Ok(())
}

/// Takes the value of the option `name` as text.
fn text(name: &str, parser: &mut Parser) -> Result<String> {
    let value = parser.value().map_err(lexopt_error)?;
    value
        .into_string()
        .map_err(|value| Error::usage(format!("{name} {value:?}: not valid UTF-8")))
}

/// Takes the value of an option as a path.
///
/// The path may hold bytes that are not UTF-8.
fn path(parser: &mut Parser) -> Result<PathBuf> {
    Ok(parser.value().map_err(lexopt_error)?.into())
}

/// Parses a decimal number without a sign.
fn number(text: &str) -> Option<usize> {
    if text.is_empty() || !text.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    text.parse().ok()
}

/// Turns a `lexopt` error into a usage error worded like the other netf
/// errors.
fn lexopt_error(error: lexopt::Error) -> Error {
    Error::usage(match error {
        lexopt::Error::MissingValue {
            option: Some(option),
        } => format!("{option}: missing value; see netf --help"),
        lexopt::Error::UnexpectedValue { option, .. } => format!("{option}: takes no value"),
        lexopt::Error::UnexpectedOption(option) => {
            format!("{option}: unknown option; see netf --help")
        }
        lexopt::Error::NonUnicodeValue(value) => format!("{value:?}: not valid UTF-8"),
        other => other.to_string(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::query::Field;

    fn args(list: &[&str]) -> Vec<OsString> {
        list.iter().map(OsString::from).collect()
    }

    fn run(list: &[&str]) -> Cli {
        match parse(&args(list)) {
            Ok(Command::Run(cli)) => *cli,
            other => panic!("{list:?}: {other:?}"),
        }
    }

    /// Returns the error line of `list`, which must be a usage error.
    fn error(list: &[&str]) -> String {
        let error = parse(&args(list)).expect_err("an error");
        assert_eq!(error.exit_code().code(), 2, "{error}");
        error.to_string()
    }

    #[test]
    fn options_before_or_after_the_query() {
        let before = run(&["-4", "-f", "/tmp/ex.txt", "as.asn:", "64510"]);
        let after = run(&["as.asn:", "64510", "-4", "-f", "/tmp/ex.txt"]);
        assert_eq!(before, after);
        assert_eq!(before.query.as_deref(), Some("as.asn: 64510"));
        assert!(before.v4);
        assert_eq!(before.file, Some(PathBuf::from("/tmp/ex.txt")));
        // Options on both sides of the query.
        let both = run(&["--ipset", "ip:", "192.0.2.1", "-6"]);
        assert!(both.ipset && both.v6);
        assert_eq!(both.query.as_deref(), Some("ip: 192.0.2.1"));
    }

    #[test]
    fn option_inside_the_query() {
        assert_eq!(
            error(&["as.asn:", "-4", "64510"]),
            "netf: -4: option inside the query; put options before or after the query"
        );
        assert_eq!(
            error(&["ip:", "192.0.2.1", "--limit", "5", "or", "ip:", "192.0.2.2"]),
            "netf: --limit: option inside the query; put options before or after the query"
        );
    }

    #[test]
    fn every_option() {
        let cli = run(&[
            "-c",
            "router.toml",
            "-46",
            "--file=out.txt",
            "--fields",
            "net.org, net.country",
            "--limit",
            "0",
            "--ttl",
            "30m",
            "--cache-dir",
            "/tmp/c",
            "--no-cache",
            "--proxy",
            "http://10.0.0.2:3128",
            "--proxy=http://10.0.0.3:3128",
            "--concurrency",
            "16",
            "--ripe-emails",
            "--doh",
            "https://dns.example/dns-query",
            "x",
        ]);
        assert_eq!(cli.config, Some(PathBuf::from("router.toml")));
        assert!(cli.v4 && cli.v6);
        assert_eq!(cli.file, Some(PathBuf::from("out.txt")));
        assert_eq!(
            cli.fields,
            Some(vec![Field::NetOrg.into(), Field::NetCountry.into()])
        );
        assert_eq!(cli.limit, Some(0));
        assert_eq!(cli.ttl, Some(Duration::from_secs(1800)));
        assert_eq!(cli.cache_dir, Some(PathBuf::from("/tmp/c")));
        assert!(cli.no_cache);
        assert_eq!(
            cli.proxies,
            ["http://10.0.0.2:3128", "http://10.0.0.3:3128"]
        );
        assert_eq!(cli.concurrency, Some(16));
        assert!(cli.ripe_emails);
        assert_eq!(cli.doh.as_deref(), Some("https://dns.example/dns-query"));
        assert!(!cli.ipset && !cli.interactive);
        assert_eq!(cli.query.as_deref(), Some("x"));
    }

    #[test]
    fn set_option() {
        let cli = run(&[
            "-c",
            "/etc/netf/router.toml",
            "-s",
            "vpn",
            "-f",
            "/tmp/vpn4.txt",
        ]);
        assert_eq!(cli.set.as_deref(), Some("vpn"));
        assert_eq!(cli.query, None);
        assert_eq!(run(&["--set=vpn"]).set.as_deref(), Some("vpn"));
        assert_eq!(
            error(&["-s", "a", "-s", "b"]),
            "netf: -s: only one set; combine sets in a query: 'set: a or set: b'"
        );
        assert_eq!(
            error(&["-s", "vpn", "as.country:", "XF"]),
            "netf: -s vpn: a set takes no query; use the query 'set: vpn and …' instead"
        );
    }

    #[test]
    fn no_query() {
        assert_eq!(error(&[]), format!("netf: {}", help::FIRST_RUN));
        assert_eq!(error(&["-4"]), "netf: no query; see netf --help");
        assert_eq!(error(&["", " "]), "netf: no query; see netf --help");
    }

    #[test]
    fn unknown_options_and_missing_values() {
        assert_eq!(
            error(&["--bogus", "x"]),
            "netf: --bogus: unknown option; see netf --help"
        );
        assert_eq!(
            error(&["-x", "x"]),
            "netf: -x: unknown option; see netf --help"
        );
        assert_eq!(
            error(&["-4x", "x"]),
            "netf: -x: unknown option; see netf --help"
        );
        // A negative number is an option, not a query word.
        assert_eq!(error(&["-1"]), "netf: -1: unknown option; see netf --help");
        assert_eq!(
            error(&["x", "--limit"]),
            "netf: --limit: missing value; see netf --help"
        );
        assert_eq!(
            error(&["x", "-f"]),
            "netf: -f: missing value; see netf --help"
        );
        assert_eq!(
            error(&["--ipset=yes", "x"]),
            "netf: --ipset: takes no value"
        );
    }

    #[test]
    fn bad_values() {
        assert_eq!(
            error(&["--limit", "ten", "x"]),
            "netf: --limit ten: expected a number"
        );
        assert_eq!(
            error(&["--limit", "-1", "x"]),
            "netf: --limit -1: expected a number"
        );
        assert_eq!(
            error(&["--concurrency", "0", "x"]),
            "netf: --concurrency 0: expected a number, at least 1"
        );
        assert_eq!(
            error(&["--ttl", "5x", "x"]),
            "netf: --ttl 5x: expected a duration such as 30m, 12h, 7d, or 0"
        );
        assert_eq!(run(&["--ttl", "0", "x"]).ttl, Some(Duration::ZERO));
        assert_eq!(
            error(&["--fields", "net.org,holder", "x"]),
            "netf: --fields: holder: unknown field; see netf --help=fields"
        );
        assert_eq!(
            error(&["--fields", "route", "x"]),
            "netf: --fields: route: already a column"
        );
        assert_eq!(
            error(&["--fields", "net.org,", "x"]),
            "netf: --fields: empty field name"
        );
        assert_eq!(
            error(&["--limit", "1", "--limit", "2", "x"]),
            "netf: --limit: given twice"
        );
        assert_eq!(
            error(&["-c", "a", "--config", "b", "x"]),
            "netf: --config: given twice"
        );
    }

    #[test]
    fn fields_with_ipset() {
        assert_eq!(
            error(&["--ipset", "--fields", "net.org", "x"]),
            "netf: --fields cannot be combined with --ipset: the list has no columns"
        );
        assert_eq!(
            error(&["-s", "vpn", "--fields", "net.org"]),
            "netf: --fields cannot be combined with -s: the list has no columns"
        );
    }

    #[test]
    fn interactive() {
        assert!(run(&["-i", "x"]).interactive);
        assert_eq!(
            error(&["-i", "--ipset", "x"]),
            "netf: -i cannot be combined with --ipset"
        );
        assert_eq!(
            error(&["-i", "-s", "vpn"]),
            "netf: -i cannot be combined with -s"
        );
        assert_eq!(
            error(&["-i", "-f", "out", "x"]),
            "netf: -i cannot be combined with -f"
        );
    }

    #[cfg(unix)]
    #[test]
    fn non_utf8_words() {
        use std::os::unix::ffi::OsStringExt as _;

        let bad = OsString::from_vec(vec![b'a', 0xff]);
        let error = parse(std::slice::from_ref(&bad)).unwrap_err();
        assert_eq!(error.exit_code().code(), 2);
        assert!(error.to_string().contains("not valid UTF-8"), "{error}");
        // A path may hold bytes that are not UTF-8.
        let cli = match parse(&[OsString::from("-f"), bad, OsString::from("x")]) {
            Ok(Command::Run(cli)) => cli,
            other => panic!("{other:?}"),
        };
        assert!(cli.file.is_some());
    }
}
