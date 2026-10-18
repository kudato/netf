//! The config files and the settings of a run.
//!
//! netf creates an empty `~/.netf/config.toml` on the first run (see
//! [`home`]). netf merges the file given with `-c FILE` over it, and the
//! values of `-c` win. A config file holds settings, which are the defaults
//! of options, and named sets. A set is a `[set.NAME]` table with a `query`
//! key and the optional family keys `ipv4` and `ipv6`. Unknown keys, wrong
//! types, and TOML errors are usage errors (code 2) that name the file and
//! the line, so a typo is never ignored.
//!
//! [`load`] produces [`Settings`], which hold everything the rest of a run
//! needs, so the lower layers see neither the command line nor the files.
//! These rules decide which value wins:
//!
//! - An option on the command line wins over both files.
//! - For the address family, the `ipv4` and `ipv6` keys of the set given
//!   with `-s` come next. Then come the keys of the files, then IPv4 alone.
//! - When `-c` is merged over the base file, every key of `-c` replaces the
//!   base key, including the lists `proxies` and `fields`. The `[set.NAME]`
//!   tables and the `[sources]` URLs merge by name. A set from `-c`
//!   replaces the base set of the same name whole.
//!
//! Durations are written `30m`, `12h`, `7d`, or `45s`. `0` means
//! "revalidate now". See [`parse_duration`].

pub(crate) mod home;

use std::{collections::BTreeMap, fmt, fs, num::NonZeroUsize, path::PathBuf, time::Duration};

use serde::{Deserialize, Deserializer, de};

use crate::{
    Environment,
    addr::Families,
    cli::Cli,
    dataset::Urls,
    error::{Error, Result},
    output::column::Column,
    plan::Mode,
};

/// The default `ttl`: a day.
pub(crate) const DEFAULT_TTL: Duration = Duration::from_secs(24 * 3600);
/// The default `limit` of rows.
pub(crate) const DEFAULT_LIMIT: usize = 100;
/// The default `concurrency`: concurrent requests to one server through
/// one egress.
pub(crate) const DEFAULT_CONCURRENCY: usize = 8;
/// The default `doh` server, used only with a proxy.
pub(crate) const DEFAULT_DOH: &str = "https://1.1.1.1/dns-query";

/// Everything a run needs from the command line and the config files.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct Settings {
    /// The query text: the words of the command line joined with spaces,
    /// or `set: NAME` for `-s NAME`.
    pub(crate) query: String,
    /// Rows with the limit and the extra columns, or the `--ipset` list.
    pub(crate) mode: Mode,
    /// The address families of the output.
    pub(crate) families: Families,
    /// `-f` as an absolute path: the file that the result replaces.
    pub(crate) file: Option<PathBuf>,
    /// The netf home, `~/.netf`, already created and checked.
    pub(crate) home: PathBuf,
    /// The absolute path of the cache directory. `~/.netf/cache` by
    /// default.
    pub(crate) cache_dir: PathBuf,
    /// `false` with `--no-cache` or `cache = false`. Then the run neither
    /// reads nor writes the cache.
    pub(crate) cache: bool,
    /// How long a cached dataset or response stays fresh. Zero revalidates
    /// everything.
    pub(crate) ttl: Duration,
    /// The proxies, as written. Empty for direct connections. The network
    /// layer checks them, because it knows which proxies it supports.
    pub(crate) proxies: Vec<String>,
    /// Concurrent requests to one server through one egress, at least 1.
    pub(crate) concurrency: usize,
    /// `--ripe-emails`: fetch the e-mail of RIPE persons.
    pub(crate) ripe_emails: bool,
    /// The DNS-over-HTTPS server, used only with proxies.
    pub(crate) doh: String,
    /// The URLs of the sources: the defaults, or those of `[sources]`.
    pub(crate) sources: Urls,
    /// The sets of both files, for `set:` in queries.
    pub(crate) sets: Sets,
    /// `-i`: the interactive tree.
    pub(crate) interactive: bool,
}

/// A named set of the config: a saved query and, optionally, its family.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct SetDef {
    /// The query of the set.
    pub(crate) query: String,
    /// The family from the `ipv4` and `ipv6` keys of the set, if the set has
    /// either key. The family applies only with `-s`. With `set:` in a
    /// query, the run keeps its own family.
    pub(crate) families: Option<Families>,
}

/// The sets of the config, by name.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub(crate) struct Sets(BTreeMap<String, SetDef>);

impl Sets {
    /// Returns the set `name`, if there is one.
    pub(crate) fn get(&self, name: &str) -> Option<&SetDef> {
        self.0.get(name)
    }

    /// Returns the query of the set `name`: the lookup that
    /// `query::expand` takes.
    pub(crate) fn query(&self, name: &str) -> Option<String> {
        self.get(name).map(|set| set.query.clone())
    }

    /// Returns the set names in sorted order.
    pub(crate) fn names(&self) -> impl Iterator<Item = &str> {
        self.0.keys().map(String::as_str)
    }
}

/// Builds the settings of a run.
///
/// The function prepares `~/.netf`, reads the base config, merges `-c` over
/// it, and applies the options of `cli`.
///
/// # Errors
///
/// Returns a runtime error (code 1) if `~/.netf` cannot be prepared or the
/// base config cannot be read. Returns a usage error (code 2) for what the
/// user has to fix: a missing `-c` file, bad TOML, an unknown key or value,
/// or a `-s` that names no set.
pub(crate) fn load(cli: &Cli, env: &Environment) -> Result<Settings> {
    let home = home::prepare(env)?;
    let base_path = home.join(home::CONFIG);
    let base_text = fs::read_to_string(&base_path)
        .map_err(|error| Error::runtime(format!("{}: {}", home::CONFIG_NAME, io_reason(&error))))?;
    let mut config = ConfigFile::parse(&base_text, home::CONFIG_NAME)?;
    if let Some(path) = &cli.config {
        let name = path.display().to_string();
        let text = fs::read_to_string(env.cwd.join(path))
            .map_err(|error| Error::usage(format!("-c {name}: {}", io_reason(&error))))?;
        config = config.merge(ConfigFile::parse(&text, &name)?);
    }
    resolve(cli, config, env, home)
}

/// Parses a duration: a number with the unit `s`, `m`, `h`, or `d`, or `0`
/// alone.
///
/// Examples of durations are `30m`, `12h`, and `7d`.
pub(crate) fn parse_duration(text: &str) -> Option<Duration> {
    if text == "0" {
        return Some(Duration::ZERO);
    }
    let unit = match text.chars().last()? {
        's' => 1,
        'm' => 60,
        'h' => 3600,
        'd' => 86_400,
        _ => return None,
    };
    let number = &text[..text.len() - 1];
    // `u64::from_str` accepts a leading `+`, but a duration does not.
    if number.is_empty() || !number.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let seconds = number.parse::<u64>().ok()?.checked_mul(unit)?;
    Some(Duration::from_secs(seconds))
}

/// The hint that follows a bad duration in an error.
pub(crate) const DURATION_HINT: &str = "expected a duration such as 30m, 12h, 7d, or 0";

/// Parses one name from `--fields` or from the `fields` key.
///
/// Accepts query fields under `as.*` and `net.*`, plus output-only names.
/// The route is already a column.
///
/// # Errors
///
/// Returns the reason if the name is empty, unknown, or already a column.
/// The caller prefixes the reason with the place that the name came from.
pub(crate) fn parse_field(name: &str) -> Result<Column, String> {
    match Column::parse(name) {
        Some(Column::Field(crate::query::Field::Route)) => Err(format!("{name}: already a column")),
        Some(field) => Ok(field),
        None if name.is_empty() => Err("empty field name".to_owned()),
        None => Err(format!("{name}: unknown field; see netf --help=fields")),
    }
}

/// Returns the text of an I/O error without the `(os error N)` suffix.
pub(crate) fn io_reason(error: &std::io::Error) -> String {
    let text = error.to_string();
    match text.find(" (os error ") {
        Some(at) => text[..at].to_owned(),
        None => text,
    }
}

/// One config file as written. Every key is optional.
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct ConfigFile {
    ttl: Option<Ttl>,
    cache_dir: Option<PathBuf>,
    cache: Option<bool>,
    limit: Option<usize>,
    proxies: Option<Vec<String>>,
    concurrency: Option<NonZeroUsize>,
    fields: Option<Vec<FieldName>>,
    ripe_emails: Option<bool>,
    doh: Option<String>,
    ipv4: Option<bool>,
    ipv6: Option<bool>,
    #[serde(default)]
    set: BTreeMap<String, SetFile>,
    /// `[sources]`: source URLs by source name. They replace the default
    /// URLs.
    #[serde(default)]
    sources: BTreeMap<String, String>,
}

/// `[set.NAME]` as written.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct SetFile {
    query: String,
    ipv4: Option<bool>,
    ipv6: Option<bool>,
}

impl ConfigFile {
    /// Parses the text of a config file.
    ///
    /// Messages call the file `name`.
    fn parse(text: &str, name: &str) -> Result<Self> {
        let config: Self = toml::from_str(text).map_err(|error| {
            let message = error.message().replace('\n', " ");
            match error.span() {
                Some(span) => {
                    let line = text[..span.start.min(text.len())].matches('\n').count() + 1;
                    Error::usage(format!("{name}: line {line}: {message}"))
                }
                None => Error::usage(format!("{name}: {message}")),
            }
        })?;
        if let Some(bad) = config.set.keys().find(|name| !valid_set_name(name)) {
            return Err(Error::usage(format!(
                "{name}: set {bad:?}: invalid name; use letters, digits, '-' and '_'"
            )));
        }
        let mut urls = Urls::default();
        for (source, url) in &config.sources {
            if !urls.set(source, url.clone()) {
                let names: Vec<&str> = Urls::names().collect();
                return Err(Error::usage(format!(
                    "{name}: sources.{source}: unknown source; sources: {}",
                    names.join(", ")
                )));
            }
            if !(url.starts_with("https://") || url.starts_with("http://")) {
                return Err(Error::usage(format!(
                    "{name}: sources.{source}: {url:?}: expected an http:// or https:// URL"
                )));
            }
        }
        Ok(config)
    }

    /// Merges `over` over `self`.
    ///
    /// Every key of `over` wins, and the sets and the sources merge by name.
    fn merge(mut self, over: Self) -> Self {
        let mut sets = std::mem::take(&mut self.set);
        sets.extend(over.set);
        let mut sources = std::mem::take(&mut self.sources);
        sources.extend(over.sources);
        Self {
            ttl: over.ttl.or(self.ttl),
            cache_dir: over.cache_dir.or(self.cache_dir),
            cache: over.cache.or(self.cache),
            limit: over.limit.or(self.limit),
            proxies: over.proxies.or(self.proxies),
            concurrency: over.concurrency.or(self.concurrency),
            fields: over.fields.or(self.fields),
            ripe_emails: over.ripe_emails.or(self.ripe_emails),
            doh: over.doh.or(self.doh),
            ipv4: over.ipv4.or(self.ipv4),
            ipv6: over.ipv6.or(self.ipv6),
            set: sets,
            sources,
        }
    }
}

/// Returns whether `name` is a valid set name.
///
/// A valid set name is a TOML bare key, so `set: NAME` is always a plain
/// query word.
fn valid_set_name(name: &str) -> bool {
    !name.is_empty()
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

/// Returns the family that the `ipv4` and `ipv6` keys give, or `None` if
/// both keys are missing.
///
/// The keys come from one level: a config file or a set. A missing key
/// counts as `false`. If both keys are `false`, the family is IPv4 alone.
fn families_of(ipv4: Option<bool>, ipv6: Option<bool>) -> Option<Families> {
    (ipv4.is_some() || ipv6.is_some())
        .then(|| Families::from_flags(ipv4.unwrap_or(false), ipv6.unwrap_or(false)))
}

/// Applies the options of `cli` over the merged `config`.
fn resolve(cli: &Cli, config: ConfigFile, env: &Environment, home: PathBuf) -> Result<Settings> {
    let sets = Sets(
        config
            .set
            .into_iter()
            .map(|(name, set)| {
                let families = families_of(set.ipv4, set.ipv6);
                (
                    name,
                    SetDef {
                        query: set.query,
                        families,
                    },
                )
            })
            .collect(),
    );

    let (query, set_families) = match (&cli.set, &cli.query) {
        (Some(name), _) => {
            let Some(set) = sets.get(name) else {
                let known: Vec<&str> = sets.names().collect();
                let hint = if known.is_empty() {
                    "the config has no sets".to_owned()
                } else {
                    format!("sets: {}", known.join(", "))
                };
                return Err(Error::usage(format!("-s {name}: no such set; {hint}")));
            };
            (format!("set: {name}"), set.families)
        }
        (None, Some(query)) => (query.clone(), None),
        // `cli::parse` never returns a run without one of them.
        (None, None) => return Err(Error::usage("no query; see netf --help")),
    };

    let families = if cli.v4 || cli.v6 {
        Families::from_flags(cli.v4, cli.v6)
    } else {
        set_families
            .or(families_of(config.ipv4, config.ipv6))
            .unwrap_or(Families::V4)
    };

    let mode = if cli.ipset || cli.set.is_some() {
        Mode::Ipset
    } else {
        let limit = cli.limit.or(config.limit).unwrap_or(DEFAULT_LIMIT);
        let fields = match cli.columns.as_ref().or(cli.fields.as_ref()) {
            Some(fields) => fields.clone(),
            None => config
                .fields
                .unwrap_or_default()
                .into_iter()
                .map(|FieldName(field)| field)
                .collect(),
        };
        Mode::Rows {
            limit: (limit != 0).then_some(limit),
            fields,
        }
    };

    let cache_dir = match cli.cache_dir.as_ref().or(config.cache_dir.as_ref()) {
        Some(dir) => env.cwd.join(dir),
        None => home.join(home::CACHE),
    };
    let proxies = if cli.proxies.is_empty() {
        config.proxies.unwrap_or_default()
    } else {
        cli.proxies.clone()
    };
    let mut sources = Urls::default();
    for (name, url) in config.sources {
        // `ConfigFile::parse` has already checked the names.
        sources.set(&name, url);
    }

    Ok(Settings {
        query,
        mode,
        families,
        file: cli.file.as_ref().map(|file| env.cwd.join(file)),
        cache_dir,
        cache: !cli.no_cache && config.cache.unwrap_or(true),
        ttl: cli
            .ttl
            .or(config.ttl.map(|Ttl(ttl)| ttl))
            .unwrap_or(DEFAULT_TTL),
        proxies,
        concurrency: cli
            .concurrency
            .or(config.concurrency.map(NonZeroUsize::get))
            .unwrap_or(DEFAULT_CONCURRENCY),
        ripe_emails: cli.ripe_emails || config.ripe_emails.unwrap_or(false),
        doh: cli
            .doh
            .clone()
            .or(config.doh)
            .unwrap_or_else(|| DEFAULT_DOH.to_owned()),
        sources,
        sets,
        interactive: cli.interactive,
        home,
    })
}

/// The `ttl` key: a duration string, or the integer `0`.
#[derive(Clone, Copy, Debug)]
struct Ttl(Duration);

impl<'de> Deserialize<'de> for Ttl {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct Visitor;

        impl de::Visitor<'_> for Visitor {
            type Value = Ttl;

            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("a duration such as \"30m\", \"12h\", \"7d\", or 0")
            }

            fn visit_str<E: de::Error>(self, text: &str) -> Result<Ttl, E> {
                parse_duration(text)
                    .map(Ttl)
                    .ok_or_else(|| E::custom(format!("ttl {text:?}: {DURATION_HINT}")))
            }

            fn visit_i64<E: de::Error>(self, number: i64) -> Result<Ttl, E> {
                if number == 0 {
                    Ok(Ttl(Duration::ZERO))
                } else {
                    Err(E::custom(format!(
                        "ttl {number}: a duration needs a unit: \"{number}h\"; {DURATION_HINT}"
                    )))
                }
            }
        }

        deserializer.deserialize_any(Visitor)
    }
}

/// An item of the `fields` key.
#[derive(Clone, Copy, Debug)]
struct FieldName(Column);

impl<'de> Deserialize<'de> for FieldName {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let name = String::deserialize(deserializer)?;
        parse_field(&name)
            .map(FieldName)
            .map_err(|reason| de::Error::custom(format!("fields: {reason}")))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::Role;
    use crate::query::Field;

    fn parse(text: &str) -> Result<ConfigFile> {
        ConfigFile::parse(text, "test.toml")
    }

    fn env() -> Environment {
        Environment {
            home: Some(PathBuf::from("/home/u")),
            cwd: PathBuf::from("/work"),
            ..Environment::default()
        }
    }

    fn cli(query: &str) -> Cli {
        Cli {
            query: Some(query.to_owned()),
            ..Cli::default()
        }
    }

    fn settings(cli: &Cli, config: &str) -> Result<Settings> {
        resolve(cli, parse(config)?, &env(), PathBuf::from("/home/u/.netf"))
    }

    #[test]
    fn durations() {
        assert_eq!(parse_duration("0"), Some(Duration::ZERO));
        assert_eq!(parse_duration("30m"), Some(Duration::from_secs(1800)));
        assert_eq!(parse_duration("12h"), Some(Duration::from_secs(43_200)));
        assert_eq!(parse_duration("7d"), Some(Duration::from_secs(604_800)));
        assert_eq!(parse_duration("45s"), Some(Duration::from_secs(45)));
        assert_eq!(parse_duration("0h"), Some(Duration::ZERO));
        for bad in [
            "", "h", "12", "+1h", "-1h", "1.5h", "1h30m", "12H", " 1h", "1w", "١h",
        ] {
            assert_eq!(parse_duration(bad), None, "{bad:?}");
        }
        assert_eq!(parse_duration("99999999999999999999d"), None);
        assert_eq!(parse_duration(&format!("{}d", u64::MAX / 2)), None);
    }

    #[test]
    fn fields() {
        assert_eq!(parse_field("net.org"), Ok(Field::NetOrg.into()));
        assert_eq!(
            parse_field("as.contact.abuse"),
            Ok(Field::AsContact(Some(Role::Abuse)).into())
        );
        assert_eq!(parse_field("route"), Err("route: already a column".into()));
        assert_eq!(
            parse_field("holder"),
            Err("holder: unknown field; see netf --help=fields".into())
        );
        assert!(parse_field("ip").is_err());
        assert_eq!(parse_field(""), Err("empty field name".into()));
    }

    #[test]
    fn io_reason_drops_the_os_code() {
        let error = std::io::Error::from_raw_os_error(2);
        assert!(!io_reason(&error).contains("os error"));
        assert_eq!(io_reason(&std::io::Error::other("boom")), "boom");
    }

    const FULL: &str = r#"
        ttl = "12h"
        cache_dir = "/tmp/netf-cache"
        cache = false
        limit = 0
        proxies = ["http://10.0.0.2:3128", "http://10.0.0.3:3128"]
        concurrency = 4
        fields = ["net.contact.administrative", "as.org"]
        ripe_emails = true
        doh = "https://dns.example/dns-query"
        ipv4 = true
        ipv6 = true

        [set.alpha]
        query = "as.asn: {domain: chat.example.test}"

        [set.vpn6]
        query = "set: alpha"
        ipv6  = true
    "#;

    #[test]
    fn every_key() {
        let s = settings(&cli("x"), FULL).unwrap();
        assert_eq!(s.ttl, Duration::from_secs(43_200));
        assert_eq!(s.cache_dir, PathBuf::from("/tmp/netf-cache"));
        assert!(!s.cache);
        assert_eq!(
            s.mode,
            Mode::Rows {
                limit: None,
                fields: vec![
                    Field::NetContact(Some(Role::Administrative)).into(),
                    Field::AsOrg.into()
                ],
            }
        );
        assert_eq!(s.proxies.len(), 2);
        assert_eq!(s.concurrency, 4);
        assert!(s.ripe_emails);
        assert_eq!(s.doh, "https://dns.example/dns-query");
        assert_eq!(s.families, Families::BOTH);
        assert_eq!(
            s.sets.query("alpha").as_deref(),
            Some("as.asn: {domain: chat.example.test}")
        );
        assert_eq!(s.sets.get("alpha").unwrap().families, None);
        assert_eq!(s.sets.get("vpn6").unwrap().families, Some(Families::V6));
        assert_eq!(s.sets.query("nope"), None);
    }

    #[test]
    fn options_win_over_the_config() {
        let cli = Cli {
            query: Some("x".into()),
            v4: true,
            ttl: Some(Duration::ZERO),
            cache_dir: Some(PathBuf::from("cache")),
            limit: Some(5),
            proxies: vec!["http://10.9.9.9:8080".into()],
            concurrency: Some(2),
            fields: Some(vec![Field::NetOrg.into()]),
            doh: Some("https://doh.example/q".into()),
            file: Some(PathBuf::from("out.txt")),
            ..Cli::default()
        };
        let s = settings(&cli, FULL).unwrap();
        assert_eq!(s.families, Families::V4);
        assert_eq!(s.ttl, Duration::ZERO);
        // Relative paths are resolved against the current directory.
        assert_eq!(s.cache_dir, PathBuf::from("/work/cache"));
        assert_eq!(s.file, Some(PathBuf::from("/work/out.txt")));
        assert_eq!(
            s.mode,
            Mode::Rows {
                limit: Some(5),
                fields: vec![Field::NetOrg.into()]
            }
        );
        assert_eq!(s.proxies, ["http://10.9.9.9:8080"]);
        assert_eq!(s.concurrency, 2);
        assert_eq!(s.doh, "https://doh.example/q");
    }

    #[test]
    fn family_precedence() {
        let set = |name: &str| Cli {
            set: Some(name.into()),
            ..Cli::default()
        };
        let config = r#"
            ipv4 = true
            ipv6 = true
            [set.plain]
            query = "ip: 192.0.2.1"
            [set.six]
            query = "ip: 192.0.2.1"
            ipv6 = true
        "#;
        // The config wins over the default.
        assert_eq!(
            settings(&cli("x"), config).unwrap().families,
            Families::BOTH
        );
        assert_eq!(
            settings(&cli("x"), "ipv6 = true").unwrap().families,
            Families::V6
        );
        assert_eq!(
            settings(&cli("x"), "ipv4 = false").unwrap().families,
            Families::V4
        );
        // The keys of a set win over the config, but only with `-s`.
        assert_eq!(
            settings(&set("six"), config).unwrap().families,
            Families::V6
        );
        assert_eq!(
            settings(&set("plain"), config).unwrap().families,
            Families::BOTH
        );
        assert_eq!(
            settings(&cli("set: six"), config).unwrap().families,
            Families::BOTH
        );
        // Flags win over everything.
        let flagged = Cli {
            v4: true,
            ..set("six")
        };
        assert_eq!(settings(&flagged, config).unwrap().families, Families::V4);
        let both = Cli {
            v4: true,
            v6: true,
            ..cli("x")
        };
        assert_eq!(settings(&both, "").unwrap().families, Families::BOTH);
    }

    #[test]
    fn set_option() {
        let config = "[set.vpn]\nquery = \"set: alpha\"\n";
        let cli = Cli {
            set: Some("vpn".into()),
            ..Cli::default()
        };
        let s = settings(&cli, config).unwrap();
        assert_eq!(s.query, "set: vpn");
        assert_eq!(s.mode, Mode::Ipset);

        let missing = Cli {
            set: Some("nope".into()),
            ..Cli::default()
        };
        assert_eq!(
            settings(&missing, config).unwrap_err().to_string(),
            "netf: -s nope: no such set; sets: vpn"
        );
        assert_eq!(
            settings(&missing, "").unwrap_err().to_string(),
            "netf: -s nope: no such set; the config has no sets"
        );
    }

    #[test]
    fn merge_replaces_keys_and_merges_sets() {
        let base = parse(
            r#"
            ttl = "7d"
            proxies = ["http://10.0.0.1:3128", "http://10.0.0.2:3128"]
            limit = 10
            [set.a]
            query = "ip: 192.0.2.1"
            [set.b]
            query = "ip: 192.0.2.2"
            ipv6 = true
        "#,
        )
        .unwrap();
        let over = parse(
            r#"
            proxies = ["http://10.0.0.9:3128"]
            [set.b]
            query = "ip: 198.51.100.1"
            [set.c]
            query = "set: a or set: b"
        "#,
        )
        .unwrap();
        let s = resolve(
            &cli("x"),
            base.merge(over),
            &env(),
            PathBuf::from("/h/.netf"),
        )
        .unwrap();
        assert_eq!(s.ttl, Duration::from_secs(7 * 86_400));
        assert_eq!(s.proxies, ["http://10.0.0.9:3128"]);
        assert_eq!(
            s.mode,
            Mode::Rows {
                limit: Some(10),
                fields: Vec::new()
            }
        );
        assert_eq!(s.sets.names().collect::<Vec<_>>(), ["a", "b", "c"]);
        // The set from `-c` replaces the base set whole, family keys
        // included.
        let b = s.sets.get("b").unwrap();
        assert_eq!(b.query, "ip: 198.51.100.1");
        assert_eq!(b.families, None);
    }

    #[test]
    fn sources_replace_the_defaults_by_name() {
        assert_eq!(settings(&cli("x"), "").unwrap().sources, Urls::default());
        let base =
            parse("[sources]\nris-v4 = \"https://ris.test/v4.gz\"\nasn = \"https://asn.test/a\"\n")
                .unwrap();
        let over = parse("[sources]\nasn = \"http://127.0.0.1:9/asn.txt\"\n").unwrap();
        let s = resolve(
            &cli("x"),
            base.merge(over),
            &env(),
            PathBuf::from("/h/.netf"),
        )
        .unwrap();
        let mut expected = Urls::default();
        expected.set("ris-v4", "https://ris.test/v4.gz".to_owned());
        expected.set("asn", "http://127.0.0.1:9/asn.txt".to_owned());
        assert_eq!(s.sources, expected);
        let unknown = error("[sources]\nris = \"https://ris.test/\"\n");
        assert!(
            unknown.starts_with("netf: test.toml: sources.ris: unknown source; sources: ris-v4, "),
            "{unknown}"
        );
        assert!(unknown.ends_with(", ripe-rest"), "{unknown}");
        assert_eq!(
            error("[sources]\nripe-rest = \"ftp://rest.test\"\n"),
            "netf: test.toml: sources.ripe-rest: \"ftp://rest.test\": expected an http:// or \
             https:// URL"
        );
        assert!(error("[sources]\nasn = 1\n").contains("line 2"));
    }

    fn error(text: &str) -> String {
        parse(text).unwrap_err().to_string()
    }

    #[test]
    fn strict_parsing() {
        let unknown = error("ttl = \"1h\"\ncach = false\n");
        assert!(
            unknown.starts_with("netf: test.toml: line 2: unknown field `cach`"),
            "{unknown}"
        );
        let in_set = error("[set.a]\nquery = \"x\"\noutput = \"/tmp/a\"\n");
        assert!(
            in_set.starts_with("netf: test.toml: line 3: unknown field `output`"),
            "{in_set}"
        );
        assert!(error("[set.a]\nipv6 = true\n").contains("missing field `query`"));
        assert!(error("limit = \"ten\"").starts_with("netf: test.toml: line 1: "));
        assert!(error("limit = -1").contains("line 1"));
        assert!(error("concurrency = 0").contains("line 1"));
        assert!(error("cache = 1").contains("line 1"));
        assert!(error("proxies = \"http://a:1\"").contains("line 1"));
        assert!(error("ttl = ").starts_with("netf: test.toml: line 1: "));
        assert_eq!(
            error("[set.\"my set\"]\nquery = \"x\"\n"),
            "netf: test.toml: set \"my set\": invalid name; use letters, digits, '-' and '_'"
        );
        // A dotted name is a nested table, not a set.
        assert!(error("[set.a.b]\nquery = \"x\"\n").contains("unknown field `b`"));
    }

    #[test]
    fn ttl_and_fields_keys() {
        assert_eq!(settings(&cli("x"), "ttl = 0").unwrap().ttl, Duration::ZERO);
        assert_eq!(
            settings(&cli("x"), "ttl = \"0\"").unwrap().ttl,
            Duration::ZERO
        );
        let bad = error("\nttl = \"5x\"");
        assert!(
            bad.starts_with("netf: test.toml: line 2: ttl \"5x\": expected a duration"),
            "{bad}"
        );
        let no_unit = error("ttl = 12");
        assert!(no_unit.contains("a duration needs a unit"), "{no_unit}");
        let field = error("fields = [\"net.org\", \"holder\"]");
        assert!(
            field.starts_with("netf: test.toml: line 1: fields: holder: unknown field"),
            "{field}"
        );
    }
}
