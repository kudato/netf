//! The IANA RDAP bootstrap files for AS, IPv4, and IPv6. They tell which
//! registry serves a number or an address.
//!
//! Each file (RFC 9224) is a dataset of the cache, such as
//! `bootstrap-asn.bin`, with the same TTL and revalidation as every other
//! dataset. With `--no-cache`, netf downloads each file once per run. A
//! file loads on the first question that it answers. The cache keeps only
//! the services, as compact JSON in section 1. A file without a single
//! usable service is an error, not a dataset.
//!
//! A service is a list of keys and the base URLs of its server. The keys
//! are AS numbers such as `64496-64499` or `64510`, or CIDR blocks for
//! addresses. netf takes the first `https` URL, or the first `http` URL if
//! there is no `https` one. An address goes to the longest block that holds
//! it. A number goes to the range that holds it. The host of the base URL
//! names the registry: `rdap.db.ripe.net` is `ripencc`. A host that belongs
//! to none of the five keeps its own name in messages.

use std::sync::Arc;

use serde::{Deserialize, Serialize};
use serde_json::Value;
use tokio::sync::OnceCell;

use crate::{
    addr::{Family, Prefix, Range},
    cache::{
        Builder, Cache, CacheFile, Entry,
        container::{Corrupt, Section},
    },
    dataset::{Kind, Urls},
    error::{Error, Result},
    fetch::{
        self, JSON_LIMIT,
        lines::{Control, LineSink},
    },
    model::{Asn, Rir},
    sources,
    transport::{Class, Transport},
};

/// The section with the services.
const SERVICES: u16 = 1;

/// An RDAP server of the bootstrap.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct Server {
    /// The base URL for requests, after `NETF_SOURCE_BASE`. The URL ends in
    /// `/`, so a request is `<base>ip/192.0.2.0/24`.
    pub(crate) base: String,
    /// The name in messages: `arin`, or the host.
    pub(crate) name: Arc<str>,
    /// The registry, if the host is one of the five.
    pub(crate) rir: Option<Rir>,
}

/// One service as stored: its keys and its base URL, before
/// `NETF_SOURCE_BASE`.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
struct Service {
    keys: Vec<String>,
    url: String,
}

/// The lookup tables of one file.
#[derive(Debug, Default)]
struct Directory {
    /// AS ranges, first and last number included.
    asns: Vec<(Asn, Asn, Arc<Server>)>,
    /// Address blocks.
    blocks: Vec<(Prefix, Arc<Server>)>,
}

/// The three bootstrap files of one run, loaded on first use.
pub(crate) struct Bootstrap {
    transport: Arc<dyn Transport>,
    cache: Option<Cache>,
    base: Option<String>,
    urls: Urls,
    asn: OnceCell<Directory>,
    ipv4: OnceCell<Directory>,
    ipv6: OnceCell<Directory>,
}

impl Bootstrap {
    /// Creates the bootstrap that downloads through `transport` and keeps
    /// the files in `cache`, if there is one.
    ///
    /// The file URLs come from `urls`, rewritten with `base`.
    pub(crate) fn new(
        transport: Arc<dyn Transport>,
        cache: Option<Cache>,
        base: Option<String>,
        urls: Urls,
    ) -> Self {
        Self {
            transport,
            cache,
            base,
            urls,
            asn: OnceCell::new(),
            ipv4: OnceCell::new(),
            ipv6: OnceCell::new(),
        }
    }

    /// Returns the server of the longest block that holds all of `range`,
    /// or `None` if no registry serves the range.
    ///
    /// # Errors
    ///
    /// Returns an error if the bootstrap file cannot be downloaded or read from
    /// the cache, or has no usable service.
    pub(crate) async fn for_range(&self, range: &Range) -> Result<Option<Arc<Server>>> {
        let kind = match range.family() {
            Family::V4 => Kind::BootstrapIpv4,
            Family::V6 => Kind::BootstrapIpv6,
        };
        let directory = self.directory(kind).await?;
        Ok(directory
            .blocks
            .iter()
            .filter(|(prefix, _)| prefix.range().contains(range))
            .max_by_key(|(prefix, _)| prefix.len())
            .map(|(_, server)| Arc::clone(server)))
    }

    /// Returns the server for AS `asn`, or `None` if no registry serves it.
    ///
    /// # Errors
    ///
    /// Returns an error if the bootstrap file cannot be downloaded or read from
    /// the cache, or has no usable service.
    pub(crate) async fn for_asn(&self, asn: Asn) -> Result<Option<Arc<Server>>> {
        let directory = self.directory(Kind::BootstrapAsn).await?;
        Ok(directory
            .asns
            .iter()
            .find(|(first, last, _)| (*first..=*last).contains(&asn))
            .map(|(_, _, server)| Arc::clone(server)))
    }

    /// Returns the server of `rir`, or `None` if no service belongs to
    /// `rir`.
    ///
    /// The server is that of the first service of `rir` in the AS file,
    /// then in the IPv4 file, then in the IPv6 file.
    ///
    /// # Errors
    ///
    /// Returns an error if a bootstrap file cannot be downloaded or read from
    /// the cache, or has no usable service.
    pub(crate) async fn for_rir(&self, rir: Rir) -> Result<Option<Arc<Server>>> {
        for kind in [Kind::BootstrapAsn, Kind::BootstrapIpv4, Kind::BootstrapIpv6] {
            let directory = self.directory(kind).await?;
            let servers = directory
                .asns
                .iter()
                .map(|(_, _, server)| server)
                .chain(directory.blocks.iter().map(|(_, server)| server));
            if let Some(server) = servers.into_iter().find(|s| s.rir == Some(rir)) {
                return Ok(Some(Arc::clone(server)));
            }
        }
        Ok(None)
    }

    /// Returns the lookup tables of the file `kind`, loaded once per run.
    async fn directory(&self, kind: Kind) -> Result<&Directory> {
        let cell = match kind {
            Kind::BootstrapAsn => &self.asn,
            Kind::BootstrapIpv4 => &self.ipv4,
            _ => &self.ipv6,
        };
        cell.get_or_try_init(|| self.load(kind)).await
    }

    async fn load(&self, kind: Kind) -> Result<Directory> {
        let source = kind.source();
        let url = sources::rewrite(self.base.as_deref(), self.urls.of(kind));
        let services = match &self.cache {
            Some(cache) => {
                let entry = Entry {
                    name: source.file,
                    kind: kind.code(),
                    url: &url,
                };
                cache
                    .load(
                        &*self.transport,
                        &entry,
                        || Collector::new(kind),
                        |file| open(&file),
                    )
                    .await?
            }
            None => {
                let (status, value) =
                    fetch::json(&*self.transport, &url, Class::Dataset(source.file)).await?;
                if !(200..300).contains(&status) {
                    return Err(Error::runtime(format!("HTTP {status}"))
                        .with_prefix(format_args!("{}: {url}", source.file)));
                }
                services(kind, &value)
                    .map_err(|error| error.with_prefix(format_args!("{}: {url}", source.file)))?
            }
        };
        Ok(self.directory_of(kind, &services))
    }

    /// Builds the lookup tables of `services`.
    ///
    /// Keys that do not parse are skipped. In practice there are none,
    /// because [`services`] keeps only valid keys.
    fn directory_of(&self, kind: Kind, services: &[Service]) -> Directory {
        let mut directory = Directory::default();
        for service in services {
            let server = Arc::new(server(self.base.as_deref(), &service.url));
            for key in &service.keys {
                if kind == Kind::BootstrapAsn {
                    if let Some((first, last)) = asn_range(key) {
                        directory.asns.push((first, last, Arc::clone(&server)));
                    }
                } else if let Ok(prefix) = key.parse::<Prefix>() {
                    directory.blocks.push((prefix, Arc::clone(&server)));
                }
            }
        }
        directory
    }
}

/// Returns the server at the bootstrap URL `url`.
fn server(base: Option<&str>, url: &str) -> Server {
    let (fetch, host) = route(base, url);
    let rir = rir_of_host(&host);
    let name = rir.map_or_else(|| Arc::from(host.as_str()), |rir| Arc::from(rir.name()));
    let mut base = fetch;
    if !base.ends_with('/') {
        base.push('/');
    }
    Server { base, name, rir }
}

/// Returns the URL to send for the registry URL `url`, and the host of the
/// registry.
///
/// A URL already under `base`, such as a test fixture written for the base,
/// is sent as is. The registry host is then the first segment after the
/// base.
pub(crate) fn route(base: Option<&str>, url: &str) -> (String, String) {
    if let Some(base) = base {
        let base = base.trim_end_matches('/');
        if let Some(rest) = url.strip_prefix(base).and_then(|r| r.strip_prefix('/')) {
            let host = rest.split(['/', '?', '#']).next().unwrap_or("");
            return (url.to_owned(), host_only(host));
        }
    }
    let rest = url.split_once("://").map_or(url, |(_, rest)| rest);
    let authority = rest.split(['/', '?', '#']).next().unwrap_or("");
    (sources::rewrite(base, url), host_only(authority))
}

/// Returns the host of an authority, without the user and the port, in
/// lowercase.
fn host_only(authority: &str) -> String {
    let host = authority.rsplit('@').next().unwrap_or(authority);
    let host = match host.strip_prefix('[') {
        Some(v6) => v6.split(']').next().unwrap_or(v6),
        None => host.split(':').next().unwrap_or(host),
    };
    host.to_ascii_lowercase()
}

/// Returns the registry whose RDAP server is at `host`.
///
/// A label of `host` names the registry, as in `rdap.db.ripe.net`,
/// `rdap.arin.net`, or `rdap.lacnic.test`.
pub(crate) fn rir_of_host(host: &str) -> Option<Rir> {
    host.split('.').find_map(|label| match label {
        "ripe" | "ripencc" => Some(Rir::Ripencc),
        "arin" => Some(Rir::Arin),
        "apnic" => Some(Rir::Apnic),
        "lacnic" => Some(Rir::Lacnic),
        "afrinic" => Some(Rir::Afrinic),
        _ => None,
    })
}

/// Parses an AS key: `64496-64511` or `64496`.
fn asn_range(key: &str) -> Option<(Asn, Asn)> {
    let (first, last) = key.split_once('-').unwrap_or((key, key));
    let first = first.trim().parse().ok()?;
    let last = last.trim().parse().ok()?;
    (first <= last).then_some((first, last))
}

/// Returns `true` if `key` is a valid key for a file of `kind`.
///
/// An address key must belong to the address family of the file.
fn valid_key(kind: Kind, key: &str) -> bool {
    match kind {
        Kind::BootstrapAsn => asn_range(key).is_some(),
        _ => key.parse::<Prefix>().is_ok_and(|prefix| {
            (prefix.range().family() == Family::V4) == (kind == Kind::BootstrapIpv4)
        }),
    }
}

/// Returns the usable services of a bootstrap file of `kind`.
///
/// A file without a usable service is an error.
fn services(kind: Kind, value: &Value) -> Result<Vec<Service>> {
    let mut out = Vec::new();
    for service in value
        .get("services")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        let Some([keys, urls, ..]) = service.as_array().map(Vec::as_slice) else {
            continue;
        };
        let keys: Vec<String> = keys
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(Value::as_str)
            .filter(|key| valid_key(kind, key))
            .map(str::to_owned)
            .collect();
        let urls: Vec<&str> = urls
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(Value::as_str)
            .collect();
        let url = urls
            .iter()
            .find(|url| url.starts_with("https://"))
            .or_else(|| urls.iter().find(|url| url.starts_with("http://")));
        if let Some(url) = url
            && !keys.is_empty()
        {
            out.push(Service {
                keys,
                url: (*url).to_owned(),
            });
        }
    }
    if out.is_empty() {
        return Err(Error::runtime("not an RDAP bootstrap file: no services"));
    }
    Ok(out)
}

/// Opens a cached bootstrap file.
fn open(file: &CacheFile) -> Result<Vec<Service>, Corrupt> {
    let services: Vec<Service> =
        serde_json::from_slice(file.section(SERVICES)?).map_err(|_| Corrupt)?;
    if services.is_empty() {
        return Err(Corrupt);
    }
    Ok(services)
}

/// Collects the body of a bootstrap file for the cache.
struct Collector {
    kind: Kind,
    body: Vec<u8>,
}

impl Collector {
    fn new(kind: Kind) -> Self {
        Self {
            kind,
            body: Vec::new(),
        }
    }
}

impl LineSink for Collector {
    fn line(&mut self, line: &[u8]) -> Result<Control> {
        if self.body.len() + line.len() >= JSON_LIMIT {
            return Err(Error::runtime("the file is too large"));
        }
        self.body.extend_from_slice(line);
        self.body.push(b'\n');
        Ok(Control::Continue)
    }
}

impl Builder for Collector {
    fn finish(self) -> Result<Vec<Section>> {
        let value: Value = serde_json::from_slice(&self.body)
            .map_err(|error| Error::runtime(format!("invalid JSON: {error}")))?;
        let services = services(self.kind, &value)?;
        let json = serde_json::to_vec(&services).expect("services serialize");
        Ok(vec![Section::new(SERVICES, json)])
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use std::time::Duration;

    use super::*;
    use crate::fetch::testing::{Collect, FakeClock, Reply, Stub, TempDir};

    /// A bootstrap file for AS numbers with fictional servers.
    pub(crate) const ASN: &str = r#"{"version":"1.0","services":[
        [["64496-64499"],["http://rdap.arin.test/registry/","https://rdap.arin.test/registry/"]],
        [["64500-64502","64503"],["https://rdap.db.ripe.test/"]],
        [["64504-64505"],["https://rdap.apnic.test/"]],
        [["64506-64507"],["https://rdap.lacnic.test/rdap/"]],
        [["64508-64509"],["https://rdap.afrinic.test/rdap/"]],
        [["bad"],["https://rdap.nowhere.test/"]]
    ]}"#;

    /// A bootstrap file for IPv4.
    pub(crate) const IPV4: &str = r#"{"version":"1.0","services":[
        [["198.18.0.0/16"],["https://rdap.arin.test/registry/"]],
        [["192.0.2.0/24","198.18.2.0/24"],["https://rdap.db.ripe.test/"]],
        [["198.51.100.0/24"],["https://rdap.apnic.test/"]],
        [["203.0.113.0/24"],["https://rdap.lacnic.test/rdap/"]],
        [["198.19.0.0/16"],["https://rdap.afrinic.test/rdap/"]],
        [["2001:db8::/32"],["https://rdap.wrong.test/"]]
    ]}"#;

    /// A bootstrap file for IPv6.
    pub(crate) const IPV6: &str = r#"{"version":"1.0","services":[
        [["2001:db8::/32"],["https://rdap.db.ripe.test/"]],
        [["2001:db8:8000::/33"],["https://registry.example.test/rdap"]]
    ]}"#;

    /// Queues the three files on `stub` at their URLs without a base.
    pub(crate) fn serve(stub: &Stub) {
        stub.on("https://data.iana.test/rdap/asn.json", Reply::ok(ASN));
        stub.on("https://data.iana.test/rdap/ipv4.json", Reply::ok(IPV4));
        stub.on("https://data.iana.test/rdap/ipv6.json", Reply::ok(IPV6));
    }

    fn range(text: &str) -> Range {
        text.parse().unwrap()
    }

    #[tokio::test]
    async fn picks_the_server_by_number_and_longest_block() {
        let stub = Arc::new(Stub::new());
        serve(&stub);
        let bootstrap = Bootstrap::new(stub.clone(), None, None, Urls::test());
        let server = bootstrap.for_asn(64496).await.unwrap().unwrap();
        assert_eq!(server.base, "https://rdap.arin.test/registry/");
        assert_eq!(&*server.name, "arin");
        assert_eq!(server.rir, Some(Rir::Arin));
        let ripe = bootstrap.for_asn(64503).await.unwrap().unwrap();
        assert_eq!((&*ripe.name, ripe.rir), ("ripencc", Some(Rir::Ripencc)));
        assert_eq!(bootstrap.for_asn(64510).await.unwrap(), None);
        // A range in the RIPE /24 goes to RIPE, although the ARIN /16 also
        // holds the range.
        let net = bootstrap
            .for_range(&range("198.18.2.128/25"))
            .await
            .unwrap();
        assert_eq!(net.unwrap().rir, Some(Rir::Ripencc));
        let net = bootstrap.for_range(&range("198.18.3.0/24")).await.unwrap();
        assert_eq!(net.unwrap().rir, Some(Rir::Arin));
        // A range across two blocks goes to the block that holds all of it.
        let net = bootstrap
            .for_range(&range("198.18.2.0-198.18.3.255"))
            .await
            .unwrap();
        assert_eq!(net.unwrap().rir, Some(Rir::Arin));
        assert_eq!(
            bootstrap.for_range(&range("10.0.0.0/8")).await.unwrap(),
            None
        );
        let v6 = bootstrap
            .for_range(&range("2001:db8:8000::/48"))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(v6.base, "https://registry.example.test/rdap/");
        assert_eq!((&*v6.name, v6.rir), ("registry.example.test", None));
        assert_eq!(
            bootstrap.for_rir(Rir::Afrinic).await.unwrap().unwrap().base,
            "https://rdap.afrinic.test/rdap/"
        );
        // Each file is downloaded once.
        assert_eq!(stub.count(), 3);
    }

    #[tokio::test]
    async fn uses_the_cache_and_the_base() {
        let dir = TempDir::new("rdap-bootstrap-cache");
        let base = "http://127.0.0.1:9";
        let stub = Arc::new(Stub::new());
        stub.on(
            "http://127.0.0.1:9/data.iana.test/rdap/asn.json",
            Reply::ok(ASN),
        );
        let cache = || {
            Cache::new(
                dir.path().to_owned(),
                Duration::from_secs(3600),
                Arc::new(FakeClock::new()),
                Arc::new(Collect::default()),
            )
        };
        let bootstrap = Bootstrap::new(
            stub.clone(),
            Some(cache()),
            Some(base.to_owned()),
            Urls::test(),
        );
        let server = bootstrap.for_asn(64506).await.unwrap().unwrap();
        assert_eq!(server.base, "http://127.0.0.1:9/rdap.lacnic.test/rdap/");
        assert_eq!(&*server.name, "lacnic");
        assert!(dir.path().join("bootstrap-asn.bin").exists());
        // The next run reads the cached file.
        let again = Bootstrap::new(
            stub.clone(),
            Some(cache()),
            Some(base.to_owned()),
            Urls::test(),
        );
        assert_eq!(again.for_asn(64506).await.unwrap(), Some(server));
        assert_eq!(stub.count(), 1);
    }

    #[tokio::test]
    async fn a_file_without_services_is_an_error() {
        let stub = Arc::new(Stub::new());
        stub.on(
            "https://data.iana.test/rdap/asn.json",
            Reply::ok(r#"{"services":[]}"#),
        );
        stub.on("https://data.iana.test/rdap/asn.json", Reply::status(503));
        let bootstrap = Bootstrap::new(stub.clone(), None, None, Urls::test());
        let error = bootstrap.for_asn(64496).await.unwrap_err();
        assert_eq!(
            error.message(),
            "bootstrap-asn: https://data.iana.test/rdap/asn.json: not an RDAP bootstrap file: no services"
        );
        // The bootstrap does not remember a failure. The next question
        // tries again.
        let error = bootstrap.for_asn(64496).await.unwrap_err();
        assert_eq!(
            error.message(),
            "bootstrap-asn: https://data.iana.test/rdap/asn.json: HTTP 503"
        );
    }

    #[test]
    fn hosts_and_routes() {
        assert_eq!(rir_of_host("rdap.db.ripe.test"), Some(Rir::Ripencc));
        assert_eq!(rir_of_host("rdap.arin.test"), Some(Rir::Arin));
        assert_eq!(rir_of_host("rdap.registro.test"), None);
        assert_eq!(
            route(None, "https://rdap.apnic.test/ip/192.0.2.0/24"),
            (
                "https://rdap.apnic.test/ip/192.0.2.0/24".to_owned(),
                "rdap.apnic.test".to_owned()
            )
        );
        let base = Some("http://127.0.0.1:8080/");
        assert_eq!(
            route(base, "https://user@rdap.arin.test:443/registry/"),
            (
                "http://127.0.0.1:8080/user@rdap.arin.test:443/registry/".to_owned(),
                "rdap.arin.test".to_owned()
            )
        );
        assert_eq!(
            route(
                base,
                "http://127.0.0.1:8080/rdap.lacnic.test/rdap/ip/203.0.113.0"
            ),
            (
                "http://127.0.0.1:8080/rdap.lacnic.test/rdap/ip/203.0.113.0".to_owned(),
                "rdap.lacnic.test".to_owned()
            )
        );
        assert_eq!(asn_range("64496"), Some((64496, 64496)));
        assert_eq!(asn_range("64511-64496"), None);
    }
}
