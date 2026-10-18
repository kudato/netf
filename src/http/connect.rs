//! Connectors: direct HTTPS, or HTTPS through an HTTP `CONNECT` tunnel with
//! `Proxy-Authorization` from the proxy URL.
//!
//! ```text
//! Direct: HttpsConnector<HttpConnector>            TCP → TLS (if https)
//! Proxy:  HttpsConnector<Tunnel<HttpConnector>>    TCP to the proxy → CONNECT host:port → TLS
//! ```
//!
//! Through a proxy, the name of the server goes out in the `CONNECT` line,
//! and the proxy resolves it, so the local resolver sees only the host of
//! the proxy. netf accepts only `http://` proxies with an explicit port. An
//! `https://` proxy, a SOCKS proxy, or a missing port is a usage error.
//!
//! Both connectors are `https_or_http`, because every source URL is `https`
//! but the stub server of the tests is plain `http`.

use std::{error::Error as StdError, fmt, io, sync::Arc, time::Duration};

use http::{HeaderValue, Uri, uri::Scheme};
use hyper_rustls::HttpsConnector;
use hyper_util::client::legacy::connect::{HttpConnector, proxy::Tunnel};

use super::tls;
use crate::transport::{EgressId, TransportError};

/// The connector of the direct egress.
pub(crate) type DirectConnector = HttpsConnector<HttpConnector>;

/// The connector of a proxy egress.
pub(crate) type ProxyConnector = HttpsConnector<Tunnel<HttpConnector>>;

/// A `--proxy` URL that netf cannot use: a usage error, exit code 2.
///
/// [`Display`](fmt::Display) gives the message without the `netf: ` prefix:
/// `--proxy socks5://10.0.0.2:1080: unsupported proxy scheme, only http://
/// is supported`. The message replaces the entire userinfo with `***`,
/// or omits the URL if it cannot be safely redacted.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProxyError {
    url: Option<String>,
    reason: &'static str,
}

impl fmt::Display for ProxyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("--proxy")?;
        if let Some(url) = &self.url {
            write!(f, " {url}")?;
        }
        write!(f, ": {}", self.reason)
    }
}

impl std::error::Error for ProxyError {}

/// A parsed proxy URL.
#[derive(Clone, Debug)]
pub(crate) struct ProxyUrl {
    /// `http://host:port`, without credentials. It names the egress in
    /// messages and in the RIPE limit counter, which is stored on disk.
    pub(crate) id: EgressId,
    /// Where the TCP connection goes.
    pub(crate) uri: Uri,
    /// The `Proxy-Authorization` value, from `user:pass@`.
    pub(crate) authorization: Option<HeaderValue>,
}

/// Parses `http://[user[:pass]@]host:port[/]`.
///
/// The user and the password may be percent-encoded, so that they can
/// contain `@` and `:`.
///
/// # Errors
///
/// Returns a [`ProxyError`] that names the problem: the scheme, the host,
/// the port, a path, or the credentials.
pub(crate) fn parse_proxy(url: &str) -> Result<ProxyUrl, ProxyError> {
    let error = |reason| ProxyError {
        url: mask_credentials(url),
        reason,
    };
    let Some((scheme, rest)) = url.split_once("://") else {
        return Err(error("not a URL, expected http://host:port"));
    };
    if !scheme.eq_ignore_ascii_case("http") {
        return Err(error("unsupported proxy scheme, only http:// is supported"));
    }
    let authority = rest.strip_suffix('/').unwrap_or(rest);
    if authority.contains(['/', '?', '#']) {
        return Err(error("a proxy URL has no path"));
    }
    let (userinfo, host_port) = match authority.rsplit_once('@') {
        Some((userinfo, host_port)) => (Some(userinfo), host_port),
        None => (None, authority),
    };
    let (host, port) = match host_port.rsplit_once(':') {
        // `[::1]` alone splits inside the brackets.
        Some((host, port)) if !port.contains(']') => (host, port),
        _ => return Err(error("missing port")),
    };
    if host.is_empty() {
        return Err(error("missing host"));
    }
    if !port.bytes().all(|b| b.is_ascii_digit()) || !matches!(port.parse::<u16>(), Ok(1..)) {
        return Err(error("invalid port"));
    }
    let host_port = host_port.to_ascii_lowercase();
    let uri: Uri = format!("http://{host_port}")
        .parse()
        .map_err(|_| error("invalid host"))?;

    let authorization = match userinfo {
        None => None,
        Some(userinfo) => {
            let decoded = percent_decode(userinfo).ok_or_else(|| error("invalid credentials"))?;
            let credentials = if decoded.contains(':') {
                decoded
            } else {
                // A user without a password.
                format!("{decoded}:")
            };
            let mut value =
                HeaderValue::try_from(format!("Basic {}", base64(credentials.as_bytes())))
                    .map_err(|_| error("invalid credentials"))?;
            value.set_sensitive(true);
            Some(value)
        }
    };
    Ok(ProxyUrl {
        id: EgressId(Arc::from(format!("http://{host_port}"))),
        uri,
        authorization,
    })
}

/// Replaces all userinfo with `***` before the URL enters an error.
/// Omits URLs that cannot be parsed even after redaction.
fn mask_credentials(url: &str) -> Option<String> {
    let (scheme, rest) = url.split_once("://")?;
    scheme.parse::<Scheme>().ok()?;
    // A malformed password can contain '/', '?' or '#', so find the last
    // '@' before trying to parse the URL. Hiding all userinfo also handles
    // a percent-encoded ':' without decoding or retaining credentials.
    let masked = match rest.rsplit_once('@') {
        Some((_, host)) => format!("{scheme}://***@{host}"),
        None => url.to_owned(),
    };
    masked.parse::<Uri>().ok()?;
    Some(masked)
}

/// Decodes `%XX` escapes.
///
/// Returns `None` on a broken escape or on invalid UTF-8.
fn percent_decode(text: &str) -> Option<String> {
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' {
            let hex = text.get(i + 1..i + 3)?;
            out.push(u8::from_str_radix(hex, 16).ok()?);
            i += 3;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    String::from_utf8(out).ok()
}

/// Encodes bytes in standard base64 with padding, as RFC 4648 defines it.
///
/// The `Basic` credentials of `Proxy-Authorization` use this encoding.
pub(crate) fn base64(input: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(input.len().div_ceil(3) * 4);
    for chunk in input.chunks(3) {
        let b = [
            chunk[0],
            *chunk.get(1).unwrap_or(&0),
            *chunk.get(2).unwrap_or(&0),
        ];
        let n = u32::from(b[0]) << 16 | u32::from(b[1]) << 8 | u32::from(b[2]);
        for (i, shift) in [18, 12, 6, 0].into_iter().enumerate() {
            if i <= chunk.len() {
                out.push(char::from(ALPHABET[(n >> shift & 0x3F) as usize]));
            } else {
                out.push('=');
            }
        }
    }
    out
}

/// The TCP connector under both kinds of egress.
fn tcp(connect_timeout: Duration) -> HttpConnector {
    let mut connector = HttpConnector::new();
    // The TLS layer above handles `https`, so this layer must let it pass.
    connector.enforce_http(false);
    connector.set_nodelay(true);
    connector.set_connect_timeout(Some(connect_timeout));
    connector
}

/// Builds the connector of the direct egress.
pub(crate) fn direct(connect_timeout: Duration) -> DirectConnector {
    HttpsConnector::from((tcp(connect_timeout), tls::config()))
}

/// Builds the connector of a proxy egress: TCP to the proxy, `CONNECT`,
/// then TLS to the server through the tunnel.
pub(crate) fn proxy(proxy: &ProxyUrl, connect_timeout: Duration) -> ProxyConnector {
    let mut tunnel = Tunnel::new(proxy.uri.clone(), tcp(connect_timeout));
    if let Some(authorization) = &proxy.authorization {
        tunnel = tunnel.with_auth(authorization.clone());
    }
    HttpsConnector::from((tunnel, tls::config()))
}

/// Turns an error of the hyper client into a [`TransportError`].
///
/// `proxy` is the egress if the egress is a proxy. A failure to set up the
/// connection is then a [`TransportError::Proxy`], because netf connects
/// only to the proxy.
pub(crate) fn classify(
    error: &hyper_util::client::legacy::Error,
    proxy: Option<&EgressId>,
) -> TransportError {
    let mut io_error: Option<&io::Error> = None;
    let mut tunnel = None;
    let mut dns = false;
    let mut innermost = error.to_string();
    let mut current: Option<&(dyn StdError + 'static)> = Some(error);
    while let Some(e) = current {
        if io_error.is_none() {
            io_error = e.downcast_ref::<io::Error>();
        }
        let text = e.to_string();
        if let Some(rest) = text.strip_prefix("tunnel error: ") {
            tunnel.get_or_insert_with(|| rest.to_owned());
        }
        dns |= text.starts_with("dns error");
        innermost = text;
        current = e.source();
    }

    if io_error.is_some_and(|e| e.kind() == io::ErrorKind::TimedOut) {
        return TransportError::Timeout("connect");
    }
    let cause = if dns {
        "cannot resolve the host".to_owned()
    } else if let Some(e) = io_error {
        describe_io(e)
    } else if let Some(tunnel) = tunnel {
        match tunnel.as_str() {
            "unsuccessful" => "CONNECT refused".to_owned(),
            _ => tunnel,
        }
    } else {
        innermost
    };
    match (error.is_connect(), proxy) {
        (true, Some(proxy)) => TransportError::Proxy(format!("{proxy}: {cause}")),
        (true, None) => TransportError::Connect(cause),
        (false, _) => TransportError::Io(cause),
    }
}

/// Describes an I/O error as messages show it, such as `connection
/// refused`, without the OS error number.
pub(crate) fn describe_io(error: &io::Error) -> String {
    match error.kind() {
        io::ErrorKind::ConnectionRefused => "connection refused".to_owned(),
        io::ErrorKind::ConnectionReset => "connection reset".to_owned(),
        io::ErrorKind::ConnectionAborted => "connection aborted".to_owned(),
        io::ErrorKind::UnexpectedEof => "connection closed".to_owned(),
        _ => describe(&error.to_string()),
    }
}

/// Cleans an error text for messages.
///
/// Removes `(os error N)` and makes the first letter lowercase.
pub(crate) fn describe(text: &str) -> String {
    let text = match text.find(" (os error") {
        Some(at) => &text[..at],
        None => text,
    };
    let mut chars = text.chars();
    match chars.next() {
        Some(first) => first.to_lowercase().chain(chars).collect(),
        None => String::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base64_rfc4648_vectors() {
        for (input, output) in [
            ("", ""),
            ("f", "Zg=="),
            ("fo", "Zm8="),
            ("foo", "Zm9v"),
            ("foob", "Zm9vYg=="),
            ("fooba", "Zm9vYmE="),
            ("foobar", "Zm9vYmFy"),
        ] {
            assert_eq!(base64(input.as_bytes()), output);
        }
    }

    #[test]
    fn proxy_urls() {
        let proxy = parse_proxy("http://10.0.0.2:3128").unwrap();
        assert_eq!(proxy.id.to_string(), "http://10.0.0.2:3128");
        assert_eq!(proxy.uri, "http://10.0.0.2:3128/");
        assert!(proxy.authorization.is_none());

        let proxy = parse_proxy("HTTP://User:p%40ss@Proxy.Example:8080/").unwrap();
        assert_eq!(proxy.id.to_string(), "http://proxy.example:8080");
        assert_eq!(
            proxy.authorization.unwrap(),
            format!("Basic {}", base64(b"User:p@ss"))
        );

        let proxy = parse_proxy("http://user@[::1]:3128").unwrap();
        assert_eq!(proxy.id.to_string(), "http://[::1]:3128");
        assert_eq!(
            proxy.authorization.unwrap(),
            format!("Basic {}", base64(b"user:"))
        );

        let proxy = parse_proxy("http://alice%3Ademo%2Fpassword@127.0.0.1:8080").unwrap();
        assert_eq!(proxy.id.to_string(), "http://127.0.0.1:8080");
        let authorization = proxy.authorization.unwrap();
        assert!(authorization.is_sensitive());
        assert_eq!(
            authorization,
            format!("Basic {}", base64(b"alice:demo/password"))
        );
    }

    #[test]
    fn bad_proxy_urls() {
        let message = |url| parse_proxy(url).unwrap_err().to_string();
        assert_eq!(
            message("socks5://10.0.0.2:1080"),
            "--proxy socks5://10.0.0.2:1080: unsupported proxy scheme, only http:// is supported"
        );
        assert_eq!(
            message("https://10.0.0.2:3128"),
            "--proxy https://10.0.0.2:3128: unsupported proxy scheme, only http:// is supported"
        );
        assert_eq!(
            message("http://10.0.0.2"),
            "--proxy http://10.0.0.2: missing port"
        );
        assert_eq!(
            message("http://[::1]"),
            "--proxy http://[::1]: missing port"
        );
        assert_eq!(
            message("http://:3128"),
            "--proxy http://:3128: missing host"
        );
        assert_eq!(message("http://h:0"), "--proxy http://h:0: invalid port");
        assert_eq!(
            message("http://h:99999"),
            "--proxy http://h:99999: invalid port"
        );
        assert_eq!(
            message("http://h:3128/x"),
            "--proxy http://h:3128/x: a proxy URL has no path"
        );
        assert_eq!(
            message("10.0.0.2:3128"),
            "--proxy: not a URL, expected http://host:port"
        );
        assert_eq!(
            message("socks5://user:secret@h:1080"),
            "--proxy socks5://***@h:1080: unsupported proxy scheme, only http:// is supported"
        );
        assert_eq!(
            message("http://user:%zz@h:1"),
            "--proxy http://***@h:1: invalid credentials"
        );
    }

    #[test]
    fn proxy_errors_hide_credentials() {
        for (url, shown, reason) in [
            (
                "http://alice:demo/password@127.0.0.1:8080",
                "http://***@127.0.0.1:8080",
                "a proxy URL has no path",
            ),
            (
                "http://alice%3Ademo-password@127.0.0.1:bad",
                "http://***@127.0.0.1:bad",
                "invalid port",
            ),
            (
                "http://alice%3ademo%2Fpassword@127.0.0.1:bad",
                "http://***@127.0.0.1:bad",
                "invalid port",
            ),
            (
                "http://alice:demo?password@127.0.0.1:8080",
                "http://***@127.0.0.1:8080",
                "a proxy URL has no path",
            ),
            (
                "http://alice:demo#password@127.0.0.1:8080",
                "http://***@127.0.0.1:8080",
                "a proxy URL has no path",
            ),
            (
                "http://alice:demo@password@127.0.0.1:bad",
                "http://***@127.0.0.1:bad",
                "invalid port",
            ),
            (
                "http://alice:demo://password@127.0.0.1:8080",
                "http://***@127.0.0.1:8080",
                "a proxy URL has no path",
            ),
            (
                "http://alice:demo%zz@127.0.0.1:8080",
                "http://***@127.0.0.1:8080",
                "invalid credentials",
            ),
            (
                "http://alice@127.0.0.1:bad",
                "http://***@127.0.0.1:bad",
                "invalid port",
            ),
            (
                "https://alice:demo-password@[::1]:3128/",
                "https://***@[::1]:3128/",
                "unsupported proxy scheme, only http:// is supported",
            ),
        ] {
            let error = parse_proxy(url).unwrap_err();
            assert_eq!(error.to_string(), format!("--proxy {shown}: {reason}"));
            let debug = format!("{error:?}");
            assert!(debug.contains(shown), "{debug}");
            assert!(!debug.contains("alice"), "{debug}");
            assert!(!debug.contains("demo"), "{debug}");
        }
    }

    #[test]
    fn proxy_errors_omit_urls_that_cannot_be_safely_redacted() {
        for (url, reason) in [
            (
                "alice:demo-password@127.0.0.1:8080",
                "not a URL, expected http://host:port",
            ),
            (
                "alice:demo://password@127.0.0.1:8080",
                "unsupported proxy scheme, only http:// is supported",
            ),
            ("http://alice:demo-password@bad host:8080", "invalid host"),
            ("http://alice:demo-password@[::1:8080", "invalid host"),
            (
                "http://alice%3Ademo-password%40127.0.0.1:8080",
                "invalid host",
            ),
        ] {
            let error = parse_proxy(url).unwrap_err();
            assert_eq!(error.to_string(), format!("--proxy: {reason}"));
            let debug = format!("{error:?}");
            assert!(!debug.contains("alice"), "{debug}");
            assert!(!debug.contains("demo"), "{debug}");
            assert!(!debug.contains("127.0.0.1"), "{debug}");
        }
    }

    #[test]
    fn error_texts() {
        assert_eq!(
            describe_io(&io::Error::from(io::ErrorKind::ConnectionRefused)),
            "connection refused"
        );
        assert_eq!(describe("Broken pipe (os error 32)"), "broken pipe");
    }
}
