//! The texts of `--help` and `--version`.
//!
//! `--help` prints the usage and then the fields that a query can test.
//! Both texts go to stdout, and netf exits with code 0.
//!
//! The help text is made of constants, so that tests can compare it byte for
//! byte and the binary needs no code to lay it out.

/// The usage: the command forms and the first options.
const USAGE: &str = "\
Usage: netf [OPTIONS] <QUERY>... [OPTIONS]
       netf [OPTIONS] -s <SET>

  -s, --set <NAME>       Use a set from the config
  -c, --config <FILE>    Config file (TOML), merged over ~/.netf/config.toml
      --ipset            Print the collapsed CIDR list (default with -s)
  -i                     Browse the result as a tree: organizations, their AS, the routes
";

/// The options after `-i`.
const OPTIONS: &str = "  -4                     IPv4 [default]; with -6, both families
  -6                     IPv6; with -4, both families
  -f, --file <PATH>      Write the result to PATH; the old file is replaced only on success
      --fields <LIST>    Add columns: fields from the help, comma-separated
      --limit <N>        Show at most N networks [default: 100]; 0 shows all; --ipset is never limited
      --ttl <DURATION>   Cache lifetime: 30m, 12h, 7d; 0 revalidates now [default: 24h]
      --cache-dir <DIR>  Cache directory [default: ~/.netf/cache]
      --no-cache         Do not read or write the cache
      --proxy <URL>      Send all traffic through this proxy; repeat for a pool
      --concurrency <N>  Concurrent requests per server per IP [default: 8]
      --ripe-emails      Fetch e-mail of RIPE persons; spends the RIPE daily limit (1000/day per IP)
      --doh <URL>        DNS-over-HTTPS server used with --proxy [default: https://1.1.1.1/dns-query]
  -h, --help             Print help
  -V, --version          Print version
";

/// The fields, the selectors, and the patterns of a query.
const FIELDS: &str = "\
Fields:

  A field tests a route, its registry network or its AS; the answer lists
  routes and networks without a route.

  Route, a prefix announced in BGP (RIPE RIS):
    route         Prefix; route: <ip> is the most specific route covering <ip>;
                  route: * is announced only

  Registry network of the route: the block from the registry and records
  inside it (RDAP ip network, RIPE inetnum):
    net.country   Country of registration, not geolocation: XA
    net.org       Holder, by name or handle: \"Example LLC\", ORG-EX1-RIPE
    net.rir       Registry: afrinic, apnic, arin, lacnic, ripencc
    net.mnt       Maintainers: EXAMPLE-MNT
    net.contact   Contact in any role, by handle: EXA1-RIPE; by role:
                  net.contact.abuse, .administrative, .technical

  AS:
    as.asn        Number: 64496 or AS64496; range: as.asn >= 64512
    as.name       Name: EXAMPLE
    as.org        Holder, by name or handle: \"Example LLC\", ORG-EX1-RIPE
    as.country    Country of registration: XA
    as.rir        Registry: ripencc
    as.mnt        Maintainers: EXAMPLE-MNT
    as.contact    Contact in any role, by handle: EXA1-RIPE; by role:
                  as.contact.abuse, .administrative, .technical

  Selectors are not fields: the value comes from the query, DNS or the config:
    ip            Address or network as is: ip: 192.0.2.1
    domain        Addresses of the domain, A; with -6, AAAA: domain: example.com
    set           Set from the config: set: office

  Patterns:
    presence      net.mnt: *  the record has the field (in any field)
    in value      as.name: example*  (in as.name, net.org, as.org)
    in field name *country: XA = net.country: XA or as.country: XA

  Names and organizations are case-insensitive.
  ARIN and LACNIC have no maintainers; LACNIC cannot be searched by contact;
  AFRINIC has no abuse contact.
  Conditions on as.* must hold for one AS of the route, on net.* for one network.
";

/// Returns the text of `--help`.
pub(crate) fn help() -> String {
    format!("{USAGE}{OPTIONS}\n{FIELDS}")
}

/// Returns the text of `--version`: `netf` and the package version.
pub(crate) fn version() -> String {
    format!("netf {}\n", env!("CARGO_PKG_VERSION"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn help_has_usage_then_fields() {
        let text = help();
        assert!(text.starts_with("Usage: netf [OPTIONS] <QUERY>... [OPTIONS]\n"));
        assert!(text.contains("  -V, --version          Print version\n\nFields:\n"));
        assert!(text.ends_with("on net.* for one network.\n"));
    }

    #[test]
    fn interactive_option_follows_ipset() {
        let text = help();
        assert!(
            text.contains("(default with -s)\n  -i                     Browse"),
            "{text}"
        );
        assert!(
            text.contains("the routes\n  -4                     IPv4"),
            "{text}"
        );
    }

    #[test]
    fn version_line() {
        assert_eq!(version(), format!("netf {}\n", env!("CARGO_PKG_VERSION")));
    }
}
