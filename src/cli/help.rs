//! General help and topic references. All example data is synthetic.

use crate::error::{Error, Result};

/// A help topic selected with `--help=TOPIC`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Topic {
    /// Purpose, examples, and options.
    Main,
    /// Query syntax and selectors.
    Query,
    /// Query fields and output fields.
    Fields,
    /// Every topic in one reference.
    All,
}

impl Topic {
    /// Parses an attached topic name without loading settings or sources.
    pub(crate) fn parse(name: &str) -> Result<Self> {
        match name {
            "query" => Ok(Self::Query),
            "fields" => Ok(Self::Fields),
            "all" => Ok(Self::All),
            _ => Err(Error::usage(format!(
                "--help={name}: unknown topic; use --help, --help=query, --help=fields, or --help=all"
            ))),
        }
    }
}

/// The no-argument screen, passed to the error reporter with exit code 2.
/// The reporter's error already supplies the `netf: ` prefix.
pub(crate) const FIRST_RUN: &str = "\
enter a query or use --set.

Find internet networks using BGP, registry data, and DNS.

Usage: netf [OPTIONS] <QUERY>... [OPTIONS]
       netf [OPTIONS] -s <SET>

Examples:
  netf 'route: 192.0.2.140'
  netf 'as.asn: 64498'
  netf --ipset 'as.asn: 64498'

Default: IPv4. Use -6 for IPv6. Use -4 -6 for both.
-i: explore a tree. --ipset: export CIDRs. -f PATH: save to a file.

Help: netf --help
Query syntax: netf --help=query
All fields and options: netf --help=all";

const MAIN: &str = "\
Find internet networks using BGP, registry data, and DNS.

Usage: netf [OPTIONS] <QUERY>... [OPTIONS]
       netf [OPTIONS] -s <SET>

Examples:
  netf 'route: 192.0.2.140'
  netf 'as.asn: 64498'
  netf --ipset 'as.asn: 64498'

Default: IPv4. Use -6 for IPv6. Use -4 -6 for both.

Output:
  -i                     Explore organizations, AS, and routes in a tree
      --ipset            Export the selected addresses as collapsed CIDRs
  -f, --file <PATH>       Save to PATH. Replace the old file only on success.
      --fields <LIST>    Add comma-separated fields. See --help=fields.
      --columns <LIST>   Show exactly these fields, in this order
      --format <NAME>    auto, table, details, or plain. See --help=fields.
      --limit <N>        Show at most N matches [default: 100]. 0 shows all.
                         CIDR exports have no limit.

Help topics: --help=query, --help=fields, --help=all

Queries and settings:
  -s, --set <NAME>        Export a saved query from the config as CIDRs
  -c, --config <FILE>     Merge TOML settings over ~/.netf/config.toml
  -4                     IPv4 [default]. With -6, both families.
  -6                     IPv6. With -4, both families.

Cache:
      --ttl <DURATION>   Cache lifetime [default: 24h]. Examples: 30m, 12h, 7d.
                         0 revalidates now.
      --cache-dir <DIR>  Cache directory [default: ~/.netf/cache]
      --no-cache         Disable cache reads and writes

Network:
      --proxy <URL>      Proxy for all traffic. Repeat for a pool.
      --concurrency <N>  Requests per server per IP [default: 8]
      --ripe-emails      Fetch hidden emails of RIPE persons
                         Uses the RIPE daily limit of 1000 queries per IP.
      --doh <URL>        DNS-over-HTTPS endpoint used with --proxy

Information:
  -h, --help             Show this help
      --help=<TOPIC>     Show query, fields, or all
  -V, --version          Show the version

Terminal results show BGP route, Origin AS, AS organization, and Network holder.
Match shows selected addresses that differ from the route.
Registry network shows a different or unavailable registration range.
Results that do not fit the terminal use cards.
Pipes and files keep plain output unless --columns or --format is set.
Examples use synthetic data and may return no matches.
";

const QUERY: &str = "\
Query syntax

Options go before or after the query, not between its words.
Shell single quotes keep spaces, *, and parentheses in one argument.
KQL double quotes enclose a value with spaces:
  netf 'as.org: \"Example Networks LLC\"'

A condition is FIELD: VALUE. as.asn also accepts <, <=, >, and >=.
The precedence is not, then and, then or. Parentheses group conditions:
  netf '(as.asn: 64498 or as.asn: 64499) and not ip: 192.0.2.140'
  netf 'as.asn >= 64498 and as.asn <= 64500'

Conditions on as.* must hold for the same AS of a route.
Conditions on net.* must hold for the same registry network.

Selectors:
  ip       Select addresses as given, including addresses without a BGP route
  domain   Select DNS addresses. IPv4 uses A. IPv6 uses AAAA.
  set      Use a query saved in the config

route: IP finds the most specific BGP route that covers the address.
ip: IP keeps the address itself. --ipset exports those exact selected addresses:
  netf 'route: 192.0.2.140'
  netf --ipset 'ip: 192.0.2.140'
  netf -6 'domain: service.example'

A bare address means ip:. AS64498 means as.asn: 64498.
A bare word searches AS names and organizations.

Patterns:
  as.name: example*    Match names that start with example
  net.mnt: *          Test whether a field has a value
  *country: XA        Match either net.country or as.country
Names and organizations are case-insensitive. A backslash escapes a literal *.

Scopes take field values from another query.
They find networks with those values:
  netf 'as.asn: {route: 192.0.2.140}'
A scope uses braces {}. Parentheses () group conditions without a scope.

@PATH reads values from a UTF-8 file, one per line. Blank lines and # comments
are ignored. Values are combined as a set, without input order or duplicates.
If addresses.txt contains addresses:
  netf --ipset 'ip: @addresses.txt'

Saved sets are queries in [set.NAME] in the TOML config.
If the config defines [set.office] with a query key:
  netf --set office
  netf 'set: office'
--set (or -s) exports all matching CIDRs. set: uses the normal output mode.

not ip: and not domain: need a positive condition to subtract addresses from.
For example, netf 'as.asn: 64498 and not ip: 192.0.2.140' is bounded.
A standalone not ip: or not domain: query is a usage error.

Field reference: netf --help=fields
";

const FIELDS: &str = "\
Query fields

A field tests a route, a registry network, or an origin AS.

BGP route observed by RIPE RIS:
  route         Prefix. route: IP finds the most specific covering route.
                route: * matches announced routes only.

Registry networks, from the delegated block to more specific records:
  net.country   Country of registration, not geolocation: XA
  net.org       Holder name or handle: \"Example LLC\", ORG-EX1-RIPE
  net.rir       Registry: afrinic, apnic, arin, lacnic, ripencc
  net.mnt       Maintainer handle: EXAMPLE-MNT
  net.contact   Contact handle in any contact role: EXA1-RIPE
                Roles: net.contact.abuse, net.contact.administrative,
                net.contact.technical

Origin AS:
  as.asn        Number: 64498 or AS64498
  as.name       Short AS name: EXAMPLE-NET
  as.org        Organization name or handle: \"Example LLC\", ORG-EX1-RIPE
  as.country    Country of registration: XA
  as.rir        Registry: ripencc
  as.mnt        Maintainer handle: EXAMPLE-MNT
  as.contact    Contact handle in any contact role: EXA1-RIPE
                Roles: as.contact.abuse, as.contact.administrative,
                as.contact.technical

ip, domain, and set are selectors. See --help=query.
ARIN and LACNIC have no maintainers. LACNIC has no contact search.
AFRINIC has no abuse contact.

Output fields (--fields, --columns)

Default terminal columns: BGP route, Origin AS, AS organization, Network holder.
AS organization is as.org, not the short as.name.
Network holder comes from the most specific obtained registry record.
An unavailable value is explicit. A registry identifier includes its RIR.

--fields adds details. It accepts all as.* and net.* query fields above.
Already visible default fields are not repeated in terminal output.
  netf --fields net.country,net.rir 'as.asn: 64498'

Output-only fields (not query predicates):
  match         All selected addresses, including every disjoint range
  net.holder    Holder of the most specific obtained registry record
  net.range     Registry record ranges, from parent to child
  net.abuse     Abuse emails of the most specific network record
  as.abuse      Abuse emails of each origin AS

net.org keeps the full organization chain, from parent to child.
net.range follows the same record order as net.org.
net.country and net.rir also include a wider delegated block if present.
*.contact fields keep contact handles, names, emails, and phone numbers.
They are not aliases for *.abuse, which shows only email addresses.
Each as.* value stays with its origin AS. Countries describe registration.
  netf --fields net.abuse,as.abuse 'ip: 192.0.2.140'

Match appears when selected addresses differ from the route or no route is seen.
Registry network appears when the most specific record differs from the route,
when no route is seen, or when the record is unavailable.
A narrower terminal changes the layout, not the fields or values.
--columns selects exact fields and their order, including route.
It replaces configured fields. It cannot be combined with --fields.
Only requested fields appear: include match for exact selected addresses,
or net.range for the registry chain. No other context fields are added.
  netf --columns route,as.asn 'as.asn: 64498'

Formats (--format):
  auto     Table if all columns fit; otherwise cards with the same values
  table    Aligned table; may exceed the terminal width; no truncation
  details  Wrapped cards; the same selected fields
  plain    The original format; additive --fields; no --columns
Explicit --columns and --format also apply to pipes and -f files.
Without either option, pipes and files keep the original plain format.
Redirected auto/details output uses a width of 80 columns.
--fields, --columns, and --format are unavailable with --ipset or --set.
--columns and --format are unavailable with -i.

";

/// Returns one topic, or the complete reference.
pub(crate) fn help(topic: Topic) -> String {
    match topic {
        Topic::Main => MAIN.into(),
        Topic::Query => QUERY.into(),
        Topic::Fields => FIELDS.into(),
        Topic::All => format!("{MAIN}\n{QUERY}\n{FIELDS}"),
    }
}

/// Returns `netf` and the package version.
pub(crate) fn version() -> String {
    format!("netf {}\n", env!("CARGO_PKG_VERSION"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn help_fits_eighty_columns_and_first_run_fits_one_screen() {
        for topic in [Topic::Main, Topic::Query, Topic::Fields, Topic::All] {
            for line in help(topic).lines() {
                assert!(line.chars().count() <= 80, "{line}");
            }
        }
        assert!(FIRST_RUN.lines().count() <= 24);
        assert!(FIRST_RUN.lines().all(|line| line.len() <= 80));
        let first_screen: Vec<_> = MAIN.lines().take(24).collect();
        assert!(
            first_screen
                .iter()
                .any(|line| line.contains("netf 'route:"))
        );
        assert!(
            first_screen
                .iter()
                .any(|line| line.contains("--help=query"))
        );
    }

    #[test]
    fn standalone_query_examples_parse_and_plan() {
        for text in [MAIN, QUERY, FIELDS, FIRST_RUN] {
            for line in text.lines().filter(|line| line.starts_with("  netf ")) {
                let Some((_, quoted)) = line.split_once('\'') else {
                    continue;
                };
                let query = quoted.strip_suffix('\'').unwrap();
                // These examples explicitly require a file or saved set.
                if query.contains('@') || query.starts_with("set:") {
                    continue;
                }
                let ast =
                    crate::query::parse(query).unwrap_or_else(|error| panic!("{line}: {error}"));
                let (expr, _) = crate::query::expand::expand_in(
                    &ast,
                    &|_| None,
                    crate::Families::BOTH,
                    std::path::Path::new("."),
                )
                .unwrap();
                crate::plan::build(expr, crate::plan::Mode::Ipset, crate::Families::BOTH).unwrap();
            }
        }
    }
}
