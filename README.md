# netf

A command-line tool for finding IP networks by autonomous system,
organization, registration country, or domain.

netf combines BGP routing data, Internet registry records, and DNS
through KQL-style queries. Inspect matching networks and their holders,
or export the selected addresses as an aggregated CIDR list.

```console
$ netf 'route: 192.0.2.0/24 or as.asn: 64498'
192.0.2.0/24   AS64496 EXAMPLE-NET, AS64497 TELE-EDGE  192.0.2.0/24  Example Networks LLC, XA  abuse@example.net / as-abuse@example.net, abuse@tele-edge.example
192.0.2.64/27  AS64498 DOCNET                          192.0.2.0/24  Example Networks LLC, XA  abuse@example.net / abuse@docnet.example

$ netf --ipset 'as.asn: 64496 and not ip: 192.0.2.0/25'
192.0.2.128/25
```

## Install

netf needs Rust 1.98.1 or later.

```sh
cargo install --locked netf
```

To build from the repository:

```sh
cargo install --locked --git https://github.com/kudato/netf
```

## Where the data comes from

netf downloads public data on demand and caches it in `~/.netf/cache` for
24 hours:

- the routes that RIPE RIS sees in BGP;
- `asn.txt` from RIPE NCC, for AS names;
- the delegated stats of the five registries: AFRINIC, APNIC, ARIN,
  LACNIC, and the RIPE NCC;
- RDAP, the RIPE database REST API, and the APNIC and AFRINIC database
  dumps, for holders, maintainers, and contacts;
- DNS, for `domain:`.

`--ttl` changes the cache lifetime, and `--no-cache` turns the cache off.

## Write a query

A query is one or more conditions joined with `and`, `or`, and `not`, with
parentheses for grouping. Each condition is a field, a colon, and a value:

```sh
netf 'as.name: example* and net.country: NL'
netf 'net.org: "Example LLC" and not net.mnt: EXAMPLE-MNT'
netf 'as.asn >= 64512 and as.rir: ripencc'
netf 'domain: example.com'
```

- `as.*` fields test the AS that announces a route: `as.asn`, `as.name`,
  `as.org`, `as.country`, `as.rir`, `as.mnt`, and `as.contact`.
- `net.*` fields test the registry network of the route: `net.country`,
  `net.org`, `net.rir`, `net.mnt`, and `net.contact`.
- `route`, `ip`, `domain`, and `set` select addresses directly.
- `field: (a or b)` tests several values. `ip: @file` reads the values from
  a file, one per line.
- `field: *` matches every record that has the field.
- A `*` inside a value is a wildcard in `as.name`, `as.org`, and `net.org`.
- A word without a field matches AS names and holders. An address becomes
  `ip:`, and `AS64496` becomes `as.asn:`.

Names and organizations ignore case. `netf --help` lists every field and
option.

## Choose the output

By default, netf prints a table with one row per route or network. The
columns are the route, the AS, the registry network, the holder, and the
abuse contacts. `--fields` adds columns, and `--limit` sets the number of
rows, 100 by default.

`--ipset` prints the addresses as a collapsed CIDR list, ready for a
firewall. `-4` and `-6` choose the address family, IPv4 by default. `-f`
writes the result to a file and replaces the old file only on success.

`-i` opens an interactive tree: organizations, their AS, and the routes.
netf asks the registries about a branch only when you expand it.

## Save queries in the config

netf creates an empty `~/.netf/config.toml` on the first run. The config
holds the defaults of options and named sets:

```toml
ttl = "7d"
limit = 0

[set.office]
query = "net.org: \"Example LLC\""

[set.office6]
query = "set: office"
ipv6 = true
```

`netf -s office` prints the CIDR list of a set. `set: office` uses the set
inside a query. `-c FILE` merges another config over the base one.

## Mind the RIPE limit

The RIPE database allows each IP address 1000 queries for personal data
per UTC day. netf spends them only with `--ripe-emails`, which fetches the
e-mail of RIPE persons, and stops at the limit. `--proxy` sends the
traffic through a proxy. Repeat it to spread the requests over a pool:
each proxy has its own limit.

## Exit codes

- 0: the run succeeded.
- 1: the run failed, for example on a network error.
- 2: the options, the query, or the config are wrong.
- 130: the run was interrupted.

## License

netf is licensed under either of

- Apache License, Version 2.0, ([LICENSE-APACHE](LICENSE-APACHE) or
  <https://www.apache.org/licenses/LICENSE-2.0>)
- MIT license ([LICENSE-MIT](LICENSE-MIT) or
  <https://opensource.org/licenses/MIT>)

at your option.

Unless you explicitly state otherwise, any contribution intentionally
submitted for inclusion in netf by you, as defined in the Apache-2.0
license, shall be dually licensed as above, without any additional
terms or conditions.
