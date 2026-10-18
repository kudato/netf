//! The `--ipset` list: the collapsed CIDRs, one per line, IPv4 before IPv6.
//!
//! fw4 (`option loadfile`) and FireHOL read this format as it is.

use std::fmt::Write as _;

use crate::addr::{Family, set::AddrSet};

/// Renders the minimal CIDR list, one CIDR per line, IPv4 first.
///
/// A set with no addresses renders as an empty string.
pub(crate) fn render(set: &AddrSet) -> String {
    let mut out = String::new();
    for family in [Family::V4, Family::V6] {
        for prefix in set.prefixes(family) {
            // Writing into a `String` does not fail.
            let _ = writeln!(out, "{prefix}");
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::addr::Range;

    #[test]
    fn collapsed_ipv4_first() {
        let set: AddrSet = [
            "2001:db8::/33",
            "192.0.2.128/25",
            "2001:db8:8000::/33",
            "192.0.2.0/25",
            "198.51.100.7",
            "203.0.113.0-203.0.113.2",
        ]
        .iter()
        .map(|text| text.parse::<Range>().unwrap())
        .collect();
        assert_eq!(
            render(&set),
            "192.0.2.0/24\n198.51.100.7/32\n203.0.113.0/31\n203.0.113.2/32\n2001:db8::/32\n"
        );
        assert_eq!(render(&AddrSet::new()), "");
    }
}
