//! Addresses, prefixes, and ranges of both families.
//!
//! All arithmetic is done on `u128`: an IPv4 address lives in the low 32 bits,
//! so the same code serves both families and nothing is generic. Every
//! value carries its [`Family`], and values of different families never
//! compare as overlapping.
//!
//! - [`Addr`] is one address.
//! - [`Prefix`] is a CIDR network with the host bits cleared: `192.0.2.4/24`
//!   parses as `192.0.2.0/24`. In `ip:`, an address with a mask means its
//!   network.
//! - [`Range`] is an inclusive range of addresses. Registry blocks are
//!   ranges, not CIDRs: delegated stats count IPv4 blocks in addresses, so a
//!   block of 768 addresses is not one prefix. [`Range::prefixes`] gives the
//!   minimal CIDR cover. A range that is not one CIDR prints as `first-last`.
//! - [`AddrSet`](set::AddrSet) holds disjoint sorted ranges with union,
//!   subtraction, and intersection. `not ip:` and `--ipset` use it.
//!
//! [`Family`] and [`Families`] are public: [`Resolver`](crate::Resolver)
//! implementations receive the families a query asks for.

pub(crate) mod set;

use std::{
    fmt,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    str::FromStr,
};

/// An address family.
///
/// IPv4 sorts first, as in the output of `-4 -6`.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum Family {
    /// IPv4.
    V4,
    /// IPv6.
    V6,
}

impl Family {
    /// Returns the address width in bits: 32 or 128.
    pub(crate) fn bits(self) -> u8 {
        match self {
            Self::V4 => 32,
            Self::V6 => 128,
        }
    }

    /// Returns the largest address of the family as a number.
    pub(crate) fn max(self) -> u128 {
        match self {
            Self::V4 => u128::from(u32::MAX),
            Self::V6 => u128::MAX,
        }
    }

    /// Returns the option that selects this family: `-4` or `-6`.
    pub(crate) fn flag(self) -> &'static str {
        match self {
            Self::V4 => "-4",
            Self::V6 => "-6",
        }
    }
}

/// Prints `IPv4` or `IPv6`.
impl fmt::Display for Family {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::V4 => "IPv4",
            Self::V6 => "IPv6",
        })
    }
}

/// A set of address families: the families that a run outputs, or that a
/// resolver looks up.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
pub struct Families {
    v4: bool,
    v6: bool,
}

impl Families {
    /// No family, for a source that is not needed at all.
    pub const NONE: Self = Self {
        v4: false,
        v6: false,
    };
    /// IPv4 only, the default.
    pub const V4: Self = Self {
        v4: true,
        v6: false,
    };
    /// IPv6 only (`-6`).
    pub const V6: Self = Self {
        v4: false,
        v6: true,
    };
    /// Both families (`-4 -6`).
    pub const BOTH: Self = Self { v4: true, v6: true };

    /// Returns the families that `-4` and `-6` select.
    ///
    /// The `ipv4` and `ipv6` config keys work the same way. Neither flag
    /// means IPv4 only.
    pub fn from_flags(v4: bool, v6: bool) -> Self {
        if !v4 && !v6 {
            Self::V4
        } else {
            Self { v4, v6 }
        }
    }

    /// Returns `true` if IPv4 is included.
    pub fn v4(self) -> bool {
        self.v4
    }

    /// Returns `true` if IPv6 is included.
    pub fn v6(self) -> bool {
        self.v6
    }

    /// Returns `true` if `family` is included.
    pub fn contains(self, family: Family) -> bool {
        match family {
            Family::V4 => self.v4,
            Family::V6 => self.v6,
        }
    }

    /// Returns `true` if no family is included.
    pub fn is_empty(self) -> bool {
        !self.v4 && !self.v6
    }

    /// Returns the families included in either set.
    #[must_use]
    pub fn union(self, other: Self) -> Self {
        Self {
            v4: self.v4 || other.v4,
            v6: self.v6 || other.v6,
        }
    }

    /// Iterates over the included families, IPv4 first.
    pub fn iter(self) -> impl Iterator<Item = Family> {
        [(self.v4, Family::V4), (self.v6, Family::V6)]
            .into_iter()
            .filter_map(|(on, family)| on.then_some(family))
    }
}

/// Why an address, a prefix, or a range did not parse.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum AddrError {
    /// Not an IPv4 or IPv6 address.
    InvalidAddress,
    /// The prefix length is not a number or exceeds the family width.
    InvalidLength,
    /// The two ends of a range belong to different families.
    MixedFamilies,
    /// The first address of a range is after the last one.
    Reversed,
}

impl fmt::Display for AddrError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::InvalidAddress => "invalid address",
            Self::InvalidLength => "invalid prefix length",
            Self::MixedFamilies => "addresses of different families",
            Self::Reversed => "the first address is after the last",
        })
    }
}

impl std::error::Error for AddrError {}

/// One address of either family.
///
/// Ordered by family, then numerically: all IPv4 before all IPv6.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub(crate) struct Addr {
    family: Family,
    bits: u128,
}

impl Addr {
    /// Creates an address from its number, or `None` if the number does not
    /// fit the family.
    pub(crate) fn new(family: Family, bits: u128) -> Option<Self> {
        (bits <= family.max()).then_some(Self { family, bits })
    }

    /// Returns the family.
    pub(crate) fn family(self) -> Family {
        self.family
    }

    /// Returns the address as a number, with IPv4 in the low 32 bits.
    pub(crate) fn bits(self) -> u128 {
        self.bits
    }

    /// Converts to the standard library's address.
    pub(crate) fn to_ip(self) -> IpAddr {
        match self.family {
            // Lossless: an IPv4 `Addr` never exceeds `u32::MAX` (see `new`).
            Family::V4 => IpAddr::V4(Ipv4Addr::from(self.bits as u32)),
            Family::V6 => IpAddr::V6(Ipv6Addr::from(self.bits)),
        }
    }
}

impl From<Ipv4Addr> for Addr {
    fn from(ip: Ipv4Addr) -> Self {
        Self {
            family: Family::V4,
            bits: u128::from(u32::from(ip)),
        }
    }
}

impl From<Ipv6Addr> for Addr {
    fn from(ip: Ipv6Addr) -> Self {
        Self {
            family: Family::V6,
            bits: u128::from(ip),
        }
    }
}

impl From<IpAddr> for Addr {
    fn from(ip: IpAddr) -> Self {
        match ip {
            IpAddr::V4(ip) => ip.into(),
            IpAddr::V6(ip) => ip.into(),
        }
    }
}

impl FromStr for Addr {
    type Err = AddrError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        s.parse::<IpAddr>()
            .map(Self::from)
            .map_err(|_| AddrError::InvalidAddress)
    }
}

/// Prints the usual notation: `192.0.2.242`, `2001:db8::2:242`.
impl fmt::Display for Addr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.to_ip().fmt(f)
    }
}

/// Returns the mask of the host bits of a prefix of length `len`.
fn host_mask(family: Family, len: u8) -> u128 {
    let host = u32::from(family.bits() - len);
    if host == 128 {
        u128::MAX
    } else {
        (1u128 << host) - 1
    }
}

/// A CIDR network: an address with the host bits cleared and a length.
///
/// Ordered by family, first address, then length. A network sorts before
/// the networks inside it, as in RIS and in the output.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub(crate) struct Prefix {
    addr: Addr,
    len: u8,
}

impl Prefix {
    /// Creates the prefix of length `len` that contains `addr`, clearing the
    /// host bits.
    ///
    /// # Errors
    ///
    /// Returns [`AddrError::InvalidLength`] if `len` is longer than the
    /// address.
    pub(crate) fn new(addr: Addr, len: u8) -> Result<Self, AddrError> {
        if len > addr.family.bits() {
            return Err(AddrError::InvalidLength);
        }
        let bits = addr.bits & !host_mask(addr.family, len);
        Ok(Self {
            addr: Addr {
                family: addr.family,
                bits,
            },
            len,
        })
    }

    /// Returns the prefix of one address: `/32` or `/128`.
    pub(crate) fn host(addr: Addr) -> Self {
        Self {
            addr,
            len: addr.family.bits(),
        }
    }

    /// Returns the network address.
    pub(crate) fn addr(self) -> Addr {
        self.addr
    }

    /// Returns the length in bits.
    pub(crate) fn len(self) -> u8 {
        self.len
    }

    /// Returns the family.
    pub(crate) fn family(self) -> Family {
        self.addr.family
    }

    /// Returns the first address as a number.
    pub(crate) fn first(self) -> u128 {
        self.addr.bits
    }

    /// Returns the last address as a number.
    pub(crate) fn last(self) -> u128 {
        self.addr.bits | host_mask(self.addr.family, self.len)
    }

    /// Returns the addresses of the prefix as a range.
    pub(crate) fn range(self) -> Range {
        Range::from_prefix(self)
    }
}

/// Parses `address/length` and clears the host bits, so `192.0.2.4/24` is
/// `192.0.2.0/24`.
///
/// A bare address is not a prefix. Callers that accept both try [`Addr`] or
/// check for `/` themselves.
impl FromStr for Prefix {
    type Err = AddrError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (addr, len) = s.split_once('/').ok_or(AddrError::InvalidLength)?;
        let addr: Addr = addr.parse()?;
        // Only plain decimal digits: `u8::from_str` would accept `+24`.
        if len.is_empty() || len.len() > 3 || !len.bytes().all(|b| b.is_ascii_digit()) {
            return Err(AddrError::InvalidLength);
        }
        let len: u8 = len.parse().map_err(|_| AddrError::InvalidLength)?;
        Self::new(addr, len)
    }
}

/// Prints `a.b.c.d/n` or `x::/n`.
impl fmt::Display for Prefix {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.addr, self.len)
    }
}

/// An inclusive range of addresses of one family.
///
/// Ordered by family, first address, then last address.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub(crate) struct Range {
    family: Family,
    first: u128,
    last: u128,
}

impl Range {
    /// Creates a range, or `None` if `first > last` or an end does not fit
    /// the family.
    pub(crate) fn new(family: Family, first: u128, last: u128) -> Option<Self> {
        (first <= last && last <= family.max()).then_some(Self {
            family,
            first,
            last,
        })
    }

    /// Returns the addresses of a prefix.
    pub(crate) fn from_prefix(prefix: Prefix) -> Self {
        Self {
            family: prefix.family(),
            first: prefix.first(),
            last: prefix.last(),
        }
    }

    /// Returns the range of one address.
    pub(crate) fn from_addr(addr: Addr) -> Self {
        Self {
            family: addr.family,
            first: addr.bits,
            last: addr.bits,
        }
    }

    /// Returns the family.
    pub(crate) fn family(&self) -> Family {
        self.family
    }

    /// Returns the first address as a number.
    pub(crate) fn first(&self) -> u128 {
        self.first
    }

    /// Returns the last address as a number.
    pub(crate) fn last(&self) -> u128 {
        self.last
    }

    /// Returns the first address.
    pub(crate) fn first_addr(&self) -> Addr {
        Addr {
            family: self.family,
            bits: self.first,
        }
    }

    /// Returns the last address.
    pub(crate) fn last_addr(&self) -> Addr {
        Addr {
            family: self.family,
            bits: self.last,
        }
    }

    /// Returns `true` if `other` lies entirely within this range.
    pub(crate) fn contains(&self, other: &Range) -> bool {
        self.family == other.family && self.first <= other.first && other.last <= self.last
    }

    /// Returns `true` if the ranges share at least one address.
    pub(crate) fn intersects(&self, other: &Range) -> bool {
        self.family == other.family && self.first <= other.last && other.first <= self.last
    }

    /// Returns the common addresses, if any.
    pub(crate) fn intersection(&self, other: &Range) -> Option<Range> {
        self.intersects(other).then(|| Range {
            family: self.family,
            first: self.first.max(other.first),
            last: self.last.min(other.last),
        })
    }

    /// Returns the minimal list of CIDR prefixes that covers exactly this
    /// range, in address order.
    pub(crate) fn prefixes(&self) -> Prefixes {
        Prefixes {
            family: self.family,
            next: self.first,
            last: self.last,
            done: false,
        }
    }

    /// Returns the prefix if the range is exactly one CIDR.
    pub(crate) fn as_prefix(&self) -> Option<Prefix> {
        let mut prefixes = self.prefixes();
        let first = prefixes.next()?;
        prefixes.next().is_none().then_some(first)
    }
}

impl From<Prefix> for Range {
    fn from(prefix: Prefix) -> Self {
        Self::from_prefix(prefix)
    }
}

/// Parses `first-last`, `address/length`, or a single address.
impl FromStr for Range {
    type Err = AddrError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if let Some((first, last)) = s.split_once('-') {
            let first: Addr = first.parse()?;
            let last: Addr = last.parse()?;
            if first.family != last.family {
                return Err(AddrError::MixedFamilies);
            }
            Range::new(first.family, first.bits, last.bits).ok_or(AddrError::Reversed)
        } else if s.contains('/') {
            s.parse::<Prefix>().map(Range::from_prefix)
        } else {
            s.parse::<Addr>().map(Range::from_addr)
        }
    }
}

/// Prints the prefix if the range is one CIDR, otherwise `first-last`.
///
/// `192.0.2.0-192.0.3.255` prints as `192.0.2.0/23`, and
/// `192.0.2.0-192.0.4.255` prints as is.
impl fmt::Display for Range {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.as_prefix() {
            Some(prefix) => prefix.fmt(f),
            None => write!(f, "{}-{}", self.first_addr(), self.last_addr()),
        }
    }
}

/// Stored in cached responses as its text form, because JSON has no 128-bit
/// numbers.
impl serde::Serialize for Range {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(self)
    }
}

impl<'de> serde::Deserialize<'de> for Range {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let text = <std::borrow::Cow<'de, str>>::deserialize(deserializer)?;
        text.parse().map_err(serde::de::Error::custom)
    }
}

/// The minimal CIDR cover of a [`Range`], from [`Range::prefixes`].
#[derive(Clone, Debug)]
pub(crate) struct Prefixes {
    family: Family,
    next: u128,
    last: u128,
    done: bool,
}

impl Iterator for Prefixes {
    type Item = Prefix;

    fn next(&mut self) -> Option<Prefix> {
        if self.done {
            return None;
        }
        let width = u32::from(self.family.bits());
        let first = self.next;
        // The block at `first` may be as large as its alignment allows…
        let align = if first == 0 {
            width
        } else {
            first.trailing_zeros().min(width)
        };
        // …and as the rest of the range allows: floor(log2(count)).
        let span = self.last - first;
        let fit = if span == u128::MAX {
            128
        } else {
            127 - (span + 1).leading_zeros()
        };
        let host = align.min(fit);
        let size_minus_one = if host == 128 {
            u128::MAX
        } else {
            (1u128 << host) - 1
        };
        let block_last = first + size_minus_one;
        if block_last >= self.last {
            self.done = true;
        } else {
            self.next = block_last + 1;
        }
        // `host <= width <= 128`, so the length fits in `u8`.
        let len = (width - host) as u8;
        Some(Prefix {
            addr: Addr {
                family: self.family,
                bits: first,
            },
            len,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn prefix(s: &str) -> Prefix {
        s.parse().unwrap()
    }

    fn range(s: &str) -> Range {
        s.parse().unwrap()
    }

    #[test]
    fn addresses_round_trip() {
        for text in ["10.88.55.242", "0.0.0.0", "3fff::2:242", "::"] {
            assert_eq!(text.parse::<Addr>().unwrap().to_string(), text);
        }
        assert_eq!("192.0.2".parse::<Addr>(), Err(AddrError::InvalidAddress));
        assert_eq!("10.88.55.242".parse::<Addr>().unwrap().family(), Family::V4);
    }

    #[test]
    fn prefixes_are_normalized() {
        assert_eq!(prefix("192.0.2.4/24").to_string(), "192.0.2.0/24");
        assert_eq!(prefix("3fff::1/32").to_string(), "3fff::/32");
        assert_eq!(prefix("0.0.0.0/0").last(), u128::from(u32::MAX));
        assert_eq!(prefix("::/0").last(), u128::MAX);
        assert_eq!(
            "192.0.2.4/33".parse::<Prefix>(),
            Err(AddrError::InvalidLength)
        );
        assert_eq!(
            "192.0.2.4/+3".parse::<Prefix>(),
            Err(AddrError::InvalidLength)
        );
        assert_eq!("192.0.2.4".parse::<Prefix>(), Err(AddrError::InvalidLength));
    }

    #[test]
    fn range_cover_is_minimal() {
        let cover: Vec<_> = range("192.0.2.1-192.0.2.6")
            .prefixes()
            .map(|p| p.to_string())
            .collect();
        assert_eq!(
            cover,
            [
                "192.0.2.1/32",
                "192.0.2.2/31",
                "192.0.2.4/31",
                "192.0.2.6/32"
            ]
        );
        let all: Vec<_> = range("::-ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff")
            .prefixes()
            .collect();
        assert_eq!(all, [prefix("::/0")]);
        let all: Vec<_> = range("0.0.0.0-255.255.255.255").prefixes().collect();
        assert_eq!(all, [prefix("0.0.0.0/0")]);
    }

    #[test]
    fn ranges_print_as_cidr_when_possible() {
        assert_eq!(
            range("198.18.2.0-198.18.3.255").to_string(),
            "198.18.2.0/23"
        );
        assert_eq!(
            range("198.18.2.0-198.18.4.255").to_string(),
            "198.18.2.0-198.18.4.255"
        );
        assert_eq!(range("192.0.2.7").to_string(), "192.0.2.7/32");
        assert_eq!(
            "192.0.2.9-192.0.2.1".parse::<Range>(),
            Err(AddrError::Reversed)
        );
        assert_eq!(
            "192.0.2.1-2001:db8::".parse::<Range>(),
            Err(AddrError::MixedFamilies)
        );
    }

    #[test]
    fn range_relations() {
        let outer = range("198.18.100.0/22");
        let inner = range("198.18.100.0/24");
        let other = range("2001:db8::/32");
        assert!(outer.contains(&inner));
        assert!(!inner.contains(&outer));
        assert!(!outer.intersects(&other));
        assert_eq!(
            range("198.18.2.0/24").intersection(&range("198.18.2.128-198.18.3.10")),
            Some(range("198.18.2.128/25"))
        );
    }

    #[test]
    fn families_from_flags() {
        assert_eq!(Families::from_flags(false, false), Families::V4);
        assert_eq!(Families::from_flags(false, true), Families::V6);
        assert_eq!(Families::from_flags(true, true), Families::BOTH);
        let order: Vec<_> = Families::BOTH.iter().collect();
        assert_eq!(order, [Family::V4, Family::V6]);
        assert!(Families::NONE.is_empty());
    }

    #[test]
    fn range_serde_uses_text() {
        let json = serde_json::to_string(&range("2001:db8::/32")).unwrap();
        assert_eq!(json, "\"2001:db8::/32\"");
        let back: Range = serde_json::from_str(&json).unwrap();
        assert_eq!(back, range("2001:db8::/32"));
    }
}
