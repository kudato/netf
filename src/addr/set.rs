//! [`AddrSet`]: a set of addresses as disjoint, sorted ranges.
//!
//! The set does the arithmetic for three things:
//!
//! - `not ip:` and `not domain:`, which cut addresses out of a route
//! - the parts of a row, shown in the "part" column
//! - `--ipset`, the collapsed CIDR list
//!
//! Invariant: within each family the ranges are sorted, do not overlap, and
//! are not adjacent, because insertion merges touching ranges. Two sets with
//! the same addresses are therefore equal, and [`AddrSet::pieces`] and
//! [`AddrSet::prefixes`] read the canonical form directly. The minimal CIDR
//! list is [`Range::prefixes`] of every maximal range, because a CIDR
//! never spans two ranges that are not adjacent.
//!
//! [`AddrSet::insert`] is a binary search and one splice. [`AddrSet::union`],
//! [`AddrSet::subtract`], and [`AddrSet::intersect`] are linear merges of the
//! sorted lists, so a result of a million routes costs a few passes, not a
//! quadratic loop. All of the arithmetic works on `u128` and never adds one
//! past the end of the family: the last address of IPv6 is `u128::MAX`.

use super::{Families, Family, Prefix, Range};

/// A set of addresses of both families.
#[derive(Clone, Debug, Default, Eq, Hash, PartialEq)]
pub(crate) struct AddrSet {
    /// IPv4 ranges: sorted, disjoint, not adjacent.
    v4: Vec<Range>,
    /// IPv6 ranges: sorted, disjoint, not adjacent.
    v6: Vec<Range>,
}

impl AddrSet {
    /// Returns an empty set.
    pub(crate) fn new() -> Self {
        Self::default()
    }

    /// Returns `true` if the set has no addresses.
    pub(crate) fn is_empty(&self) -> bool {
        self.v4.is_empty() && self.v6.is_empty()
    }

    /// Returns the maximal ranges of one family, in address order.
    pub(crate) fn ranges(&self, family: Family) -> &[Range] {
        match family {
            Family::V4 => &self.v4,
            Family::V6 => &self.v6,
        }
    }

    fn ranges_mut(&mut self, family: Family) -> &mut Vec<Range> {
        match family {
            Family::V4 => &mut self.v4,
            Family::V6 => &mut self.v6,
        }
    }

    /// Adds the addresses of `range`, merging it with overlapping and
    /// adjacent ranges.
    pub(crate) fn insert(&mut self, range: Range) {
        let list = self.ranges_mut(range.family);
        // The ranges that end before `range` starts and do not touch it stay
        // in front: `last + 1 < first`, written without the `+ 1` that would
        // overflow at the end of IPv6.
        let start = list.partition_point(|r| range.first > 0 && r.last < range.first - 1);
        // The ranges that start no later than one past `range` merge with it.
        // At the very end of the family, everything after `start` does.
        let end = list.partition_point(|r| r.first <= range.last.saturating_add(1));
        let mut merged = range;
        if start < end {
            merged.first = merged.first.min(list[start].first);
            merged.last = merged.last.max(list[end - 1].last);
        }
        list.splice(start..end, [merged]);
    }

    /// Returns the addresses in either set.
    pub(crate) fn union(&self, other: &AddrSet) -> AddrSet {
        AddrSet {
            v4: union(&self.v4, &other.v4),
            v6: union(&self.v6, &other.v6),
        }
    }

    /// Returns the addresses of `self` that are not in `other`: `not ip:`
    /// and `not domain:`.
    pub(crate) fn subtract(&self, other: &AddrSet) -> AddrSet {
        AddrSet {
            v4: subtract(&self.v4, &other.v4),
            v6: subtract(&self.v6, &other.v6),
        }
    }

    /// Returns the addresses in both sets.
    pub(crate) fn intersect(&self, other: &AddrSet) -> AddrSet {
        AddrSet {
            v4: intersect(&self.v4, &other.v4),
            v6: intersect(&self.v6, &other.v6),
        }
    }

    /// Returns `true` if the address range lies entirely within the set.
    pub(crate) fn contains(&self, range: &Range) -> bool {
        let list = self.ranges(range.family);
        // Ranges are maximal, so a contained range is inside exactly one.
        let at = list.partition_point(|r| r.last < range.first);
        list.get(at).is_some_and(|r| r.contains(range))
    }

    /// Returns `true` if the set has at least one address of `range`.
    pub(crate) fn intersects(&self, range: &Range) -> bool {
        let list = self.ranges(range.family);
        let at = list.partition_point(|r| r.last < range.first);
        list.get(at).is_some_and(|r| r.intersects(range))
    }

    /// Iterates over the maximal ranges of the set, IPv4 first: the parts
    /// of a row.
    pub(crate) fn pieces(&self) -> impl Iterator<Item = Range> + '_ {
        self.v4.iter().chain(&self.v6).copied()
    }

    /// Returns the minimal CIDR list of one family: the lines of `--ipset`.
    pub(crate) fn prefixes(&self, family: Family) -> Vec<Prefix> {
        self.ranges(family)
            .iter()
            .flat_map(Range::prefixes)
            .collect()
    }

    /// Drops the addresses of the families that are not in `families`.
    pub(crate) fn retain_family(&mut self, families: Families) {
        if !families.v4() {
            self.v4.clear();
        }
        if !families.v6() {
            self.v6.clear();
        }
    }
}

impl From<Range> for AddrSet {
    fn from(range: Range) -> Self {
        let mut set = Self::new();
        set.insert(range);
        set
    }
}

impl From<Prefix> for AddrSet {
    fn from(prefix: Prefix) -> Self {
        Self::from(Range::from_prefix(prefix))
    }
}

impl FromIterator<Range> for AddrSet {
    fn from_iter<I: IntoIterator<Item = Range>>(iter: I) -> Self {
        let mut set = Self::new();
        for range in iter {
            set.insert(range);
        }
        set
    }
}

impl Extend<Range> for AddrSet {
    fn extend<I: IntoIterator<Item = Range>>(&mut self, iter: I) {
        for range in iter {
            self.insert(range);
        }
    }
}

/// Appends `range` to a sorted canonical list whose ranges all start no
/// later than `range`, merging it with the last range if they overlap or
/// touch.
fn push_merged(out: &mut Vec<Range>, range: Range) {
    if let Some(last) = out.last_mut()
        && (range.first <= last.last || range.first - last.last == 1)
    {
        last.last = last.last.max(range.last);
        return;
    }
    out.push(range);
}

/// Merges two canonical lists of one family.
fn union(a: &[Range], b: &[Range]) -> Vec<Range> {
    let mut out = Vec::with_capacity(a.len() + b.len());
    let (mut i, mut j) = (0, 0);
    while i < a.len() || j < b.len() {
        // Take whichever starts first, so `out` stays sorted by start.
        let take_a = j == b.len() || (i < a.len() && a[i].first <= b[j].first);
        let next = if take_a {
            i += 1;
            a[i - 1]
        } else {
            j += 1;
            b[j - 1]
        };
        push_merged(&mut out, next);
    }
    out
}

/// Returns the addresses of `a` that are not in `b`.
///
/// `a` and `b` are canonical lists of one family.
fn subtract(a: &[Range], b: &[Range]) -> Vec<Range> {
    let mut out = Vec::with_capacity(a.len());
    let mut j = 0;
    for &range in a {
        // `b` ranges that end before this one starts cannot cut it, nor any
        // later range of `a`.
        while j < b.len() && b[j].last < range.first {
            j += 1;
        }
        let mut first = range.first;
        let mut k = j;
        let mut whole_cut = false;
        while k < b.len() && b[k].first <= range.last {
            let cut = b[k];
            if cut.first > first {
                out.push(Range {
                    first,
                    last: cut.first - 1,
                    ..range
                });
            }
            if cut.last >= range.last {
                whole_cut = true;
                break;
            }
            first = cut.last + 1;
            k += 1;
        }
        if !whole_cut {
            out.push(Range { first, ..range });
        }
        // A cut that reaches past this range may cut the next one too, so
        // `j` stays at the first cut that has not ended.
    }
    out
}

/// Returns the addresses in both `a` and `b`.
///
/// `a` and `b` are canonical lists of one family.
fn intersect(a: &[Range], b: &[Range]) -> Vec<Range> {
    let mut out = Vec::new();
    let (mut i, mut j) = (0, 0);
    while i < a.len() && j < b.len() {
        if let Some(common) = a[i].intersection(&b[j]) {
            // Pieces of disjoint, non-adjacent inputs are disjoint and
            // non-adjacent themselves, so no merge is needed.
            out.push(common);
        }
        // Drop the range that ends first. The other may meet the next one.
        if a[i].last < b[j].last {
            i += 1;
        } else {
            j += 1;
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::addr::Addr;

    fn range(s: &str) -> Range {
        s.parse().unwrap()
    }

    fn set(items: &[&str]) -> AddrSet {
        items.iter().map(|s| range(s)).collect()
    }

    fn printed(set: &AddrSet, family: Family) -> Vec<String> {
        set.prefixes(family)
            .iter()
            .map(ToString::to_string)
            .collect()
    }

    #[test]
    fn insert_merges_overlapping_and_adjacent() {
        let s = set(&["192.0.2.0/25", "192.0.2.128/25", "198.51.100.0/24"]);
        assert_eq!(printed(&s, Family::V4), ["192.0.2.0/24", "198.51.100.0/24"]);
        let s = set(&[
            "192.0.2.10-192.0.2.20",
            "192.0.2.15-192.0.2.30",
            "192.0.2.31",
        ]);
        assert_eq!(
            s.pieces().collect::<Vec<_>>(),
            [range("192.0.2.10-192.0.2.31")]
        );
        // A range swallowing several existing ones.
        let s = set(&["10.0.0.1", "10.0.0.5", "10.0.0.9", "10.0.0.0/28"]);
        assert_eq!(printed(&s, Family::V4), ["10.0.0.0/28"]);
        // Not adjacent: a gap of one address stays.
        let s = set(&["10.0.0.0", "10.0.0.2"]);
        assert_eq!(s.pieces().count(), 2);
    }

    #[test]
    fn families_stay_apart() {
        let s = set(&["2001:db8::/33", "192.0.2.0/24", "2001:db8:8000::/33"]);
        assert_eq!(printed(&s, Family::V4), ["192.0.2.0/24"]);
        assert_eq!(printed(&s, Family::V6), ["2001:db8::/32"]);
        // IPv4 comes first, as in the output of `-4 -6`.
        let pieces: Vec<_> = s.pieces().map(|r| r.family()).collect();
        assert_eq!(pieces, [Family::V4, Family::V6]);
        let mut only6 = s.clone();
        only6.retain_family(Families::V6);
        assert!(only6.prefixes(Family::V4).is_empty());
        assert_eq!(printed(&only6, Family::V6), ["2001:db8::/32"]);
    }

    #[test]
    fn subtract_leaves_the_prefixes_around_the_cut() {
        // `as.asn: 64510 and not ip: 10.88.55.0/24` on the route 10.88.0.0/18.
        let route = set(&["10.88.0.0/18"]);
        let cut = set(&["10.88.55.0/24"]);
        assert_eq!(
            printed(&route.subtract(&cut), Family::V4),
            [
                "10.88.0.0/19",
                "10.88.32.0/20",
                "10.88.48.0/22",
                "10.88.52.0/23",
                "10.88.54.0/24",
                "10.88.56.0/21",
            ]
        );
    }

    #[test]
    fn set_operations() {
        let a = set(&["10.0.0.0/24", "10.0.2.0/24", "10.0.4.0/24"]);
        let b = set(&["10.0.0.128/25", "10.0.1.0-10.0.2.127", "10.0.4.0/24"]);
        assert_eq!(
            printed(&a.union(&b), Family::V4),
            ["10.0.0.0/23", "10.0.2.0/24", "10.0.4.0/24"]
        );
        assert_eq!(
            printed(&a.intersect(&b), Family::V4),
            ["10.0.0.128/25", "10.0.2.0/25", "10.0.4.0/24"]
        );
        assert_eq!(
            printed(&a.subtract(&b), Family::V4),
            ["10.0.0.0/25", "10.0.2.128/25"]
        );
        assert!(a.subtract(&a).is_empty());
        assert_eq!(a.intersect(&AddrSet::new()), AddrSet::new());
        assert_eq!(a.union(&AddrSet::new()), a);
    }

    #[test]
    fn whole_address_space_edges() {
        let all6 = set(&["::/0"]);
        let top = set(&["ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"]);
        let rest = all6.subtract(&top);
        assert_eq!(rest.prefixes(Family::V6).len(), 128);
        assert_eq!(rest.union(&top), all6);
        let mut grow = rest.clone();
        grow.insert(range("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"));
        assert_eq!(grow, all6);
        let all4 = set(&["0.0.0.0/0"]);
        assert_eq!(
            all4.subtract(&set(&["0.0.0.0"])).union(&set(&["0.0.0.0"])),
            all4
        );
        assert!(all4.contains(&range("255.255.255.255")));
        assert!(!all4.contains(&range("::")));
    }

    #[test]
    fn contains_and_intersects() {
        let s = set(&["198.18.2.0/24", "198.18.100.0/24"]);
        assert!(s.contains(&range("198.18.2.128/25")));
        assert!(!s.contains(&range("198.18.2.0/23")));
        assert!(s.intersects(&range("198.18.2.0/23")));
        assert!(!s.intersects(&range("198.18.3.0/24")));
        assert!(s.intersects(&range("198.18.100.255-198.18.101.0")));
    }

    /// A linear congruential generator with Knuth's MMIX constants. It gives
    /// deterministic test data without a crate.
    struct Lcg(u64);

    impl Lcg {
        fn next(&mut self) -> u64 {
            self.0 = self
                .0
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            self.0 >> 33
        }

        fn below(&mut self, n: u64) -> u64 {
            self.next() % n
        }
    }

    /// The universe of the property tests: 256 addresses from `base`, so a
    /// bitmap is the model of a set.
    const SIZE: usize = 256;

    fn random_set(rng: &mut Lcg, family: Family, base: u128) -> (AddrSet, [bool; SIZE]) {
        let mut set = AddrSet::new();
        let mut model = [false; SIZE];
        for _ in 0..rng.below(6) {
            let a = rng.below(SIZE as u64) as usize;
            let b = (a + rng.below(40) as usize).min(SIZE - 1);
            set.insert(Range::new(family, base + a as u128, base + b as u128).unwrap());
            model[a..=b].iter_mut().for_each(|bit| *bit = true);
        }
        (set, model)
    }

    /// Checks the invariant and that `set` holds exactly the model.
    fn check(set: &AddrSet, family: Family, base: u128, model: &[bool; SIZE]) {
        let list = set.ranges(family);
        for pair in list.windows(2) {
            assert!(pair[0].last + 1 < pair[1].first, "not canonical: {list:?}");
        }
        let mut seen = [false; SIZE];
        for r in list {
            assert!(r.first >= base && r.last - base < SIZE as u128);
            for x in r.first..=r.last {
                seen[(x - base) as usize] = true;
            }
        }
        assert_eq!(&seen, model);
        // The CIDR list covers the same addresses with aligned blocks.
        let mut cover = [false; SIZE];
        for p in set.prefixes(family) {
            let host = p.last() - p.first();
            assert!(host.wrapping_add(1).is_power_of_two() || host == u128::MAX);
            assert_eq!(p.first() & host, 0, "{p} is not aligned");
            for x in p.first()..=p.last() {
                cover[(x - base) as usize] = true;
            }
        }
        assert_eq!(&cover, model);
    }

    #[test]
    fn operations_match_a_bitmap_model() {
        let mut rng = Lcg(0x6e65_7466);
        for (family, base) in [
            (Family::V4, 0),
            (Family::V4, Family::V4.max() - (SIZE as u128 - 1)),
            (Family::V6, 0x2001_0db8 << 96),
            (Family::V6, u128::MAX - (SIZE as u128 - 1)),
        ] {
            for _ in 0..300 {
                let (a, ma) = random_set(&mut rng, family, base);
                let (b, mb) = random_set(&mut rng, family, base);
                check(&a, family, base, &ma);
                let model = |f: fn(bool, bool) -> bool| {
                    let mut m = [false; SIZE];
                    for i in 0..SIZE {
                        m[i] = f(ma[i], mb[i]);
                    }
                    m
                };
                check(&a.union(&b), family, base, &model(|x, y| x || y));
                check(&a.intersect(&b), family, base, &model(|x, y| x && y));
                check(&a.subtract(&b), family, base, &model(|x, y| x && !y));
                assert_eq!(a.union(&b), b.union(&a));
                assert_eq!(a.subtract(&b).union(&a.intersect(&b)), a);
            }
        }
    }

    /// Returns the fewest aligned blocks that cover `first..=last`.
    ///
    /// It uses dynamic programming over every block and is the reference
    /// for minimality.
    fn fewest_blocks(family: Family, first: u128, last: u128) -> usize {
        let n = (last - first + 1) as usize;
        let mut best = vec![usize::MAX; n + 1];
        best[n] = 0;
        for i in (0..n).rev() {
            let at = first + i as u128;
            for host in 0..=u32::from(family.bits()) {
                let size = 1u128 << host.min(127);
                if (host > 0 && !at.is_multiple_of(size)) || (i as u128) + size > n as u128 {
                    break;
                }
                let next = i + size as usize;
                if best[next] != usize::MAX {
                    best[i] = best[i].min(best[next] + 1);
                }
            }
        }
        best[0]
    }

    #[test]
    fn range_prefixes_are_minimal() {
        let mut rng = Lcg(42);
        for (family, base) in [
            (Family::V4, 0x0a00_0000),
            (Family::V4, Family::V4.max() - 511),
            (Family::V6, u128::MAX - 511),
        ] {
            for _ in 0..300 {
                let a = rng.below(512) as u128;
                let b = (a + rng.below(300) as u128).min(511);
                let r = Range::new(family, base + a, base + b).unwrap();
                let cover: Vec<Prefix> = r.prefixes().collect();
                // Exact, ordered, and contiguous.
                assert_eq!(cover.first().unwrap().first(), r.first());
                assert_eq!(cover.last().unwrap().last(), r.last());
                for pair in cover.windows(2) {
                    assert_eq!(pair[0].last() + 1, pair[1].first());
                }
                assert_eq!(
                    cover.len(),
                    fewest_blocks(family, r.first(), r.last()),
                    "{r}"
                );
                assert_eq!(r.as_prefix().is_some(), cover.len() == 1);
            }
        }
    }

    #[test]
    fn from_prefix_and_addr() {
        let p: Prefix = "192.0.2.0/24".parse().unwrap();
        let s = AddrSet::from(p);
        assert_eq!(s.prefixes(Family::V4), [p]);
        let addr: Addr = "192.0.2.1".parse().unwrap();
        assert!(s.contains(&Range::from_addr(addr)));
        let mut e = AddrSet::new();
        e.extend([range("10.0.0.0/9"), range("10.128.0.0/9")]);
        assert_eq!(printed(&e, Family::V4), ["10.0.0.0/8"]);
    }
}
