//! An index of ranges with values, searched by intersection.
//!
//! The engine indexes the networks of the rows and the ranges of a stats
//! request answered from memory.
//!
//! The items are sorted by family and first address. For each item, `reach`
//! is the greatest last address of the items up to it in its family. A
//! search walks back from the last item that starts no later than the end
//! of the range, and stops as soon as no earlier item can reach the range.

use std::cmp::Reverse;

use crate::addr::Range;

/// An index of ranges, each with a value.
#[derive(Clone, Debug)]
pub(crate) struct Intervals<T> {
    /// The items, sorted by family and first address, wider ranges first.
    items: Vec<(Range, T)>,
    /// For each item, the greatest last address of the items of its family
    /// up to it.
    reach: Vec<u128>,
}

impl<T> Default for Intervals<T> {
    fn default() -> Self {
        Self {
            items: Vec::new(),
            reach: Vec::new(),
        }
    }
}

impl<T> Intervals<T> {
    /// Builds the index of `items`.
    pub(crate) fn new(items: impl IntoIterator<Item = (Range, T)>) -> Self {
        let mut items: Vec<(Range, T)> = items.into_iter().collect();
        items.sort_by_key(|(range, _)| (range.family(), range.first(), Reverse(range.last())));
        let mut reach = Vec::with_capacity(items.len());
        let mut previous: Option<(crate::addr::Family, u128)> = None;
        for (range, _) in &items {
            let far = match previous {
                Some((family, far)) if family == range.family() => far.max(range.last()),
                _ => range.last(),
            };
            reach.push(far);
            previous = Some((range.family(), far));
        }
        Self { items, reach }
    }

    /// Returns the items that share an address with `range`, in the order
    /// of the index.
    pub(crate) fn intersecting(&self, range: Range) -> Vec<&(Range, T)> {
        let family = range.family();
        let end = self
            .items
            .partition_point(|(item, _)| (item.family(), item.first()) <= (family, range.last()));
        let mut found = Vec::new();
        for index in (0..end).rev() {
            let (item, _) = &self.items[index];
            if item.family() != family || self.reach[index] < range.first() {
                break;
            }
            if item.last() >= range.first() {
                found.push(&self.items[index]);
            }
        }
        found.reverse();
        found
    }

    /// Returns `true` if some item shares an address with `range`.
    pub(crate) fn intersects(&self, range: Range) -> bool {
        !self.intersecting(range).is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn range(text: &str) -> Range {
        text.parse().unwrap()
    }

    #[test]
    fn finds_what_intersects() {
        let index = Intervals::new([
            (range("10.0.0.0/8"), 1),
            (range("10.1.0.0/16"), 2),
            (range("10.200.0.0/16"), 3),
            (range("192.0.2.0/24"), 4),
            (range("2001:db8::/32"), 5),
        ]);
        let values = |text: &str| -> Vec<i32> {
            index
                .intersecting(range(text))
                .into_iter()
                .map(|(_, value)| *value)
                .collect()
        };
        assert_eq!(values("10.1.2.0/24"), [1, 2]);
        assert_eq!(values("10.250.0.0/16"), [1]);
        assert_eq!(values("10.0.0.0/8"), [1, 2, 3]);
        assert_eq!(values("192.0.2.128/25"), [4]);
        assert_eq!(values("198.51.100.0/24"), Vec::<i32>::new());
        assert_eq!(values("2001:db8:1::/48"), [5]);
        assert_eq!(values("::/0"), [5]);
    }
}
