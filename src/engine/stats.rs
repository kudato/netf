//! The delegated stats of a run.
//!
//! With the cache, the five indexes answer every request. Without the
//! cache, every request would download the five files again, so the first
//! request reads every block into a snapshot in memory and later requests
//! are answered from the snapshot. Each file is downloaded once per run,
//! whatever the number of requests.

use tokio::sync::OnceCell;

use super::intervals::Intervals;
use crate::{
    addr::Range,
    dataset::stats::{StatsAnswer, StatsRequest},
    error::Result,
    model::{AsBlock, Block},
    sources::Sources,
};

/// The stats of one run.
#[derive(Debug, Default)]
pub(crate) struct Stats {
    /// Every block, read by the first request when there is no cache.
    snapshot: OnceCell<StatsAnswer>,
}

impl Stats {
    /// Answers `request` on the stats of all five registries.
    ///
    /// # Errors
    ///
    /// Returns an error if the stats cannot be read.
    pub(crate) async fn answer(
        &self,
        sources: &Sources,
        request: &StatsRequest,
    ) -> Result<StatsAnswer> {
        if request.is_empty() {
            return Ok(StatsAnswer::empty(request));
        }
        if !sources.is_streaming() {
            return sources.stats(request).await;
        }
        let snapshot = self
            .snapshot
            .get_or_try_init(|| async {
                sources
                    .stats(&StatsRequest {
                        all_blocks: true,
                        all_as: true,
                        ..StatsRequest::default()
                    })
                    .await
            })
            .await?;
        Ok(local(snapshot, request))
    }
}

/// Answers `request` from `all`, the answer for every block.
fn local(all: &StatsAnswer, request: &StatsRequest) -> StatsAnswer {
    let opaque_in = |opaque: &Option<std::sync::Arc<str>>, wanted: &[std::sync::Arc<str>]| {
        opaque
            .as_deref()
            .is_some_and(|id| wanted.iter().any(|w| w.eq_ignore_ascii_case(id)))
    };
    let intersecting = Intervals::new(request.intersecting.iter().map(|range| (*range, ())));
    let blocks = all
        .blocks
        .iter()
        .filter(|block| {
            request.all_blocks
                || request.by_cc.contains(&block.cc)
                || request.by_rir.contains(&block.rir)
                || opaque_in(&block.opaque_id, &request.by_opaque)
                || intersecting.intersects(block.range)
        })
        .cloned()
        .collect();
    let covering = request
        .covering
        .iter()
        .map(|range| narrowest(&all.blocks, *range).cloned())
        .collect();
    let as_blocks = all
        .as_blocks
        .iter()
        .filter(|block| {
            request.all_as
                || request.as_by_cc.contains(&block.cc)
                || request.as_by_rir.contains(&block.rir)
                || opaque_in(&block.opaque_id, &request.as_by_opaque)
                || as_in(block, request)
        })
        .cloned()
        .collect();
    StatsAnswer {
        blocks,
        covering,
        as_blocks,
    }
}

/// Returns the narrowest of `blocks` that holds `range`, or the first one
/// on a tie.
fn narrowest(blocks: &[Block], range: Range) -> Option<&Block> {
    let mut best: Option<&Block> = None;
    for block in blocks.iter().filter(|block| block.range.contains(&range)) {
        let size = block.range.last() - block.range.first();
        if best.is_none_or(|best| size < best.range.last() - best.range.first()) {
            best = Some(block);
        }
    }
    best
}

/// Returns `true` if the AS block holds a number in `request.asn`.
fn as_in(block: &AsBlock, request: &StatsRequest) -> bool {
    let ranges = request.asn.ranges();
    let next = ranges.partition_point(|(_, last)| *last < block.first);
    ranges
        .get(next)
        .is_some_and(|(first, _)| *first <= block.last)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        dataset::AsnSet,
        model::{Cc, Rir},
    };

    fn block(range: &str, rir: Rir, cc: &str, opaque: &str) -> Block {
        Block {
            rir,
            range: range.parse().unwrap(),
            cc: cc.parse::<Cc>().unwrap(),
            opaque_id: Some(opaque.into()),
        }
    }

    fn snapshot() -> StatsAnswer {
        StatsAnswer {
            blocks: vec![
                block("192.0.2.0/24", Rir::Ripencc, "XA", "A1"),
                block("192.0.2.0/25", Rir::Arin, "XE", "B2"),
                block("198.51.100.0/24", Rir::Arin, "XE", "B2"),
            ],
            covering: Vec::new(),
            as_blocks: vec![AsBlock {
                rir: Rir::Afrinic,
                first: 64508,
                last: 64510,
                cc: "XI".parse().unwrap(),
                opaque_id: Some("FEXAMPLE1".into()),
            }],
        }
    }

    #[test]
    fn answers_like_the_index() {
        let all = snapshot();
        let request = StatsRequest {
            covering: vec![
                "192.0.2.1/32".parse().unwrap(),
                "10.0.0.0/8".parse().unwrap(),
            ],
            by_opaque: vec!["b2".into()],
            asn: AsnSet::from_ranges([(64509, 64509)]),
            ..StatsRequest::default()
        };
        let answer = local(&all, &request);
        assert_eq!(answer.blocks, all.blocks[1..]);
        assert_eq!(answer.covering, [Some(all.blocks[1].clone()), None]);
        assert_eq!(answer.as_blocks, all.as_blocks);
        let request = StatsRequest {
            intersecting: vec!["192.0.2.200/32".parse().unwrap()],
            ..StatsRequest::default()
        };
        assert_eq!(local(&all, &request).blocks, all.blocks[..1]);
        assert!(local(&all, &StatsRequest::default()).as_blocks.is_empty());
    }
}
