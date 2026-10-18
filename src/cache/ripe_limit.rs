//! The counter of the RIPE limit on personal data, per egress.
//!
//! The RIPE limit is a daily limit. RIPE allows each IP address 1000
//! queries for personal data per UTC day. With `--ripe-emails`, netf stops
//! using an egress once it has sent that many.
//!
//! The file `ripe-limit.bin` in the cache directory is a container of kind
//! [`super::KIND_RIPE_LIMIT`]. Its section 1 is JSON:
//! `{"day": <UTC days since the epoch>, "egress": {"<id>": {"count": n,
//! "exhausted": bool}}}`. netf writes the file even with `--no-cache`,
//! because the limit belongs to the egress and not to the run. A query is
//! counted before it is sent, and the file is rewritten at once. A new UTC
//! day starts from zero. An egress is spent until the end of the day after
//! 1000 queries, or after RIPE responds with 429.
//!
//! The limit is a safeguard and not an exact account, so netf does not lock
//! the file. Each write merges with the file first, but two processes that
//! run at once can still lose an update.
//!
//! A missing or unreadable file counts as an empty counter, without a
//! notice. Unlike a dataset, the counter has no source to download again.

use std::{
    collections::BTreeMap,
    io::{self, Write as _},
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time::SystemTime,
};

use serde::{Deserialize, Serialize};

use super::{
    CacheFile, KIND_RIPE_LIMIT,
    container::{self, Section},
    io_error,
    mapped::MappedFile,
    responses::create_dir,
    temp::TempPath,
};
use crate::{Clock, error::Result, fetch::Validators, transport::EgressId};

/// The number of queries for personal data that one IP can send to RIPE in
/// a UTC day.
pub(crate) const DAILY_LIMIT: u32 = 1000;

/// The name of the file in the cache directory.
const FILE: &str = "ripe-limit.bin";

/// The section with the JSON state.
const STATE: u16 = 1;

/// The counter of one cache directory.
pub(crate) struct RipeLimit {
    dir: PathBuf,
    clock: Arc<dyn Clock>,
    state: Mutex<Counter>,
}

/// The state in memory: the state on disk and the round-robin position.
#[derive(Debug, Default)]
struct Counter {
    state: State,
    next: usize,
}

/// The JSON of the file.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
struct State {
    day: u64,
    egress: BTreeMap<String, Count>,
}

/// The queries that one egress sent today.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
struct Count {
    count: u32,
    exhausted: bool,
}

impl Count {
    fn spent(self) -> bool {
        self.exhausted || self.count >= DAILY_LIMIT
    }
}

impl RipeLimit {
    /// Opens the counter in the cache directory `dir`.
    ///
    /// The file is created on the first write.
    pub(crate) fn open(dir: PathBuf, clock: Arc<dyn Clock>) -> Self {
        let state = read(&dir.join(FILE)).unwrap_or_default();
        Self {
            dir,
            clock,
            state: Mutex::new(Counter { state, next: 0 }),
        }
    }

    /// Counts one query for the next egress in `egresses` that is not spent
    /// today, saves the counter, and returns that egress.
    ///
    /// The egresses take turns, round robin. Returns `None` if all of them
    /// are spent.
    ///
    /// # Errors
    ///
    /// Returns an error if the file cannot be written.
    pub(crate) fn take(&self, egresses: &[EgressId]) -> Result<Option<EgressId>> {
        let mut counter = self.lock();
        self.refresh(&mut counter.state);
        let len = egresses.len();
        for step in 0..len {
            let index = (counter.next + step) % len;
            let id = &egresses[index];
            let count = counter.state.egress.entry(id.0.to_string()).or_default();
            if count.spent() {
                continue;
            }
            count.count += 1;
            counter.next = index + 1;
            self.save(&counter.state)?;
            return Ok(Some(id.clone()));
        }
        Ok(None)
    }

    /// Records `egress` as spent until the end of the UTC day, and saves the
    /// counter.
    ///
    /// Callers use this method after RIPE responds with 429.
    ///
    /// # Errors
    ///
    /// Returns an error if the file cannot be written.
    pub(crate) fn exhaust(&self, egress: &EgressId) -> Result<()> {
        let mut counter = self.lock();
        self.refresh(&mut counter.state);
        counter
            .state
            .egress
            .entry(egress.0.to_string())
            .or_default()
            .exhausted = true;
        self.save(&counter.state)
    }

    /// Returns the number of `egresses` that are spent today.
    pub(crate) fn exhausted(&self, egresses: &[EgressId]) -> usize {
        let mut counter = self.lock();
        let today = day(self.clock.now());
        if counter.state.day != today {
            counter.state = State {
                day: today,
                ..State::default()
            };
        }
        egresses
            .iter()
            .filter(|id| {
                counter
                    .state
                    .egress
                    .get(&*id.0)
                    .is_some_and(|count| count.spent())
            })
            .count()
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Counter> {
        self.state
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
    }

    /// Starts a new day if the UTC day changed, and merges in the queries
    /// that other processes counted today.
    fn refresh(&self, state: &mut State) {
        let today = day(self.clock.now());
        if state.day != today {
            *state = State {
                day: today,
                ..State::default()
            };
        }
        if let Some(disk) = read(&self.dir.join(FILE))
            && disk.day == today
        {
            for (id, theirs) in disk.egress {
                let ours = state.egress.entry(id).or_default();
                ours.count = ours.count.max(theirs.count);
                ours.exhausted |= theirs.exhausted;
            }
        }
    }

    /// Writes `state` to a temporary file and renames that file into place.
    fn save(&self, state: &State) -> Result<()> {
        let path = self.dir.join(FILE);
        let json = serde_json::to_vec(state).expect("the counter serializes");
        create_dir(&self.dir)?;
        let mut temp = TempPath::create(&path).map_err(|error| io_error(&self.dir, &error))?;
        let written = (|| {
            let mut out = io::BufWriter::new(temp.file());
            container::write(
                &mut out,
                KIND_RIPE_LIMIT,
                &Validators::default(),
                "",
                &[Section::new(STATE, json)],
            )?;
            out.flush()
        })();
        written.map_err(|error| io_error(temp.path(), &error))?;
        temp.persist().map_err(|error| io_error(&path, &error))
    }
}

/// Reads the file, or returns `None` if it is missing or unusable.
fn read(path: &Path) -> Option<State> {
    let file = CacheFile::new(MappedFile::open(path).ok()?).ok()?;
    if file.layout.kind != KIND_RIPE_LIMIT {
        return None;
    }
    serde_json::from_slice(file.section(STATE).ok()?).ok()
}

/// Returns the UTC day of `time`, in days since the epoch.
fn day(time: SystemTime) -> u64 {
    time.duration_since(SystemTime::UNIX_EPOCH)
        .map_or(0, |since| since.as_secs() / 86_400)
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;
    use crate::fetch::testing::{FakeClock, TempDir};

    /// Moves `clock` forward to the next moment that is `seconds` after
    /// the start of a UTC day.
    fn at_time_of_day(clock: &FakeClock, seconds: u64) {
        let since = clock
            .now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let target = since - since % 86_400 + seconds;
        if target > since {
            clock.advance(Duration::from_secs(target - since));
        } else {
            clock.advance(Duration::from_secs(86_400 - (since - target)));
        }
    }

    #[test]
    fn counts_to_the_limit_then_stops() {
        let dir = TempDir::new("ripe-limit-count");
        let clock = Arc::new(FakeClock::new());
        let limit = RipeLimit::open(dir.path().to_owned(), clock.clone());
        let direct = vec![EgressId::direct()];
        for _ in 0..DAILY_LIMIT {
            assert_eq!(limit.take(&direct).unwrap(), Some(EgressId::direct()));
        }
        assert_eq!(limit.take(&direct).unwrap(), None);
        assert_eq!(limit.exhausted(&direct), 1);
        let state = read(&dir.path().join(FILE)).unwrap();
        assert_eq!(state.egress["direct"].count, DAILY_LIMIT);
    }

    #[test]
    fn a_new_utc_day_starts_from_zero() {
        let dir = TempDir::new("ripe-limit-day");
        let clock = Arc::new(FakeClock::new());
        at_time_of_day(&clock, 86_400 - 60);
        let limit = RipeLimit::open(dir.path().to_owned(), clock.clone());
        let direct = vec![EgressId::direct()];
        limit.exhaust(&EgressId::direct()).unwrap();
        assert_eq!(limit.take(&direct).unwrap(), None);
        // A minute before midnight, a new run sees the same day.
        let again = RipeLimit::open(dir.path().to_owned(), clock.clone());
        assert_eq!(again.take(&direct).unwrap(), None);
        assert_eq!(again.exhausted(&direct), 1);
        clock.advance(Duration::from_secs(60));
        assert_eq!(limit.exhausted(&direct), 0);
        assert_eq!(limit.take(&direct).unwrap(), Some(EgressId::direct()));
        let state = read(&dir.path().join(FILE)).unwrap();
        assert_eq!(
            state.egress["direct"],
            Count {
                count: 1,
                exhausted: false
            }
        );
        assert_eq!(state.day, day(clock.now()));
    }

    #[test]
    fn persists_and_merges_with_another_process() {
        let dir = TempDir::new("ripe-limit-merge");
        let clock = Arc::new(FakeClock::new());
        let direct = vec![EgressId::direct()];
        let first = RipeLimit::open(dir.path().to_owned(), clock.clone());
        let second = RipeLimit::open(dir.path().to_owned(), clock.clone());
        first.take(&direct).unwrap();
        first.take(&direct).unwrap();
        second.take(&direct).unwrap();
        let state = read(&dir.path().join(FILE)).unwrap();
        assert_eq!(state.egress["direct"].count, 3);
        second.exhaust(&EgressId::direct()).unwrap();
        assert_eq!(first.take(&direct).unwrap(), None);
    }
}
