//! Cached RDAP and REST responses, one file per request.
//!
//! The file `responses/<fnv1a64("GET <url>") hex>.bin` is a container of
//! kind [`super::KIND_RESPONSE`]. The URL in its header is the whole
//! request, `GET <url>`, and a read checks it. Section 1 holds the JSON of
//! the parsed response: the value that the caller stored, not the bytes of
//! the registry. A file for another request means a hash collision, and
//! the read counts it as a miss. Each response is written as soon as it
//! arrives, so an interrupted run keeps the responses it got.
//!
//! Freshness follows the rule for dataset files: a file is fresh if it is
//! younger than the TTL, no file is fresh with a TTL of zero, and a
//! modification time in the future is always fresh.
//!
//! At most once per TTL, a sweep removes the files older than the TTL,
//! including temporary files that killed runs left behind. The modification
//! time of `responses/.sweep` records the last sweep.

use std::{
    fs,
    io::{self, Write as _},
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, SystemTime},
};

use serde::{Serialize, de::DeserializeOwned};

use super::{
    CacheFile, KIND_RESPONSE,
    container::{self, Invalid, Section},
    io_error,
    mapped::MappedFile,
    temp::TempPath,
};
use crate::{
    Clock,
    error::Result,
    fetch::Validators,
    report::{Notice, Reporter},
    transport::Method,
};

/// The section with the JSON of the response.
const BODY: u16 = 1;

/// The marker file whose modification time records the last sweep.
const SWEEP_MARKER: &str = ".sweep";

/// The directory of cached responses.
pub(crate) struct Responses {
    dir: PathBuf,
    ttl: Duration,
    clock: Arc<dyn Clock>,
    reporter: Arc<dyn Reporter>,
    swept: AtomicBool,
}

impl Responses {
    /// Records the retrieval time of a response already read or stored successfully.
    pub(crate) fn observe(&self, method: Method, url: &str, class: crate::Class) {
        let path = self.dir.join(file_name(&key(method, url)));
        let checked = fs::metadata(path).and_then(|m| m.modified()).ok();
        self.reporter
            .source(crate::Source::new(class, checked, None));
    }

    /// Returns the responses in `dir`, which is `<cache dir>/responses`.
    ///
    /// The directory is created on the first write. A `ttl` of zero makes
    /// every response stale.
    pub(crate) fn new(
        dir: PathBuf,
        ttl: Duration,
        clock: Arc<dyn Clock>,
        reporter: Arc<dyn Reporter>,
    ) -> Self {
        Self {
            dir,
            ttl,
            clock,
            reporter,
            swept: AtomicBool::new(false),
        }
    }

    /// Returns the fresh response stored for `method url`, if any.
    ///
    /// A damaged file is reported and removed. A file of another format
    /// version is removed without a notice. Both cases are misses, like a
    /// hash collision.
    pub(crate) fn get<T: DeserializeOwned>(&self, method: Method, url: &str) -> Option<T> {
        self.sweep_once();
        let request = key(method, url);
        let name = file_name(&request);
        let path = self.dir.join(&name);
        let map = MappedFile::open(&path).ok()?;
        let mtime = fs::metadata(&path).and_then(|m| m.modified()).ok()?;
        if !self.is_fresh(mtime) {
            return None;
        }
        let corrupt = match CacheFile::new(map) {
            Ok(file) if file.layout.kind != KIND_RESPONSE => true,
            Ok(file) if file.layout.url != request => return None,
            Ok(file) => match file
                .section(BODY)
                .ok()
                .and_then(|body| serde_json::from_slice(body).ok())
            {
                Some(value) => return Some(value),
                None => true,
            },
            Err(Invalid::Stale) => false,
            Err(Invalid::Corrupt) => true,
        };
        if corrupt {
            let file = name.strip_suffix(".bin").unwrap_or(&name);
            self.reporter.notice(&Notice::CacheCorrupt {
                file: format!("responses/{file}"),
            });
        }
        let _ = fs::remove_file(&path);
        None
    }

    /// Stores `value` as the response for `method url`, and replaces the old
    /// response.
    ///
    /// # Errors
    ///
    /// Returns an error if `value` does not serialize or the file cannot be
    /// written.
    pub(crate) fn put<T: Serialize>(&self, method: Method, url: &str, value: &T) -> Result<()> {
        self.sweep_once();
        let request = key(method, url);
        let path = self.dir.join(file_name(&request));
        let body = serde_json::to_vec(value)
            .map_err(|error| io_error(&path, &io::Error::new(io::ErrorKind::InvalidData, error)))?;
        create_dir(&self.dir)?;
        let mut temp = TempPath::create(&path).map_err(|error| io_error(&self.dir, &error))?;
        let written = (|| {
            let mut out = io::BufWriter::new(temp.file());
            container::write(
                &mut out,
                KIND_RESPONSE,
                &Validators::default(),
                &request,
                &[Section::new(BODY, body)],
            )?;
            out.flush()?;
            drop(out);
            temp.file().set_modified(self.clock.now())
        })();
        written.map_err(|error| io_error(temp.path(), &error))?;
        temp.persist().map_err(|error| io_error(&path, &error))
    }

    /// Runs [`Responses::sweep`] on the first use in this run.
    fn sweep_once(&self) {
        if !self.swept.swap(true, Ordering::Relaxed) {
            self.sweep();
        }
    }

    /// Removes the files older than the TTL, unless the last sweep was less
    /// than a TTL ago.
    ///
    /// A file that cannot be removed stays, and the sweep goes on.
    pub(crate) fn sweep(&self) {
        let marker = self.dir.join(SWEEP_MARKER);
        if let Ok(mtime) = fs::metadata(&marker).and_then(|m| m.modified())
            && self.is_fresh(mtime)
        {
            return;
        }
        let Ok(entries) = fs::read_dir(&self.dir) else {
            return;
        };
        for entry in entries.flatten() {
            if entry.file_name() == SWEEP_MARKER {
                continue;
            }
            let Ok(metadata) = entry.metadata() else {
                continue;
            };
            if metadata.is_file()
                && let Ok(mtime) = metadata.modified()
                && !self.is_fresh(mtime)
            {
                let _ = fs::remove_file(entry.path());
            }
        }
        let _ = fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .open(&marker)
            .and_then(|file| file.set_modified(self.clock.now()));
    }

    /// Returns `true` if a file modified at `mtime` is still fresh.
    fn is_fresh(&self, mtime: SystemTime) -> bool {
        if self.ttl.is_zero() {
            return false;
        }
        match self.clock.now().duration_since(mtime) {
            Ok(age) => age < self.ttl,
            Err(_) => true,
        }
    }
}

/// Returns the request as the file stores it: `GET <url>`.
fn key(method: Method, url: &str) -> String {
    format!("{method} {url}")
}

/// Returns the file name of `request`: `<fnv1a64 hex>.bin`.
fn file_name(request: &str) -> String {
    format!("{:016x}.bin", fnv1a64(request.as_bytes()))
}

/// Returns the 64-bit FNV-1a hash of `bytes`.
pub(crate) fn fnv1a64(bytes: &[u8]) -> u64 {
    bytes.iter().fold(0xcbf2_9ce4_8422_2325, |hash, &byte| {
        (hash ^ u64::from(byte)).wrapping_mul(0x0100_0000_01b3)
    })
}

/// Creates `dir` and its parents, with mode `0700` on Unix.
///
/// # Errors
///
/// Returns an error if the directory cannot be created.
pub(crate) fn create_dir(dir: &Path) -> Result<()> {
    let mut builder = fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    std::os::unix::fs::DirBuilderExt::mode(&mut builder, 0o700);
    builder.create(dir).map_err(|error| io_error(dir, &error))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fetch::testing::{Collect, FakeClock, TempDir};

    const URL: &str = "https://rdap.example.test/ip/192.0.2.0/24";
    const DAY: Duration = Duration::from_secs(86_400);

    struct Fixture {
        _dir: TempDir,
        root: PathBuf,
        clock: Arc<FakeClock>,
        reporter: Arc<Collect>,
        responses: Responses,
    }

    impl Fixture {
        fn new(name: &str, ttl: Duration) -> Self {
            let dir = TempDir::new(name);
            let root = dir.path().join("responses");
            let clock = Arc::new(FakeClock::new());
            let reporter = Arc::new(Collect::default());
            let responses = Responses::new(root.clone(), ttl, clock.clone(), reporter.clone());
            Self {
                _dir: dir,
                root,
                clock,
                reporter,
                responses,
            }
        }

        /// Returns a new handle on the same directory, as in the next run.
        fn reopen(&self, ttl: Duration) -> Responses {
            Responses::new(
                self.root.clone(),
                ttl,
                self.clock.clone(),
                self.reporter.clone(),
            )
        }

        fn path(&self, url: &str) -> PathBuf {
            self.root.join(file_name(&key(Method::Get, url)))
        }

        /// Replaces the bytes of a file and sets its modification time to
        /// now, so the file stays fresh.
        fn overwrite(&self, path: &Path, bytes: &[u8]) {
            fs::write(path, bytes).unwrap();
            fs::OpenOptions::new()
                .write(true)
                .open(path)
                .and_then(|file| file.set_modified(self.clock.now()))
                .unwrap();
        }

        fn files(&self) -> Vec<String> {
            let mut names: Vec<_> = fs::read_dir(&self.root)
                .map(|entries| {
                    entries
                        .flatten()
                        .map(|e| e.file_name().to_string_lossy().into_owned())
                        .collect()
                })
                .unwrap_or_default();
            names.sort();
            names
        }
    }

    #[test]
    fn fnv1a64_matches_the_reference_values() {
        assert_eq!(fnv1a64(b""), 0xcbf2_9ce4_8422_2325);
        assert_eq!(fnv1a64(b"a"), 0xaf63_dc4c_8601_ec8c);
        assert_eq!(fnv1a64(b"foobar"), 0x8594_4171_f739_67e8);
    }

    #[test]
    fn stores_and_reads_back_until_the_ttl() {
        let fx = Fixture::new("responses-roundtrip", DAY);
        assert_eq!(fx.responses.get::<Vec<u32>>(Method::Get, URL), None);
        fx.responses.put(Method::Get, URL, &vec![1_u32, 2]).unwrap();
        assert_eq!(
            fx.responses.get::<Vec<u32>>(Method::Get, URL),
            Some(vec![1, 2])
        );
        // Another method or URL is another file.
        assert_eq!(fx.responses.get::<Vec<u32>>(Method::Post, URL), None);
        let other = format!("{URL}x");
        assert_eq!(fx.responses.get::<Vec<u32>>(Method::Get, &other), None);
        // A `None`, the response to a 404, is a value like any other.
        fx.responses
            .put::<Option<u32>>(Method::Get, &other, &None)
            .unwrap();
        assert_eq!(
            fx.responses.get::<Option<u32>>(Method::Get, &other),
            Some(None)
        );
        fx.clock.advance(DAY - Duration::from_secs(1));
        assert!(fx.reopen(DAY).get::<Vec<u32>>(Method::Get, URL).is_some());
        fx.clock.advance(Duration::from_secs(1));
        assert!(fx.reopen(DAY).get::<Vec<u32>>(Method::Get, URL).is_none());
        assert!(fx.reporter.lines().is_empty());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            let mode = fs::metadata(&fx.root).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o700);
        }
    }

    #[test]
    fn zero_ttl_is_never_fresh_and_future_mtime_is() {
        let fx = Fixture::new("responses-ttl", Duration::ZERO);
        fx.responses.put(Method::Get, URL, &1_u32).unwrap();
        assert_eq!(fx.responses.get::<u32>(Method::Get, URL), None);
        let fx = Fixture::new("responses-future", DAY);
        fx.responses.put(Method::Get, URL, &1_u32).unwrap();
        let file = fs::OpenOptions::new()
            .write(true)
            .open(fx.path(URL))
            .unwrap();
        file.set_modified(fx.clock.now() + DAY * 10).unwrap();
        assert_eq!(fx.responses.get::<u32>(Method::Get, URL), Some(1));
    }

    #[test]
    fn a_collision_is_a_miss() {
        let fx = Fixture::new("responses-collision", DAY);
        let other = "https://rdap.example.test/autnum/64496";
        fx.responses.put(Method::Get, other, &7_u32).unwrap();
        // Pretend `URL` hashes to the file of `other`.
        fs::create_dir_all(&fx.root).unwrap();
        fs::rename(fx.path(other), fx.path(URL)).unwrap();
        assert_eq!(fx.responses.get::<u32>(Method::Get, URL), None);
        assert!(fx.reporter.lines().is_empty());
        // The right response replaces the file.
        fx.responses.put(Method::Get, URL, &8_u32).unwrap();
        assert_eq!(fx.responses.get::<u32>(Method::Get, URL), Some(8));
    }

    #[test]
    fn damaged_files_are_reported_and_removed() {
        let fx = Fixture::new("responses-corrupt", DAY);
        fx.responses.put(Method::Get, URL, &1_u32).unwrap();
        let path = fx.path(URL);
        let bytes = fs::read(&path).unwrap();
        fx.overwrite(&path, &bytes[..bytes.len() - 1]);
        assert_eq!(fx.responses.get::<u32>(Method::Get, URL), None);
        assert!(!path.exists());
        let name = file_name(&key(Method::Get, URL));
        assert_eq!(
            fx.reporter.lines(),
            [format!(
                "netf: cache: responses/{}: corrupt, downloading again",
                name.strip_suffix(".bin").unwrap()
            )]
        );
        // A body of the wrong shape is damage too.
        fx.responses.put(Method::Get, URL, &"text").unwrap();
        assert_eq!(fx.responses.get::<u32>(Method::Get, URL), None);
        assert_eq!(fx.reporter.lines().len(), 2);
        // Another format version is dropped silently.
        fx.responses.put(Method::Get, URL, &1_u32).unwrap();
        let mut bytes = fs::read(&path).unwrap();
        bytes[4] = 9;
        fx.overwrite(&path, &bytes);
        assert_eq!(fx.responses.get::<u32>(Method::Get, URL), None);
        assert!(!path.exists());
        assert_eq!(fx.reporter.lines().len(), 2);
    }

    #[test]
    fn sweep_removes_old_files_at_most_once_per_ttl() {
        let hour = Duration::from_secs(3600);
        let fx = Fixture::new("responses-sweep", DAY);
        let old = "https://rdap.example.test/ip/198.51.100.0/24";
        fx.responses.put(Method::Get, old, &1_u32).unwrap();
        let temp = fx.root.join("0000000000000000.bin.tmp-1-1");
        fs::write(&temp, b"left").unwrap();
        fs::OpenOptions::new()
            .write(true)
            .open(&temp)
            .and_then(|file| file.set_modified(fx.clock.now()))
            .unwrap();
        // The first sweep with files removes nothing and sets the marker.
        fx.clock.advance(hour * 12);
        fx.reopen(DAY).sweep();
        assert_eq!(fx.files().len(), 3);
        assert!(fx.files().contains(&SWEEP_MARKER.to_owned()));
        fx.clock.advance(hour * 8);
        fx.responses.put(Method::Get, URL, &2_u32).unwrap();
        // The old response is stale now, but the last sweep is too recent.
        fx.clock.advance(hour * 10);
        fx.reopen(DAY).sweep();
        assert_eq!(fx.files().len(), 4);
        // One TTL after the last sweep, the sweep removes the old files and
        // keeps the younger ones.
        fx.clock.advance(hour * 7);
        let next = fx.reopen(DAY);
        assert_eq!(next.get::<u32>(Method::Get, URL), Some(2));
        let files = fx.files();
        assert_eq!(files.len(), 2, "{files:?}");
        assert!(files.contains(&SWEEP_MARKER.to_owned()));
        assert!(fx.path(URL).exists());
    }
}
