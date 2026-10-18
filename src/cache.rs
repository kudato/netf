//! The cache of datasets and registry responses.
//!
//! The cache lives in `~/.netf/cache` by default. A file is fresh for
//! `--ttl`. After that, netf revalidates it with its validators, and a 304
//! updates only its modification time. netf writes a new file next to the
//! old one and renames it into place, so an interrupted run never leaves a
//! half-written file. A file that fails its checks is reported as
//! `cache: <file>: corrupt, downloading again` and built again.
//! `--no-cache` neither reads nor writes the cache.
//!
//! [`Cache::load`] handles the whole life of a dataset file:
//!
//! 1. It opens `<dir>/<name>.bin` and checks the header
//!    ([`container::Layout`]). Then the dataset's `open` checks the
//!    sections. A damaged file is reported and removed. A file of another
//!    format version or URL is removed without a notice.
//! 2. A file younger than the TTL is used as is. The age is `now - mtime`,
//!    with `now` from the [`Clock`] of the run. With a TTL of zero, no file
//!    is fresh. A modification time in the future is always fresh, so a
//!    clock that went back does not empty the cache.
//! 3. Otherwise, it asks the source again, with a conditional request if
//!    the file has validators. A 304 sets the modification time to now and
//!    keeps the file. A 200 streams the body into the dataset's builder.
//!    It writes the builder's sections to a [`TempPath`], renames that file
//!    over the old one, and maps the new file.
//! 4. Any failure of the source is an error, even if an old file exists.
//!    netf does not answer from stale data.
//!
//! A lookup can find damage later, when an index points outside its section.
//! [`Cache::reload`] handles that case: it prints the same notice, then
//! downloads and builds the file again.
//!
//! The header stores the kind of a file as a `u16` code. Datasets define
//! their own codes (`dataset::Kind::code`). Codes from `0x100` up are
//! reserved for this module's own files: cached responses and the RIPE
//! counter.

pub(crate) mod container;
pub(crate) mod mapped;
pub(crate) mod responses;
pub(crate) mod ripe_limit;
pub(crate) mod temp;

use std::{
    fs,
    io::{self, BufWriter, Write as _},
    path::{Path, PathBuf},
    sync::Arc,
    time::{Duration, SystemTime},
};

use self::{
    container::{Corrupt, Invalid, Layout, Section},
    mapped::MappedFile,
    temp::TempPath,
};
use crate::{
    Clock,
    error::{Error, Result},
    fetch::{self, Fetched, Validators, lines::LineSink},
    report::{Notice, Reporter},
    transport::{Class, Transport},
};

/// The kind code of a cached RDAP or REST response.
pub(crate) const KIND_RESPONSE: u16 = 0x100;

/// The kind code of the RIPE limit counter.
pub(crate) const KIND_RIPE_LIMIT: u16 = 0x101;

/// The cache directory and how long its files are fresh.
pub(crate) struct Cache {
    dir: PathBuf,
    ttl: Duration,
    clock: Arc<dyn Clock>,
    reporter: Arc<dyn Reporter>,
}

/// One dataset file: its name, its kind, and its source.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Entry<'a> {
    /// The file name without `.bin`, which messages also use as the dataset
    /// name: `ris-v4`.
    pub(crate) name: &'static str,
    /// The kind code written in the header.
    pub(crate) kind: u16,
    /// The URL to download, after `NETF_SOURCE_BASE`.
    pub(crate) url: &'a str,
}

/// Builds the sections of a dataset file from the lines of its source.
pub(crate) trait Builder: LineSink + Send {
    /// Ends the input and returns the sections to write.
    ///
    /// # Errors
    ///
    /// Returns an error if the download is unusable, for example if it has
    /// no records. In that case the cache writes no file.
    fn finish(self) -> Result<Vec<Section>>;
}

/// An open cache file: its bytes and its checked header.
#[derive(Debug)]
pub(crate) struct CacheFile {
    map: MappedFile,
    layout: Layout,
}

impl CacheFile {
    /// Checks the header of `map`.
    ///
    /// # Errors
    ///
    /// Returns [`Invalid::Stale`] for another format version and
    /// [`Invalid::Corrupt`] for a damaged header.
    pub(crate) fn new(map: MappedFile) -> Result<Self, Invalid> {
        let layout = Layout::parse(map.bytes())?;
        Ok(Self { map, layout })
    }

    /// Returns the section `tag`.
    ///
    /// # Errors
    ///
    /// Returns [`Corrupt`] if the file has no such section.
    pub(crate) fn section(&self, tag: u16) -> Result<&[u8], Corrupt> {
        self.layout.section(self.map.bytes(), tag).ok_or(Corrupt)
    }
}

impl Cache {
    /// Returns a cache in `dir`.
    ///
    /// The directory is created on the first write. A `ttl` of zero makes
    /// every file stale.
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
        }
    }

    /// Returns the cache directory.
    #[cfg(test)] // Tests check the mode of the created directory.
    pub(crate) fn dir(&self) -> &Path {
        &self.dir
    }

    /// Returns the path of the file `name`.
    pub(crate) fn path(&self, name: &str) -> PathBuf {
        self.dir.join(format!("{name}.bin"))
    }

    /// Returns the dataset `entry` from the cache, or downloads and builds it.
    ///
    /// The cached file is used if it is fresh or if the source confirms that
    /// it is still valid, as the module documentation describes. `open`
    /// checks the sections of a file and wraps it. If `open` returns
    /// [`Corrupt`], the cache reports the file and builds it again.
    ///
    /// # Errors
    ///
    /// Returns an error if the source fails, the download is unusable, the
    /// file system fails, or the file just written does not open.
    pub(crate) async fn load<B, T>(
        &self,
        transport: &dyn Transport,
        entry: &Entry<'_>,
        make: impl FnOnce() -> B,
        open: impl Fn(CacheFile) -> Result<T, Corrupt>,
    ) -> Result<T>
    where
        B: Builder,
    {
        let path = self.path(entry.name);
        let existing = self.open_existing(&path, entry, &open)?;
        if let Some((_, validators, mtime)) = &existing
            && self.is_fresh(*mtime)
        {
            self.reporter.source(crate::Source::new(
                Class::Dataset(entry.name),
                Some(*mtime),
                validators.last_modified.clone(),
            ));
            return Ok(existing.expect("checked above").0);
        }
        let validators = existing
            .as_ref()
            .map(|(_, validators, _)| validators)
            .filter(|validators| !validators.is_empty());
        let class = Class::Dataset(entry.name);
        let body = match fetch::get(transport, entry.url, class, validators).await? {
            Fetched::NotModified => {
                let (value, validators, _) = existing.expect("304 only for a conditional request");
                self.touch(&path)?;
                self.reporter.source(crate::Source::new(
                    Class::Dataset(entry.name),
                    Some(self.clock.now()),
                    validators.last_modified,
                ));
                return Ok(value);
            }
            Fetched::Body(body) if !body.is_success() => return Err(body.status_error()),
            Fetched::Body(body) => body,
        };
        let validators = body.validators.clone();
        let mut builder = make();
        body.lines(&mut builder).await?;
        let sections = builder
            .finish()
            .map_err(|error| error.with_prefix(format_args!("{}: {}", entry.name, entry.url)))?;
        // Close the old file first, because Windows cannot replace a file
        // that is open.
        drop(existing);
        self.write(&path, entry, &validators, &sections)?;
        self.reporter.source(crate::Source::new(
            Class::Dataset(entry.name),
            Some(self.clock.now()),
            validators.last_modified.clone(),
        ));
        drop(sections);
        let reopened = MappedFile::open(&path)
            .map_err(|error| io_error(&path, &error))
            .and_then(|map| {
                CacheFile::new(map)
                    .ok()
                    .and_then(|file| open(file).ok())
                    .ok_or_else(|| {
                        Error::runtime(format!(
                            "cache: {}: the file just written is unreadable",
                            entry.name
                        ))
                    })
            })?;
        Ok(reopened)
    }

    /// Reports the file of `entry` as corrupt, removes it, and loads the
    /// dataset again.
    ///
    /// Callers use this method when a lookup finds damage after the file was
    /// opened.
    ///
    /// # Errors
    ///
    /// Returns the errors of [`Cache::load`].
    pub(crate) async fn reload<B, T>(
        &self,
        transport: &dyn Transport,
        entry: &Entry<'_>,
        make: impl FnOnce() -> B,
        open: impl Fn(CacheFile) -> Result<T, Corrupt>,
    ) -> Result<T>
    where
        B: Builder,
    {
        self.discard(entry.name, true);
        self.load(transport, entry, make, open).await
    }

    /// Opens the current file of `entry` if it is usable, and removes it
    /// otherwise.
    fn open_existing<T>(
        &self,
        path: &Path,
        entry: &Entry<'_>,
        open: &impl Fn(CacheFile) -> Result<T, Corrupt>,
    ) -> Result<Option<(T, Validators, SystemTime)>> {
        let map = match MappedFile::open(path) {
            Ok(map) => map,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(io_error(path, &error)),
        };
        let mtime = fs::metadata(path)
            .and_then(|metadata| metadata.modified())
            .map_err(|error| io_error(path, &error))?;
        let invalid = match CacheFile::new(map) {
            Ok(file) if file.layout.kind != entry.kind => Invalid::Corrupt,
            // Built from another URL, for example with another
            // `NETF_SOURCE_BASE`. The file is valid but holds another dataset.
            Ok(file) if file.layout.url != entry.url => Invalid::Stale,
            Ok(file) => {
                let validators = file.layout.validators.clone();
                match open(file) {
                    Ok(value) => return Ok(Some((value, validators, mtime))),
                    Err(Corrupt) => Invalid::Corrupt,
                }
            }
            Err(invalid) => invalid,
        };
        self.discard(entry.name, invalid == Invalid::Corrupt);
        Ok(None)
    }

    /// Removes the file `name`, and reports it as corrupt if `corrupt`.
    fn discard(&self, name: &str, corrupt: bool) {
        if corrupt {
            self.reporter.notice(&Notice::CacheCorrupt {
                file: name.to_owned(),
            });
        }
        // If the removal fails, the rename of the new file replaces the old
        // one.
        let _ = fs::remove_file(self.path(name));
    }

    /// Returns `true` if a file modified at `mtime` needs no revalidation.
    fn is_fresh(&self, mtime: SystemTime) -> bool {
        if self.ttl.is_zero() {
            return false;
        }
        match self.clock.now().duration_since(mtime) {
            Ok(age) => age < self.ttl,
            Err(_) => true,
        }
    }

    /// Sets the modification time of the file at `path` to now.
    fn touch(&self, path: &Path) -> Result<()> {
        fs::OpenOptions::new()
            .write(true)
            .open(path)
            .and_then(|file| file.set_modified(self.clock.now()))
            .map_err(|error| io_error(path, &error))
    }

    /// Writes a new file for `entry` and renames it into place.
    fn write(
        &self,
        path: &Path,
        entry: &Entry<'_>,
        validators: &Validators,
        sections: &[Section],
    ) -> Result<()> {
        self.create_dir()?;
        let mut temp = TempPath::create(path).map_err(|error| io_error(&self.dir, &error))?;
        let written = (|| {
            let mut out = BufWriter::with_capacity(1 << 16, temp.file());
            container::write(&mut out, entry.kind, validators, entry.url, sections)?;
            out.flush()?;
            drop(out);
            temp.file().set_modified(self.clock.now())
        })();
        written.map_err(|error| io_error(temp.path(), &error))?;
        temp.persist().map_err(|error| io_error(path, &error))
    }

    /// Creates the cache directory, with mode `0700` on Unix.
    fn create_dir(&self) -> Result<()> {
        let mut builder = fs::DirBuilder::new();
        builder.recursive(true);
        #[cfg(unix)]
        std::os::unix::fs::DirBuilderExt::mode(&mut builder, 0o700);
        builder
            .create(&self.dir)
            .map_err(|error| io_error(&self.dir, &error))
    }
}

/// Returns a file system error: `cache: <path>: <cause>`.
fn io_error(path: &Path, error: &io::Error) -> Error {
    Error::runtime(format!("cache: {}: {error}", path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        fetch::{
            lines::Control,
            testing::{Collect, FakeClock, Reply, Stub, TempDir},
        },
        transport::TransportError,
    };

    const URL: &str = "https://ftp.ripe.test/ripe/asnames/asn.txt";
    const DAY: Duration = Duration::from_secs(86_400);

    /// Joins the lines into section 1.
    #[derive(Default)]
    struct Join(Vec<u8>);

    impl LineSink for Join {
        fn line(&mut self, line: &[u8]) -> Result<Control> {
            self.0.extend_from_slice(line);
            self.0.push(b'\n');
            Ok(Control::Continue)
        }
    }

    impl Builder for Join {
        fn finish(self) -> Result<Vec<Section>> {
            if self.0.is_empty() {
                return Err(Error::runtime("no records"));
            }
            Ok(vec![Section::new(1, self.0)])
        }
    }

    fn open(file: CacheFile) -> Result<String, Corrupt> {
        let text = file.section(1)?;
        String::from_utf8(text.to_vec()).map_err(|_| Corrupt)
    }

    struct Fixture {
        dir: TempDir,
        clock: Arc<FakeClock>,
        reporter: Arc<Collect>,
        cache: Cache,
        stub: Stub,
    }

    impl Fixture {
        fn new(name: &str, ttl: Duration) -> Self {
            let dir = TempDir::new(name);
            let clock = Arc::new(FakeClock::new());
            let reporter = Arc::new(Collect::default());
            let cache = Cache::new(
                dir.path().join("cache"),
                ttl,
                clock.clone(),
                reporter.clone(),
            );
            Self {
                dir,
                clock,
                reporter,
                cache,
                stub: Stub::new(),
            }
        }

        async fn load(&self) -> Result<String> {
            self.load_from(URL).await
        }

        async fn load_from(&self, url: &str) -> Result<String> {
            let entry = Entry {
                name: "asn",
                kind: 3,
                url,
            };
            self.cache
                .load(&self.stub, &entry, Join::default, open)
                .await
        }

        fn file(&self) -> PathBuf {
            self.cache.path("asn")
        }

        fn files(&self) -> Vec<String> {
            let mut names: Vec<String> = fs::read_dir(self.dir.path().join("cache"))
                .unwrap()
                .map(|e| e.unwrap().file_name().into_string().unwrap())
                .collect();
            names.sort();
            names
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn builds_once_then_serves_from_disk() {
        let f = Fixture::new("cache-fresh", DAY);
        f.stub
            .on(URL, Reply::ok("64496 TEST-AS\n").header("ETag", "\"1\""));
        assert_eq!(f.load().await.unwrap(), "64496 TEST-AS\n");
        assert_eq!(f.load().await.unwrap(), "64496 TEST-AS\n");
        assert_eq!(f.stub.count(), 1);
        assert_eq!(f.files(), ["asn.bin"]);
        let mtime = fs::metadata(f.file()).unwrap().modified().unwrap();
        assert_eq!(mtime, f.clock.now());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            let mode = fs::metadata(f.cache.dir()).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o700);
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn ttl_and_304() {
        let f = Fixture::new("cache-304", DAY);
        f.stub.on(
            URL,
            Reply::ok("a\n")
                .header("ETag", "\"1\"")
                .header("Last-Modified", "Sat, 17 Oct 2026 00:00:00 GMT"),
        );
        f.load().await.unwrap();
        f.clock.advance(DAY - Duration::from_secs(1));
        f.load().await.unwrap();
        assert_eq!(f.stub.count(), 1, "still fresh");

        f.clock.advance(Duration::from_secs(1));
        f.stub.on(URL, Reply::status(304));
        assert_eq!(f.load().await.unwrap(), "a\n");
        let request = &f.stub.log()[1];
        assert_eq!(request.header("If-None-Match"), Some("\"1\""));
        assert_eq!(
            request.header("If-Modified-Since"),
            Some("Sat, 17 Oct 2026 00:00:00 GMT")
        );
        let mtime = fs::metadata(f.file()).unwrap().modified().unwrap();
        assert_eq!(mtime, f.clock.now(), "304 touches the file");

        f.clock.advance(DAY / 2);
        f.load().await.unwrap();
        assert_eq!(f.stub.count(), 2, "fresh again after the 304");

        f.clock.advance(DAY);
        f.stub.on(URL, Reply::ok("b\n").header("ETag", "\"2\""));
        assert_eq!(f.load().await.unwrap(), "b\n");
        assert_eq!(f.files(), ["asn.bin"]);
        assert!(f.reporter.lines().is_empty());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn damaged_and_truncated_files_are_rebuilt() {
        let f = Fixture::new("cache-corrupt", DAY);
        f.stub.on(URL, Reply::ok("a\n"));
        f.load().await.unwrap();
        let good = fs::read(f.file()).unwrap();
        let cases: Vec<Vec<u8>> = vec![
            b"garbage".to_vec(),
            Vec::new(),
            good[..good.len() - 1].to_vec(),
            good[..good.len() / 2].to_vec(),
            {
                // The kind of another dataset.
                let mut other = good.clone();
                other[6] ^= 0x7f;
                other
            },
            {
                // A section past the end of the file.
                let mut other = good.clone();
                let header_len = container::u32_at(&other, 8) as usize;
                let len_at = header_len - 8;
                other[len_at..header_len].copy_from_slice(&u64::MAX.to_le_bytes());
                other
            },
        ];
        for (i, damaged) in cases.into_iter().enumerate() {
            fs::write(f.file(), damaged).unwrap();
            f.stub.on(URL, Reply::ok("a\n"));
            assert_eq!(f.load().await.unwrap(), "a\n", "case {i}");
            assert_eq!(f.stub.count(), i + 2, "case {i} downloads again");
            assert_eq!(
                f.reporter.lines().last().unwrap(),
                "netf: cache: asn: corrupt, downloading again"
            );
            assert_eq!(f.reporter.lines().len(), i + 1);
        }
        assert_eq!(f.files(), ["asn.bin"]);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn a_file_rejected_by_its_dataset_is_corrupt() {
        let f = Fixture::new("cache-open", DAY);
        f.stub.on(URL, Reply::ok("a\n"));
        f.load().await.unwrap();
        // Valid header, but section 1 is not UTF-8.
        let mut bytes = Vec::new();
        container::write(
            &mut bytes,
            3,
            &Validators::default(),
            URL,
            &[Section::new(1, vec![0xff])],
        )
        .unwrap();
        fs::write(f.file(), bytes).unwrap();
        f.stub.on(URL, Reply::ok("b\n"));
        assert_eq!(f.load().await.unwrap(), "b\n");
        assert_eq!(f.reporter.lines().len(), 1);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn failures_keep_the_old_file_and_leave_no_temporary_one() {
        let f = Fixture::new("cache-fail", Duration::ZERO);
        f.stub.on(URL, Reply::ok("a\n").header("ETag", "\"1\""));
        f.load().await.unwrap();
        let before = fs::read(f.file()).unwrap();

        f.stub.on(URL, Reply::status(503));
        let error = f.load().await.unwrap_err();
        assert_eq!(error.message(), format!("asn: {URL}: HTTP 503"));

        f.stub.on(
            URL,
            Reply::ok("b\nc").cut(TransportError::Io("connection reset".into())),
        );
        let error = f.load().await.unwrap_err();
        assert_eq!(error.message(), format!("asn: {URL}: connection reset"));

        f.stub.on(URL, Reply::ok(""));
        let error = f.load().await.unwrap_err();
        assert_eq!(error.message(), format!("asn: {URL}: no records"));

        assert_eq!(fs::read(f.file()).unwrap(), before);
        assert_eq!(f.files(), ["asn.bin"]);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn reload_reports_and_downloads() {
        let f = Fixture::new("cache-reload", DAY);
        f.stub.on(URL, Reply::ok("a\n"));
        f.stub.on(URL, Reply::ok("b\n"));
        f.load().await.unwrap();
        let entry = Entry {
            name: "asn",
            kind: 3,
            url: URL,
        };
        let text = f
            .cache
            .reload(&f.stub, &entry, Join::default, open)
            .await
            .unwrap();
        assert_eq!(text, "b\n");
        assert_eq!(
            f.reporter.lines(),
            ["netf: cache: asn: corrupt, downloading again"]
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn mtime_in_the_future_is_fresh() {
        let f = Fixture::new("cache-future", DAY);
        f.stub.on(URL, Reply::ok("a\n"));
        f.load().await.unwrap();
        let file = fs::OpenOptions::new().write(true).open(f.file()).unwrap();
        file.set_modified(f.clock.now() + DAY * 10).unwrap();
        f.load().await.unwrap();
        assert_eq!(f.stub.count(), 1);
    }
}
