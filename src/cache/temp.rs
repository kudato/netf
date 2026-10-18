//! Temporary files next to their target.
//!
//! A temporary file is renamed into place on success and removed on drop,
//! so a failed or interrupted run leaves nothing behind. A killed process
//! skips the drop and can leave `<target>.tmp-<pid>-<n>`. The next writer
//! with the same pid takes the next `<n>`. In `responses/`, the sweep
//! removes such files.
//!
//! netf never writes a cache file in place. The new version goes to
//! `<target>.tmp-<pid>-<n>` in the same directory, so the rename stays on
//! one file system and is atomic. The new version replaces the target only
//! when it is complete, and a reader of the old file keeps the old inode.
//! Two processes that build the same file write different temporary files.
//! The last rename wins, and either version is correct.
//!
//! Dropping a [`TempPath`] that was not persisted removes the file, so an
//! error, a panic, or a Ctrl+C that drops the future leaves no temporary
//! file behind.

use std::{
    fs::{File, OpenOptions},
    io,
    path::{Path, PathBuf},
    sync::atomic::{AtomicU32, Ordering},
};

/// A temporary file that becomes `target` on [`TempPath::persist`].
#[derive(Debug)]
pub(crate) struct TempPath {
    path: PathBuf,
    target: PathBuf,
    file: Option<File>,
}

impl TempPath {
    /// Creates a new, empty temporary file next to `target`, with mode
    /// `0600` on Unix.
    ///
    /// # Errors
    ///
    /// Returns an error if `target` has no file name or the file cannot be
    /// created.
    pub(crate) fn create(target: &Path) -> io::Result<Self> {
        static NEXT: AtomicU32 = AtomicU32::new(0);
        let name = target.file_name().ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, "a target without a name")
        })?;
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
        loop {
            let mut temp = name.to_owned();
            temp.push(format!(
                ".tmp-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            let path = target.with_file_name(temp);
            match options.open(&path) {
                Ok(file) => {
                    return Ok(Self {
                        path,
                        target: target.to_owned(),
                        file: Some(file),
                    });
                }
                // A dead process with the same pid left this file. Take the
                // next number.
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
                Err(error) => return Err(error),
            }
        }
    }

    /// Returns the path of the temporary file.
    pub(crate) fn path(&self) -> &Path {
        &self.path
    }

    /// Returns the open file, for writing.
    pub(crate) fn file(&mut self) -> &mut File {
        self.file.as_mut().expect("the file is open until persist")
    }

    /// Closes the file and renames it over the target.
    ///
    /// # Errors
    ///
    /// Returns an error if the rename fails. In that case, the temporary
    /// file is removed on drop.
    pub(crate) fn persist(mut self) -> io::Result<()> {
        drop(self.file.take());
        std::fs::rename(&self.path, &self.target)?;
        // The file is now the target, so the drop must not remove it.
        self.path = PathBuf::new();
        Ok(())
    }
}

impl Drop for TempPath {
    fn drop(&mut self) {
        drop(self.file.take());
        if !self.path.as_os_str().is_empty() {
            let _ = std::fs::remove_file(&self.path);
        }
    }
}

#[cfg(test)]
mod tests {
    use std::io::Write as _;

    use super::*;
    use crate::fetch::testing::TempDir;

    fn names(dir: &Path) -> Vec<String> {
        let mut names: Vec<String> = std::fs::read_dir(dir)
            .unwrap()
            .map(|e| e.unwrap().file_name().into_string().unwrap())
            .collect();
        names.sort();
        names
    }

    #[test]
    fn persist_replaces_the_target() {
        let dir = TempDir::new("temp-persist");
        let target = dir.path().join("asn.bin");
        std::fs::write(&target, b"old").unwrap();
        let mut temp = TempPath::create(&target).unwrap();
        let name = temp
            .path()
            .file_name()
            .unwrap()
            .to_str()
            .unwrap()
            .to_owned();
        assert!(name.starts_with("asn.bin.tmp-"), "{name}");
        temp.file().write_all(b"new").unwrap();
        temp.persist().unwrap();
        assert_eq!(std::fs::read(&target).unwrap(), b"new");
        assert_eq!(names(dir.path()), ["asn.bin"]);
    }

    #[test]
    fn drop_removes_the_file() {
        let dir = TempDir::new("temp-drop");
        let target = dir.path().join("ris-v4.bin");
        {
            let mut a = TempPath::create(&target).unwrap();
            let b = TempPath::create(&target).unwrap();
            assert_ne!(a.path(), b.path());
            a.file().write_all(b"partial").unwrap();
            assert_eq!(names(dir.path()).len(), 2);
        }
        assert!(names(dir.path()).is_empty());
    }

    #[cfg(unix)]
    #[test]
    fn private_mode() {
        use std::os::unix::fs::PermissionsExt as _;
        let dir = TempDir::new("temp-mode");
        let temp = TempPath::create(&dir.path().join("x.bin")).unwrap();
        let mode = std::fs::metadata(temp.path()).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
    }
}
