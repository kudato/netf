//! Atomic replacement of the `-f PATH` output file.
//!
//! [`Output::create`] reserves `PATH` with a lock file in the same directory.
//! For example, `-f networks.txt` uses `.networks.txt.lock`.
//! The lock file holds the replacement contents.
//! If the lock path exists or the directory is unwritable, the run fails
//! before any downloads. An existing entry, including a symbolic link,
//! stays unchanged. On Unix, the umask controls the lock file permissions.
//!
//! [`Output::commit`] writes the result and calls [`File::sync_all`] before
//! it renames the lock file over `PATH`. If publication fails, `PATH` keeps
//! its previous contents. On failure or interruption, [`Drop`] attempts to
//! remove the lock file.
//!
//! Process termination without `Drop` can leave the lock file behind.
//! That file blocks later runs and requires manual removal after its writer
//! stops.

use std::{
    ffi::OsString,
    fs::{self, File, OpenOptions},
    io::{self, Write as _},
    path::{Path, PathBuf},
};

use crate::{
    config::io_reason,
    error::{Error, Result},
};

/// The output path and the lock file that holds its replacement contents.
#[derive(Debug)]
pub(crate) struct Output {
    /// The file to replace.
    path: PathBuf,
    /// The `.NAME.lock` path. `None` after a successful rename.
    temp: Option<PathBuf>,
    /// The open lock file. `None` after `publish` takes the handle.
    file: Option<File>,
}

impl Output {
    /// Creates the lock file with `create_new(true)` to reserve `path`.
    ///
    /// # Errors
    ///
    /// Returns a runtime error if `path` has no file name or the lock file
    /// cannot be created. An existing entry at the lock path, including a
    /// symbolic link, causes an error.
    pub(crate) fn create(path: &Path) -> Result<Self> {
        let file_name = path
            .file_name()
            .ok_or_else(|| failed(path, "expected a file name"))?;
        let mut name = OsString::from(".");
        name.push(file_name);
        name.push(".lock");
        let temp = path.with_file_name(name);
        let file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temp)
            .map_err(|error| {
                if error.kind() == io::ErrorKind::AlreadyExists {
                    failed(
                        path,
                        &format!("output is busy: {} already exists", temp.display()),
                    )
                } else {
                    failed(path, &io_reason(&error))
                }
            })?;
        Ok(Self {
            path: path.to_owned(),
            temp: Some(temp),
            file: Some(file),
        })
    }

    /// Writes `bytes` to the lock file, syncs it, and replaces the output file.
    ///
    /// # Errors
    ///
    /// Returns a runtime error if the write, the sync, or the rename fails.
    pub(crate) fn commit(mut self, bytes: &[u8]) -> Result<()> {
        self.publish(bytes)
    }

    /// Renames the lock file over the output file after the write and sync.
    /// On error, `Drop` attempts to remove the lock file.
    /// After a successful rename, `Drop` leaves the lock path unchanged.
    fn publish(&mut self, bytes: &[u8]) -> Result<()> {
        let mut file = self
            .file
            .take()
            .ok_or_else(|| failed(&self.path, "closed"))?;
        file.write_all(bytes)
            .and_then(|()| file.sync_all())
            .map_err(|error| failed(&self.path, &io_reason(&error)))?;
        drop(file);
        let temp = self.temp.as_deref().expect("unpublished output");
        fs::rename(temp, &self.path).map_err(|error| failed(&self.path, &io_reason(&error)))?;
        // A new run can create a lock file as soon as `rename` returns.
        // Clear `temp` so `Drop` cannot remove the new lock file.
        self.temp = None;
        Ok(())
    }
}

impl Drop for Output {
    fn drop(&mut self) {
        drop(self.file.take());
        if let Some(temp) = self.temp.take() {
            let _ = fs::remove_file(temp);
        }
    }
}

/// Returns the runtime error `netf: -f PATH: <error>`.
fn failed(path: &Path, error: &str) -> Error {
    Error::runtime(format!("-f {}: {error}", path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dir(name: &str) -> PathBuf {
        let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("target")
            .join("test-output-file")
            .join(format!("{}-{name}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn assert_io_error(error: &Error, path: &Path) {
        assert_eq!(error.exit_code().code(), 1);
        let message = error.to_string();
        let prefix = format!("netf: -f {}: ", path.display());
        let reason = message.strip_prefix(&prefix).expect(&message);
        assert!(!reason.is_empty(), "{message}");
        assert!(!reason.contains("(os error "), "{message}");
    }

    #[test]
    fn replaces_the_file_on_commit() {
        let dir = dir("commit");
        let path = dir.join("out.txt");
        fs::write(&path, "old\n").unwrap();
        let output = Output::create(&path).unwrap();
        assert_eq!(fs::read_dir(&dir).unwrap().count(), 2);
        output.commit(b"new\n").unwrap();
        assert_eq!(fs::read_to_string(&path).unwrap(), "new\n");
        assert_eq!(fs::read_dir(&dir).unwrap().count(), 1);
    }

    #[test]
    fn keeps_the_old_file_on_failure() {
        let dir = dir("drop");
        let path = dir.join("out.txt");
        fs::write(&path, "old\n").unwrap();
        drop(Output::create(&path).unwrap());
        assert_eq!(fs::read_to_string(&path).unwrap(), "old\n");
        assert_eq!(fs::read_dir(&dir).unwrap().count(), 1);
        let missing = dir.join("no-such-dir (os error 123)").join("out.txt");
        let error = Output::create(&missing).unwrap_err();
        assert_io_error(&error, &missing);
    }

    #[test]
    fn existing_reservation_is_left_untouched() {
        let dir = dir("occupied");
        let path = dir.join("out.txt");
        let lock = dir.join(".out.txt.lock");
        fs::write(&path, "old\n").unwrap();
        fs::write(&lock, "another writer\n").unwrap();

        let error = Output::create(&path).unwrap_err();

        assert_eq!(error.exit_code().code(), 1);
        assert_eq!(
            error.to_string(),
            format!(
                "netf: -f {}: output is busy: {} already exists",
                path.display(),
                lock.display()
            )
        );
        assert_eq!(fs::read_to_string(&path).unwrap(), "old\n");
        assert_eq!(fs::read_to_string(&lock).unwrap(), "another writer\n");
    }

    #[cfg(unix)]
    #[test]
    fn reservation_symlinks_are_left_untouched() {
        use std::os::unix::fs::symlink;

        let dir = dir("symlinks");
        let path = dir.join("out.txt");
        let lock = dir.join(".out.txt.lock");
        let missing = dir.join("missing.txt");
        fs::write(&path, "old\n").unwrap();
        for target in [&path, &missing] {
            symlink(target, &lock).unwrap();

            let error = Output::create(&path).unwrap_err();

            assert!(error.to_string().contains("output is busy"), "{error}");
            assert_eq!(fs::read_link(&lock).unwrap(), *target);
            assert_eq!(fs::read_to_string(&path).unwrap(), "old\n");
            assert!(!missing.exists());
            fs::remove_file(&lock).unwrap();
        }
    }

    #[test]
    fn a_second_writer_is_rejected_until_the_first_finishes() {
        let dir = dir("writers");
        let path = dir.join("out.txt");
        fs::write(&path, "old\n").unwrap();
        let first = Output::create(&path).unwrap();

        let error = Output::create(&path).unwrap_err();
        assert!(error.to_string().contains("output is busy"), "{error}");
        first.commit(b"first\n").unwrap();
        assert_eq!(fs::read_to_string(&path).unwrap(), "first\n");

        Output::create(&path).unwrap().commit(b"second\n").unwrap();
        assert_eq!(fs::read_to_string(&path).unwrap(), "second\n");
        assert_eq!(fs::read_dir(&dir).unwrap().count(), 1);
    }

    #[test]
    fn write_errors_keep_the_old_file_and_release_the_reservation() {
        let dir = dir("write-error");
        let path = dir.join("out.txt");
        let lock = dir.join(".out.txt.lock");
        fs::write(&path, "old\n").unwrap();
        let mut output = Output::create(&path).unwrap();
        // A read-only handle makes `write_all` fail.
        output.file = Some(File::open(&lock).unwrap());

        let error = output.commit(b"new\n").unwrap_err();
        assert_io_error(&error, &path);

        assert_eq!(fs::read_to_string(&path).unwrap(), "old\n");
        assert!(!lock.exists());
        drop(Output::create(&path).unwrap());
        assert!(!lock.exists());
    }

    #[test]
    fn rename_errors_release_the_reservation() {
        let dir = dir("rename-error");
        let path = dir.join("out.txt");
        let lock = dir.join(".out.txt.lock");
        let output = Output::create(&path).unwrap();
        // A directory created after reservation makes `rename` fail.
        fs::create_dir(&path).unwrap();
        fs::write(path.join("keep.txt"), "keep\n").unwrap();

        let error = output.commit(b"new\n").unwrap_err();
        assert_io_error(&error, &path);

        assert!(!lock.exists());
        assert_eq!(fs::read_to_string(path.join("keep.txt")).unwrap(), "keep\n");
    }

    #[test]
    fn published_output_keeps_the_next_reservation() {
        let dir = dir("published");
        let path = dir.join("out.txt");
        let lock = dir.join(".out.txt.lock");
        let mut first = Output::create(&path).unwrap();
        first.publish(b"first\n").unwrap();
        let mut next = Output::create(&path).unwrap();
        next.file
            .as_mut()
            .unwrap()
            .write_all(b"next writer\n")
            .unwrap();

        drop(first);

        assert_eq!(fs::read_to_string(&lock).unwrap(), "next writer\n");
        assert_eq!(fs::read_to_string(&path).unwrap(), "first\n");
        drop(next);
        assert!(!lock.exists());
    }
}
