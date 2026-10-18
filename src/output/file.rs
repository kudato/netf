//! The `-f PATH` file: an adjacent `.NAME.lock`, renamed over `PATH`.
//! If the run fails, the old file stays as it was. The lock also holds the
//! replacement contents, so only one run can write a given output at a time.
//!
//! netf creates the lock exclusively before the run starts, so an occupied
//! name or an unwritable directory fails at once, before any downloads.
//! An existing entry, including a symbolic link, is left untouched.
//! The temporary file gets the permissions of the umask, like any new file.
//! netf removes the temporary file if the run fails or is interrupted.
//! A killed process can leave a lock behind. After checking that no run is
//! using it, remove it manually to allow another write.

use std::{
    ffi::OsString,
    fs::{self, File, OpenOptions},
    io::{self, Write as _},
    path::{Path, PathBuf},
};

use crate::error::{Error, Result};

/// The `-f` file, written through a temporary file.
#[derive(Debug)]
pub(crate) struct Output {
    /// The file to replace.
    path: PathBuf,
    /// The adjacent `.NAME.lock`. `None` once the rename consumes it.
    temp: Option<PathBuf>,
    /// The open temporary file. `None` once committed.
    file: Option<File>,
}

impl Output {
    /// Reserves `path` by creating its adjacent temporary file exclusively.
    ///
    /// # Errors
    ///
    /// Returns a runtime error if the name is already occupied, the path
    /// has no file name, or the temporary file cannot be created.
    pub(crate) fn create(path: &Path) -> Result<Self> {
        let file_name = path
            .file_name()
            .ok_or_else(|| failed(path, &"expected a file name"))?;
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
                    failed(path, &error)
                }
            })?;
        Ok(Self {
            path: path.to_owned(),
            temp: Some(temp),
            file: Some(file),
        })
    }

    /// Writes `bytes` and renames the temporary file over the target file.
    ///
    /// # Errors
    ///
    /// Returns a runtime error if the write, the sync, or the rename fails.
    pub(crate) fn commit(mut self, bytes: &[u8]) -> Result<()> {
        self.publish(bytes)
    }

    /// Publishes the complete contents and gives up ownership of the lock
    /// name. On failure, `Drop` still owns and removes the temporary file.
    fn publish(&mut self, bytes: &[u8]) -> Result<()> {
        let mut file = self
            .file
            .take()
            .ok_or_else(|| failed(&self.path, &"closed"))?;
        file.write_all(bytes)
            .and_then(|()| file.sync_all())
            .map_err(|error| failed(&self.path, &error))?;
        drop(file);
        let temp = self.temp.as_deref().expect("unpublished output");
        fs::rename(temp, &self.path).map_err(|error| failed(&self.path, &error))?;
        // Another run may reserve the same name as soon as rename returns.
        // Drop must not remove that run's file.
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
fn failed(path: &Path, error: &dyn std::fmt::Display) -> Error {
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
        let missing = dir.join("no-such-dir").join("out.txt");
        let error = Output::create(&missing).unwrap_err();
        assert!(error.to_string().contains("-f "), "{error}");
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
        // Force a write error without depending on the user's permissions.
        output.file = Some(File::open(&lock).unwrap());

        assert!(output.commit(b"new\n").is_err());

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
        // A directory that appeared during the run cannot be replaced by
        // the output file.
        fs::create_dir(&path).unwrap();
        fs::write(path.join("keep.txt"), "keep\n").unwrap();

        assert!(output.commit(b"new\n").is_err());

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
