//! The `-f PATH` file: a temporary file next to `PATH`, renamed over it.
//! If the run fails, the old file stays as it was.
//!
//! netf creates the temporary file before the run starts, so a directory
//! that netf cannot write to fails the run at once, not after the downloads.
//! The temporary file gets the permissions of the umask, like any new file.
//! netf removes the temporary file if the run fails or is interrupted.

use std::{
    fs::{self, File, OpenOptions},
    io::Write as _,
    path::{Path, PathBuf},
};

use crate::error::{Error, Result};

/// The `-f` file, written through a temporary file.
#[derive(Debug)]
pub(crate) struct Output {
    /// The file to replace.
    path: PathBuf,
    /// The temporary file next to `path`: `PATH.tmp-<pid>`. Empty once the
    /// rename is done.
    temp: PathBuf,
    /// The open temporary file. `None` once committed.
    file: Option<File>,
}

impl Output {
    /// Creates the temporary file for `path`.
    ///
    /// # Errors
    ///
    /// Returns a runtime error if the temporary file cannot be created.
    pub(crate) fn create(path: &Path) -> Result<Self> {
        let mut name = path.file_name().unwrap_or_default().to_os_string();
        name.push(format!(".tmp-{}", std::process::id()));
        let temp = path.with_file_name(name);
        let file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(&temp)
            .map_err(|error| failed(path, &error))?;
        Ok(Self {
            path: path.to_owned(),
            temp,
            file: Some(file),
        })
    }

    /// Writes `bytes` and renames the temporary file over the target file.
    ///
    /// # Errors
    ///
    /// Returns a runtime error if the write, the sync, or the rename fails.
    pub(crate) fn commit(mut self, bytes: &[u8]) -> Result<()> {
        let mut file = self
            .file
            .take()
            .ok_or_else(|| failed(&self.path, &"closed"))?;
        file.write_all(bytes)
            .and_then(|()| file.sync_all())
            .map_err(|error| failed(&self.path, &error))?;
        drop(file);
        fs::rename(&self.temp, &self.path).map_err(|error| failed(&self.path, &error))?;
        // The rename moved the temporary file, so `drop` has nothing to
        // remove.
        self.temp = PathBuf::new();
        Ok(())
    }
}

impl Drop for Output {
    fn drop(&mut self) {
        if !self.temp.as_os_str().is_empty() {
            drop(self.file.take());
            let _ = fs::remove_file(&self.temp);
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
            .join(name);
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
}
