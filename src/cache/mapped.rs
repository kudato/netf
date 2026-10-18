//! Reading cache files: `mmap` on Unix, a plain read elsewhere.
//!
//! The mapping needs `unsafe`, and this module allows it only in
//! `MappedFile::map`.
//!
//! A lookup touches a few pages of a 50 MB index, so a mapping is better
//! than a read. The file opens at once, and its memory is the page cache,
//! which runs share. On Windows, another process cannot replace a mapped
//! file with `rename`. The cache updates files with `rename`, so on
//! Windows netf reads the file into memory instead.

use std::{fs::File, io, path::Path};

/// The bytes of a cache file, mapped or read.
#[derive(Debug)]
pub(crate) struct MappedFile {
    inner: Inner,
}

#[derive(Debug)]
enum Inner {
    /// A read-only mapping of the whole file.
    #[cfg(unix)]
    Map(memmap2::Mmap),
    /// The bytes in memory: on Windows, for empty files, and in tests.
    Owned(Vec<u8>),
}

impl MappedFile {
    /// Opens a file, and maps it whole on Unix or reads it elsewhere.
    ///
    /// # Errors
    ///
    /// Returns an error if the file cannot be opened, mapped, or read.
    pub(crate) fn open(path: &Path) -> io::Result<Self> {
        let file = File::open(path)?;
        let len = file.metadata()?.len();
        if len == 0 {
            // Some systems fail to map zero bytes, and an empty file has
            // nothing to map.
            return Ok(Self::from_vec(Vec::new()));
        }
        Self::map(file)
    }

    /// Wraps bytes that are already in memory.
    pub(crate) fn from_vec(bytes: Vec<u8>) -> Self {
        Self {
            inner: Inner::Owned(bytes),
        }
    }

    /// Returns the contents of the file.
    pub(crate) fn bytes(&self) -> &[u8] {
        match &self.inner {
            #[cfg(unix)]
            Inner::Map(map) => map,
            Inner::Owned(bytes) => bytes,
        }
    }

    #[cfg(unix)]
    #[allow(unsafe_code)]
    fn map(file: File) -> io::Result<Self> {
        // SAFETY: The mapping is read-only, and netf never modifies a cache
        // file in place. It writes a new version to a temporary file and
        // renames that file over the old one (`cache/temp.rs`). The rename
        // leaves the mapped inode intact until it is unmapped, so the bytes
        // behind the slice cannot change while the slice is borrowed. A
        // program outside netf can still truncate the file and cause a
        // SIGBUS, a risk that every user of mmap accepts. Against damaged
        // contents, the readers check bounds on every access.
        let map = unsafe { memmap2::Mmap::map(&file)? };
        Ok(Self {
            inner: Inner::Map(map),
        })
    }

    #[cfg(not(unix))]
    fn map(mut file: File) -> io::Result<Self> {
        use std::io::Read as _;
        let mut bytes = Vec::new();
        file.read_to_end(&mut bytes)?;
        Ok(Self::from_vec(bytes))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fetch::testing::TempDir;

    #[test]
    fn maps_and_survives_replacement() {
        let dir = TempDir::new("mapped");
        let path = dir.path().join("f.bin");
        std::fs::write(&path, b"old contents").unwrap();
        let old = MappedFile::open(&path).unwrap();
        // A rename over the file leaves the mapping of the old inode intact.
        let next = dir.path().join("f.tmp");
        std::fs::write(&next, b"new").unwrap();
        std::fs::rename(&next, &path).unwrap();
        assert_eq!(old.bytes(), b"old contents");
        assert_eq!(MappedFile::open(&path).unwrap().bytes(), b"new");

        std::fs::write(&path, b"").unwrap();
        assert!(MappedFile::open(&path).unwrap().bytes().is_empty());
        assert!(MappedFile::open(&dir.path().join("missing")).is_err());
    }
}
