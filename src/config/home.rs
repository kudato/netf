//! The netf home directory, `~/.netf`.
//!
//! [`prepare`] creates the directory on the first run, with mode 0700 and
//! an empty `config.toml` inside, and checks the directory on every run. On
//! unix, the directory must belong to the user that netf runs as, and the
//! group and others must have no access at all. Someone who can change the
//! config or the cache can change what netf prints, and the cache shows what
//! the user asked. A violation is a runtime error (code 1) that names the
//! owner or the mode, so the user can fix it, for example with
//! `chmod 700 ~/.netf`. On Windows, netf
//! skips the checks: there are no modes, and the profile directory is
//! private by default.
//!
//! The home directory comes from [`Environment::home`], so tests can point
//! it at a temporary directory.

use std::{fs, io, path::PathBuf};

use super::io_reason;
use crate::{
    Environment,
    error::{Error, Result},
};

/// The name of the directory in the home directory.
pub(crate) const DIR: &str = ".netf";
/// The name of the base config in [`DIR`].
pub(crate) const CONFIG: &str = "config.toml";
/// The base config as messages name it.
pub(crate) const CONFIG_NAME: &str = "~/.netf/config.toml";
/// The default cache directory in [`DIR`].
pub(crate) const CACHE: &str = "cache";

/// Creates `~/.netf` and `~/.netf/config.toml` if they do not exist, checks
/// the directory, and returns its path.
///
/// An existing directory is used as it is. An existing config is never
/// changed.
///
/// # Errors
///
/// Returns a runtime error (code 1) if the home directory is unknown, if
/// `~/.netf` or its config cannot be created, or if `~/.netf` is not a
/// directory or fails the checks.
pub(crate) fn prepare(env: &Environment) -> Result<PathBuf> {
    let home = env
        .home
        .as_ref()
        .ok_or_else(|| Error::runtime("cannot find the home directory for ~/.netf; set HOME"))?;
    let dir = home.join(DIR);
    match create_dir(&dir) {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
        Err(error) => {
            return Err(Error::runtime(format!(
                "~/.netf: cannot create: {}",
                io_reason(&error)
            )));
        }
    }
    // `fs::metadata` follows a symlink, so a `~/.netf` link is checked at
    // its target.
    let metadata = fs::metadata(&dir)
        .map_err(|error| Error::runtime(format!("~/.netf: {}", io_reason(&error))))?;
    if !metadata.is_dir() {
        return Err(Error::runtime("~/.netf is not a directory"));
    }
    check(&metadata)?;
    match fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(dir.join(CONFIG))
    {
        Ok(_) => {}
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
        Err(error) => {
            return Err(Error::runtime(format!(
                "{CONFIG_NAME}: cannot create: {}",
                io_reason(&error)
            )));
        }
    }
    Ok(dir)
}

/// Creates the directory.
///
/// On Unix, the directory is private from the start.
fn create_dir(dir: &std::path::Path) -> io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt as _;

        fs::DirBuilder::new().mode(0o700).create(dir)
    }
    #[cfg(not(unix))]
    fs::create_dir(dir)
}

/// Checks the owner and the mode of the directory.
#[cfg(unix)]
fn check(metadata: &fs::Metadata) -> Result<()> {
    use std::os::unix::fs::MetadataExt as _;

    // SAFETY: `geteuid` takes no arguments and touches no memory of this
    // process. POSIX says that it cannot fail.
    #[allow(unsafe_code)]
    let user = unsafe { libc::geteuid() };
    check_mode(metadata.mode(), metadata.uid(), user)
}

/// Checks nothing, because systems other than unix have no modes.
#[cfg(not(unix))]
fn check(_: &fs::Metadata) -> Result<()> {
    Ok(())
}

/// Checks the unix `mode` and `owner` of `~/.netf` against the effective
/// `user`.
#[cfg(any(unix, test))] // Off unix, only the tests call it.
fn check_mode(mode: u32, owner: u32, user: u32) -> Result<()> {
    if owner != user {
        return Err(Error::runtime(format!(
            "~/.netf belongs to another user (uid {owner}, netf runs as uid {user})"
        )));
    }
    if mode & 0o077 != 0 {
        return Err(Error::runtime(format!(
            "~/.netf is group- or world-accessible (mode {:04o}); expected 0700",
            mode & 0o7777
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn private_directory_passes() {
        assert_eq!(check_mode(0o040700, 501, 501), Ok(()));
        // The owner may have fewer rights than 0700 gives.
        assert_eq!(check_mode(0o040500, 501, 501), Ok(()));
    }

    #[test]
    fn open_mode_fails_with_the_mode() {
        let error = check_mode(0o040755, 501, 501).unwrap_err();
        assert_eq!(error.exit_code().code(), 1);
        assert_eq!(
            error.to_string(),
            "netf: ~/.netf is group- or world-accessible (mode 0755); expected 0700"
        );
        for mode in [0o710, 0o701, 0o720, 0o702, 0o740, 0o704] {
            assert!(check_mode(mode, 0, 0).is_err(), "{mode:o}");
        }
    }

    #[test]
    fn foreign_owner_fails() {
        let error = check_mode(0o040700, 0, 501).unwrap_err();
        assert_eq!(error.exit_code().code(), 1);
        assert_eq!(
            error.to_string(),
            "netf: ~/.netf belongs to another user (uid 0, netf runs as uid 501)"
        );
    }

    #[test]
    fn unknown_home_is_an_error() {
        let error = prepare(&Environment::default()).unwrap_err();
        assert_eq!(error.exit_code().code(), 1);
        assert!(error.to_string().contains("set HOME"));
    }
}
