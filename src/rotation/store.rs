//! The rotation state on disk.
//!
//! One JSON file per wallet, guarded by a lock file so that two processes
//! cannot hand out the same key index. Writes go through a temporary file and
//! a rename, so a crash leaves either the old state or the new one.

use std::fs::{self, File, OpenOptions, TryLockError};
use std::io::Write;
use std::path::{Path, PathBuf};

use alloy::primitives::Address;

use crate::error::{Error, Result};
use crate::rotation::state::{RotationState, STATE_VERSION};

fn io_error(path: &Path) -> impl FnOnce(std::io::Error) -> Error + '_ {
    move |e| Error::Io {
        path: path.display().to_string(),
        reason: e.to_string(),
    }
}

/// Opens `path` for writing, private to the user where the platform allows it.
pub(crate) fn create_private(path: &Path) -> std::io::Result<File> {
    let mut options = OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    options.open(path)
}

/// Writes `contents` to `path` atomically, readable by the user only.
///
/// The data is written to a temporary file in the same directory, synced, and
/// renamed over `path`; the directory is then synced so the rename survives a
/// crash.
pub fn write_private(path: &Path, contents: &[u8]) -> Result<()> {
    let dir = path.parent().filter(|dir| !dir.as_os_str().is_empty());
    if let Some(dir) = dir {
        fs::create_dir_all(dir).map_err(io_error(dir))?;
    }
    let mut tmp = path.as_os_str().to_owned();
    tmp.push(format!(".tmp.{}", std::process::id()));
    let tmp = PathBuf::from(tmp);

    let mut file = create_private(&tmp).map_err(io_error(&tmp))?;
    file.write_all(contents).map_err(io_error(&tmp))?;
    file.sync_all().map_err(io_error(&tmp))?;
    drop(file);
    fs::rename(&tmp, path).map_err(io_error(path))?;
    if let Some(dir) = dir {
        // Best effort: directories cannot be opened for syncing everywhere.
        if let Ok(handle) = File::open(dir) {
            let _ = handle.sync_all();
        }
    }
    Ok(())
}

/// A locked rotation state file.
///
/// The lock is held until the value is dropped, so keep it for the whole
/// command: reserving an index, signing and recording the outcome must not
/// interleave with another process using the same wallet.
#[derive(Debug)]
pub struct StateFile {
    path: PathBuf,
    _lock: File,
    /// The state, as loaded or as last modified in memory
    pub state: RotationState,
}

impl StateFile {
    /// Opens (or creates in memory) the state at `path` for wallet `wallet_id`.
    ///
    /// Fails with [`Error::StateLocked`] if another process holds the lock, and
    /// with [`Error::Rotation`] if the file belongs to a different wallet or was
    /// written by a newer layout version.
    pub fn open(path: impl Into<PathBuf>, wallet_id: Address) -> Result<Self> {
        let path = path.into();
        if let Some(dir) = path.parent().filter(|dir| !dir.as_os_str().is_empty()) {
            fs::create_dir_all(dir).map_err(io_error(dir))?;
        }
        let mut lock_path = path.as_os_str().to_owned();
        lock_path.push(".lock");
        let lock_path = PathBuf::from(lock_path);
        let lock = create_private(&lock_path).map_err(io_error(&lock_path))?;
        match lock.try_lock() {
            Ok(()) => {}
            Err(TryLockError::WouldBlock) => {
                return Err(Error::StateLocked(path.display().to_string()))
            }
            Err(TryLockError::Error(e)) => return Err(io_error(&lock_path)(e)),
        }

        let state = match fs::read_to_string(&path) {
            Ok(json) => {
                let state: RotationState =
                    serde_json::from_str(&json).map_err(|e| Error::Io {
                        path: path.display().to_string(),
                        reason: format!("not a rotation state file: {e}"),
                    })?;
                if state.version != STATE_VERSION {
                    return Err(Error::Rotation(format!(
                        "{} has state version {}, this build reads version {STATE_VERSION}",
                        path.display(),
                        state.version
                    )));
                }
                if state.wallet_id != wallet_id {
                    return Err(Error::Rotation(format!(
                        "{} belongs to wallet {}, not {wallet_id}",
                        path.display(),
                        state.wallet_id
                    )));
                }
                state
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                RotationState::new(wallet_id, 1)
            }
            Err(e) => return Err(io_error(&path)(e)),
        };

        Ok(Self {
            path,
            _lock: lock,
            state,
        })
    }

    /// Where the state is stored.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Writes the state to disk and syncs it.
    ///
    /// Call this before acting on a change: an index must be on disk before
    /// its key is used, and an exposure before the signature leaves the process.
    pub fn save(&self) -> Result<()> {
        let json = serde_json::to_vec_pretty(&self.state)
            .map_err(|e| Error::Encoding(e.to_string()))?;
        write_private(&self.path, &json)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rotation::state::OwnerRef;

    const KEY: &str = "1:0x00000000000000000000000000000000000005AF";

    fn wallet() -> Address {
        Address::repeat_byte(0x11)
    }

    #[test]
    fn a_missing_file_starts_empty_and_saves_round_trip() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("nested").join("state.json");
        let mut file = StateFile::open(&path, wallet()).unwrap();
        assert_eq!(file.state, RotationState::new(wallet(), 1));
        assert!(!path.exists(), "nothing is written until save()");

        file.state
            .bind(
                KEY,
                OwnerRef::External {
                    address: Address::repeat_byte(0x22),
                },
            )
            .unwrap();
        file.save().unwrap();
        let saved = file.state.clone();
        drop(file);

        let reopened = StateFile::open(&path, wallet()).unwrap();
        assert_eq!(reopened.state, saved);
        assert_eq!(reopened.path(), path);
    }

    #[test]
    fn a_second_open_is_refused_while_the_first_holds_the_lock() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("state.json");
        let first = StateFile::open(&path, wallet()).unwrap();
        assert!(matches!(
            StateFile::open(&path, wallet()),
            Err(Error::StateLocked(_))
        ));
        drop(first);
        StateFile::open(&path, wallet()).unwrap();
    }

    #[test]
    fn a_file_for_another_wallet_or_version_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("state.json");
        StateFile::open(&path, wallet()).unwrap().save().unwrap();
        assert!(matches!(
            StateFile::open(&path, Address::repeat_byte(0x33)),
            Err(Error::Rotation(_))
        ));

        let mut newer = RotationState::new(wallet(), 1);
        newer.version = STATE_VERSION + 1;
        fs::write(&path, serde_json::to_vec(&newer).unwrap()).unwrap();
        assert!(matches!(
            StateFile::open(&path, wallet()),
            Err(Error::Rotation(_))
        ));

        fs::write(&path, b"not json").unwrap();
        assert!(matches!(
            StateFile::open(&path, wallet()),
            Err(Error::Io { .. })
        ));
    }

    #[cfg(unix)]
    #[test]
    fn files_are_private_to_the_user() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("state.json");
        let file = StateFile::open(&path, wallet()).unwrap();
        file.save().unwrap();
        let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);

        // A rewrite replaces the file and leaves no temporary file behind.
        file.save().unwrap();
        let names: Vec<_> = fs::read_dir(dir.path())
            .unwrap()
            .map(|entry| entry.unwrap().file_name().into_string().unwrap())
            .collect();
        assert!(
            names.iter().all(|name| !name.contains(".tmp.")),
            "{names:?}"
        );
    }
}
