//! Reading and writing serializable results as JSON files.

use std::path::Path;

use serde::de::DeserializeOwned;
use serde::Serialize;

use crate::error::{Error, Result};

fn io_error(path: &Path, reason: impl std::fmt::Display) -> Error {
    Error::Io {
        path: path.display().to_string(),
        reason: reason.to_string(),
    }
}

/// Writes `value` to `path` as pretty-printed JSON, replacing the file.
pub(crate) fn write_file<T: Serialize>(path: &Path, value: &T) -> Result<()> {
    let json = serde_json::to_string_pretty(value).map_err(|e| io_error(path, e))?;
    std::fs::write(path, json).map_err(|e| io_error(path, e))
}

/// Reads a `T` from the JSON file at `path`.
pub(crate) fn read_file<T: DeserializeOwned>(path: &Path) -> Result<T> {
    let json = std::fs::read_to_string(path).map_err(|e| io_error(path, e))?;
    serde_json::from_str(&json)
        .map_err(|e| io_error(path, format!("not valid JSON for this type: {e}")))
}
