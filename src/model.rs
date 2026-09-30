use anyhow::{bail, Result};
use serde::{Deserialize, Serialize};
use sha1::{Digest, Sha1};
use std::path::{Component, Path};

pub const MANIFEST_VERSION: u32 = 1;
pub const PIECE_SIZE: usize = 4 * 1024 * 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EntryKind {
    Directory,
    File,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct Entry {
    pub path: String,
    pub kind: EntryKind,
    pub size: u64,
    pub mode: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub uid: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gid: Option<u32>,
    pub mtime_seconds: i64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub file_hash: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub pieces: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct Manifest {
    pub version: u32,
    pub root_hash: String,
    pub entries: Vec<Entry>,
}

impl Manifest {
    pub fn new(mut entries: Vec<Entry>) -> Result<Self> {
        entries.sort_by(|left, right| left.path.cmp(&right.path));
        for entry in &entries {
            validate_relative_path(&entry.path)?;
        }
        let root_hash = root_hash(&entries)?;
        Ok(Self {
            version: MANIFEST_VERSION,
            root_hash,
            entries,
        })
    }

    pub fn validate(&self) -> Result<()> {
        if self.version != MANIFEST_VERSION {
            bail!("unsupported manifest version {}", self.version);
        }
        let expected = root_hash(&self.entries)?;
        if self.root_hash != expected {
            bail!("manifest root hash mismatch");
        }
        for entry in &self.entries {
            validate_relative_path(&entry.path)?;
            match entry.kind {
                EntryKind::File => {
                    if entry.file_hash.as_deref().unwrap_or_default().len() != 64 {
                        bail!("file entry {} has invalid SHA-256 hash", entry.path);
                    }
                    let expected_pieces = entry.size.div_ceil(PIECE_SIZE as u64) as usize;
                    if entry.pieces.len() != expected_pieces
                        || entry.pieces.iter().any(|piece| piece.len() != 40)
                    {
                        bail!("file entry {} has invalid piece hashes", entry.path);
                    }
                }
                EntryKind::Directory => {
                    if !entry.pieces.is_empty() || entry.file_hash.is_some() {
                        bail!("directory entry {} has file metadata", entry.path);
                    }
                }
            }
        }
        Ok(())
    }
}

pub fn validate_relative_path(path: &str) -> Result<()> {
    if path.is_empty() || Path::new(path).is_absolute() {
        bail!("path must be a non-empty relative path");
    }
    for component in Path::new(path).components() {
        match component {
            Component::Normal(value) if value != ".sync" => {}
            _ => bail!("path contains an unsafe component: {path}"),
        }
    }
    Ok(())
}

pub fn root_hash(entries: &[Entry]) -> Result<String> {
    let canonical = serde_json::to_vec(entries)?;
    let mut hasher = Sha1::new();
    hasher.update((canonical.len() as u64).to_be_bytes());
    hasher.update(canonical);
    Ok(hex::encode(hasher.finalize()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_unsafe_paths() {
        let absolute = Path::new(Component::RootDir.as_os_str())
            .join("etc")
            .join("passwd");
        let traversal = Path::new(Component::ParentDir.as_os_str())
            .join("etc")
            .join("passwd");
        assert!(validate_relative_path(&traversal.to_string_lossy()).is_err());
        assert!(validate_relative_path(&absolute.to_string_lossy()).is_err());
        assert!(validate_relative_path(".sync/ID").is_err());
        assert!(validate_relative_path("origin/file.txt").is_ok());
    }

    #[test]
    fn validates_manifest_hash() {
        let entries = vec![Entry {
            path: "a".into(),
            kind: EntryKind::Directory,
            size: 0,
            mode: 0o755,
            uid: None,
            gid: None,
            mtime_seconds: 1,
            file_hash: None,
            pieces: vec![],
        }];
        let mut manifest = Manifest::new(entries).unwrap();
        manifest.validate().unwrap();
        manifest.root_hash = "00".into();
        assert!(manifest.validate().is_err());
    }
}
