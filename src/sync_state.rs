use crate::bencode::{decode, encode};
use crate::protocol::{EntryState, EntryType, FileMetadata};
use anyhow::{Context, Result};
use fs2::FileExt;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fs::{self, File};
use std::path::{Path, PathBuf};

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct StateRecord {
    pub entry_type: u8,
    pub state: u8,
    pub metadata_hash: String,
    pub owner: String,
    pub otime: i64,
    pub write_times: i64,
    pub perm: u32,
    pub size: u64,
    pub npieces: usize,
    pub mtime: i64,
    pub time: i64,
    pub file_hash: String,
    pub signature: String,
    pub local_fingerprint: String,
    #[serde(default)]
    pub sync_file_hash: String,
    #[serde(default)]
    pub sync_fingerprint: String,
    #[serde(default)]
    pub sync_metadata_hash: String,
    #[serde(default)]
    pub wire_main: Option<String>,
}

#[derive(Debug, Default, Deserialize, Serialize)]
pub struct SyncState {
    pub version: u8,
    pub entries: BTreeMap<String, StateRecord>,
    /// The metadata signing key of the folder's writer, learned from a peer's
    /// identity message and remembered so a read-only folder can still relay
    /// the writer's entries after the writer goes offline.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub writer_public_key: Option<String>,
}

pub struct SyncStateStore {
    path: PathBuf,
    state: SyncState,
    _state_lock: File,
}

impl SyncStateStore {
    pub fn load(root: &Path) -> Result<Self> {
        let directory = root.join(".sync");
        fs::create_dir_all(&directory)
            .with_context(|| format!("create {}", directory.display()))?;
        let path = directory.join("rustsync-state.json");
        let lock_path = directory.join("rustsync-state.lock");
        let state_lock = File::options()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .open(&lock_path)
            .with_context(|| format!("open {}", lock_path.display()))?;
        state_lock
            .lock_exclusive()
            .with_context(|| format!("lock {}", lock_path.display()))?;
        let state = if path.exists() {
            serde_json::from_slice(
                &fs::read(&path).with_context(|| format!("read {}", path.display()))?,
            )
            .with_context(|| format!("parse {}", path.display()))?
        } else {
            SyncState {
                version: 1,
                ..SyncState::default()
            }
        };
        Ok(Self {
            path,
            state,
            _state_lock: state_lock,
        })
    }

    pub fn save(&self) -> Result<()> {
        let payload = serde_json::to_vec_pretty(&self.state)?;
        let temporary = self.path.with_extension("json.tmp");
        fs::write(&temporary, payload).with_context(|| format!("write {}", temporary.display()))?;
        fs::rename(&temporary, &self.path)
            .with_context(|| format!("commit {}", self.path.display()))?;
        Ok(())
    }

    pub fn get(&self, path: &str) -> Option<&StateRecord> {
        self.state.entries.get(path)
    }

    pub fn entries(&self) -> impl Iterator<Item = (&String, &StateRecord)> {
        self.state.entries.iter()
    }

    pub fn metadata_values(&self) -> Vec<FileMetadata> {
        self.state
            .entries
            .keys()
            .filter_map(|path| self.metadata(path))
            .collect()
    }

    pub fn insert_metadata(&mut self, metadata: &FileMetadata, local_fingerprint: &str) {
        self.insert(metadata, local_fingerprint);
    }

    pub fn insert(&mut self, metadata: &FileMetadata, local_fingerprint: &str) {
        self.insert_with_sync(metadata, local_fingerprint, true);
    }

    pub fn insert_local(&mut self, metadata: &FileMetadata, local_fingerprint: &str) {
        self.insert_with_sync(metadata, local_fingerprint, false);
    }

    fn insert_with_sync(
        &mut self,
        metadata: &FileMetadata,
        local_fingerprint: &str,
        update_sync: bool,
    ) {
        let previous = self.state.entries.get(&metadata.wire_path_string());
        let file_hash = hex::encode(metadata.file_hash);
        let (sync_file_hash, sync_fingerprint, sync_metadata_hash) = if update_sync {
            (
                file_hash.clone(),
                local_fingerprint.to_owned(),
                hex::encode(metadata.metadata_hash()),
            )
        } else if let Some(previous) = previous {
            (
                if previous.sync_file_hash.is_empty() {
                    previous.file_hash.clone()
                } else {
                    previous.sync_file_hash.clone()
                },
                if previous.sync_fingerprint.is_empty() {
                    previous.local_fingerprint.clone()
                } else {
                    previous.sync_fingerprint.clone()
                },
                if previous.sync_metadata_hash.is_empty() {
                    previous.metadata_hash.clone()
                } else {
                    previous.sync_metadata_hash.clone()
                },
            )
        } else {
            (
                file_hash.clone(),
                local_fingerprint.to_owned(),
                hex::encode(metadata.metadata_hash()),
            )
        };
        let record = StateRecord {
            entry_type: metadata.entry_type.wire_value() as u8,
            state: metadata.state.wire_value() as u8,
            metadata_hash: hex::encode(metadata.metadata_hash()),
            owner: hex::encode(metadata.owner),
            otime: metadata.otime,
            write_times: metadata.write_times,
            perm: metadata.mode,
            size: metadata.size,
            npieces: metadata.piece_count,
            mtime: metadata.mtime_seconds,
            time: metadata.time_seconds,
            file_hash,
            signature: hex::encode(&metadata.signature),
            local_fingerprint: local_fingerprint.to_owned(),
            sync_file_hash,
            sync_fingerprint,
            sync_metadata_hash,
            wire_main: metadata
                .encrypted_main
                .as_ref()
                .map(|main| hex::encode(encode(main))),
        };
        self.state
            .entries
            .insert(metadata.wire_path_string(), record);
    }

    pub fn metadata(&self, path: &str) -> Option<FileMetadata> {
        let record = self.state.entries.get(path)?;
        let relative_path = path.split('/').map(str::to_owned).collect();
        let entry_type = match record.entry_type {
            1 => EntryType::RegularFile,
            2 => EntryType::Directory,
            _ => return None,
        };
        let state = match record.state {
            1 => EntryState::Active,
            2 => EntryState::Deleted,
            _ => return None,
        };
        let mut metadata = FileMetadata {
            relative_path,
            entry_type,
            size: record.size,
            mode: record.perm,
            mtime_seconds: record.mtime,
            time_seconds: record.time,
            state,
            file_hash: decode_hash(&record.file_hash).unwrap_or([0; 20]),
            piece_count: record.npieces,
            piece_hashes: Vec::new(),
            random_prefix: Vec::new(),
            owner: decode_hash(&record.owner).unwrap_or([0; 20]),
            otime: record.otime,
            write_times: record.write_times,
            signature: hex::decode(&record.signature).unwrap_or_default(),
            encrypted_path: None,
            encrypted_epart: None,
            encrypted_main: None,
        };
        if let Some(encoded) = &record.wire_main {
            let bytes = hex::decode(encoded).ok()?;
            let main = decode(&bytes).ok()?;
            metadata.restore_encrypted_main(main).ok()?;
        }
        Some(metadata)
    }

    /// The writer identity this folder relays, when one has been observed.
    pub fn writer_public_key(&self) -> Option<[u8; 32]> {
        hex::decode(self.state.writer_public_key.as_deref()?)
            .ok()?
            .try_into()
            .ok()
    }

    /// Remember the writer identity announced by a peer.
    pub fn remember_writer_public_key(&mut self, public_key: &[u8; 32]) -> bool {
        let encoded = hex::encode(public_key);
        if self.state.writer_public_key.as_deref() == Some(encoded.as_str()) {
            return false;
        }
        self.state.writer_public_key = Some(encoded);
        true
    }

    pub fn local_fingerprint(&self, path: &str) -> Option<&str> {
        self.state
            .entries
            .get(path)
            .map(|record| record.local_fingerprint.as_str())
    }
}

pub fn local_fingerprint(metadata: &FileMetadata) -> String {
    let mut hasher = Sha256::new();
    hasher.update([metadata.entry_type.wire_value() as u8]);
    hasher.update(metadata.mode.to_le_bytes());
    if metadata.entry_type == EntryType::RegularFile {
        hasher.update(metadata.size.to_le_bytes());
        hasher.update(metadata.mtime_seconds.to_le_bytes());
        hasher.update(metadata.file_hash);
    }
    hex::encode(hasher.finalize())
}

fn decode_hash(value: &str) -> Option<[u8; 20]> {
    let decoded = hex::decode(value).ok()?;
    decoded.try_into().ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use tempfile::tempdir;

    #[test]
    fn state_store_persists_metadata_tombstone_and_local_baseline() {
        let root = tempdir().unwrap();
        let path = root.path().join("state.txt");
        fs::write(&path, b"baseline").unwrap();
        let owner = [7_u8; 20];
        let mut metadata = FileMetadata::from_path(&path, "state.txt", owner).unwrap();
        metadata.sign(&SigningKey::from_bytes(&[9_u8; 32])).unwrap();
        let fingerprint = local_fingerprint(&metadata);

        let mut store = SyncStateStore::load(root.path()).unwrap();
        store.insert_local(&metadata, &fingerprint);
        store.save().unwrap();
        drop(store);

        let mut store = SyncStateStore::load(root.path()).unwrap();
        assert_eq!(
            store.local_fingerprint("state.txt"),
            Some(fingerprint.as_str())
        );
        assert_eq!(
            store.get("state.txt").unwrap().sync_fingerprint,
            fingerprint
        );
        let mut tombstone = metadata.tombstone(1234);
        tombstone
            .sign(&SigningKey::from_bytes(&[9_u8; 32]))
            .unwrap();
        store.insert(&tombstone, &local_fingerprint(&tombstone));
        store.save().unwrap();
        drop(store);

        let store = SyncStateStore::load(root.path()).unwrap();
        let restored = store.metadata("state.txt").unwrap();
        assert_eq!(restored.state, EntryState::Deleted);
        assert_eq!(restored.time_seconds, 1234);
    }

    #[test]
    fn writer_public_key_round_trips_through_the_state_file() {
        let root = tempdir().unwrap();
        let mut store = SyncStateStore::load(root.path()).unwrap();
        assert_eq!(store.writer_public_key(), None);

        let key = [0x5a_u8; 32];
        assert!(store.remember_writer_public_key(&key));
        assert_eq!(store.writer_public_key(), Some(key));
        // Re-remembering the same key is a no-op so callers can skip a save.
        assert!(!store.remember_writer_public_key(&key));
        store.save().unwrap();
        drop(store);

        let store = SyncStateStore::load(root.path()).unwrap();
        assert_eq!(store.writer_public_key(), Some(key));
        // The store holds an exclusive lock while open, so it must be released
        // before the same state file is reopened.
        drop(store);

        // A different writer replaces the remembered one.
        let mut store = SyncStateStore::load(root.path()).unwrap();
        let replacement = [0x6b_u8; 32];
        assert!(store.remember_writer_public_key(&replacement));
        assert_eq!(store.writer_public_key(), Some(replacement));
    }

    #[test]
    fn state_store_holds_exclusive_lock_while_open() {
        let root = tempdir().unwrap();
        let store = SyncStateStore::load(root.path()).unwrap();
        let lock = File::open(root.path().join(".sync/rustsync-state.lock")).unwrap();
        assert!(lock.try_lock_exclusive().is_err());
        drop(store);
        lock.try_lock_exclusive().unwrap();
    }
}
