use crate::model::{Entry, EntryKind, Manifest, PIECE_SIZE};
use crate::selective::SyncSelection;
use anyhow::{bail, Context, Result};
use sha1::{Digest, Sha1};
use sha2::Sha256;
use std::fs::File;
use std::io::Read;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use walkdir::WalkDir;

pub fn scan_root(root: &Path) -> Result<Manifest> {
    scan_root_with_selection(root, &SyncSelection::all())
}

pub fn scan_root_with_selection(root: &Path, selection: &SyncSelection) -> Result<Manifest> {
    if !root.is_dir() {
        bail!("scan root is not a directory: {}", root.display());
    }
    let mut entries = Vec::new();
    for item in WalkDir::new(root)
        .sort_by_file_name()
        .into_iter()
        .filter_entry(|item| {
            let relative = item.path().strip_prefix(root).unwrap_or(item.path());
            if relative.as_os_str().is_empty() {
                return true;
            }
            let path = relative.to_string_lossy().replace('\\', "/");
            !path.split('/').any(|part| part == ".sync")
                && selection.allows_traversal(&path, item.file_type().is_dir())
        })
    {
        let item = item.with_context(|| format!("walking {}", root.display()))?;
        let relative = item
            .path()
            .strip_prefix(root)
            .context("entry is outside scan root")?;
        if relative.as_os_str().is_empty() {
            continue;
        }
        let path = relative.to_string_lossy().replace('\\', "/");
        if path.split('/').any(|part| part == ".sync") {
            continue;
        }
        if !selection.allows_path(&path) {
            continue;
        }
        if item.file_type().is_symlink() {
            bail!("symlinks are not supported: {}", item.path().display());
        }
        let metadata = item
            .metadata()
            .with_context(|| format!("stat {}", item.path().display()))?;
        let mode = metadata.permissions().mode() & 0o7777;
        let mtime_seconds = metadata.mtime();
        if metadata.is_dir() {
            entries.push(Entry {
                path,
                kind: EntryKind::Directory,
                size: 0,
                mode,
                uid: Some(metadata.uid()),
                gid: Some(metadata.gid()),
                mtime_seconds,
                file_hash: None,
                pieces: vec![],
            });
        } else if metadata.is_file() {
            let (file_hash, pieces) = hash_file(item.path())?;
            entries.push(Entry {
                path,
                kind: EntryKind::File,
                size: metadata.len(),
                mode,
                uid: Some(metadata.uid()),
                gid: Some(metadata.gid()),
                mtime_seconds,
                file_hash: Some(file_hash),
                pieces,
            });
        } else {
            bail!("unsupported filesystem entry: {}", item.path().display());
        }
    }
    Manifest::new(entries)
}

pub fn hash_file(path: &Path) -> Result<(String, Vec<String>)> {
    let mut file = File::open(path).with_context(|| format!("open {}", path.display()))?;
    let mut content_hash = Sha256::new();
    let mut pieces = Vec::new();
    let mut buffer = vec![0_u8; PIECE_SIZE];
    loop {
        let mut filled = 0;
        while filled < buffer.len() {
            let count = file
                .read(&mut buffer[filled..])
                .with_context(|| format!("read {}", path.display()))?;
            if count == 0 {
                break;
            }
            filled += count;
        }
        if filled == 0 {
            break;
        }
        content_hash.update(&buffer[..filled]);
        let mut piece_hash = Sha1::new();
        piece_hash.update(&buffer[..filled]);
        pieces.push(hex::encode(piece_hash.finalize()));
        if filled < buffer.len() {
            break;
        }
    }
    Ok((hex::encode(content_hash.finalize()), pieces))
}

pub fn manifest_path(root: &Path) -> PathBuf {
    root.join(".rustsync-manifest.json")
}
