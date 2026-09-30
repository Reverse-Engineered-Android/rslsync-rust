use crate::model::{Entry, EntryKind, Manifest, PIECE_SIZE};
use crate::permissions::{apply_permissions, read_permissions, PermissionPolicy, PermissionRecord};
use anyhow::{bail, Context, Result};
use filetime::FileTime;
use sha1::{Digest, Sha1};
use sha2::Sha256;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConflictPolicy {
    Preserve,
    Overwrite,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ApplyPolicy {
    pub conflict: ConflictPolicy,
    pub permissions: PermissionPolicy,
}

pub fn apply_manifest(
    source_root: &Path,
    target_root: &Path,
    manifest: &Manifest,
    conflict: ConflictPolicy,
) -> Result<()> {
    apply_manifest_with_policy(
        source_root,
        target_root,
        manifest,
        ApplyPolicy {
            conflict,
            permissions: PermissionPolicy::Preserve,
        },
    )
}

pub fn apply_manifest_with_policy(
    source_root: &Path,
    target_root: &Path,
    manifest: &Manifest,
    policy: ApplyPolicy,
) -> Result<()> {
    manifest.validate()?;
    fs::create_dir_all(target_root).with_context(|| format!("create {}", target_root.display()))?;
    for entry in &manifest.entries {
        let source = source_root.join(&entry.path);
        let target = target_root.join(&entry.path);
        if policy.permissions == PermissionPolicy::CheckOnly {
            if !target.exists() {
                bail!("permission check target is missing: {}", target.display());
            }
            let actual = read_permissions(&target)?;
            apply_permissions(
                &target,
                PermissionRecord {
                    mode: entry.mode,
                    uid: entry.uid.unwrap_or(actual.uid),
                    gid: entry.gid.unwrap_or(actual.gid),
                },
                policy.permissions,
            )?;
            continue;
        }
        let previous_permissions = target
            .exists()
            .then(|| read_permissions(&target))
            .transpose()?;
        if entry.kind == EntryKind::File
            && target.exists()
            && policy.conflict == ConflictPolicy::Preserve
        {
            continue;
        }
        match entry.kind {
            EntryKind::Directory => fs::create_dir_all(&target)
                .with_context(|| format!("create directory {}", target.display()))?,
            EntryKind::File => apply_file(source, target.clone(), entry, policy.conflict)?,
        }
        if policy.permissions == PermissionPolicy::Ignore {
            if let Some(previous) = previous_permissions {
                apply_permissions(&target, previous, PermissionPolicy::Preserve)?;
            }
        } else {
            let actual = read_permissions(&target)?;
            apply_permissions(
                &target,
                PermissionRecord {
                    mode: entry.mode,
                    uid: entry.uid.unwrap_or(actual.uid),
                    gid: entry.gid.unwrap_or(actual.gid),
                },
                policy.permissions,
            )?;
        }
    }
    // Writing or renaming a child refreshes the modification time of its
    // parent directory, so directory timestamps can only be restored after
    // every entry below them exists. Without this the applied tree keeps the
    // fresh directory mtimes and its manifest root hash never matches the
    // source, which makes peers re-sync trees that are already identical.
    if policy.permissions != PermissionPolicy::CheckOnly {
        for entry in manifest.entries.iter().rev() {
            if entry.kind != EntryKind::Directory {
                continue;
            }
            let target = target_root.join(&entry.path);
            if !target.is_dir() {
                continue;
            }
            filetime::set_file_mtime(&target, FileTime::from_unix_time(entry.mtime_seconds, 0))?;
        }
    }
    Ok(())
}

fn apply_file(
    source: PathBuf,
    target: PathBuf,
    entry: &Entry,
    conflict: ConflictPolicy,
) -> Result<()> {
    if target.exists() && conflict == ConflictPolicy::Preserve {
        return Ok(());
    }
    if let Some(parent) = target.parent() {
        fs::create_dir_all(parent).with_context(|| format!("create {}", parent.display()))?;
    }
    let temporary = temporary_path(&target);
    let mut input = File::open(&source).with_context(|| format!("open {}", source.display()))?;
    let mut output = OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o666)
        .open(&temporary)
        .with_context(|| format!("create {}", temporary.display()))?;
    let mut file_hash = Sha256::new();
    let mut piece_hashes = Vec::new();
    let mut buffer = vec![0_u8; PIECE_SIZE];
    loop {
        let mut filled = 0;
        while filled < buffer.len() {
            let count = input
                .read(&mut buffer[filled..])
                .with_context(|| format!("read {}", source.display()))?;
            if count == 0 {
                break;
            }
            filled += count;
        }
        if filled == 0 {
            break;
        }
        output
            .write_all(&buffer[..filled])
            .with_context(|| format!("write {}", temporary.display()))?;
        file_hash.update(&buffer[..filled]);
        let mut piece = Sha1::new();
        piece.update(&buffer[..filled]);
        piece_hashes.push(hex::encode(piece.finalize()));
        if filled < buffer.len() {
            break;
        }
    }
    output.flush()?;
    output.sync_all()?;
    let actual_hash = hex::encode(file_hash.finalize());
    if entry.file_hash.as_deref() != Some(actual_hash.as_str()) || entry.pieces != piece_hashes {
        let _ = fs::remove_file(&temporary);
        bail!("source content hash mismatch for {}", entry.path);
    }
    filetime::set_file_mtime(&temporary, FileTime::from_unix_time(entry.mtime_seconds, 0))?;
    fs::rename(&temporary, &target).with_context(|| format!("commit {}", target.display()))?;
    if let Some(parent) = target.parent() {
        if let Ok(directory) = File::open(parent) {
            let _ = directory.sync_all();
        }
    }
    Ok(())
}

fn temporary_path(target: &Path) -> PathBuf {
    let name = target
        .file_name()
        .map(|value| value.to_string_lossy().into_owned())
        .unwrap_or_else(|| "file".into());
    target.with_file_name(format!(".{name}.rustsync-tmp-{}", std::process::id()))
}

pub fn verify_source(source: &Path, entry: &Entry) -> Result<()> {
    let mut file = File::open(source)?;
    let mut data = Vec::new();
    file.read_to_end(&mut data)?;
    let mut hash = Sha256::new();
    hash.update(&data);
    if hex::encode(hash.finalize()) != entry.file_hash.clone().unwrap_or_default() {
        bail!("source hash mismatch");
    }
    Ok(())
}

pub fn restore_metadata(path: &Path, entry: &Entry) -> Result<()> {
    fs::set_permissions(path, fs::Permissions::from_mode(entry.mode))?;
    filetime::set_file_mtime(path, FileTime::from_unix_time(entry.mtime_seconds, 0))?;
    Ok(())
}
