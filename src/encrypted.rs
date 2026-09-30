use crate::model::validate_relative_path;
use crate::permissions::{apply_permissions, read_permissions, PermissionPolicy, PermissionRecord};
use anyhow::{bail, Context, Result};
use filetime::FileTime;
use openssl::symm::{decrypt_aead, encrypt_aead, Cipher};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::fs::{self, File};
use std::io::{Read, Write};
use std::os::unix::fs::MetadataExt;
use std::path::{Component, Path, PathBuf};

const MAGIC: &[u8; 5] = b"RSEF2";
const VERSION: u8 = 2;
const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 12;
const KEY_LEN: usize = 32;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EncryptedFileEntry {
    pub path: String,
    pub object: String,
    pub kind: String,
    pub size: u64,
    pub mode: u32,
    pub uid: u32,
    pub gid: u32,
    pub mtime_seconds: i64,
    pub sha256: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct VaultManifest {
    pub version: u32,
    pub vault_id: String,
    pub files: Vec<EncryptedFileEntry>,
}

pub fn derive_key(passphrase: &[u8], salt: &[u8]) -> Result<[u8; KEY_LEN]> {
    if salt.len() != SALT_LEN {
        bail!("encrypted folder salt must be {SALT_LEN} bytes");
    }
    let mut key = [0_u8; KEY_LEN];
    openssl::pkcs5::pbkdf2_hmac(
        passphrase,
        salt,
        200_000,
        openssl::hash::MessageDigest::sha256(),
        &mut key,
    )
    .context("derive encrypted folder key")?;
    Ok(key)
}

pub fn encrypt_blob(passphrase: &[u8], plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
    let mut salt = [0_u8; SALT_LEN];
    rand::thread_rng().fill_bytes(&mut salt);
    let key = derive_key(passphrase, &salt)?;
    encrypt_payload(&salt, &key, plaintext, aad)
}

fn encrypt_payload(
    salt: &[u8],
    key: &[u8; KEY_LEN],
    plaintext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>> {
    if salt.len() != SALT_LEN {
        bail!("encrypted folder salt must be {SALT_LEN} bytes");
    }
    let mut nonce = [0_u8; NONCE_LEN];
    rand::thread_rng().fill_bytes(&mut nonce);
    let mut tag = [0_u8; 16];
    let ciphertext = encrypt_aead(
        Cipher::aes_256_gcm(),
        key,
        Some(&nonce),
        aad,
        plaintext,
        &mut tag,
    )
    .context("encrypt encrypted folder data")?;
    let mut output =
        Vec::with_capacity(MAGIC.len() + 2 + SALT_LEN + NONCE_LEN + ciphertext.len() + tag.len());
    output.extend_from_slice(MAGIC);
    output.push(VERSION);
    output.push(0);
    output.extend_from_slice(salt);
    output.extend_from_slice(&nonce);
    output.extend_from_slice(&ciphertext);
    output.extend_from_slice(&tag);
    Ok(output)
}

pub fn decrypt_blob(passphrase: &[u8], payload: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
    let decoded = decode_payload(payload)?;
    let key = derive_key(passphrase, decoded.salt)?;
    decrypt_payload(&decoded, &key, aad)
}

struct DecodedPayload<'a> {
    salt: &'a [u8],
    nonce: &'a [u8],
    ciphertext: &'a [u8],
    tag: &'a [u8],
}

fn decode_payload(payload: &[u8]) -> Result<DecodedPayload<'_>> {
    let header_len = MAGIC.len() + 2 + SALT_LEN + NONCE_LEN;
    if payload.len() < header_len + Cipher::aes_256_gcm().block_size() {
        bail!("encrypted folder object is truncated");
    }
    if &payload[..MAGIC.len()] != MAGIC {
        bail!("unknown encrypted folder object magic");
    }
    if payload[MAGIC.len()] != VERSION {
        bail!(
            "unsupported encrypted folder object version {}",
            payload[MAGIC.len()]
        );
    }
    let salt = &payload[MAGIC.len() + 2..MAGIC.len() + 2 + SALT_LEN];
    let nonce_start = MAGIC.len() + 2 + SALT_LEN;
    let nonce = &payload[nonce_start..nonce_start + NONCE_LEN];
    let tag_start = payload.len() - 16;
    Ok(DecodedPayload {
        salt,
        nonce,
        ciphertext: &payload[nonce_start + NONCE_LEN..tag_start],
        tag: &payload[tag_start..],
    })
}

fn decrypt_payload(
    payload: &DecodedPayload<'_>,
    key: &[u8; KEY_LEN],
    aad: &[u8],
) -> Result<Vec<u8>> {
    decrypt_aead(
        Cipher::aes_256_gcm(),
        key,
        Some(payload.nonce),
        aad,
        payload.ciphertext,
        payload.tag,
    )
    .context("decrypt encrypted folder data")
}

pub fn encrypt_tree(source: &Path, destination: &Path, passphrase: &[u8]) -> Result<VaultManifest> {
    if !source.is_dir() {
        bail!("encrypted source is not a directory: {}", source.display());
    }
    ensure_disjoint_paths(source, destination)?;
    fs::create_dir_all(destination.join("objects")).context("create encrypted vault")?;
    let mut salt = [0_u8; SALT_LEN];
    rand::thread_rng().fill_bytes(&mut salt);
    let key = derive_key(passphrase, &salt)?;
    let vault_id = random_object_name()?.replace(".rsef", "");
    let mut entries = Vec::new();
    collect_tree(
        source,
        source,
        &salt,
        &key,
        &vault_id,
        destination,
        &mut entries,
    )?;
    entries.sort_by(|left, right| left.path.cmp(&right.path));
    let manifest = VaultManifest {
        version: VERSION as u32,
        vault_id,
        files: entries,
    };
    let plaintext = serde_json::to_vec(&manifest)?;
    let payload = encrypt_payload(&salt, &key, &plaintext, b"RSEF2 manifest")?;
    fs::write(destination.join("manifest.rsef"), payload).context("write encrypted manifest")?;
    Ok(manifest)
}

fn collect_tree(
    source_root: &Path,
    current: &Path,
    salt: &[u8],
    key: &[u8; KEY_LEN],
    vault_id: &str,
    destination: &Path,
    entries: &mut Vec<EncryptedFileEntry>,
) -> Result<()> {
    for item in fs::read_dir(current).with_context(|| format!("read {}", current.display()))? {
        let item = item?;
        let path = item.path();
        let relative = path
            .strip_prefix(source_root)
            .context("entry outside encrypted source")?
            .to_string_lossy()
            .replace('\\', "/");
        validate_relative_path(&relative)?;
        let metadata = fs::symlink_metadata(&path)?;
        let permissions = read_permissions(&path)?;
        if metadata.is_dir() {
            entries.push(EncryptedFileEntry {
                path: relative,
                object: String::new(),
                kind: "directory".into(),
                size: 0,
                mode: permissions.mode,
                uid: permissions.uid,
                gid: permissions.gid,
                mtime_seconds: metadata.mtime(),
                sha256: String::new(),
            });
            collect_tree(
                source_root,
                &path,
                salt,
                key,
                vault_id,
                destination,
                entries,
            )?;
        } else if metadata.is_file() {
            let mut content = Vec::new();
            File::open(&path)?.read_to_end(&mut content)?;
            let digest = Sha256::digest(&content);
            let object = random_object_name()?;
            let aad = format!("RSEF2 file\0{vault_id}\0{relative}");
            let payload = encrypt_payload(salt, key, &content, aad.as_bytes())?;
            fs::write(destination.join("objects").join(&object), payload)?;
            entries.push(EncryptedFileEntry {
                path: relative,
                object,
                kind: "file".into(),
                size: content.len() as u64,
                mode: permissions.mode,
                uid: permissions.uid,
                gid: permissions.gid,
                mtime_seconds: metadata.mtime(),
                sha256: hex::encode(digest),
            });
        } else {
            bail!("unsupported encrypted source entry: {}", path.display());
        }
    }
    Ok(())
}

pub fn decrypt_tree(vault: &Path, destination: &Path, passphrase: &[u8]) -> Result<VaultManifest> {
    let payload = fs::read(vault.join("manifest.rsef")).context("read encrypted manifest")?;
    let decoded = decode_payload(&payload)?;
    let key = derive_key(passphrase, decoded.salt)?;
    let plaintext = decrypt_payload(&decoded, &key, b"RSEF2 manifest")?;
    let manifest: VaultManifest =
        serde_json::from_slice(&plaintext).context("parse encrypted manifest")?;
    if manifest.version != VERSION as u32 {
        bail!("unsupported encrypted vault version {}", manifest.version);
    }
    validate_manifest(&manifest)?;
    fs::create_dir_all(destination).context("create decrypted destination")?;
    for entry in &manifest.files {
        validate_relative_path(&entry.path)?;
        let target = safe_destination(destination, &entry.path)?;
        if entry.kind == "directory" {
            fs::create_dir_all(&target)?;
        } else if entry.kind == "file" {
            if let Some(parent) = target.parent() {
                fs::create_dir_all(parent)?;
            }
            let object = safe_object_path(&vault.join("objects"), &entry.object)?;
            let object_metadata = fs::symlink_metadata(&object).context("stat encrypted object")?;
            if object_metadata.file_type().is_symlink() {
                bail!("encrypted object is a symlink: {}", object.display());
            }
            let payload = fs::read(&object).context("read encrypted object")?;
            let aad = format!("RSEF2 file\0{}\0{}", manifest.vault_id, entry.path);
            let object_payload = decode_payload(&payload)?;
            if object_payload.salt != decoded.salt {
                bail!("encrypted object salt does not match vault: {}", entry.path);
            }
            let content = decrypt_payload(&object_payload, &key, aad.as_bytes())?;
            if content.len() as u64 != entry.size
                || hex::encode(Sha256::digest(&content)) != entry.sha256
            {
                bail!("encrypted object content mismatch for {}", entry.path);
            }
            let temporary = temporary_path(&target);
            let mut output = fs::OpenOptions::new()
                .create_new(true)
                .write(true)
                .open(&temporary)?;
            output.write_all(&content)?;
            output.sync_all()?;
            drop(output);
            fs::rename(&temporary, &target)
                .with_context(|| format!("commit decrypted {}", entry.path))?;
        } else {
            bail!("unsupported encrypted entry kind {}", entry.kind);
        }
        let desired = PermissionRecord {
            mode: entry.mode,
            uid: entry.uid,
            gid: entry.gid,
        };
        apply_permissions(&target, desired, PermissionPolicy::Preserve)?;
        filetime::set_file_mtime(&target, FileTime::from_unix_time(entry.mtime_seconds, 0))?;
    }
    Ok(manifest)
}

fn safe_destination(root: &Path, relative: &str) -> Result<PathBuf> {
    let root_metadata = fs::symlink_metadata(root).context("stat decrypted destination")?;
    if root_metadata.file_type().is_symlink() {
        bail!("encrypted destination is a symlink: {}", root.display());
    }
    let path = root.join(relative);
    if !path.starts_with(root) {
        bail!("encrypted entry escapes destination");
    }
    let mut current = root.to_path_buf();
    for component in Path::new(relative).components() {
        let Component::Normal(component) = component else {
            bail!("encrypted entry contains an unsafe path component");
        };
        current.push(component);
        if let Ok(metadata) = fs::symlink_metadata(&current) {
            if metadata.file_type().is_symlink() {
                bail!("encrypted entry traverses a symlink: {}", current.display());
            }
        }
    }
    Ok(path)
}

fn safe_object_path(root: &Path, object: &str) -> Result<PathBuf> {
    if object.len() != 37
        || !object.ends_with(".rsef")
        || !object[..32].bytes().all(|byte| byte.is_ascii_hexdigit())
    {
        bail!("encrypted object name is invalid");
    }
    let path = root.join(object);
    if path.parent() != Some(root) {
        bail!("encrypted object escapes vault");
    }
    Ok(path)
}

fn validate_manifest(manifest: &VaultManifest) -> Result<()> {
    if manifest.vault_id.len() != 32
        || !manifest
            .vault_id
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit())
    {
        bail!("encrypted vault id is invalid");
    }
    let mut paths = HashSet::new();
    let mut objects = HashSet::new();
    for entry in &manifest.files {
        validate_relative_path(&entry.path)?;
        if !paths.insert(entry.path.as_str()) {
            bail!("encrypted manifest repeats path {}", entry.path);
        }
        match entry.kind.as_str() {
            "directory" => {
                if !entry.object.is_empty() || entry.size != 0 || !entry.sha256.is_empty() {
                    bail!("encrypted directory metadata is invalid: {}", entry.path);
                }
            }
            "file" => {
                safe_object_path(Path::new("objects"), &entry.object)?;
                if !objects.insert(entry.object.as_str()) {
                    bail!("encrypted manifest repeats object {}", entry.object);
                }
            }
            other => bail!("unsupported encrypted entry kind {other}"),
        }
    }
    Ok(())
}

fn ensure_disjoint_paths(source: &Path, destination: &Path) -> Result<()> {
    let source = source
        .canonicalize()
        .context("canonicalize encrypted source")?;
    let destination = if destination.exists() {
        destination
            .canonicalize()
            .context("canonicalize encrypted destination")?
    } else {
        normalize_absolute(destination)?
    };
    if source == destination || source.starts_with(&destination) || destination.starts_with(&source)
    {
        bail!("encrypted source and destination must be disjoint");
    }
    Ok(())
}

fn normalize_absolute(path: &Path) -> Result<PathBuf> {
    let path = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()?.join(path)
    };
    let mut output = PathBuf::new();
    for component in path.components() {
        match component {
            Component::Prefix(prefix) => output.push(prefix.as_os_str()),
            Component::RootDir => output.push(Component::RootDir.as_os_str()),
            Component::CurDir => {}
            Component::ParentDir => {
                if !output.pop() {
                    bail!("encrypted destination escapes filesystem root");
                }
            }
            Component::Normal(value) => output.push(value),
        }
    }
    Ok(output)
}

fn temporary_path(target: &Path) -> PathBuf {
    let name = target
        .file_name()
        .map(|value| value.to_string_lossy().into_owned())
        .unwrap_or_else(|| "file".into());
    target.with_file_name(format!(".{name}.rustsync-tmp-{}", std::process::id()))
}

fn random_object_name() -> Result<String> {
    let mut bytes = [0_u8; 16];
    rand::thread_rng().fill_bytes(&mut bytes);
    Ok(format!("{}.rsef", hex::encode(bytes)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn encrypted_tree_round_trips_without_plaintext_objects() {
        let source = tempdir().unwrap();
        let vault = tempdir().unwrap();
        let target = tempdir().unwrap();
        fs::create_dir(source.path().join("nested")).unwrap();
        fs::write(source.path().join("nested/plain.txt"), b"secret").unwrap();
        let manifest = encrypt_tree(source.path(), vault.path(), b"pass").unwrap();
        assert_eq!(manifest.files.len(), 2);
        assert!(!vault
            .path()
            .join("manifest.rsef")
            .to_string_lossy()
            .contains("plain.txt"));
        decrypt_tree(vault.path(), target.path(), b"pass").unwrap();
        assert_eq!(
            fs::read(target.path().join("nested/plain.txt")).unwrap(),
            b"secret"
        );
        assert!(decrypt_tree(vault.path(), target.path(), b"wrong").is_err());
    }

    #[test]
    fn tampered_object_cannot_replace_existing_decrypted_file() {
        let source = tempdir().unwrap();
        let vault = tempdir().unwrap();
        let target = tempdir().unwrap();
        fs::write(source.path().join("file"), b"new").unwrap();
        let manifest = encrypt_tree(source.path(), vault.path(), b"pass").unwrap();
        let object = vault.path().join("objects").join(&manifest.files[0].object);
        let mut payload = fs::read(&object).unwrap();
        let middle = payload.len() / 2;
        payload[middle] ^= 0x80;
        fs::write(&object, payload).unwrap();
        fs::write(target.path().join("file"), b"existing").unwrap();

        assert!(decrypt_tree(vault.path(), target.path(), b"pass").is_err());
        assert_eq!(fs::read(target.path().join("file")).unwrap(), b"existing");
    }

    #[test]
    fn encrypt_tree_rejects_nested_source_and_destination() {
        let source = tempdir().unwrap();
        assert!(encrypt_tree(source.path(), &source.path().join("vault"), b"pass").is_err());
    }
}
