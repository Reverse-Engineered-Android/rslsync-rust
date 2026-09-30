use anyhow::{bail, Context, Result};
use argon2::password_hash::{
    rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString,
};
use argon2::Argon2;
use ipnet::IpNet;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::net::IpAddr;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

pub const STATE_VERSION: u32 = 1;
pub const DEFAULT_PASSWORD_EXEMPT_IPS: [&str; 2] = ["127.0.0.0/8", "::1/128"];

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ScanSummary {
    pub root_hash: String,
    pub entry_count: usize,
    pub file_count: usize,
    pub directory_count: usize,
    pub total_file_size: u64,
    pub output: Option<PathBuf>,
    pub completed_at: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SyncFolder {
    pub id: String,
    pub name: String,
    pub path: PathBuf,
    pub include: Option<String>,
    pub exclude: Option<String>,
    pub enabled: bool,
    pub created_at: u64,
    pub updated_at: u64,
    pub last_scan: Option<ScanSummary>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PersistedServerState {
    pub version: u32,
    pub password_hash: Option<String>,
    pub password_exempt_ips: Vec<String>,
    pub folders: Vec<SyncFolder>,
}

impl Default for PersistedServerState {
    fn default() -> Self {
        Self {
            version: STATE_VERSION,
            password_hash: None,
            password_exempt_ips: DEFAULT_PASSWORD_EXEMPT_IPS
                .iter()
                .map(|value| (*value).to_owned())
                .collect(),
            folders: Vec::new(),
        }
    }
}

impl PersistedServerState {
    pub fn validate(&self) -> Result<()> {
        if self.version != STATE_VERSION {
            bail!(
                "unsupported server state version {} (expected {})",
                self.version,
                STATE_VERSION
            );
        }
        self.parse_password_exempt_ips()?;
        let mut ids = BTreeSet::new();
        let mut paths = BTreeSet::new();
        for folder in &self.folders {
            validate_folder_fields(folder)?;
            if !ids.insert(folder.id.clone()) {
                bail!("duplicate folder id {}", folder.id);
            }
            if !paths.insert(normalized_path(&folder.path)) {
                bail!("duplicate folder path {}", folder.path.display());
            }
        }
        Ok(())
    }

    pub fn parse_password_exempt_ips(&self) -> Result<Vec<IpNet>> {
        self.password_exempt_ips
            .iter()
            .map(|value| parse_ip_or_cidr(value))
            .collect()
    }
}

pub struct ServerStateStore {
    path: PathBuf,
    state: std::sync::Mutex<PersistedServerState>,
}

impl ServerStateStore {
    pub fn load(path: impl Into<PathBuf>) -> Result<Self> {
        let path = path.into();
        let state = if path.exists() {
            let bytes =
                fs::read(&path).with_context(|| format!("read server state {}", path.display()))?;
            let state: PersistedServerState = serde_json::from_slice(&bytes)
                .with_context(|| format!("parse server state {}", path.display()))?;
            state.validate()?;
            state
        } else {
            let state = PersistedServerState::default();
            let store = Self {
                path,
                state: std::sync::Mutex::new(state.clone()),
            };
            store.persist(&state)?;
            return Ok(store);
        };
        Ok(Self {
            path,
            state: std::sync::Mutex::new(state),
        })
    }

    pub fn snapshot(&self) -> Result<PersistedServerState> {
        let state = self.state.lock().expect("server state lock poisoned");
        Ok(state.clone())
    }

    pub fn password_configured(&self) -> Result<bool> {
        let state = self.state.lock().expect("server state lock poisoned");
        Ok(state.password_hash.is_some())
    }

    pub fn ip_is_exempt(&self, address: IpAddr) -> Result<bool> {
        let state = self.state.lock().expect("server state lock poisoned");
        let networks = state.parse_password_exempt_ips()?;
        Ok(networks.iter().any(|network| network.contains(&address)))
    }

    pub fn set_password(&self, password: &str) -> Result<()> {
        validate_password(password)?;
        let hash = hash_password(password)?;
        self.update(|state| {
            state.password_hash = Some(hash);
            Ok(())
        })
    }

    pub fn clear_password(&self) -> Result<()> {
        self.update(|state| {
            state.password_hash = None;
            Ok(())
        })
    }

    pub fn verify_password(&self, password: &str) -> Result<bool> {
        let state = self.state.lock().expect("server state lock poisoned");
        let Some(hash) = &state.password_hash else {
            return Ok(false);
        };
        let parsed = PasswordHash::new(hash).context("parse stored password hash")?;
        Ok(Argon2::default()
            .verify_password(password.as_bytes(), &parsed)
            .is_ok())
    }

    pub fn set_password_exempt_ips(&self, values: &[String]) -> Result<Vec<String>> {
        let normalized = normalize_exempt_ips(values)?;
        self.update(|state| {
            state.password_exempt_ips = normalized.clone();
            Ok(())
        })?;
        Ok(normalized)
    }

    pub fn list_folders(&self) -> Result<Vec<SyncFolder>> {
        let state = self.state.lock().expect("server state lock poisoned");
        Ok(state.folders.clone())
    }

    pub fn get_folder(&self, id: &str) -> Result<SyncFolder> {
        let state = self.state.lock().expect("server state lock poisoned");
        state
            .folders
            .iter()
            .find(|folder| folder.id == id)
            .cloned()
            .with_context(|| format!("folder not found: {id}"))
    }

    pub fn add_folder(&self, request: FolderRequest) -> Result<SyncFolder> {
        let path = canonical_directory(&request.path)?;
        let folder = SyncFolder {
            id: random_id(),
            name: request.name.trim().to_owned(),
            path,
            include: normalize_optional_patterns(request.include.as_deref())?,
            exclude: normalize_optional_patterns(request.exclude.as_deref())?,
            enabled: request.enabled.unwrap_or(true),
            created_at: unix_time(),
            updated_at: unix_time(),
            last_scan: None,
        };
        validate_folder_fields(&folder)?;
        self.update(|state| {
            if state
                .folders
                .iter()
                .any(|existing| normalized_path(&existing.path) == normalized_path(&folder.path))
            {
                bail!(
                    "folder path is already registered: {}",
                    folder.path.display()
                );
            }
            state.folders.push(folder.clone());
            state
                .folders
                .sort_by_key(|folder| folder.name.to_lowercase());
            Ok(())
        })?;
        Ok(folder)
    }

    pub fn update_folder(&self, id: &str, request: FolderUpdate) -> Result<SyncFolder> {
        let mut updated = None;
        self.update(|state| {
            let folder = state
                .folders
                .iter_mut()
                .find(|folder| folder.id == id)
                .with_context(|| format!("folder not found: {id}"))?;
            if let Some(name) = request.name {
                folder.name = name.trim().to_owned();
            }
            if let Some(path) = request.path {
                folder.path = canonical_directory(path)?;
            }
            if let Some(include) = request.include {
                folder.include = normalize_optional_patterns(include.as_deref())?;
            }
            if let Some(exclude) = request.exclude {
                folder.exclude = normalize_optional_patterns(exclude.as_deref())?;
            }
            if let Some(enabled) = request.enabled {
                folder.enabled = enabled;
            }
            folder.updated_at = unix_time();
            validate_folder_fields(folder)?;
            let folder_id = folder.id.clone();
            let folder_path = normalized_path(&folder.path);
            updated = Some(folder.clone());
            let duplicate = state.folders.iter().any(|candidate| {
                candidate.id != folder_id && normalized_path(&candidate.path) == folder_path
            });
            if duplicate {
                bail!("folder path is already registered: {folder_path}");
            }
            Ok(())
        })?;
        updated.context("folder update produced no result")
    }

    pub fn delete_folder(&self, id: &str) -> Result<SyncFolder> {
        let mut deleted = None;
        self.update(|state| {
            let index = state
                .folders
                .iter()
                .position(|folder| folder.id == id)
                .with_context(|| format!("folder not found: {id}"))?;
            deleted = Some(state.folders.remove(index));
            Ok(())
        })?;
        deleted.context("folder deletion produced no result")
    }

    pub fn record_scan(&self, id: &str, summary: ScanSummary) -> Result<SyncFolder> {
        let mut updated = None;
        self.update(|state| {
            let folder = state
                .folders
                .iter_mut()
                .find(|folder| folder.id == id)
                .with_context(|| format!("folder not found: {id}"))?;
            folder.last_scan = Some(summary);
            folder.updated_at = unix_time();
            updated = Some(folder.clone());
            Ok(())
        })?;
        updated.context("folder scan update produced no result")
    }

    fn update<T>(
        &self,
        operation: impl FnOnce(&mut PersistedServerState) -> Result<T>,
    ) -> Result<T> {
        let mut state = self.state.lock().expect("server state lock poisoned");
        let result = operation(&mut state)?;
        state.validate()?;
        self.persist(&state)?;
        Ok(result)
    }

    fn persist(&self, state: &PersistedServerState) -> Result<()> {
        if let Some(parent) = self.path.parent() {
            fs::create_dir_all(parent)
                .with_context(|| format!("create state directory {}", parent.display()))?;
        }
        let temporary = self.path.with_file_name(format!(
            ".{}.tmp-{}",
            self.path
                .file_name()
                .and_then(|name| name.to_str())
                .unwrap_or("state"),
            std::process::id()
        ));
        let json = serde_json::to_vec_pretty(state)?;
        let mut options = OpenOptions::new();
        options.write(true).create(true).truncate(true).mode(0o600);
        let mut file = options
            .open(&temporary)
            .with_context(|| format!("open temporary server state {}", temporary.display()))?;
        file.write_all(&json)?;
        file.sync_all()?;
        fs::rename(&temporary, &self.path).with_context(|| {
            format!(
                "replace server state {} with {}",
                self.path.display(),
                temporary.display()
            )
        })?;
        fs::set_permissions(&self.path, fs::Permissions::from_mode(0o600))?;
        Ok(())
    }
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct FolderRequest {
    pub name: String,
    pub path: PathBuf,
    pub include: Option<String>,
    pub exclude: Option<String>,
    pub enabled: Option<bool>,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct FolderUpdate {
    pub name: Option<String>,
    pub path: Option<PathBuf>,
    pub include: Option<Option<String>>,
    pub exclude: Option<Option<String>>,
    pub enabled: Option<bool>,
}

fn validate_folder_fields(folder: &SyncFolder) -> Result<()> {
    if folder.name.trim().is_empty() {
        bail!("folder name cannot be empty");
    }
    if folder.id.len() != 32 || !folder.id.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        bail!("folder id must be 16 random bytes encoded as hexadecimal");
    }
    if !folder.path.is_absolute() {
        bail!("folder path must be absolute");
    }
    if let Some(include) = folder.include.as_deref() {
        validate_patterns(include)?;
    }
    if let Some(exclude) = folder.exclude.as_deref() {
        validate_patterns(exclude)?;
    }
    Ok(())
}

fn canonical_directory(path: impl AsRef<Path>) -> Result<PathBuf> {
    let path = path.as_ref();
    if !path.is_absolute() {
        bail!("folder path must be absolute");
    }
    if !path.is_dir() {
        bail!("folder path is not a directory: {}", path.display());
    }
    path.canonicalize()
        .with_context(|| format!("canonicalize folder path {}", path.display()))
}

fn normalize_optional_patterns(value: Option<&str>) -> Result<Option<String>> {
    let Some(value) = value else {
        return Ok(None);
    };
    let value = value.trim();
    if value.is_empty() {
        return Ok(None);
    }
    validate_patterns(value)?;
    Ok(Some(value.to_owned()))
}

fn validate_patterns(value: &str) -> Result<()> {
    crate::selective::SyncSelection::from_csv(Some(value), None)?;
    Ok(())
}

fn normalize_exempt_ips(values: &[String]) -> Result<Vec<String>> {
    let mut normalized = values
        .iter()
        .map(|value| parse_ip_or_cidr(value).map(|network| network.to_string()))
        .collect::<Result<BTreeSet<_>>>()?
        .into_iter()
        .collect::<Vec<_>>();
    normalized.sort();
    if normalized.is_empty() {
        bail!("at least one password-exempt IP or CIDR is required");
    }
    Ok(normalized)
}

fn parse_ip_or_cidr(value: &str) -> Result<IpNet> {
    let value = value.trim();
    if value.is_empty() {
        bail!("password-exempt IP cannot be empty");
    }
    if let Ok(network) = value.parse::<IpNet>() {
        return Ok(network);
    }
    let address = value
        .parse::<IpAddr>()
        .with_context(|| format!("invalid password-exempt IP or CIDR: {value}"))?;
    Ok(IpNet::from(address))
}

fn validate_password(password: &str) -> Result<()> {
    let length = password.chars().count();
    if !(8..=1024).contains(&length) {
        bail!("password must contain between 8 and 1024 characters");
    }
    Ok(())
}

fn hash_password(password: &str) -> Result<String> {
    let salt = SaltString::generate(&mut OsRng);
    Argon2::default()
        .hash_password(password.as_bytes(), &salt)
        .map(|hash| hash.to_string())
        .context("hash password")
}

fn normalized_path(path: &Path) -> String {
    path.to_string_lossy().replace('\\', "/")
}

fn random_id() -> String {
    use rand::RngCore;
    let mut bytes = [0_u8; 16];
    rand::thread_rng().fill_bytes(&mut bytes);
    hex::encode(bytes)
}

pub fn unix_time() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn defaults_to_local_password_exemptions() {
        let state = PersistedServerState::default();
        let networks = state.parse_password_exempt_ips().unwrap();
        let loopback_v4: IpAddr = "127.0.0.1".parse().unwrap();
        let loopback_v6: IpAddr = "::1".parse().unwrap();
        assert!(networks
            .iter()
            .any(|network| network.contains(&loopback_v4)));
        assert!(networks
            .iter()
            .any(|network| network.contains(&loopback_v6)));
    }

    #[test]
    fn persists_folder_crud_and_password_hash() {
        let temp = tempdir().unwrap();
        let root = temp.path().join("folder");
        fs::create_dir(&root).unwrap();
        let store = ServerStateStore::load(temp.path().join("state.json")).unwrap();
        store.set_password("correct horse").unwrap();
        assert!(store.verify_password("correct horse").unwrap());
        assert!(!store.verify_password("wrong password").unwrap());

        let folder = store
            .add_folder(FolderRequest {
                name: "Documents".into(),
                path: root.clone(),
                include: Some("*.md".into()),
                exclude: Some("private/**".into()),
                enabled: Some(true),
            })
            .unwrap();
        let reloaded = ServerStateStore::load(temp.path().join("state.json")).unwrap();
        assert_eq!(reloaded.list_folders().unwrap().len(), 1);
        assert_eq!(reloaded.get_folder(&folder.id).unwrap().name, "Documents");

        let updated = reloaded
            .update_folder(
                &folder.id,
                FolderUpdate {
                    enabled: Some(false),
                    ..FolderUpdate::default()
                },
            )
            .unwrap();
        assert!(!updated.enabled);
        assert_eq!(reloaded.delete_folder(&folder.id).unwrap().id, folder.id);
    }
}
