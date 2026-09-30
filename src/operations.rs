use crate::apply::{apply_manifest_with_policy, ApplyPolicy, ConflictPolicy};
use crate::discovery::LanPing;
use crate::encrypted::{decrypt_tree, encrypt_tree};
use crate::model::{EntryKind, Manifest};
use crate::peer::{pull, random_peer_id};
use crate::permissions::PermissionPolicy;
use crate::scan::{manifest_path, scan_root_with_selection};
use crate::secret::ShareKey;
use crate::selective::SyncSelection;
use crate::server_state::{unix_time, ScanSummary};
use crate::tracker::{TrackerClient, TrackerRequest};
use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use std::fs;
use std::net::TcpStream;
use std::path::PathBuf;

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ScanRequest {
    pub root: PathBuf,
    pub output: Option<PathBuf>,
    pub include: Option<String>,
    pub exclude: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ScanResponse {
    pub summary: ScanSummary,
}

pub fn scan(request: ScanRequest) -> Result<ScanResponse> {
    let selection =
        SyncSelection::from_csv(request.include.as_deref(), request.exclude.as_deref())?;
    let manifest = scan_root_with_selection(&request.root, &selection)?;
    let output = request
        .output
        .unwrap_or_else(|| manifest_path(&request.root));
    fs::write(&output, serde_json::to_vec_pretty(&manifest)?)
        .with_context(|| format!("write manifest {}", output.display()))?;
    Ok(ScanResponse {
        summary: summarize(&manifest, Some(output)),
    })
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ApplyRequest {
    pub source: PathBuf,
    pub target: PathBuf,
    pub manifest: Option<PathBuf>,
    pub conflict: Option<String>,
    pub permissions: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ApplyResponse {
    pub root_hash: String,
    pub entry_count: usize,
    pub source: PathBuf,
    pub target: PathBuf,
}

pub fn apply(request: ApplyRequest) -> Result<ApplyResponse> {
    let conflict = parse_conflict(request.conflict.as_deref().unwrap_or("overwrite"))?;
    let permissions = parse_permissions(request.permissions.as_deref().unwrap_or("preserve"))?;
    let manifest_path = request
        .manifest
        .unwrap_or_else(|| manifest_path(&request.source));
    let manifest: Manifest = serde_json::from_slice(
        &fs::read(&manifest_path)
            .with_context(|| format!("read manifest {}", manifest_path.display()))?,
    )?;
    manifest.validate()?;
    apply_manifest_with_policy(
        &request.source,
        &request.target,
        &manifest,
        ApplyPolicy {
            conflict,
            permissions,
        },
    )?;
    Ok(ApplyResponse {
        root_hash: manifest.root_hash,
        entry_count: manifest.entries.len(),
        source: request.source,
        target: request.target,
    })
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PullRequest {
    pub address: String,
    pub target: PathBuf,
    pub key: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PullResponse {
    pub root_hash: String,
    pub entry_count: usize,
    pub target: PathBuf,
}

pub fn pull_tree(request: PullRequest) -> Result<PullResponse> {
    let key = ShareKey::parse(&request.key)?;
    let stream = TcpStream::connect(&request.address)
        .with_context(|| format!("connect peer {}", request.address))?;
    let manifest = pull(stream, &request.target, &key, random_peer_id())?;
    Ok(PullResponse {
        root_hash: manifest.root_hash,
        entry_count: manifest.entries.len(),
        target: request.target,
    })
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct GenerateKeyRequest {
    pub read_write: bool,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct GenerateKeyResponse {
    pub key: String,
    pub key_type: char,
}

pub fn generate_key(request: GenerateKeyRequest) -> Result<GenerateKeyResponse> {
    let key = if request.read_write {
        ShareKey::generate_read_write()
    } else {
        ShareKey::generate_read_only()
    };
    Ok(GenerateKeyResponse {
        key: key.render(),
        key_type: key.key_type,
    })
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct InspectKeyRequest {
    pub key: String,
}

pub fn inspect_key(request: InspectKeyRequest) -> Result<serde_json::Value> {
    let key = ShareKey::parse(&request.key)?;
    Ok(serde_json::json!({
        "key_type": key.key_type,
        "share_id": hex::encode(key.share_id()),
        "tls_identity": key.tls_identity(),
        "tls_psk_available": key.tls_psk().is_ok(),
    }))
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct EncodePingRequest {
    pub peer_id: String,
    pub port: u16,
    pub share_ids: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct EncodePingResponse {
    pub packet_hex: String,
}

pub fn encode_ping(request: EncodePingRequest) -> Result<EncodePingResponse> {
    let ping = LanPing {
        peer_id: parse_fixed_20(&request.peer_id, "peer ID")?,
        port: request.port,
        shares: request
            .share_ids
            .iter()
            .map(|value| parse_fixed_20(value, "share ID"))
            .collect::<Result<Vec<_>>>()?,
    };
    Ok(EncodePingResponse {
        packet_hex: hex::encode(ping.encode()),
    })
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct EncryptTreeRequest {
    pub source: PathBuf,
    pub destination: PathBuf,
    pub passphrase: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct DecryptTreeRequest {
    pub source: PathBuf,
    pub destination: PathBuf,
    pub passphrase: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct VaultResponse {
    pub vault_id: String,
    pub file_count: usize,
    pub source: PathBuf,
    pub destination: PathBuf,
}

pub fn encrypt(request: EncryptTreeRequest) -> Result<VaultResponse> {
    let manifest = encrypt_tree(
        &request.source,
        &request.destination,
        request.passphrase.as_bytes(),
    )?;
    Ok(VaultResponse {
        vault_id: manifest.vault_id,
        file_count: manifest.files.len(),
        source: request.source,
        destination: request.destination,
    })
}

pub fn decrypt(request: DecryptTreeRequest) -> Result<VaultResponse> {
    let manifest = decrypt_tree(
        &request.source,
        &request.destination,
        request.passphrase.as_bytes(),
    )?;
    Ok(VaultResponse {
        vault_id: manifest.vault_id,
        file_count: manifest.files.len(),
        source: request.source,
        destination: request.destination,
    })
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct TrackerAnnounceRequest {
    pub url: String,
    pub info_hash: String,
    pub peer_id: String,
    pub port: u16,
    pub uploaded: u64,
    pub downloaded: u64,
    pub left: u64,
    pub event: Option<String>,
}

pub fn tracker_announce(request: TrackerAnnounceRequest) -> Result<serde_json::Value> {
    let response = TrackerClient::new(request.url).announce(&TrackerRequest {
        info_hash: parse_fixed_20(&request.info_hash, "info hash")?,
        peer_id: parse_fixed_20(&request.peer_id, "peer ID")?,
        port: request.port,
        uploaded: request.uploaded,
        downloaded: request.downloaded,
        left: request.left,
        event: request.event,
    })?;
    let peers = response
        .peers
        .iter()
        .map(|peer| {
            serde_json::json!({
                "address": peer.address.to_string(),
                "peer_id": peer.peer_id.map(hex::encode),
            })
        })
        .collect::<Vec<_>>();
    Ok(serde_json::json!({
        "interval": response.interval,
        "warning": response.warning,
        "peers": peers,
    }))
}

fn summarize(manifest: &Manifest, output: Option<PathBuf>) -> ScanSummary {
    ScanSummary {
        root_hash: manifest.root_hash.clone(),
        entry_count: manifest.entries.len(),
        file_count: manifest
            .entries
            .iter()
            .filter(|entry| entry.kind == EntryKind::File)
            .count(),
        directory_count: manifest
            .entries
            .iter()
            .filter(|entry| entry.kind == EntryKind::Directory)
            .count(),
        total_file_size: manifest
            .entries
            .iter()
            .filter(|entry| entry.kind == EntryKind::File)
            .map(|entry| entry.size)
            .sum(),
        output,
        completed_at: unix_time(),
    }
}

pub fn summary_for_manifest(manifest: &Manifest, output: Option<PathBuf>) -> ScanSummary {
    summarize(manifest, output)
}

fn parse_conflict(value: &str) -> Result<ConflictPolicy> {
    match value {
        "overwrite" => Ok(ConflictPolicy::Overwrite),
        "preserve" => Ok(ConflictPolicy::Preserve),
        _ => bail!("conflict policy must be overwrite or preserve"),
    }
}

fn parse_permissions(value: &str) -> Result<PermissionPolicy> {
    match value {
        "preserve" => Ok(PermissionPolicy::Preserve),
        "ignore" => Ok(PermissionPolicy::Ignore),
        "check" => Ok(PermissionPolicy::CheckOnly),
        _ => bail!("permissions must be preserve, ignore, or check"),
    }
}

fn parse_fixed_20(value: &str, label: &str) -> Result<[u8; 20]> {
    let bytes = hex::decode(value).with_context(|| format!("decode {label}"))?;
    bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("{label} must be exactly 20 bytes"))
}
