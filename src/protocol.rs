use crate::bencode::{decode_prefix, encode, Value};
use crate::secret::{decode_base32, encode_base32, ShareKey};
use anyhow::{bail, Context, Result};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use flate2::read::ZlibDecoder;
use flate2::write::ZlibEncoder;
use flate2::Compression;
use sha1::{Digest, Sha1};
use std::collections::BTreeMap;
use std::io::{self, Cursor, Read, Write};
use std::path::Path;

pub const PEER_MESSAGE_PROTOCOL_VERSION: &str = "3.1.2";
pub const DIRECT_TORRENT_MAGIC_V2: &[u8] = b"\x13BitTorrent proto v2";
pub const DIRECT_TORRENT_MAGIC_V3: &[u8] = b"\x13BitTorrent proto v3";
pub const DIRECT_TORRENT_MAGIC: &[u8] = DIRECT_TORRENT_MAGIC_V2;
pub const PIECE_LENGTH: u64 = 32 * 1024;
pub const MAX_FRAME: usize = 64 * 1024 * 1024;
pub const TUNNEL_PACKET_OPEN: u8 = 1;
pub const TUNNEL_PACKET_ACK: u8 = 2;
pub const TUNNEL_PACKET_DATA: u8 = 3;
pub const TUNNEL_PACKET_CLOSE: u8 = 4;
pub const TUNNEL_PACKET_PING: u8 = 5;
pub const TUNNEL_PACKET_DATA_COMPRESSED: u8 = 6;
pub const IDENTITY_KEY: [u8; 32] = [
    0x24, 0xc6, 0xe4, 0xf7, 0x96, 0xcb, 0x09, 0x43, 0x68, 0x4c, 0xb0, 0x77, 0x04, 0x24, 0x7e, 0x5a,
    0x00, 0xce, 0x99, 0x17, 0x39, 0xc8, 0x4c, 0x9d, 0x70, 0x1d, 0x7a, 0x3b, 0x79, 0x30, 0x37, 0x50,
];

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PeerIdentity {
    pub name: String,
    pub peer_id: [u8; 20],
    pub identity_key: [u8; 32],
    pub share_id: [u8; 20],
}

impl PeerIdentity {
    pub fn from_key(name: impl Into<String>, key: &ShareKey, peer_id: [u8; 20]) -> Result<Self> {
        Ok(Self::from_keys(
            name,
            key.share_id(),
            key.ed25519_public_key().unwrap_or([0; 32]),
            peer_id,
        ))
    }

    /// Build an identity whose advertised key need not come from the share key.
    ///
    /// A read-only share key carries no Ed25519 seed, yet the official
    /// read-only peer still advertises a real `pk` and signs every entry it
    /// relays with it; the receiver verifies against that advertised key.
    pub fn from_keys(
        name: impl Into<String>,
        share_id: [u8; 20],
        identity_key: [u8; 32],
        peer_id: [u8; 20],
    ) -> Self {
        Self {
            name: name.into(),
            peer_id,
            identity_key,
            share_id,
        }
    }

    pub fn id_message(&self) -> Value {
        self.id_message_with_key(self.identity_key)
    }

    /// The `id` message announcing a different metadata signing key.
    ///
    /// A read-only folder relaying the writer's signed entries must announce
    /// the writer's public key, because that is what the receiver verifies
    /// those entries against.
    pub fn id_message_with_key(&self, identity_key: [u8; 32]) -> Value {
        Value::dict([
            (b"m".to_vec(), Value::bytes(b"id")),
            (b"name".to_vec(), Value::bytes(self.name.clone())),
            (b"peer".to_vec(), Value::bytes(self.peer_id)),
            (b"pk".to_vec(), Value::bytes(identity_key)),
            (b"share".to_vec(), Value::bytes(self.share_id)),
            (b"tags".to_vec(), Value::List(Vec::new())),
            (
                b"v".to_vec(),
                Value::bytes(PEER_MESSAGE_PROTOCOL_VERSION.as_bytes()),
            ),
        ])
    }
}

/// The metadata signing key a peer advertises in its `m=id` message.
///
/// A read-only peer holds no Ed25519 key and therefore omits `pk` entirely
/// (verified against official client 3.1.2). Such a peer cannot sign file
/// metadata, which the rest of the code represents as an all-zero key, so the
/// absent field is not an error.
pub fn peer_identity_key(message: &Value) -> Result<[u8; 32]> {
    match message.get(b"pk") {
        Ok(value) => value
            .as_bytes()?
            .try_into()
            .map_err(|_| anyhow::anyhow!("peer identity key is not 32 bytes")),
        Err(_) => Ok([0_u8; 32]),
    }
}

/// Whether a peer's advertised key marks it as unable to sign metadata.
pub fn peer_key_cannot_sign(public_key: &[u8; 32]) -> bool {
    *public_key == [0_u8; 32]
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EntryType {
    RegularFile,
    Directory,
}

impl EntryType {
    pub fn wire_value(&self) -> i64 {
        match self {
            Self::RegularFile => 1,
            Self::Directory => 2,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EntryState {
    Active,
    Deleted,
}

impl EntryState {
    pub fn wire_value(&self) -> i64 {
        match self {
            Self::Active => 1,
            Self::Deleted => 2,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FileMetadata {
    pub relative_path: Vec<String>,
    pub entry_type: EntryType,
    pub size: u64,
    pub mode: u32,
    pub mtime_seconds: i64,
    pub time_seconds: i64,
    pub state: EntryState,
    pub file_hash: [u8; 20],
    pub piece_hashes: Vec<[u8; 20]>,
    pub piece_count: usize,
    pub random_prefix: Vec<u8>,
    pub owner: [u8; 20],
    pub otime: i64,
    pub write_times: i64,
    pub signature: Vec<u8>,
    pub encrypted_path: Option<Vec<String>>,
    pub encrypted_epart: Option<Vec<u8>>,
    pub encrypted_main: Option<Value>,
}

impl FileMetadata {
    fn wire_write_times(&self) -> Option<i64> {
        let write_times = self.write_times & 0x3;
        (write_times != 0).then_some(write_times)
    }

    pub fn from_path(path: &Path, relative_path: &str, owner: [u8; 20]) -> Result<Self> {
        use std::io::Read;
        use std::os::unix::fs::{MetadataExt, PermissionsExt};

        let metadata =
            std::fs::metadata(path).with_context(|| format!("stat {}", path.display()))?;
        let mut file =
            std::fs::File::open(path).with_context(|| format!("open {}", path.display()))?;
        let mut piece_hashes = Vec::new();
        let mut buffer = vec![0_u8; PIECE_LENGTH as usize];
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
            let digest: [u8; 20] = Sha1::digest(&buffer[..filled]).into();
            piece_hashes.push(digest);
            if filled < buffer.len() {
                break;
            }
        }
        let mtime_seconds = metadata.mtime();
        let random_prefix = random_prefix(piece_hashes.len());
        let file_hash = if metadata.len() == 0 {
            [0; 20]
        } else {
            standard_file_hash(&piece_hashes)?
        };
        Ok(Self {
            relative_path: split_path(relative_path)?,
            entry_type: EntryType::RegularFile,
            size: metadata.len(),
            mode: metadata.permissions().mode() & 0o7777,
            mtime_seconds,
            time_seconds: mtime_seconds,
            state: EntryState::Active,
            file_hash,
            piece_count: piece_hashes.len(),
            piece_hashes,
            random_prefix,
            owner,
            otime: mtime_seconds,
            write_times: 2,
            signature: Vec::new(),
            encrypted_path: None,
            encrypted_epart: None,
            encrypted_main: None,
        })
    }

    pub fn from_directory(
        path: &Path,
        relative_path: &str,
        owner: [u8; 20],
        otime: i64,
    ) -> Result<Self> {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};

        let metadata =
            std::fs::metadata(path).with_context(|| format!("stat {}", path.display()))?;
        if !metadata.is_dir() {
            bail!("not a directory: {}", path.display());
        }
        let mtime_seconds = metadata.mtime();
        Ok(Self {
            relative_path: split_path(relative_path)?,
            entry_type: EntryType::Directory,
            size: 0,
            mode: metadata.permissions().mode() & 0o7777,
            mtime_seconds,
            time_seconds: mtime_seconds,
            state: EntryState::Active,
            file_hash: [0; 20],
            piece_count: 0,
            piece_hashes: Vec::new(),
            random_prefix: Vec::new(),
            owner,
            otime,
            write_times: 2,
            signature: Vec::new(),
            encrypted_path: None,
            encrypted_epart: None,
            encrypted_main: None,
        })
    }

    pub fn tombstone(&self, deleted_at: i64) -> Self {
        Self {
            time_seconds: deleted_at,
            state: EntryState::Deleted,
            write_times: self.write_times + 1,
            piece_hashes: Vec::new(),
            random_prefix: Vec::new(),
            signature: Vec::new(),
            encrypted_path: None,
            encrypted_epart: None,
            encrypted_main: None,
            ..self.clone()
        }
    }

    pub fn sign(&mut self, signing_key: &SigningKey) -> Result<()> {
        self.signature = signing_key
            .sign(&Sha1::digest(encode(&self.main())))
            .to_bytes()
            .to_vec();
        Ok(())
    }

    pub fn prepare_encrypted(&mut self, key: &ShareKey) -> Result<()> {
        use crate::secret::ShareKeyFamily;

        if key.family() != ShareKeyFamily::EncryptCapable || key.is_encrypted_only() {
            return Ok(());
        }
        // The canonical form changes, so a signature computed over the
        // previous (plaintext) form must not be reused.
        self.signature.clear();
        let content_key = key.encryption_key()?;
        let encrypted_path = crate::encrypted_folder::wrap_path(&content_key, &self.relative_path)?;
        let protected_mtime = match self.entry_type {
            EntryType::RegularFile => Some(self.mtime_seconds),
            EntryType::Directory => None,
        };
        let encrypted_epart = crate::encrypted_folder::encrypt_epart(
            &content_key,
            protected_mtime,
            self.time_seconds,
            crate::encrypted_folder::normalize_mode(self.mode),
            self.entry_type.wire_value(),
            self.write_times,
        )?;
        self.encrypted_path = Some(encrypted_path);
        self.encrypted_epart = Some(encrypted_epart);
        self.encrypted_main = Some(self.build_encrypted_main()?);
        Ok(())
    }

    pub fn prepare_encrypted_with_content(&mut self, key: &ShareKey, content: &[u8]) -> Result<()> {
        self.prepare_encrypted(key)?;
        if self.encrypted_epart.is_none()
            || self.entry_type != EntryType::RegularFile
            || self.state != EntryState::Active
            || self.size == 0
        {
            return Ok(());
        }
        // `file_hash` is the info-hash of the torrent the receiver rebuilds
        // from the wire form, and that torrent advertises the *ciphertext*
        // piece hashes (the bytes that travel in `data`). Derive it from the
        // encrypted content so a peer can match it byte for byte.
        let content_key = key.encryption_key()?;
        let wire_content = crate::encrypted_folder::encrypt_content(
            &content_key,
            &self.piece_hashes,
            PIECE_LENGTH as usize,
            content,
        )?;
        let torrent_info = self.torrent_info_for_content(&wire_content, Some(&content_key))?;
        let torrent_metadata = Value::dict([(b"info".to_vec(), torrent_info)]);
        self.file_hash = Sha1::digest(encode(&torrent_metadata)).into();
        self.encrypted_main = Some(self.build_encrypted_main()?);
        Ok(())
    }

    pub fn restore_encrypted_main(&mut self, main: Value) -> Result<()> {
        let path = main
            .get(b"path")?
            .as_list()?
            .iter()
            .map(|part| {
                String::from_utf8(part.as_bytes()?.to_vec()).context("encrypted path is not UTF-8")
            })
            .collect::<Result<Vec<_>>>()?;
        let epart = main.get(b"epart")?.as_bytes()?.to_vec();
        self.encrypted_path = Some(path);
        self.encrypted_epart = Some(epart);
        self.encrypted_main = Some(main);
        Ok(())
    }

    pub fn info_hash(&self, share_id: &[u8; 20]) -> [u8; 20] {
        self.info_hash_for_wire(share_id, self.encrypted_path.is_some())
    }

    pub fn info_hash_for_wire(&self, share_id: &[u8; 20], encrypted: bool) -> [u8; 20] {
        let mut hasher = Sha1::new();
        hasher.update(share_id);
        let path = if encrypted {
            self.encrypted_path.as_ref().unwrap_or(&self.relative_path)
        } else {
            &self.relative_path
        };
        for (index, component) in path.iter().enumerate() {
            if index != 0 {
                hasher.update([0]);
            }
            hasher.update(component.as_bytes());
        }
        hasher.update(self.file_hash);
        hasher.finalize().into()
    }

    pub fn wire_path(&self) -> Vec<u8> {
        self.encrypted_path
            .as_ref()
            .unwrap_or(&self.relative_path)
            .join("/")
            .into_bytes()
    }

    pub fn main(&self) -> Value {
        if let Some(main) = &self.encrypted_main {
            return main.clone();
        }
        self.plain_main()
    }

    pub fn plain_main(&self) -> Value {
        // Inside an encrypted folder upstream folds the mode to `0644`/`0755`
        // (any execute bit wins) before publishing it; the exact mode only
        // travels in the protected `epart`. Publishing the raw mode here made
        // peers reject the signature, which always covers the canonical form.
        let wire_mode = if self.encrypted_epart.is_some() {
            i64::from(crate::encrypted_folder::normalize_mode(self.mode))
        } else {
            self.mode as i64
        };
        let mut path = Vec::with_capacity(self.relative_path.len());
        for component in &self.relative_path {
            path.push(Value::bytes(component.clone()));
        }
        if self.entry_type == EntryType::Directory {
            let mut fields = BTreeMap::new();
            fields.insert(b"otime".to_vec(), Value::Int(self.otime));
            fields.insert(b"owner".to_vec(), Value::bytes(self.owner));
            fields.insert(b"path".to_vec(), Value::List(path));
            fields.insert(b"perm".to_vec(), Value::Int(wire_mode));
            fields.insert(b"state".to_vec(), Value::Int(self.state.wire_value()));
            fields.insert(b"time".to_vec(), Value::Int(self.time_seconds));
            fields.insert(b"type".to_vec(), Value::Int(self.entry_type.wire_value()));
            if let Some(write_times) = self.wire_write_times() {
                fields.insert(b"write_times".to_vec(), Value::Int(write_times));
            }
            return Value::Dict(fields);
        }
        let mut fields = BTreeMap::new();
        let empty_file = self.size == 0 && self.file_hash == [0; 20] && self.piece_count == 0;
        if !empty_file {
            fields.insert(b"hash".to_vec(), Value::bytes(self.file_hash));
            fields.insert(b"npieces".to_vec(), Value::Int(self.piece_count as i64));
        }
        fields.insert(b"mtime".to_vec(), Value::Int(self.mtime_seconds));
        fields.insert(b"otime".to_vec(), Value::Int(self.otime));
        fields.insert(b"owner".to_vec(), Value::bytes(self.owner));
        fields.insert(b"path".to_vec(), Value::List(path));
        fields.insert(b"perm".to_vec(), Value::Int(wire_mode));
        fields.insert(b"size".to_vec(), Value::Int(self.size as i64));
        fields.insert(b"state".to_vec(), Value::Int(self.state.wire_value()));
        fields.insert(b"time".to_vec(), Value::Int(self.time_seconds));
        fields.insert(b"type".to_vec(), Value::Int(self.entry_type.wire_value()));
        if let Some(write_times) = self.wire_write_times() {
            fields.insert(b"write_times".to_vec(), Value::Int(write_times));
        }
        Value::Dict(fields)
    }

    fn build_encrypted_main(&self) -> Result<Value> {
        let path = self
            .encrypted_path
            .as_ref()
            .context("encrypted metadata path is missing")?
            .iter()
            .map(|component| Value::bytes(component.clone()))
            .collect::<Vec<_>>();
        let epart = self
            .encrypted_epart
            .clone()
            .context("encrypted metadata epart is missing")?;
        let wire_mode = i64::from(crate::encrypted_folder::ENCRYPTED_WIRE_MODE);
        let mut fields = BTreeMap::new();
        fields.insert(b"epart".to_vec(), Value::bytes(epart));
        // The encrypted wire form always publishes `0644` and drops
        // `write_times`: the real mode and version bits live inside `epart`.
        if self.entry_type == EntryType::Directory {
            fields.insert(b"otime".to_vec(), Value::Int(self.otime));
            fields.insert(b"owner".to_vec(), Value::bytes(self.owner));
            fields.insert(b"path".to_vec(), Value::List(path));
            fields.insert(b"perm".to_vec(), Value::Int(wire_mode));
            fields.insert(b"state".to_vec(), Value::Int(self.state.wire_value()));
            fields.insert(b"time".to_vec(), Value::Int(self.time_seconds));
            fields.insert(b"type".to_vec(), Value::Int(self.entry_type.wire_value()));
            return Ok(Value::Dict(fields));
        }
        let empty_file = self.size == 0 && self.file_hash == [0; 20] && self.piece_count == 0;
        if !empty_file {
            fields.insert(b"hash".to_vec(), Value::bytes(self.file_hash));
            fields.insert(b"npieces".to_vec(), Value::Int(self.piece_count as i64));
        }
        fields.insert(b"otime".to_vec(), Value::Int(self.otime));
        fields.insert(b"owner".to_vec(), Value::bytes(self.owner));
        fields.insert(b"path".to_vec(), Value::List(path));
        fields.insert(b"perm".to_vec(), Value::Int(wire_mode));
        fields.insert(b"size".to_vec(), Value::Int(self.size as i64));
        fields.insert(b"state".to_vec(), Value::Int(self.state.wire_value()));
        fields.insert(b"time".to_vec(), Value::Int(self.time_seconds));
        fields.insert(b"type".to_vec(), Value::Int(self.entry_type.wire_value()));
        Ok(Value::Dict(fields))
    }

    pub fn metadata_hash(&self) -> [u8; 20] {
        Sha1::digest(encode(&self.main())).into()
    }

    pub fn metadata_hash_for_wire(&self, encrypted: bool) -> Result<[u8; 20]> {
        Ok(Sha1::digest(encode(&self.main_for_wire(encrypted)?)).into())
    }

    pub fn main_for_wire(&self, encrypted: bool) -> Result<Value> {
        if encrypted {
            self.encrypted_main
                .clone()
                .context("encrypted metadata main is missing")
        } else {
            Ok(self.plain_main())
        }
    }

    pub fn signed_file(&self, signing_key: &SigningKey, have: i64) -> Result<Value> {
        self.signed_file_for_wire(self.encrypted_main.is_some(), signing_key, have)
    }

    pub fn signed_file_for_wire(
        &self,
        encrypted: bool,
        signing_key: &SigningKey,
        have: i64,
    ) -> Result<Value> {
        let main = self.main_for_wire(encrypted)?;
        // The signature must cover exactly the `main` published next to it.
        let signature = self.signature_for_wire_with_form(signing_key, encrypted)?;
        let mut fields = BTreeMap::new();
        if self.entry_type == EntryType::RegularFile
            && self.state == EntryState::Active
            && !(self.size == 0 && self.file_hash == [0; 20] && self.piece_count == 0)
        {
            fields.insert(b"have".to_vec(), Value::Int(have));
        }
        fields.insert(b"main".to_vec(), main);
        fields.insert(b"sig".to_vec(), Value::bytes(signature));
        Ok(Value::Dict(fields))
    }

    pub fn signature_for_wire(&self, signing_key: &SigningKey) -> Result<Vec<u8>> {
        self.signature_for_wire_with_form(signing_key, self.encrypted_main.is_some())
    }

    /// Upstream signs the *canonical* metadata of an encrypted folder, i.e. the
    /// form carrying `epart` and the wrapped path, even when the wire form it
    /// publishes next to the signature is the plaintext one. Both directions
    /// rely on this: a peer that receives the plaintext form still expects the
    /// signature to cover the encrypted form, and a peer that receives the
    /// encrypted form verifies it against the same bytes.
    ///
    /// `encrypted` therefore only selects which `main` is published; the
    /// signature always covers [`FileMetadata::main`].
    pub fn signature_for_wire_with_form(
        &self,
        signing_key: &SigningKey,
        _encrypted: bool,
    ) -> Result<Vec<u8>> {
        if !self.signature.is_empty() {
            return Ok(self.signature.clone());
        }
        let main = self.main();
        Ok(signing_key
            .sign(&Sha1::digest(encode(&main)))
            .to_bytes()
            .to_vec())
    }

    pub fn torrent_metadata(&self) -> Value {
        Value::dict([(b"info".to_vec(), self.torrent_info())])
    }

    pub fn torrent_info(&self) -> Value {
        self.torrent_info_with_wire_hashes(&self.piece_hashes, None)
            .expect("legacy torrent metadata generation")
    }

    /// Build the torrent `info` dictionary for one file.
    ///
    /// `hashed_content` is the byte stream `pieces` must describe. Outside an
    /// encrypted folder that is the content itself; inside one it is the
    /// **ciphertext**, even when the `data` body sent to a read-only peer is
    /// the plaintext. This was verified against official client 3.1.2, whose
    /// own `meta` table stores `pieces` as the SHA-1 of the ciphertext while
    /// `epieces` carries the AES-wrapped SHA-1 of the plaintext; the same meta
    /// is reused verbatim for `E` and `F` peers. Hashing the plaintext here
    /// made the peer reject the metadata with "Failed to verify metadata hash"
    /// and ban the sender.
    pub fn torrent_info_for_content(
        &self,
        hashed_content: &[u8],
        content_key: Option<&[u8; 16]>,
    ) -> Result<Value> {
        let wire_piece_hashes = hashed_content
            .chunks(PIECE_LENGTH as usize)
            .map(|chunk| Sha1::digest(chunk).into())
            .collect::<Vec<[u8; 20]>>();
        if wire_piece_hashes.len() != self.piece_hashes.len() {
            bail!("torrent piece hash count does not match content");
        }
        let info = self.torrent_info_with_wire_hashes(&wire_piece_hashes, content_key)?;
        Ok(info)
    }

    fn torrent_info_with_wire_hashes(
        &self,
        wire_piece_hashes: &[[u8; 20]],
        content_key: Option<&[u8; 16]>,
    ) -> Result<Value> {
        // An entry with no pieces has nothing to protect, so an encrypted
        // folder publishes it exactly like a plain one: no `epieces` field.
        let use_epieces = self.encrypted_epart.is_some() && !self.piece_hashes.is_empty();
        let mut pieces = Vec::with_capacity(wire_piece_hashes.len() * 20);
        for piece in wire_piece_hashes {
            pieces.extend_from_slice(piece);
        }
        let mut fields = BTreeMap::new();
        if use_epieces {
            let content_key = content_key.context("torrent epieces requires a content key")?;
            fields.insert(
                b"epieces".to_vec(),
                Value::bytes(crate::encrypted_folder::encrypt_epieces(
                    content_key,
                    &self.piece_hashes,
                )?),
            );
        }
        fields.insert(b"length".to_vec(), Value::Int(self.size as i64));
        fields.insert(b"piece length".to_vec(), Value::Int(PIECE_LENGTH as i64));
        fields.insert(b"pieces".to_vec(), Value::bytes(pieces));
        if !use_epieces {
            fields.insert(b"rp".to_vec(), Value::bytes(self.random_prefix.clone()));
        }
        Ok(Value::Dict(fields))
    }

    pub fn content_message(&self, content: &[u8]) -> Result<Value> {
        self.verify_content(content)?;
        self.content_message_unchecked(content)
    }

    pub fn content_message_unchecked(&self, content: &[u8]) -> Result<Value> {
        self.content_message_unchecked_with_key(content, None)
    }

    /// The `data` + `meta` pair sent for one file.
    ///
    /// `data_bytes` is the body actually placed in `data` while
    /// `hashed_bytes` is what `pieces` describes; they differ inside an
    /// encrypted folder. Official client 3.1.2 publishes the *same* torrent
    /// info to a read-only `E` peer and to an encrypted-only `F` peer — the
    /// `meta` row of its storage database is byte-identical for both — and
    /// only varies `data`: ciphertext for `F`, plaintext for `E`. `pieces`
    /// therefore always covers the ciphertext, and `epieces` protects the
    /// plaintext hashes so an `E` receiver can verify the plaintext body.
    pub fn content_message_for_wire(
        &self,
        data_bytes: &[u8],
        hashed_bytes: &[u8],
        content_key: Option<&[u8; 16]>,
    ) -> Result<Value> {
        let info = self.torrent_info_for_content(hashed_bytes, content_key)?;
        let meta_bytes = encode(&Value::dict([(b"info".to_vec(), info)]));
        Ok(Value::dict([
            (b"data".to_vec(), Value::bytes(data_bytes)),
            (b"meta".to_vec(), Value::Bytes(meta_bytes)),
        ]))
    }

    pub fn content_message_unchecked_with_key(
        &self,
        content: &[u8],
        content_key: Option<&[u8; 16]>,
    ) -> Result<Value> {
        let wire_data = self.metadata_content_for_wire(content, content_key)?;
        self.content_message_for_wire(&wire_data, &wire_data, content_key)
    }

    pub fn metadata_content_for_wire(
        &self,
        content: &[u8],
        content_key: Option<&[u8; 16]>,
    ) -> Result<Vec<u8>> {
        if self.encrypted_epart.is_none() {
            return Ok(content.to_vec());
        }
        let content_key = content_key.context("encrypted metadata requires a content key")?;
        crate::encrypted_folder::encrypt_content(
            content_key,
            &self.piece_hashes,
            PIECE_LENGTH as usize,
            content,
        )
    }

    pub fn direct_login(
        &self,
        share_id: &[u8; 20],
        peer_id: &[u8; 20],
        signing_key: &SigningKey,
        encrypted_wire: bool,
        encrypted_path: bool,
    ) -> Result<Vec<u8>> {
        encode_direct_torrent(&self.direct_login_message(
            share_id,
            peer_id,
            signing_key,
            encrypted_wire,
            encrypted_path,
        )?)
    }

    /// `encrypted_wire` selects the info hash that identifies the torrent;
    /// `encrypted_path` selects the name sent in `f`. They are not the same
    /// flag: the name must be one the *responder* can look up in its own tree.
    /// A `D`/`E` responder publishes plaintext names, while an encrypted-only
    /// `F` responder holds only the encrypted ones, so asking it by plaintext
    /// name makes the lookup fail and it closes the download connection.
    pub fn direct_login_message(
        &self,
        share_id: &[u8; 20],
        peer_id: &[u8; 20],
        signing_key: &SigningKey,
        encrypted_wire: bool,
        encrypted_path: bool,
    ) -> Result<Value> {
        let signature = if self.signature.is_empty() {
            signing_key
                .sign(&Sha1::digest(encode(&self.main())))
                .to_bytes()
                .to_vec()
        } else {
            self.signature.clone()
        };
        let path = if encrypted_path {
            self.protocol_path_string()
        } else {
            self.wire_path_string()
        };
        Ok(Value::dict([
            (b"f".to_vec(), Value::bytes(path.into_bytes())),
            (
                b"i".to_vec(),
                Value::bytes(self.info_hash_for_wire(share_id, encrypted_wire)),
            ),
            (b"p".to_vec(), Value::bytes(*peer_id)),
            (b"s".to_vec(), Value::bytes(*share_id)),
            (b"sig".to_vec(), Value::bytes(signature)),
        ]))
    }

    pub fn direct_login_body(
        &self,
        share_id: &[u8; 20],
        peer_id: &[u8; 20],
        signing_key: &SigningKey,
        encrypted_wire: bool,
    ) -> Result<Vec<u8>> {
        encode_direct_torrent_body(&self.direct_login_message(
            share_id,
            peer_id,
            signing_key,
            encrypted_wire,
            encrypted_wire,
        )?)
    }

    pub fn verify_content(&self, content: &[u8]) -> Result<()> {
        if content.len() as u64 != self.size {
            bail!(
                "content length mismatch for {}: {} != {}",
                self.wire_path_string(),
                content.len(),
                self.size
            );
        }
        if self.size == 0 && self.file_hash == [0; 20] && self.piece_hashes.is_empty() {
            return Ok(());
        }
        let mut pieces = Vec::new();
        for (index, chunk) in content.chunks(PIECE_LENGTH as usize).enumerate() {
            let actual: [u8; 20] = Sha1::digest(chunk).into();
            let expected = self
                .piece_hashes
                .get(index)
                .context("content has more pieces than metadata")?;
            if actual != *expected {
                bail!(
                    "piece {index} hash mismatch for {}",
                    self.wire_path_string()
                );
            }
            pieces.extend_from_slice(&actual);
        }
        if pieces.len() / 20 != self.piece_hashes.len() {
            bail!("content has fewer pieces than metadata");
        }
        // `piece_hashes` always cover the local plaintext. A plain folder's
        // `file_hash` is their SHA-1; an encrypted folder's is the info-hash of
        // the torrent built from the ciphertext, so it is only derivable from
        // the wire form and is checked by `torrent_file_hash` instead.
        if self.encrypted_epart.is_none() {
            let file_hash = standard_file_hash(self.piece_hashes.as_slice())?;
            if file_hash != self.file_hash {
                bail!("file hash mismatch for {}", self.wire_path_string());
            }
        }
        Ok(())
    }

    pub fn wire_path_string(&self) -> String {
        self.relative_path.join("/")
    }

    pub fn protocol_path_string(&self) -> String {
        self.encrypted_path
            .as_ref()
            .unwrap_or(&self.relative_path)
            .join("/")
    }
}

pub(crate) fn standard_file_hash(piece_hashes: &[[u8; 20]]) -> Result<[u8; 20]> {
    let mut input = Vec::with_capacity(piece_hashes.len().saturating_mul(20));
    for piece_hash in piece_hashes {
        input.extend_from_slice(piece_hash);
    }
    Ok(Sha1::digest(input).into())
}

pub fn encode_direct_torrent(value: &Value) -> Result<Vec<u8>> {
    let payload = encode(value);
    if payload.len() > MAX_FRAME {
        bail!("DirectTorrent message is too large: {}", payload.len());
    }
    let mut output = Vec::with_capacity(DIRECT_TORRENT_MAGIC.len() + 4 + payload.len());
    output.extend_from_slice(DIRECT_TORRENT_MAGIC);
    output.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    output.extend_from_slice(&payload);
    Ok(output)
}

pub fn verify_file_signature(public_key: &[u8; 32], main: &Value, signature: &[u8]) -> Result<()> {
    let public = VerifyingKey::from_bytes(public_key).context("invalid Ed25519 public key")?;
    let signature = Signature::from_slice(signature).context("invalid Ed25519 signature")?;
    if public
        .verify(&Sha1::digest(encode(main)), &signature)
        .is_ok()
    {
        return Ok(());
    }
    let mut normalized = main.as_dict()?.clone();
    if let Some(value) = normalized.get(&b"write_times"[..]) {
        let write_times = value.as_int()? & 0x3;
        if write_times == 0 {
            normalized.remove(&b"write_times"[..]);
        } else {
            normalized.insert(b"write_times".to_vec(), Value::Int(write_times));
        }
    }
    public
        .verify(&Sha1::digest(encode(&Value::Dict(normalized))), &signature)
        .context("invalid file metadata signature")
}

pub fn write_frame(stream: &mut impl Write, payload: &[u8]) -> Result<()> {
    if payload.len() > MAX_FRAME {
        bail!("peer frame is too large: {}", payload.len());
    }
    let compressed = compress_if_smaller(payload)?;
    let mut frame = Vec::with_capacity(4 + compressed.len());
    frame.extend_from_slice(&(compressed.len() as u32).to_be_bytes());
    frame.extend_from_slice(&compressed);
    stream.write_all(&frame)?;
    stream.flush()?;
    Ok(())
}

pub fn write_frame_uncompressed(stream: &mut impl Write, payload: &[u8]) -> Result<()> {
    if payload.len() > MAX_FRAME {
        bail!("peer frame is too large: {}", payload.len());
    }
    let mut frame = Vec::with_capacity(4 + payload.len());
    frame.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    frame.extend_from_slice(payload);
    stream.write_all(&frame)?;
    stream.flush()?;
    Ok(())
}

pub fn read_frame(stream: &mut impl Read) -> Result<Vec<u8>> {
    let mut header = [0_u8; 4];
    stream.read_exact(&mut header)?;
    let length = u32::from_be_bytes(header) as usize;
    if length > MAX_FRAME {
        bail!("peer frame exceeds limit: {length}");
    }
    let mut payload = vec![0_u8; length];
    stream.read_exact(&mut payload)?;
    if payload.starts_with(&[0x78, 0x01])
        || payload.starts_with(&[0x78, 0x5e])
        || payload.starts_with(&[0x78, 0x9c])
        || payload.starts_with(&[0x78, 0xda])
    {
        let mut decoded = Vec::new();
        ZlibDecoder::new(&payload[..])
            .read_to_end(&mut decoded)
            .context("decode zlib peer frame")?;
        if decoded.len() > MAX_FRAME {
            bail!("decompressed peer frame exceeds limit");
        }
        Ok(decoded)
    } else {
        Ok(payload)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum WirePayload {
    Peer(Vec<u8>),
    Direct(Vec<u8>),
    DirectHandshake([u8; 20]),
}

pub fn read_wire_payload(stream: &mut impl Read) -> Result<WirePayload> {
    let mut payload = Vec::new();
    stream.read_to_end(&mut payload)?;
    if payload == DIRECT_TORRENT_MAGIC_V2 || payload == DIRECT_TORRENT_MAGIC_V3 {
        return Ok(WirePayload::DirectHandshake(payload.try_into().unwrap()));
    }
    if is_direct_torrent_frame(&payload) {
        let length_offset = DIRECT_TORRENT_MAGIC_V3.len();
        let length = payload
            .get(length_offset..length_offset + 4)
            .context("truncated DirectTorrent length")?;
        let length = u32::from_be_bytes(length.try_into()?) as usize;
        if length > MAX_FRAME || length_offset + 4 + length != payload.len() {
            bail!("invalid DirectTorrent frame length");
        }
        return Ok(WirePayload::Direct(payload));
    }
    let length = payload.get(..4).context("truncated peer frame length")?;
    let length = u32::from_be_bytes(length.try_into()?) as usize;
    if length > MAX_FRAME || 4 + length != payload.len() {
        bail!("peer frame exceeds limit: {length}");
    }
    let mut body = payload[4..].to_vec();
    if body.starts_with(&[0x78, 0x01])
        || body.starts_with(&[0x78, 0x5e])
        || body.starts_with(&[0x78, 0x9c])
        || body.starts_with(&[0x78, 0xda])
    {
        let mut decoded = Vec::new();
        ZlibDecoder::new(&body[..])
            .read_to_end(&mut decoded)
            .context("decode zlib peer frame")?;
        if decoded.len() > MAX_FRAME {
            bail!("decompressed peer frame exceeds limit");
        }
        body = decoded;
    }
    Ok(WirePayload::Peer(body))
}

pub fn read_bencode_frame(stream: &mut impl Read) -> Result<Value> {
    let payload = read_frame(stream)?;
    let (value, consumed) = decode_prefix(&payload)?;
    if consumed != payload.len() {
        bail!("trailing bytes in peer message");
    }
    Ok(value)
}

pub fn write_bencode_frame(stream: &mut impl Write, value: &Value) -> Result<()> {
    write_frame(stream, &encode(value))
}

pub fn write_bencode_frame_uncompressed(stream: &mut impl Write, value: &Value) -> Result<()> {
    write_frame_uncompressed(stream, &encode(value))
}

pub fn encode_frame(payload: &[u8]) -> Result<Vec<u8>> {
    let compressed = compress_if_smaller(payload)?;
    let mut frame = Vec::with_capacity(4 + compressed.len());
    frame.extend_from_slice(&(compressed.len() as u32).to_be_bytes());
    frame.extend_from_slice(&compressed);
    Ok(frame)
}

pub fn write_tunnel_frame(
    stream: &mut impl Write,
    connection_id: u32,
    packet_type: u8,
    payload: &[u8],
    compressed: bool,
) -> Result<()> {
    let compressed = compressed || packet_type == TUNNEL_PACKET_DATA_COMPRESSED;
    let packet_type = if compressed && packet_type == TUNNEL_PACKET_DATA {
        TUNNEL_PACKET_DATA_COMPRESSED
    } else {
        packet_type
    };
    let body = if compressed {
        let mut encoder = ZlibEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(payload)?;
        encoder.finish()?
    } else {
        payload.to_vec()
    };
    if body.len() + 10 > u32::MAX as usize {
        bail!("tunnel packet is too large");
    }
    let mut frame = Vec::with_capacity(10 + body.len());
    frame.push(2);
    frame.extend_from_slice(&((body.len() + 10) as u32).to_be_bytes());
    frame.push(packet_type);
    frame.extend_from_slice(&connection_id.to_be_bytes());
    frame.extend_from_slice(&body);
    stream.write_all(&frame)?;
    stream.flush()?;
    Ok(())
}

pub fn write_tunnel_frame_v1(
    stream: &mut impl Write,
    connection_id: u32,
    packet_type: u8,
    payload: &[u8],
) -> Result<()> {
    if payload.len() + 8 > u16::MAX as usize {
        bail!("V1 tunnel packet is too large");
    }
    let mut frame = Vec::with_capacity(8 + payload.len());
    frame.extend_from_slice(&((payload.len() + 8) as u16).to_be_bytes());
    frame.push(1);
    frame.push(packet_type);
    frame.extend_from_slice(&connection_id.to_be_bytes());
    frame.extend_from_slice(payload);
    stream.write_all(&frame)?;
    stream.flush()?;
    Ok(())
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TunnelPacket {
    pub connection_id: u32,
    pub packet_type: u8,
    pub payload: Vec<u8>,
    pub compressed: bool,
}

pub fn read_tunnel_frame(stream: &mut impl Read) -> Result<TunnelPacket> {
    let mut first = [0_u8; 1];
    if stream.read(&mut first)? == 0 {
        return Err(
            io::Error::new(io::ErrorKind::UnexpectedEof, TUNNEL_EOF_AT_FRAME_BOUNDARY).into(),
        );
    }
    if first[0] == 2 {
        let mut length = [0_u8; 4];
        read_exact_truncated(stream, &mut length, "V2 tunnel packet length")?;
        let length = u32::from_be_bytes(length) as usize;
        if !(10..=MAX_FRAME + 10).contains(&length) {
            bail!("invalid V2 tunnel packet length {length}");
        }
        let mut header = [0_u8; 5];
        read_exact_truncated(stream, &mut header, "V2 tunnel packet header")?;
        let packet_type = header[0];
        let connection_id = u32::from_be_bytes(header[1..5].try_into()?);
        let mut body = vec![0_u8; length - 10];
        read_exact_truncated(stream, &mut body, "V2 tunnel packet body")?;
        if packet_type == TUNNEL_PACKET_DATA_COMPRESSED {
            let mut decoded = Vec::new();
            ZlibDecoder::new(&body[..]).read_to_end(&mut decoded)?;
            body = decoded;
        }
        let packet = TunnelPacket {
            connection_id,
            packet_type,
            payload: body,
            compressed: packet_type == TUNNEL_PACKET_DATA_COMPRESSED,
        };
        Ok(packet)
    } else {
        let mut header = [0_u8; 7];
        read_exact_truncated(stream, &mut header, "V1 tunnel packet header")?;
        let length = u16::from_be_bytes([first[0], header[0]]) as usize;
        if !(8..=MAX_FRAME + 8).contains(&length) {
            bail!("invalid V1 tunnel packet length {length}");
        }
        if header[1] != 1 {
            bail!("unsupported tunnel packet version {}", header[1]);
        }
        let packet_type = header[2];
        let connection_id = u32::from_be_bytes(header[3..7].try_into()?);
        let mut body = vec![0_u8; length - 8];
        read_exact_truncated(stream, &mut body, "V1 tunnel packet body")?;
        let packet = TunnelPacket {
            connection_id,
            packet_type,
            payload: body,
            compressed: false,
        };
        Ok(packet)
    }
}

pub const TUNNEL_EOF_AT_FRAME_BOUNDARY: &str = "stream ended at tunnel frame boundary";

fn read_exact_truncated(
    stream: &mut impl Read,
    mut buffer: &mut [u8],
    label: &str,
) -> std::io::Result<()> {
    while !buffer.is_empty() {
        match stream.read(buffer) {
            Err(error)
                if error.kind() == std::io::ErrorKind::WouldBlock
                    || error.kind() == std::io::ErrorKind::TimedOut =>
            {
                continue;
            }
            Err(error) => return Err(error),
            Ok(0) => {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    format!("truncated {label}"),
                ))
            }
            Ok(count) => buffer = &mut buffer[count..],
        }
    }
    Ok(())
}

pub fn read_wire_payload_bytes(payload: &[u8]) -> Result<WirePayload> {
    read_wire_payload(&mut Cursor::new(payload))
}

pub fn is_direct_torrent_frame(payload: &[u8]) -> bool {
    payload.starts_with(DIRECT_TORRENT_MAGIC_V2) || payload.starts_with(DIRECT_TORRENT_MAGIC_V3)
}

pub fn decode_direct_torrent(payload: &[u8]) -> Result<Value> {
    if !is_direct_torrent_frame(payload) {
        bail!("missing DirectTorrent magic");
    }
    let length_offset = DIRECT_TORRENT_MAGIC_V3.len();
    let length = payload
        .get(length_offset..length_offset + 4)
        .context("truncated DirectTorrent length")?;
    let length = u32::from_be_bytes(length.try_into()?) as usize;
    let start = length_offset + 4;
    let body = payload
        .get(start..start + length)
        .context("truncated DirectTorrent message")?;
    if start + length != payload.len() {
        bail!("trailing DirectTorrent bytes");
    }
    crate::bencode::decode(body)
}

pub fn encode_direct_torrent_body(value: &Value) -> Result<Vec<u8>> {
    let payload = encode(value);
    if payload.len() > MAX_FRAME {
        bail!("DirectTorrent message is too large: {}", payload.len());
    }
    let mut output = Vec::with_capacity(4 + payload.len());
    output.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    output.extend_from_slice(&payload);
    Ok(output)
}

pub fn decode_direct_torrent_body(payload: &[u8]) -> Result<Value> {
    let length = payload
        .get(..4)
        .context("truncated DirectTorrent body length")?;
    let length = u32::from_be_bytes(length.try_into()?) as usize;
    let body = payload
        .get(4..4 + length)
        .context("truncated DirectTorrent body")?;
    if 4 + length != payload.len() {
        bail!("trailing DirectTorrent body bytes");
    }
    crate::bencode::decode(body)
}

pub fn parse_file(value: &Value, public_key: &[u8; 32]) -> Result<FileMetadata> {
    parse_file_with_key(value, public_key, None)
}

pub fn parse_file_with_key(
    value: &Value,
    public_key: &[u8; 32],
    share_key: Option<&ShareKey>,
) -> Result<FileMetadata> {
    let main = value.get(b"main")?;
    let signature = value.get(b"sig")?.as_bytes()?.to_vec();
    // Signature checking happens after the metadata is built: an encrypted
    // folder publishes the plaintext wire form while signing the canonical
    // encrypted one, so verification needs the decoded entry.
    let path = main.get(b"path")?;
    let encrypted_path = path
        .as_list()?
        .iter()
        .map(|part| {
            let bytes = part.as_bytes()?;
            String::from_utf8(bytes.to_vec()).context("file path is not UTF-8")
        })
        .collect::<Result<Vec<_>>>()?;
    let encrypted_epart = match main.as_dict()?.get(&b"epart"[..]) {
        Some(value) => Some(value.as_bytes()?.to_vec()),
        None => None,
    };
    let encrypted_folder = encrypted_epart.is_some();
    let mut relative_path = encrypted_path.clone();
    let mut protected_mtime = None;
    let mut protected_mode = None;
    let mut protected_type = None;
    let mut protected_write_times = 0;
    if let Some(epart) = &encrypted_epart {
        if let Some(key) = share_key.filter(|key| key.can_encrypt()) {
            let protected = crate::encrypted_folder::decrypt_epart(&key.encryption_key()?, epart)
                .context("decrypt file epart")?;
            let protected = crate::bencode::decode(&protected).context("parse file epart")?;
            protected_mtime = Some(protected.get(b"mtime")?.as_int()?);
            protected_mode = Some(protected.get(b"perm")?.as_int()?);
            protected_type = Some(protected.get(b"type")?.as_int()?);
            protected_write_times = match protected.as_dict()?.get(&b"write_times"[..]) {
                Some(value) => value.as_int()?,
                None => 0,
            };
            let content_key = key.encryption_key()?;
            relative_path = crate::encrypted_folder::unwrap_path(&content_key, &encrypted_path)
                .context("decrypt file path")?;
        }
    }
    let entry_type = match main.get(b"type")?.as_int()? {
        1 => EntryType::RegularFile,
        2 => EntryType::Directory,
        other => bail!("unsupported upstream entry type {other}"),
    };
    if protected_type.is_some_and(|value| value != entry_type.wire_value()) {
        bail!("encrypted file epart type differs from metadata type");
    }
    let size = match entry_type {
        EntryType::RegularFile => main.get(b"size")?.as_int()?,
        EntryType::Directory => 0,
    };
    // The encrypted wire form always advertises `0644`; the real mode lives in
    // the protected epart. Without a decryptable epart keep the wire value.
    let mode = protected_mode.unwrap_or(main.get(b"perm")?.as_int()?);
    let mtime_seconds = match protected_mtime {
        Some(value) => value,
        None if encrypted_epart.is_some() => main.get(b"time")?.as_int()?,
        None => match entry_type {
            EntryType::RegularFile => main.get(b"mtime")?.as_int()?,
            EntryType::Directory => main.get(b"time")?.as_int()?,
        },
    };
    let time_seconds = main.get(b"time")?.as_int()?;
    let state = match main.get(b"state")?.as_int()? {
        1 => EntryState::Active,
        2 => EntryState::Deleted,
        other => bail!("unsupported upstream entry state {other}"),
    };
    let file_hash: [u8; 20] = match entry_type {
        EntryType::RegularFile => match main.as_dict()?.get(&b"hash"[..]) {
            Some(value) => value
                .as_bytes()?
                .try_into()
                .map_err(|_| anyhow::anyhow!("file hash is not 20 bytes"))?,
            None if size == 0 => [0; 20],
            None => bail!("missing file hash for non-empty file"),
        },
        EntryType::Directory => [0; 20],
    };
    let piece_count = match entry_type {
        EntryType::RegularFile => match main.as_dict()?.get(&b"npieces"[..]) {
            Some(value) => value.as_int()? as usize,
            None if size == 0 => 0,
            None => bail!("missing piece count for non-empty file"),
        },
        EntryType::Directory => 0,
    };
    let mut metadata = FileMetadata {
        relative_path,
        entry_type,
        size: size.try_into()?,
        mode: mode.try_into()?,
        mtime_seconds,
        time_seconds,
        state,
        file_hash,
        piece_count,
        piece_hashes: Vec::new(),
        random_prefix: Vec::new(),
        owner: main
            .get(b"owner")?
            .as_bytes()?
            .try_into()
            .map_err(|_| anyhow::anyhow!("owner is not 20 bytes"))?,
        otime: main.get(b"otime")?.as_int()?,
        write_times: protected_write_times.max(match main.as_dict()?.get(&b"write_times"[..]) {
            Some(value) => value.as_int()?,
            None => 0,
        }),
        signature: signature.clone(),
        encrypted_path: encrypted_folder.then_some(encrypted_path),
        encrypted_epart,
        encrypted_main: encrypted_folder.then(|| main.clone()),
    };

    // A signature only covers the exact `main` dictionary published next to
    // it. Peers may present either the canonical encrypted form (active
    // encrypted entries) or the plaintext form (tombstones and entries whose
    // wire form was rewritten by a relay), so try both before failing.
    if encrypted_folder {
        let canonical_result = verify_file_signature(public_key, main, &signature);
        let plain_main = metadata.plain_main();
        let plain_result = verify_file_signature(public_key, &plain_main, &signature);
        if canonical_result.is_err() && plain_result.is_ok() {
            metadata.signature = signature;
        } else {
            canonical_result?;
        }
    } else {
        let plain_result = verify_file_signature(public_key, main, &signature);
        if plain_result.is_err() && share_key.is_some_and(|key| key.can_encrypt()) {
            let key = share_key.unwrap();
            let original_mtime = metadata.mtime_seconds;
            let original_write_times = metadata.write_times;
            let mut verified = false;
            let mut canonical = metadata.clone();
            canonical.prepare_encrypted(key)?;
            let canonical_result = verify_file_signature(public_key, &canonical.main(), &signature);
            if canonical_result.is_ok() {
                metadata = canonical;
                metadata.signature = signature.clone();
                verified = true;
            }
            // Upstream is not consistent about which timestamp the protected
            // epart carries, so accept any combination it could have signed.
            for mtime_seconds in [metadata.mtime_seconds, metadata.time_seconds] {
                for write_times in [original_write_times, 0] {
                    let mut candidate = metadata.clone();
                    candidate.mtime_seconds = mtime_seconds;
                    candidate.write_times = write_times;
                    candidate.prepare_encrypted(key)?;
                    let candidate_result =
                        verify_file_signature(public_key, &candidate.main(), &signature);
                    if candidate_result.is_ok() {
                        candidate.mtime_seconds = original_mtime;
                        candidate.write_times = original_write_times;
                        candidate.signature = signature.clone();
                        metadata = candidate;
                        verified = true;
                        break;
                    }
                }
                if verified {
                    break;
                }
            }
            if !verified {
                plain_result?;
            }
        } else {
            plain_result?;
        }
    }
    Ok(metadata)
}

pub fn parse_content(value: &Value) -> Result<(Vec<u8>, TorrentMetadata)> {
    let content = value.get(b"data")?.as_bytes()?.to_vec();
    let encoded_meta = value.get(b"meta")?.as_bytes()?;
    let meta = crate::bencode::decode(encoded_meta)?;
    let info = meta.get(b"info")?;
    Ok((content, parse_torrent_info(info)?))
}

pub fn parse_torrent_info(info: &Value) -> Result<TorrentMetadata> {
    let piece_length = info.get(b"piece length")?.as_int()?;
    if piece_length <= 0 {
        bail!("torrent piece length must be positive");
    }
    let pieces = info.get(b"pieces")?.as_bytes()?;
    if pieces.len() % 20 != 0 {
        bail!("torrent piece hash array is not divisible by 20");
    }
    let piece_hashes = pieces
        .chunks(20)
        .map(|value| {
            value
                .try_into()
                .map_err(|_| anyhow::anyhow!("piece hash is not 20 bytes"))
        })
        .collect::<Result<Vec<_>>>()?;
    let epieces = info
        .get(b"epieces")
        .ok()
        .map(|value| value.as_bytes().map(|value| value.to_vec()))
        .transpose()?;
    let random_prefix = info
        .get(b"rp")
        .ok()
        .map(|value| value.as_bytes().map(|value| value.to_vec()))
        .transpose()?;
    let random_prefix = match (epieces.as_ref(), random_prefix) {
        (Some(_), Some(_)) => bail!("torrent has both epieces and rp"),
        (Some(_), None) => Vec::new(),
        (None, Some(random_prefix)) => {
            let expected_prefix_length = piece_hashes
                .len()
                .checked_mul(4)
                .context("torrent random prefix length overflow")?;
            if random_prefix.len() != expected_prefix_length {
                bail!("torrent rp is not {} bytes", expected_prefix_length);
            }
            random_prefix
        }
        (None, None) => {
            if !piece_hashes.is_empty() {
                bail!("torrent contains no piece hashes");
            }
            Vec::new()
        }
    };
    if let Some(epieces) = &epieces {
        if epieces.len() <= 16 || (epieces.len() - 16) % 16 != 0 {
            bail!("torrent epieces has an invalid length");
        }
        let expected_epieces_len =
            crate::encrypted_folder::encrypted_epieces_len(piece_hashes.len());
        if epieces.len() != expected_epieces_len {
            bail!("torrent epieces is not {} bytes", expected_epieces_len);
        }
    }
    Ok(TorrentMetadata {
        size: info.get(b"length")?.as_int()?.try_into()?,
        piece_length: piece_length.try_into()?,
        piece_hashes,
        random_prefix,
        epieces: epieces.unwrap_or_default(),
    })
}

pub fn expected_torrent_info_size(size: u64, piece_count: usize) -> Result<usize> {
    expected_torrent_info_size_for_shape(size, piece_count, false)
}

pub fn expected_torrent_info_size_for_shape(
    size: u64,
    piece_count: usize,
    use_epieces: bool,
) -> Result<usize> {
    let pieces_len = piece_count
        .checked_mul(20)
        .context("torrent piece count overflow")?;
    let mut fields = BTreeMap::new();
    if use_epieces {
        let epieces_len = crate::encrypted_folder::encrypted_epieces_len(piece_count);
        fields.insert(b"epieces".to_vec(), Value::Bytes(vec![0_u8; epieces_len]));
    }
    fields.insert(b"length".to_vec(), Value::Int(size as i64));
    fields.insert(b"piece length".to_vec(), Value::Int(PIECE_LENGTH as i64));
    fields.insert(b"pieces".to_vec(), Value::Bytes(vec![0_u8; pieces_len]));
    if !use_epieces {
        let random_prefix_len = piece_count
            .checked_mul(4)
            .context("torrent random prefix count overflow")?;
        fields.insert(b"rp".to_vec(), Value::Bytes(vec![0_u8; random_prefix_len]));
    }
    Ok(encode(&Value::Dict(fields)).len())
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TorrentMetadata {
    pub size: u64,
    pub piece_length: u64,
    pub piece_hashes: Vec<[u8; 20]>,
    pub random_prefix: Vec<u8>,
    pub epieces: Vec<u8>,
}

impl TorrentMetadata {
    pub fn file_hash(&self) -> Result<[u8; 20]> {
        if self.size == 0 && self.piece_hashes.is_empty() {
            return Ok([0; 20]);
        }
        if !self.epieces.is_empty() {
            let mut fields = BTreeMap::new();
            fields.insert(b"epieces".to_vec(), Value::bytes(self.epieces.clone()));
            fields.insert(b"length".to_vec(), Value::Int(self.size as i64));
            fields.insert(
                b"piece length".to_vec(),
                Value::Int(self.piece_length as i64),
            );
            let mut pieces = Vec::with_capacity(self.piece_hashes.len() * 20);
            for piece_hash in &self.piece_hashes {
                pieces.extend_from_slice(piece_hash);
            }
            fields.insert(b"pieces".to_vec(), Value::bytes(pieces));
            let metadata = Value::dict([(b"info".to_vec(), Value::Dict(fields))]);
            Ok(Sha1::digest(encode(&metadata)).into())
        } else {
            standard_file_hash(&self.piece_hashes)
        }
    }

    pub fn verify(&self, content: &[u8]) -> Result<()> {
        if content.len() as u64 != self.size {
            bail!("torrent content length mismatch");
        }
        if content
            .chunks(self.piece_length as usize)
            .zip(&self.piece_hashes)
            .any(|(chunk, expected)| Sha1::digest(chunk).as_slice() != expected.as_slice())
        {
            bail!("torrent piece hash mismatch");
        }
        if content
            .chunks(self.piece_length as usize)
            .count()
            .eq(&self.piece_hashes.len())
        {
            Ok(())
        } else {
            bail!("torrent piece count mismatch")
        }
    }
}

pub fn tree_hash(nodes: &Value) -> [u8; 20] {
    Sha1::digest(encode(nodes)).into()
}

#[derive(Debug)]
pub struct FileTree {
    pub root_hash: [u8; 20],
    root: Value,
    nodes: BTreeMap<String, Value>,
}

impl FileTree {
    pub fn root_node(&self) -> Value {
        self.root.clone()
    }

    pub fn node(&self, path: &str) -> Option<Value> {
        if path.is_empty() || path == "/" {
            return Some(self.root.clone());
        }
        self.nodes.get(path.trim_matches('/')).cloned()
    }
}

pub fn build_file_tree(entries: &[FileMetadata]) -> Result<FileTree> {
    #[derive(Default)]
    struct TreeNode {
        metadata: Option<FileMetadata>,
        children: BTreeMap<String, TreeNode>,
    }

    fn insert(root: &mut TreeNode, metadata: &FileMetadata) -> Result<()> {
        let mut current = root;
        for (index, component) in metadata.relative_path.iter().enumerate() {
            current = current.children.entry(component.clone()).or_default();
            if index + 1 == metadata.relative_path.len() {
                if current.metadata.is_some() {
                    bail!("duplicate tree path {}", metadata.wire_path_string());
                }
                current.metadata = Some(metadata.clone());
            } else if current.metadata.as_ref().is_some_and(|entry| {
                entry.entry_type != EntryType::Directory && entry.state == EntryState::Active
            }) {
                bail!(
                    "active file is used as a directory: {}",
                    metadata.wire_path_string()
                );
            }
        }
        Ok(())
    }

    fn metadata_for_node(node: &TreeNode) -> Option<&FileMetadata> {
        node.metadata.as_ref().or_else(|| {
            node.children
                .values()
                .find_map(|child| child.metadata.as_ref())
        })
    }

    fn node_value(node: &TreeNode) -> Result<[u8; 20]> {
        let metadata = metadata_for_node(node).context("tree node has no metadata")?;
        let metadata_hash = metadata.metadata_hash();
        if metadata.entry_type == EntryType::Directory && !node.children.is_empty() {
            let mut child_values = Vec::with_capacity(node.children.len() * 20);
            for child in node.children.values() {
                child_values.extend_from_slice(&node_value(child)?);
            }
            let child_hash: [u8; 20] = Sha1::digest(child_values).into();
            let mut combined = Vec::with_capacity(40);
            combined.extend_from_slice(&metadata_hash);
            combined.extend_from_slice(&child_hash);
            return Ok(Sha1::digest(combined).into());
        }
        Ok(metadata_hash)
    }

    fn node_wire(node: &TreeNode, value: [u8; 20]) -> Result<Value> {
        let mut children = BTreeMap::new();
        for (name, child) in &node.children {
            children.insert(name.as_bytes().to_vec(), Value::bytes(node_value(child)?));
        }
        Ok(Value::dict([
            (b"children".to_vec(), Value::Dict(children)),
            (b"file".to_vec(), Value::bytes(value)),
            (b"offset".to_vec(), Value::Int(0)),
        ]))
    }

    let mut root = TreeNode::default();
    for metadata in entries {
        insert(&mut root, metadata)?;
    }
    let mut root_children = BTreeMap::new();
    let mut root_bytes = Vec::new();
    for (name, child) in &root.children {
        let value = node_value(child)?;
        root_children.insert(name.as_bytes().to_vec(), Value::bytes(value));
        root_bytes.extend_from_slice(&value);
    }
    let root_node = Value::dict([
        (b"children".to_vec(), Value::Dict(root_children)),
        (b"file".to_vec(), Value::bytes([0_u8; 20])),
        (b"offset".to_vec(), Value::Int(0)),
    ]);

    let mut nodes = BTreeMap::new();
    fn collect_nodes(
        node: &TreeNode,
        prefix: &str,
        output: &mut BTreeMap<String, Value>,
    ) -> Result<()> {
        let wire = node_wire(node, node_value(node)?)?;
        output.insert(prefix.trim_matches('/').to_owned(), wire);
        for (name, child) in &node.children {
            let path = if prefix.is_empty() {
                name.clone()
            } else {
                format!("{prefix}/{name}")
            };
            collect_nodes(child, &path, output)?;
        }
        Ok(())
    }
    for (name, child) in &root.children {
        collect_nodes(child, name, &mut nodes)?;
    }

    Ok(FileTree {
        root_hash: Sha1::digest(root_bytes).into(),
        root: root_node,
        nodes,
    })
}

pub fn parse_direct_login(value: &Value) -> Result<DirectLogin> {
    let peer_id = value
        .get(b"p")
        .ok()
        .map(|value| {
            value
                .as_bytes()?
                .try_into()
                .map_err(|_| anyhow::anyhow!("peer ID is not 20 bytes"))
        })
        .transpose()?;
    let share_id = value
        .get(b"s")
        .ok()
        .map(|value| {
            value
                .as_bytes()?
                .try_into()
                .map_err(|_| anyhow::anyhow!("share ID is not 20 bytes"))
        })
        .transpose()?;
    Ok(DirectLogin {
        relative_path: value.get(b"f")?.as_bytes()?.to_vec(),
        info_hash: value
            .get(b"i")?
            .as_bytes()?
            .try_into()
            .map_err(|_| anyhow::anyhow!("info hash is not 20 bytes"))?,
        peer_id,
        share_id,
        signature: value.get(b"sig")?.as_bytes()?.to_vec(),
    })
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DirectLogin {
    pub relative_path: Vec<u8>,
    pub info_hash: [u8; 20],
    pub peer_id: Option<[u8; 20]>,
    pub share_id: Option<[u8; 20]>,
    pub signature: Vec<u8>,
}

fn compress_if_smaller(payload: &[u8]) -> Result<Vec<u8>> {
    let mut encoder = ZlibEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(payload)?;
    let compressed = encoder.finish()?;
    Ok(if compressed.len() < payload.len() {
        compressed
    } else {
        payload.to_vec()
    })
}

fn split_path(path: &str) -> Result<Vec<String>> {
    if path.is_empty() || path.starts_with('/') || path.ends_with('/') {
        bail!("upstream file path must be a non-empty relative path");
    }
    let parts = path
        .split('/')
        .map(|part| {
            if part.is_empty() || part == "." || part == ".." || part == ".sync" {
                bail!("unsafe upstream path component in {path}");
            }
            Ok(part.to_owned())
        })
        .collect::<Result<Vec<_>>>()?;
    Ok(parts)
}

fn random_prefix(piece_count: usize) -> Vec<u8> {
    use rand::RngCore;
    let mut value = vec![0_u8; piece_count * 4];
    rand::thread_rng().fill_bytes(&mut value);
    value
}

pub fn bencode_file_map(files: &[Value]) -> Value {
    Value::List(files.to_vec())
}

pub fn empty_nodes(root_children: BTreeMap<Vec<u8>, Value>) -> Value {
    let root = Value::dict([
        (b"children".to_vec(), Value::Dict(root_children)),
        (b"file".to_vec(), Value::bytes([0_u8; 20])),
        (b"offset".to_vec(), Value::Int(0)),
    ]);
    Value::dict([
        (b"m".to_vec(), Value::bytes(b"nodes")),
        (b"nodes".to_vec(), Value::dict([(b"/".to_vec(), root)])),
    ])
}

pub fn identity_from_base32(value: &str) -> Result<PeerIdentity> {
    let bytes = decode_base32(value)?;
    let peer_id: [u8; 20] = bytes
        .as_slice()
        .try_into()
        .map_err(|_| anyhow::anyhow!("peer identity is not 20 bytes"))?;
    Ok(PeerIdentity {
        name: encode_base32(&peer_id),
        peer_id,
        identity_key: IDENTITY_KEY,
        share_id: [0; 20],
    })
}

/// Build the upstream merge-controller ACL message family. The empty-list
/// forms are valid for a folder without ACL entries and keep older peers on
/// the normal tree-merge path.
pub fn get_acl_nodes_message(acl_hash: [u8; 20]) -> Value {
    Value::dict([
        (b"acl_hash".to_vec(), Value::bytes(acl_hash)),
        (b"m".to_vec(), Value::bytes(b"get_acl_nodes")),
    ])
}

pub fn acl_nodes_message(acl_hash: [u8; 20], nodes: Vec<Value>) -> Value {
    Value::dict([
        (b"acl_hash".to_vec(), Value::bytes(acl_hash)),
        (b"m".to_vec(), Value::bytes(b"acl_nodes")),
        (b"nodes".to_vec(), Value::List(nodes)),
    ])
}

pub fn get_acl_entries_message(acl_hash: [u8; 20], offset: i64) -> Value {
    Value::dict([
        (b"acl_hash".to_vec(), Value::bytes(acl_hash)),
        (b"entries".to_vec(), Value::List(Vec::new())),
        (b"m".to_vec(), Value::bytes(b"get_acl_entries")),
        (b"offset".to_vec(), Value::Int(offset)),
    ])
}

pub fn acl_entries_message(acl_hash: [u8; 20], entries: Vec<Value>, offset: i64) -> Value {
    Value::dict([
        (b"acl_hash".to_vec(), Value::bytes(acl_hash)),
        (b"entries".to_vec(), Value::List(entries)),
        (b"m".to_vec(), Value::bytes(b"acl_entries")),
        (b"offset".to_vec(), Value::Int(offset)),
    ])
}

pub fn acl_entries_accepted_message(acl_hash: [u8; 20]) -> Value {
    Value::dict([
        (b"acl_hash".to_vec(), Value::bytes(acl_hash)),
        (b"m".to_vec(), Value::bytes(b"acl_entries_accepted")),
    ])
}

#[cfg(test)]
mod tests {
    use super::*;

    struct TimeoutThenData {
        payload: &'static [u8],
        timed_out: bool,
    }

    impl std::io::Read for TimeoutThenData {
        fn read(&mut self, output: &mut [u8]) -> std::io::Result<usize> {
            if !self.timed_out {
                self.timed_out = true;
                return Err(std::io::Error::from(std::io::ErrorKind::WouldBlock));
            }
            let count = output.len().min(self.payload.len());
            output[..count].copy_from_slice(&self.payload[..count]);
            self.payload = &self.payload[count..];
            Ok(count)
        }
    }

    #[test]
    fn truncated_frame_read_retries_after_timeout_without_losing_bytes() {
        let mut reader = TimeoutThenData {
            payload: b"frame-body",
            timed_out: false,
        };
        let mut output = [0_u8; 10];
        read_exact_truncated(&mut reader, &mut output, "test frame").unwrap();
        assert_eq!(&output, b"frame-body");
    }

    fn fixture_metadata(path: &[&str], entry_type: EntryType, state: EntryState) -> FileMetadata {
        FileMetadata {
            relative_path: path.iter().map(|value| (*value).to_owned()).collect(),
            entry_type,
            size: if entry_type == EntryType::RegularFile {
                24
            } else {
                0
            },
            mode: if entry_type == EntryType::RegularFile {
                420
            } else {
                493
            },
            mtime_seconds: 1790605742,
            time_seconds: if state == EntryState::Deleted {
                1790605763
            } else {
                1790605742
            },
            state,
            file_hash: if entry_type == EntryType::RegularFile {
                [
                    0x68, 0x29, 0x22, 0xd2, 0x24, 0xf6, 0xcb, 0x87, 0x09, 0xff, 0x60, 0x7b, 0x24,
                    0xa8, 0xa0, 0x23, 0xaf, 0xe0, 0x75, 0x00,
                ]
            } else {
                [0; 20]
            },
            piece_count: if entry_type == EntryType::RegularFile {
                1
            } else {
                0
            },
            piece_hashes: Vec::new(),
            random_prefix: Vec::new(),
            owner: [
                0x20, 0x24, 0xde, 0x6e, 0xdb, 0x9b, 0xde, 0xf6, 0x6f, 0x48, 0x25, 0x5e, 0x6b, 0x41,
                0xb0, 0xb8, 0x09, 0xb2, 0x13, 0x5a,
            ],
            otime: 10,
            write_times: 2,
            signature: Vec::new(),
            encrypted_path: None,
            encrypted_epart: None,
            encrypted_main: None,
        }
    }

    #[test]
    fn tombstone_metadata_has_stable_node_value() {
        let metadata = fixture_metadata(
            &["delete-probe.txt"],
            EntryType::RegularFile,
            EntryState::Deleted,
        );
        assert_eq!(
            hex::encode(metadata.metadata_hash()),
            "623b6dc74c79ad8d64ebd5473ebf70bc36af147e"
        );
    }

    #[test]
    fn metadata_signature_uses_two_bit_write_times() {
        let mut metadata = fixture_metadata(
            &["wrapped.bin"],
            EntryType::RegularFile,
            EntryState::Deleted,
        );
        metadata.write_times = 4;
        let signing_key = SigningKey::from_bytes(&[9_u8; 32]);
        metadata.sign(&signing_key).unwrap();

        let canonical = metadata.main();
        assert!(canonical
            .as_dict()
            .unwrap()
            .get(&b"write_times"[..])
            .is_none());

        let mut raw_fields = canonical.as_dict().unwrap().clone();
        raw_fields.insert(b"write_times".to_vec(), Value::Int(4));
        verify_file_signature(
            &signing_key.verifying_key().to_bytes(),
            &Value::Dict(raw_fields),
            &metadata.signature,
        )
        .unwrap();
    }

    #[test]
    fn nested_directory_hash_uses_metadata_and_child_digest() {
        let directory = fixture_metadata(&["dir"], EntryType::Directory, EntryState::Active);
        let child = fixture_metadata(
            &["dir", "child.txt"],
            EntryType::RegularFile,
            EntryState::Deleted,
        );
        let tree = build_file_tree(&[directory, child]).unwrap();
        assert_eq!(
            hex::encode(tree.root_hash),
            "9a0d5ac76277579279926935b5397af4d373f470"
        );
        let node = tree.node("dir").unwrap();
        assert_eq!(
            hex::encode(node.get(b"file").unwrap().as_bytes().unwrap()),
            "841f3ead4f97e89b51c4b8a97ecb4b6f2ac7344a"
        );
    }
    use crate::secret::ShareKey;

    #[test]
    fn file_hash_and_info_hash_match_upstream_formula() {
        let mut metadata = FileMetadata {
            relative_path: vec!["nested".into(), "file.bin".into()],
            size: 2,
            mode: 0o644,
            mtime_seconds: 1,
            time_seconds: 1,
            state: EntryState::Active,
            entry_type: EntryType::RegularFile,
            file_hash: [0; 20],
            piece_count: 1,
            piece_hashes: vec![[1; 20]],
            random_prefix: vec![2, 3, 4, 5],
            owner: [6; 20],
            otime: 7,
            write_times: 2,
            signature: Vec::new(),
            encrypted_path: None,
            encrypted_epart: None,
            encrypted_main: None,
        };
        metadata.file_hash = Sha1::digest(metadata.piece_hashes[0]).into();
        let share = [8; 20];
        let mut expected = Sha1::new();
        expected.update(share);
        expected.update(b"nested\0file.bin");
        expected.update(metadata.file_hash);
        assert_eq!(metadata.info_hash(&share), expected.finalize().as_slice());
    }

    #[test]
    fn standard_multi_piece_file_hash_concatenates_piece_hashes() {
        let metadata = FileMetadata {
            relative_path: vec!["multi.bin".into()],
            size: 70_000,
            mode: 0o644,
            mtime_seconds: 1,
            time_seconds: 1,
            state: EntryState::Active,
            entry_type: EntryType::RegularFile,
            file_hash: [0; 20],
            piece_count: 3,
            piece_hashes: vec![[1; 20], [2; 20], [3; 20]],
            random_prefix: vec![0; 12],
            owner: [6; 20],
            otime: 7,
            write_times: 2,
            signature: Vec::new(),
            encrypted_path: None,
            encrypted_epart: None,
            encrypted_main: None,
        };
        let torrent = parse_torrent_info(&metadata.torrent_info()).unwrap();
        let mut expected_input = Vec::new();
        expected_input.extend_from_slice(&[1; 20]);
        expected_input.extend_from_slice(&[2; 20]);
        expected_input.extend_from_slice(&[3; 20]);
        assert_eq!(
            torrent.file_hash().unwrap().as_slice(),
            Sha1::digest(expected_input).as_slice()
        );
        assert_eq!(torrent.random_prefix, vec![0; 12]);
        assert!(torrent.epieces.is_empty());
    }

    #[test]
    fn encrypted_multi_piece_metadata_matches_official_fixture() {
        let key = ShareKey::parse("DJMJ5MWYMBKS5SCWMBRQ7LXBGZAQGLSAQ").unwrap();
        let plain_hashes = [
            hex::decode("d47de169151cf65d085423d15540a95242871fba")
                .unwrap()
                .try_into()
                .unwrap(),
            hex::decode("3d00efee58abc0e78cd7525abac6b9bcba119fa7")
                .unwrap()
                .try_into()
                .unwrap(),
            hex::decode("cda88b27b204b60d615f897acfc80fd085d926e4")
                .unwrap()
                .try_into()
                .unwrap(),
        ];
        let wire_hashes = [
            hex::decode("c090bcd6206df365cfb4651bca1d244355c2b0cf")
                .unwrap()
                .try_into()
                .unwrap(),
            hex::decode("c1d3687b123c5d96514aac757e853a965795b737")
                .unwrap()
                .try_into()
                .unwrap(),
            hex::decode("d70ef447ba207ed8b6365b2a13682614f4ead30c")
                .unwrap()
                .try_into()
                .unwrap(),
        ];
        let metadata = FileMetadata {
            relative_path: vec!["multi.bin".into()],
            size: 70_000,
            mode: 0o644,
            mtime_seconds: 1,
            time_seconds: 1,
            state: EntryState::Active,
            entry_type: EntryType::RegularFile,
            file_hash: [0; 20],
            piece_count: 3,
            piece_hashes: plain_hashes.to_vec(),
            random_prefix: Vec::new(),
            owner: [6; 20],
            otime: 7,
            write_times: 2,
            signature: Vec::new(),
            encrypted_path: None,
            encrypted_epart: Some(Vec::new()),
            encrypted_main: None,
        };
        let info = metadata
            .torrent_info_with_wire_hashes(&wire_hashes, Some(&key.encryption_key().unwrap()))
            .unwrap();
        // The file hash covers the bencoded `{"info": …}` wrapper, which is
        // what the fixture below pins.
        let encoded = encode(&Value::dict([(b"info".to_vec(), info.clone())]));
        assert_eq!(
            hex::encode(&encoded),
            "64343a696e666f64373a6570696563657338303a24110525987be1d5cc352dbea6bdc1bf0621f29b662aaadcf23b2006d9b48bdd35d7dd0b8cfc19ee063fbf851a8bc6199e8bf7adcd4a5450bc3ed985e603ae97efccd9041909dd0015189d4357da16dd363a6c656e6774686937303030306531323a7069656365206c656e67746869333237363865363a70696563657336303ac090bcd6206df365cfb4651bca1d244355c2b0cfc1d3687b123c5d96514aac757e853a965795b737d70ef447ba207ed8b6365b2a13682614f4ead30c6565"
        );
        let torrent = parse_torrent_info(&info).unwrap();
        assert_eq!(
            hex::encode(torrent.file_hash().unwrap()),
            "5c6c7deecfb6257dfd7742de867c95e676b06211"
        );
    }

    #[test]
    fn round_trips_signed_metadata_and_content() {
        let key = ShareKey::parse(&format!("A{}", crate::secret::encode_base32(&[7; 20]))).unwrap();
        let signing_key = key.ed25519_signing_key().unwrap();
        let public_key = key.ed25519_public_key().unwrap();
        let metadata = FileMetadata {
            relative_path: vec!["file".into()],
            size: 1,
            mode: 0o644,
            mtime_seconds: 1,
            time_seconds: 1,
            state: EntryState::Active,
            entry_type: EntryType::RegularFile,
            file_hash: Sha1::digest(Sha1::digest(b"x")).into(),
            piece_count: 1,
            piece_hashes: vec![Sha1::digest(b"x").into()],
            random_prefix: vec![0; 4],
            owner: [1; 20],
            otime: 2,
            write_times: 2,
            signature: Vec::new(),
            encrypted_path: None,
            encrypted_epart: None,
            encrypted_main: None,
        };
        let file = metadata.signed_file(&signing_key, 1).unwrap();
        let parsed = parse_file(&file, &public_key).unwrap();
        assert_eq!(parsed.file_hash, metadata.file_hash);
        let (content, torrent) = parse_content(&metadata.content_message(b"x").unwrap()).unwrap();
        torrent.verify(&content).unwrap();
    }

    #[test]
    fn encrypted_metadata_matches_official_fixture_and_key_roles() {
        let read_write = ShareKey::parse("DJMJ5MWYMBKS5SCWMBRQ7LXBGZAQGLSAQ").unwrap();
        let read_only =
            ShareKey::parse("EH5L5UOAVPTVUQTRQRVGFD5XGUQB5B6ZDZR47LKBWQANFZSCU5CTMTFG3CI").unwrap();
        let encrypted_only = ShareKey::parse("FH5L5UOAVPTVUQTRQRVGFD5XGUQB5B6ZD").unwrap();
        let mut metadata = FileMetadata {
            relative_path: vec!["sample.bin".to_owned()],
            entry_type: EntryType::RegularFile,
            size: 21,
            mode: 420,
            mtime_seconds: 1790774110,
            time_seconds: 1790774110,
            state: EntryState::Active,
            file_hash: [
                0x81, 0x88, 0x38, 0x1a, 0x8e, 0x6c, 0x99, 0xc2, 0x7c, 0xe6, 0xf1, 0x74, 0x08, 0x39,
                0x32, 0x06, 0x98, 0xa9, 0x9f, 0xac,
            ],
            piece_hashes: vec![hex::decode("7159b85339d6e567ef2bf01c09afbc3a68442b0d")
                .unwrap()
                .try_into()
                .unwrap()],
            piece_count: 1,
            random_prefix: vec![0; 4],
            owner: [
                0x20, 0xb2, 0x43, 0x66, 0x12, 0xec, 0xbd, 0x88, 0x2c, 0xe7, 0xd6, 0x5e, 0xda, 0xed,
                0x15, 0xa9, 0xb4, 0xee, 0xa5, 0x9a,
            ],
            otime: 5,
            write_times: 2,
            signature: Vec::new(),
            encrypted_path: None,
            encrypted_epart: None,
            encrypted_main: None,
        };
        metadata
            .prepare_encrypted_with_content(&read_write, b"hello sample metadata")
            .unwrap();
        let main = metadata.main();
        assert_eq!(
            hex::encode(encode(&main)),
            "64353a657061727437323a4877baa041bd5a99795bd5cec6b1fd07e57e30754bb21d2965d300ff170c1ed3d9683b8e96a247d011ac5ecde716c795f3d34af0d703bf87805f34e21aad4fe9060d84836d152797343a6861736832303a8188381a8e6c99c27ce6f1740839320698a99fac373a6e706965636573693165353a6f74696d65693565353a6f776e657232303a20b2436612ecbd882ce7d65edaed15a9b4eea59a343a706174686c33393a594248375a324d594b5459543554544c56435755354d46423351585950354955574f52364b454165343a7065726d6934323065343a73697a6569323165353a7374617465693165343a74696d65693137393037373431313065343a7479706569316565"
        );
        assert_eq!(
            hex::encode(Sha1::digest(encode(&main))),
            "3ae0234a8499cd473f6f43c840d2477ce03edc9b"
        );
        assert_eq!(
            hex::encode(metadata.info_hash(&read_write.share_id())).to_uppercase(),
            "A1055DBA7D8AA6455F21D58778E6537B7D1300EA"
        );

        let signing_key = read_write.ed25519_signing_key().unwrap();
        let public_key = read_write.ed25519_public_key().unwrap();
        let file = metadata.signed_file(&signing_key, 1).unwrap();
        let plain_file = metadata
            .signed_file_for_wire(false, &signing_key, 1)
            .unwrap();
        assert!(plain_file
            .get(b"main")
            .unwrap()
            .as_dict()
            .unwrap()
            .get(&b"epart"[..])
            .is_none());
        let parsed_plain =
            parse_file_with_key(&plain_file, &public_key, Some(&read_write)).unwrap();
        assert_eq!(parsed_plain.encrypted_main.as_ref().unwrap(), &main);
        verify_file_signature(
            &public_key,
            parsed_plain.encrypted_main.as_ref().unwrap(),
            plain_file.get(b"sig").unwrap().as_bytes().unwrap(),
        )
        .unwrap();
        for key in [&read_write, &read_only, &encrypted_only] {
            let parsed = parse_file_with_key(&file, &public_key, Some(key)).unwrap();
            assert_eq!(parsed.encrypted_main.as_ref().unwrap(), &main);
            assert_eq!(parsed.encrypted_epart.as_ref().unwrap().len(), 72);
            if key.is_encrypted_only() {
                assert_eq!(
                    parsed.relative_path,
                    vec!["YBH7Z2MYKTYT5TTLVCWU5MFB3QXYP5IUWOR6KEA".to_owned()]
                );
            } else {
                assert_eq!(parsed.relative_path, vec!["sample.bin".to_owned()]);
                assert_eq!(parsed.mtime_seconds, 1790774110);
            }
        }
    }

    #[test]
    fn published_metadata_hash_matches_the_bytes_the_piece_protocol_serves() {
        // Regression: an encrypted folder used to publish the torrent info of
        // the *served* body. A `D`/`E` receiver is served plaintext but derives
        // `file_hash` from the ciphertext torrent, so it answered every
        // metadata request with "unable to parse meta ... Failed to verify
        // metadata hash" and the update never completed. The published info
        // must always describe the ciphertext, while the piece protocol serves
        // whatever the receiver can consume.
        use crate::secret::ShareKey;
        let read_write = ShareKey::parse("DJMJ5MWYMBKS5SCWMBRQ7LXBGZAQGLSAQ").unwrap();
        let content_key = read_write.encryption_key().unwrap();
        let plaintext: Vec<u8> = (0..90_000_u32).map(|value| value as u8).collect();
        let source = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(source.path(), &plaintext).unwrap();
        let mut metadata = FileMetadata::from_path(source.path(), "multi.bin", [1_u8; 20]).unwrap();
        metadata
            .prepare_encrypted_with_content(&read_write, &plaintext)
            .unwrap();

        let ciphertext = crate::encrypted_folder::encrypt_content(
            &read_write.encryption_key().unwrap(),
            &metadata.piece_hashes,
            PIECE_LENGTH as usize,
            &plaintext,
        )
        .unwrap();

        // What a `D`/`E` receiver is served, and what `ut_metadata` publishes.
        let served = plaintext.clone();
        let published = metadata
            .torrent_info_for_content(&ciphertext, Some(&content_key))
            .unwrap();
        let published = parse_torrent_info(&published).unwrap();
        assert_eq!(
            hex::encode(published.file_hash().unwrap()),
            hex::encode(metadata.file_hash),
            "the published info must reproduce the announced file hash"
        );
        let first_piece = PIECE_LENGTH as usize;
        assert_eq!(
            hex::encode(Sha1::digest(&ciphertext[..first_piece])),
            hex::encode(published.piece_hashes[0])
        );
        assert_ne!(
            hex::encode(Sha1::digest(&served[..first_piece])),
            hex::encode(published.piece_hashes[0]),
            "serving plaintext while advertising ciphertext hashes is the bug"
        );

        // The `epieces` layer still carries the plaintext hashes, which is how
        // the receiver validates the plaintext it actually stored.
        let epieces =
            crate::encrypted_folder::decrypt_epieces(&content_key, &published.epieces).unwrap();
        assert_eq!(
            hex::encode(epieces[0]),
            hex::encode(metadata.piece_hashes[0]),
            "epieces must keep describing the plaintext hashes"
        );
    }

    #[test]
    fn encrypted_torrent_pieces_describe_ciphertext_for_every_reader_role() {
        // Official client 3.1.2 publishes one torrent info per encrypted file
        // and hashes the *ciphertext* into `pieces`, then reuses that meta
        // verbatim for a read-only `E` peer (which receives the plaintext body)
        // and for an encrypted-only `F` peer (which receives the ciphertext).
        // Reproducing it requires hashing the encrypted bytes while still being
        // able to send either body.
        let read_write = ShareKey::parse("DJMJ5MWYMBKS5SCWMBRQ7LXBGZAQGLSAQ").unwrap();
        let content_key = read_write.encryption_key().unwrap();
        let plaintext = b"hello sample metadata";
        let ciphertext = crate::encrypted_folder::encrypt_content(
            &content_key,
            &[Sha1::digest(plaintext).into()],
            PIECE_LENGTH as usize,
            plaintext,
        )
        .unwrap();
        assert_eq!(
            hex::encode(&ciphertext),
            "f5b3ceaa2ffd4c720db685170ce3e30c89831673b7"
        );

        let mut metadata = FileMetadata {
            relative_path: vec!["sample.bin".to_owned()],
            entry_type: EntryType::RegularFile,
            size: 21,
            mode: 420,
            mtime_seconds: 1790774110,
            time_seconds: 1790774110,
            state: EntryState::Active,
            file_hash: [0; 20],
            piece_hashes: vec![Sha1::digest(plaintext).into()],
            piece_count: 1,
            random_prefix: vec![0; 4],
            owner: [0x20; 20],
            otime: 5,
            write_times: 2,
            signature: Vec::new(),
            encrypted_path: None,
            encrypted_epart: None,
            encrypted_main: None,
        };
        metadata
            .prepare_encrypted_with_content(&read_write, plaintext)
            .unwrap();

        // The torrent hashes the ciphertext even though `piece_hashes` -- and
        // the `epieces` field -- protect the plaintext.
        let info = metadata
            .torrent_info_for_content(&ciphertext, Some(&content_key))
            .unwrap();
        let torrent = parse_torrent_info(&info).unwrap();
        assert_eq!(
            hex::encode(Sha1::digest(&ciphertext)),
            hex::encode(torrent.piece_hashes[0])
        );
        assert_ne!(
            hex::encode(torrent.piece_hashes[0]),
            hex::encode(metadata.piece_hashes[0]),
            "pieces must describe the ciphertext, not the plaintext"
        );
        assert_eq!(
            hex::encode(torrent.file_hash().unwrap()),
            hex::encode(metadata.file_hash)
        );

        // An `F` reader gets the ciphertext body; a `D`/`E` reader the
        // plaintext one. Both are described by the very same meta.
        let for_encrypted_only = metadata
            .content_message_for_wire(&ciphertext, &ciphertext, Some(&content_key))
            .unwrap();
        let for_read_only = metadata
            .content_message_for_wire(plaintext, &ciphertext, Some(&content_key))
            .unwrap();
        assert_eq!(
            for_encrypted_only.get(b"meta").unwrap().as_bytes().unwrap(),
            for_read_only.get(b"meta").unwrap().as_bytes().unwrap()
        );
        assert_eq!(
            parse_content(&for_encrypted_only).unwrap().0,
            ciphertext.as_slice()
        );
        assert_eq!(
            parse_content(&for_read_only).unwrap().0,
            plaintext.as_slice()
        );
    }

    #[test]
    fn empty_file_wire_shape_round_trips() {
        let key = ShareKey::parse(&format!("A{}", crate::secret::encode_base32(&[7; 20]))).unwrap();
        let signing_key = key.ed25519_signing_key().unwrap();
        let public_key = key.ed25519_public_key().unwrap();
        let source = tempfile::NamedTempFile::new().unwrap();
        let metadata = FileMetadata::from_path(source.path(), "empty.bin", [1; 20]).unwrap();
        let file = metadata.signed_file(&signing_key, 0).unwrap();
        let main = file.get(b"main").unwrap();
        assert!(main.as_dict().unwrap().get(&b"hash"[..]).is_none());
        assert!(main.as_dict().unwrap().get(&b"npieces"[..]).is_none());
        assert!(file.as_dict().unwrap().get(&b"have"[..]).is_none());
        let parsed = parse_file(&file, &public_key).unwrap();
        assert_eq!(parsed.size, 0);
        assert_eq!(parsed.file_hash, [0; 20]);
        assert_eq!(parsed.piece_count, 0);
        parsed.verify_content(b"").unwrap();
        parse_torrent_info(&parsed.torrent_info()).unwrap();
    }

    #[test]
    fn peer_identity_frame_is_uncompressed() {
        let identity = PeerIdentity {
            name: "peer".into(),
            peer_id: [1; 20],
            identity_key: IDENTITY_KEY,
            share_id: [3; 20],
        };
        let payload = encode(&identity.id_message());
        let mut output = Vec::new();
        write_frame_uncompressed(&mut output, &payload).unwrap();
        assert_eq!(&output[..4], &(payload.len() as u32).to_be_bytes());
        assert_eq!(&output[4..], payload.as_slice());
    }

    #[test]
    fn torrent_random_prefix_is_four_bytes_per_piece() {
        for (piece_count, expected) in [(1_usize, 4_usize), (3_usize, 12_usize)] {
            let mut pieces = Vec::with_capacity(piece_count * 20);
            for index in 0..piece_count {
                pieces.extend_from_slice(&Sha1::digest([index as u8]));
            }
            let meta = Value::dict([(
                b"info".to_vec(),
                Value::dict([
                    (b"length".to_vec(), Value::Int(piece_count as i64)),
                    (b"piece length".to_vec(), Value::Int(1)),
                    (b"pieces".to_vec(), Value::bytes(pieces.clone())),
                    (b"rp".to_vec(), Value::bytes(vec![0_u8; expected])),
                ]),
            )]);
            let content = Value::dict([
                (b"data".to_vec(), Value::bytes(vec![0_u8; piece_count])),
                (b"meta".to_vec(), Value::Bytes(encode(&meta))),
            ]);
            let (_, torrent) = parse_content(&content).unwrap();
            assert_eq!(torrent.random_prefix.len(), expected);
            assert_eq!(expected, piece_count * 4);
        }
    }

    #[test]
    fn direct_torrent_v2_frame_decodes() {
        let value = Value::dict([
            (b"f".to_vec(), Value::bytes(b"file.bin")),
            (b"i".to_vec(), Value::bytes([1_u8; 20])),
            (b"sig".to_vec(), Value::bytes([2_u8; 64])),
        ]);
        let payload = encode(&value);
        let mut frame = Vec::new();
        frame.extend_from_slice(DIRECT_TORRENT_MAGIC_V2);
        frame.extend_from_slice(&(payload.len() as u32).to_be_bytes());
        frame.extend_from_slice(&payload);
        assert!(is_direct_torrent_frame(&frame));
        assert_eq!(decode_direct_torrent(&frame).unwrap(), value);
        match read_wire_payload(&mut frame.as_slice()).unwrap() {
            WirePayload::Direct(decoded) => {
                assert_eq!(decode_direct_torrent(&decoded).unwrap(), value)
            }
            WirePayload::Peer(_) => panic!("expected DirectTorrent frame"),
            WirePayload::DirectHandshake(_) => panic!("unexpected DirectTorrent handshake"),
        }
    }

    #[test]
    fn direct_upload_uses_login_then_content_body() {
        let login = Value::dict([
            (b"f".to_vec(), Value::bytes(b"file.bin")),
            (b"i".to_vec(), Value::bytes([1_u8; 20])),
            (b"sig".to_vec(), Value::bytes([2_u8; 64])),
        ]);
        let content = Value::dict([
            (b"data".to_vec(), Value::bytes(b"payload")),
            (b"meta".to_vec(), Value::bytes(b"3:meta")),
        ]);
        let login_frame = encode_direct_torrent(&login).unwrap();
        let content_frame = encode_direct_torrent_body(&content).unwrap();
        assert!(login_frame.starts_with(DIRECT_TORRENT_MAGIC_V2));
        assert!(!content_frame.starts_with(DIRECT_TORRENT_MAGIC_V2));
        assert_eq!(
            u32::from_be_bytes(content_frame[..4].try_into().unwrap()) as usize,
            encode(&content).len()
        );
        assert_eq!(
            decode_direct_torrent(&login_frame)
                .unwrap()
                .get(b"f")
                .unwrap()
                .as_bytes()
                .unwrap(),
            b"file.bin"
        );
        assert_eq!(
            decode_direct_torrent_body(&content_frame)
                .unwrap()
                .get(b"data")
                .unwrap()
                .as_bytes()
                .unwrap(),
            b"payload"
        );
    }

    #[test]
    fn tunnel_v1_frame_matches_wire_layout() {
        let mut output = Vec::new();
        write_tunnel_frame_v1(&mut output, 0x12345678, TUNNEL_PACKET_DATA, b"payload").unwrap();
        assert_eq!(
            output,
            [
                0x00, 0x0f, 0x01, 0x03, 0x12, 0x34, 0x56, 0x78, b'p', b'a', b'y', b'l', b'o', b'a',
                b'd'
            ]
        );
        let packet = read_tunnel_frame(&mut output.as_slice()).unwrap();
        assert_eq!(packet.connection_id, 0x12345678);
        assert_eq!(packet.packet_type, TUNNEL_PACKET_DATA);
        assert_eq!(packet.payload, b"payload");
        assert!(!packet.compressed);
    }

    #[test]
    fn tunnel_clean_and_truncated_eof_are_distinct() {
        let clean = read_tunnel_frame(&mut Cursor::new(Vec::new())).unwrap_err();
        assert_eq!(clean.to_string(), TUNNEL_EOF_AT_FRAME_BOUNDARY);

        let truncated =
            read_tunnel_frame(&mut Cursor::new([2_u8, 0x00, 0x00, 0x00, 0x0f])).unwrap_err();
        assert_eq!(clean.to_string(), TUNNEL_EOF_AT_FRAME_BOUNDARY);
        assert_eq!(truncated.to_string(), "truncated V2 tunnel packet header");
    }

    #[test]
    fn tunnel_v2_compressed_frame_round_trips() {
        let payload = vec![7_u8; 4096];
        let mut output = Vec::new();
        write_tunnel_frame(&mut output, 0x89abcdef, TUNNEL_PACKET_DATA, &payload, true).unwrap();
        assert_eq!(output[0], 2);
        assert_eq!(
            u32::from_be_bytes(output[1..5].try_into().unwrap()) as usize,
            output.len()
        );
        assert_eq!(output[5], TUNNEL_PACKET_DATA_COMPRESSED);
        let packet = read_tunnel_frame(&mut output.as_slice()).unwrap();
        assert_eq!(packet.connection_id, 0x89abcdef);
        assert_eq!(packet.packet_type, TUNNEL_PACKET_DATA_COMPRESSED);
        assert_eq!(packet.payload, payload);
        assert!(packet.compressed);
    }

    #[test]
    fn identity_message_round_trips_protocol_fields() {
        let identity = PeerIdentity {
            name: "synthetic-peer".into(),
            peer_id: [0x11; 20],
            identity_key: IDENTITY_KEY,
            share_id: [0x22; 20],
        };
        let encoded = encode(&identity.id_message());
        let decoded = crate::bencode::decode(&encoded).unwrap();
        assert_eq!(decoded.get(b"m").unwrap().as_bytes().unwrap(), b"id");
        assert_eq!(
            decoded.get(b"name").unwrap().as_bytes().unwrap(),
            b"synthetic-peer"
        );
        assert_eq!(
            decoded.get(b"peer").unwrap().as_bytes().unwrap(),
            identity.peer_id
        );
        assert_eq!(
            decoded.get(b"share").unwrap().as_bytes().unwrap(),
            identity.share_id
        );
        assert_eq!(
            decoded.get(b"v").unwrap().as_bytes().unwrap(),
            PEER_MESSAGE_PROTOCOL_VERSION.as_bytes()
        );
    }

    #[test]
    fn read_only_peer_identity_without_pk_is_accepted() {
        // Official 3.1.2 omits `pk` from `m=id` when it holds a read-only key,
        // because such a peer has no Ed25519 identity. Rejecting the message
        // drops a legitimate connection, so the field must be optional.
        let message = Value::dict([
            (b"m".to_vec(), Value::bytes(b"id")),
            (b"name".to_vec(), Value::bytes("official-read-only")),
            (b"peer".to_vec(), Value::bytes([0x11_u8; 20])),
            (b"share".to_vec(), Value::bytes([0x22_u8; 20])),
            (b"tags".to_vec(), Value::List(Vec::new())),
            (b"v".to_vec(), Value::bytes(b"1")),
        ]);
        let key = peer_identity_key(&message).unwrap();
        assert_eq!(key, [0_u8; 32]);
        assert!(peer_key_cannot_sign(&key));
    }

    #[test]
    fn writable_peer_identity_keeps_its_pk() {
        let key =
            ShareKey::parse(&format!("D{}", crate::secret::encode_base32(&[9_u8; 20]))).unwrap();
        let identity = PeerIdentity::from_key("writable", &key, [0x33; 20]).unwrap();
        let advertised = peer_identity_key(&identity.id_message()).unwrap();
        assert_eq!(advertised, key.ed25519_public_key().unwrap());
        assert!(!peer_key_cannot_sign(&advertised));
    }

    #[test]
    fn relay_identity_message_announces_the_supplied_key() {
        let key =
            ShareKey::parse(&format!("A{}", crate::secret::encode_base32(&[3_u8; 20]))).unwrap();
        let identity = PeerIdentity::from_key("relay", &key, [0x44; 20]).unwrap();
        let writer_key = [0x77_u8; 32];
        let relayed = identity.id_message_with_key(writer_key);
        assert_eq!(
            relayed.get(b"pk").unwrap().as_bytes().unwrap(),
            writer_key.as_slice()
        );
        // The relay keeps its own peer id and share id; only `pk` changes.
        assert_eq!(
            relayed.get(b"peer").unwrap().as_bytes().unwrap(),
            [0x44_u8; 20].as_slice()
        );
        assert_eq!(
            relayed.get(b"share").unwrap().as_bytes().unwrap(),
            key.share_id().as_slice()
        );
        // The default message still carries the node's own key.
        assert_eq!(
            identity
                .id_message()
                .get(b"pk")
                .unwrap()
                .as_bytes()
                .unwrap(),
            key.ed25519_public_key().unwrap().as_slice()
        );
    }

    #[test]
    fn malformed_peer_identity_key_is_rejected() {
        let message = Value::dict([
            (b"m".to_vec(), Value::bytes(b"id")),
            (b"pk".to_vec(), Value::bytes(vec![1_u8; 7])),
        ]);
        assert!(peer_identity_key(&message).is_err());
    }

    #[test]
    fn peer_identity_pk_matches_metadata_signing_key() {
        let key =
            ShareKey::parse(&format!("A{}", crate::secret::encode_base32(&[7_u8; 20]))).unwrap();
        let identity = PeerIdentity::from_key("identity-test", &key, [0x11; 20]).unwrap();
        let message = identity.id_message();
        assert_eq!(
            message.get(b"pk").unwrap().as_bytes().unwrap(),
            key.ed25519_public_key().unwrap().as_slice()
        );
    }

    #[test]
    fn acl_merge_messages_keep_upstream_wire_fields() {
        let hash = [0x2a; 20];
        let nodes = get_acl_nodes_message(hash);
        assert_eq!(
            nodes.get(b"m").unwrap().as_bytes().unwrap(),
            b"get_acl_nodes"
        );
        assert_eq!(nodes.get(b"acl_hash").unwrap().as_bytes().unwrap(), hash);

        let entries = acl_entries_message(hash, Vec::new(), 17);
        assert_eq!(
            entries.get(b"m").unwrap().as_bytes().unwrap(),
            b"acl_entries"
        );
        assert_eq!(entries.get(b"offset").unwrap().as_int().unwrap(), 17);
        assert!(entries
            .get(b"entries")
            .unwrap()
            .as_list()
            .unwrap()
            .is_empty());

        let accepted = acl_entries_accepted_message(hash);
        assert_eq!(
            accepted.get(b"m").unwrap().as_bytes().unwrap(),
            b"acl_entries_accepted"
        );
    }
}
