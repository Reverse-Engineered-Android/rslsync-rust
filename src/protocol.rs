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
        Ok(Self {
            name: name.into(),
            peer_id,
            identity_key: key.ed25519_public_key().unwrap_or([0; 32]),
            share_id: key.share_id(),
        })
    }

    pub fn id_message(&self) -> Value {
        Value::dict([
            (b"m".to_vec(), Value::bytes(b"id")),
            (b"name".to_vec(), Value::bytes(self.name.clone())),
            (b"peer".to_vec(), Value::bytes(self.peer_id)),
            (b"pk".to_vec(), Value::bytes(self.identity_key)),
            (b"share".to_vec(), Value::bytes(self.share_id)),
            (b"tags".to_vec(), Value::List(Vec::new())),
            (
                b"v".to_vec(),
                Value::bytes(PEER_MESSAGE_PROTOCOL_VERSION.as_bytes()),
            ),
        ])
    }
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
        let mut piece_hash_bytes = Vec::new();
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
            piece_hash_bytes.extend_from_slice(&digest);
            if filled < buffer.len() {
                break;
            }
        }
        let mtime_seconds = metadata.mtime();
        let random_prefix = random_prefix(piece_hashes.len());
        let file_hash = if metadata.len() == 0 {
            [0; 20]
        } else {
            Sha1::digest(&piece_hash_bytes).into()
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

    pub fn info_hash(&self, share_id: &[u8; 20]) -> [u8; 20] {
        let mut hasher = Sha1::new();
        hasher.update(share_id);
        for (index, component) in self.relative_path.iter().enumerate() {
            if index != 0 {
                hasher.update([0]);
            }
            hasher.update(component.as_bytes());
        }
        hasher.update(self.file_hash);
        hasher.finalize().into()
    }

    pub fn wire_path(&self) -> Vec<u8> {
        self.relative_path.join("/").into_bytes()
    }

    pub fn main(&self) -> Value {
        let mut path = Vec::with_capacity(self.relative_path.len());
        for component in &self.relative_path {
            path.push(Value::bytes(component.clone()));
        }
        if self.entry_type == EntryType::Directory {
            let mut fields = BTreeMap::new();
            fields.insert(b"otime".to_vec(), Value::Int(self.otime));
            fields.insert(b"owner".to_vec(), Value::bytes(self.owner));
            fields.insert(b"path".to_vec(), Value::List(path));
            fields.insert(b"perm".to_vec(), Value::Int(self.mode as i64));
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
        fields.insert(b"perm".to_vec(), Value::Int(self.mode as i64));
        fields.insert(b"size".to_vec(), Value::Int(self.size as i64));
        fields.insert(b"state".to_vec(), Value::Int(self.state.wire_value()));
        fields.insert(b"time".to_vec(), Value::Int(self.time_seconds));
        fields.insert(b"type".to_vec(), Value::Int(self.entry_type.wire_value()));
        if let Some(write_times) = self.wire_write_times() {
            fields.insert(b"write_times".to_vec(), Value::Int(write_times));
        }
        Value::Dict(fields)
    }

    pub fn metadata_hash(&self) -> [u8; 20] {
        Sha1::digest(encode(&self.main())).into()
    }

    pub fn signed_file(&self, signing_key: &SigningKey, have: i64) -> Result<Value> {
        let main = self.main();
        let signature = signing_key.sign(&Sha1::digest(encode(&main)));
        let mut fields = BTreeMap::new();
        if self.entry_type == EntryType::RegularFile
            && self.state == EntryState::Active
            && !(self.size == 0 && self.file_hash == [0; 20] && self.piece_count == 0)
        {
            fields.insert(b"have".to_vec(), Value::Int(have));
        }
        fields.insert(b"main".to_vec(), main);
        fields.insert(b"sig".to_vec(), Value::bytes(signature.to_bytes()));
        Ok(Value::Dict(fields))
    }

    pub fn torrent_metadata(&self) -> Value {
        Value::dict([(b"info".to_vec(), self.torrent_info())])
    }

    pub fn torrent_info(&self) -> Value {
        let mut pieces = Vec::with_capacity(self.piece_hashes.len() * 20);
        for piece in &self.piece_hashes {
            pieces.extend_from_slice(piece);
        }
        Value::dict([
            (b"length".to_vec(), Value::Int(self.size as i64)),
            (b"piece length".to_vec(), Value::Int(PIECE_LENGTH as i64)),
            (b"pieces".to_vec(), Value::bytes(pieces)),
            (b"rp".to_vec(), Value::bytes(self.random_prefix.clone())),
        ])
    }

    pub fn content_message(&self, content: &[u8]) -> Result<Value> {
        self.verify_content(content)?;
        Ok(Value::dict([
            (b"data".to_vec(), Value::bytes(content)),
            (
                b"meta".to_vec(),
                Value::Bytes(encode(&self.torrent_metadata())),
            ),
        ]))
    }

    pub fn direct_login(
        &self,
        share_id: &[u8; 20],
        peer_id: &[u8; 20],
        signing_key: &SigningKey,
    ) -> Result<Vec<u8>> {
        encode_direct_torrent(&self.direct_login_message(share_id, peer_id, signing_key)?)
    }

    pub fn direct_login_message(
        &self,
        share_id: &[u8; 20],
        peer_id: &[u8; 20],
        signing_key: &SigningKey,
    ) -> Result<Value> {
        let signature = if self.signature.is_empty() {
            signing_key
                .sign(&Sha1::digest(encode(&self.main())))
                .to_bytes()
                .to_vec()
        } else {
            self.signature.clone()
        };
        Ok(Value::dict([
            (b"f".to_vec(), Value::bytes(self.wire_path())),
            (b"i".to_vec(), Value::bytes(self.info_hash(share_id))),
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
    ) -> Result<Vec<u8>> {
        encode_direct_torrent_body(&self.direct_login_message(share_id, peer_id, signing_key)?)
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
        let file_hash: [u8; 20] = Sha1::digest(&pieces).into();
        if file_hash != self.file_hash {
            bail!("file hash mismatch for {}", self.wire_path_string());
        }
        Ok(())
    }

    pub fn wire_path_string(&self) -> String {
        self.relative_path.join("/")
    }
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
    let main = value.get(b"main")?;
    let signature = value.get(b"sig")?.as_bytes()?.to_vec();
    verify_file_signature(public_key, main, &signature)?;
    let path = main.get(b"path")?;
    let relative_path = path
        .as_list()?
        .iter()
        .map(|part| {
            let bytes = part.as_bytes()?;
            String::from_utf8(bytes.to_vec()).context("file path is not UTF-8")
        })
        .collect::<Result<Vec<_>>>()?;
    let entry_type = match main.get(b"type")?.as_int()? {
        1 => EntryType::RegularFile,
        2 => EntryType::Directory,
        other => bail!("unsupported upstream entry type {other}"),
    };
    let size = match entry_type {
        EntryType::RegularFile => main.get(b"size")?.as_int()?,
        EntryType::Directory => 0,
    };
    let mode = main.get(b"perm")?.as_int()?;
    let mtime_seconds = match entry_type {
        EntryType::RegularFile => main.get(b"mtime")?.as_int()?,
        EntryType::Directory => main.get(b"time")?.as_int()?,
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
    Ok(FileMetadata {
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
        write_times: match main.as_dict()?.get(&b"write_times"[..]) {
            Some(value) => value.as_int()?,
            None => 0,
        },
        signature,
    })
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
    let random_prefix = info.get(b"rp")?.as_bytes()?.to_vec();
    let expected_prefix_length = piece_hashes
        .len()
        .checked_mul(4)
        .context("torrent random prefix length overflow")?;
    if random_prefix.len() != expected_prefix_length {
        bail!("torrent rp is not {} bytes", expected_prefix_length);
    }
    Ok(TorrentMetadata {
        size: info.get(b"length")?.as_int()?.try_into()?,
        piece_length: piece_length.try_into()?,
        piece_hashes,
        random_prefix,
    })
}

pub fn expected_torrent_info_size(size: u64, piece_count: usize) -> Result<usize> {
    let pieces_len = piece_count
        .checked_mul(20)
        .context("torrent piece count overflow")?;
    let random_prefix_len = piece_count
        .checked_mul(4)
        .context("torrent random prefix count overflow")?;
    let info = Value::dict([
        (b"length".to_vec(), Value::Int(size as i64)),
        (b"piece length".to_vec(), Value::Int(PIECE_LENGTH as i64)),
        (b"pieces".to_vec(), Value::Bytes(vec![0_u8; pieces_len])),
        (b"rp".to_vec(), Value::Bytes(vec![0_u8; random_prefix_len])),
    ]);
    Ok(encode(&info).len())
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TorrentMetadata {
    pub size: u64,
    pub piece_length: u64,
    pub piece_hashes: Vec<[u8; 20]>,
    pub random_prefix: Vec<u8>,
}

impl TorrentMetadata {
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
        };
        let file = metadata.signed_file(&signing_key, 1).unwrap();
        let parsed = parse_file(&file, &public_key).unwrap();
        assert_eq!(parsed.file_hash, metadata.file_hash);
        let (content, torrent) = parse_content(&metadata.content_message(b"x").unwrap()).unwrap();
        torrent.verify(&content).unwrap();
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
