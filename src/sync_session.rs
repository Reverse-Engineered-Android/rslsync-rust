use crate::acl::{empty_hash, parse_entries, AclState};
use crate::bencode::{decode, decode_prefix_wire, encode, Value};
use crate::discovery::spawn_advertiser;
use crate::encrypted_folder;
use crate::protocol::{
    acl_entries_accepted_message, acl_entries_message, acl_nodes_message, build_file_tree,
    decode_direct_torrent, expected_torrent_info_size_for_shape, get_acl_entries_message,
    get_acl_nodes_message, parse_content, parse_file_with_key, parse_torrent_info,
    read_bencode_frame, read_tunnel_frame, read_wire_payload_bytes, write_bencode_frame,
    write_bencode_frame_uncompressed, write_tunnel_frame, EntryState, EntryType, FileMetadata,
    FileTree, PeerIdentity, TorrentMetadata, WirePayload, DIRECT_TORRENT_MAGIC_V2,
    DIRECT_TORRENT_MAGIC_V3, PIECE_LENGTH, TUNNEL_EOF_AT_FRAME_BOUNDARY, TUNNEL_PACKET_ACK,
    TUNNEL_PACKET_CLOSE, TUNNEL_PACKET_DATA, TUNNEL_PACKET_DATA_COMPRESSED, TUNNEL_PACKET_OPEN,
    TUNNEL_PACKET_PING,
};
use crate::secret::ShareKey;
use crate::selective::SyncSelection;
use crate::srpeh;
use crate::sync_state::{local_fingerprint, StateRecord, SyncStateStore};
use crate::tls::{accept_psk, connect_psk};
use crate::tracker::{TrackerClient, TrackerPeer, TrackerRequest};
use anyhow::{bail, Context, Result};
use ed25519_dalek::SigningKey;
use sha1::{Digest, Sha1};
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet, VecDeque};
use std::fs;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

#[derive(Clone, Debug)]
struct LocalFile {
    metadata: FileMetadata,
    content: Vec<u8>,
    baseline: Option<StateRecord>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum DownloadPhase {
    LoginSent,
    LoginAccepted,
    MetadataDownloading,
    PiecesDownloading,
}

#[derive(Debug)]
struct DownloadSession {
    path: String,
    metadata_hash: [u8; 20],
    conflict_target: Option<PathBuf>,
    preserve_target: bool,
    phase: DownloadPhase,
    remote_metadata_id: Option<u8>,
    metadata_size: usize,
    metadata_parts: HashMap<usize, Vec<u8>>,
    torrent: Option<TorrentMetadata>,
    content: Vec<u8>,
    requested_blocks: HashMap<(u32, u32), usize>,
    received_blocks: HashSet<(u32, u32)>,
}

#[derive(Debug)]
struct UploadSession {
    metadata: FileMetadata,
    /// Bytes served over the piece protocol, i.e. what the receiver stores.
    content: Vec<u8>,
    /// Ciphertext form of the same content. The torrent info published through
    /// `ut_metadata` must describe these bytes, because `file_hash` was derived
    /// from them; a receiver rejects a metadata blob whose hash differs.
    torrent_content: Vec<u8>,
    remote_metadata_id: Option<u8>,
}

impl DownloadSession {
    fn new(path: String, metadata_hash: [u8; 20]) -> Self {
        Self {
            path,
            metadata_hash,
            conflict_target: None,
            preserve_target: false,
            phase: DownloadPhase::LoginSent,
            remote_metadata_id: None,
            metadata_size: 0,
            metadata_parts: HashMap::new(),
            torrent: None,
            content: Vec::new(),
            requested_blocks: HashMap::new(),
            received_blocks: HashSet::new(),
        }
    }

    fn with_conflict_target(
        path: String,
        metadata_hash: [u8; 20],
        conflict_target: Option<PathBuf>,
        preserve_target: bool,
    ) -> Self {
        Self {
            conflict_target,
            preserve_target,
            ..Self::new(path, metadata_hash)
        }
    }

    fn metadata_complete(&self) -> bool {
        self.metadata_size > 0
            && self.metadata_parts.values().map(Vec::len).sum::<usize>() >= self.metadata_size
    }
}

const METADATA_PIECE_SIZE: usize = 16 * 1024;
const LOCAL_UT_METADATA_ID: u8 = 3;
const SYNC_SETTLE_SECONDS: u64 = 5;
const PEER_IDLE_SECONDS: u64 = 30;
const MERGE_NEGOTIATION_DELAY: Duration = Duration::from_secs(2);
const MERGE_ROOT_RETRY: Duration = Duration::from_secs(2);
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum FileReconciliation {
    Equal,
    LocalWins,
    RemoteWins,
    Conflict,
}

#[derive(Debug)]
enum TunnelEvent {
    Opened,
    Ack(u32),
    Data(crate::protocol::TunnelPacket),
    Closed(u32),
}

struct TunnelMux<'a, S> {
    stream: &'a mut S,
    known: HashSet<u32>,
    queued: VecDeque<TunnelEvent>,
}

impl<'a, S: Read + Write> TunnelMux<'a, S> {
    fn new(stream: &'a mut S) -> Self {
        Self {
            stream,
            known: HashSet::new(),
            queued: VecDeque::new(),
        }
    }

    fn open_session(&mut self) -> Result<u32> {
        loop {
            let connection_id = random_connection_id();
            if self.known.insert(connection_id) {
                write_tunnel_frame(self.stream, connection_id, TUNNEL_PACKET_OPEN, &[], false)?;
                loop {
                    match self.read_event() {
                        Ok(TunnelEvent::Ack(ack_id)) if ack_id == connection_id => {
                            return Ok(connection_id)
                        }
                        Ok(TunnelEvent::Closed(closed_id)) if closed_id == connection_id => {
                            self.known.remove(&connection_id);
                            bail!("peer closed tunnel connection during open");
                        }
                        Ok(event) => self.queued.push_back(event),
                        Err(error) if is_timeout(&error) => continue,
                        Err(error) => return Err(error),
                    }
                }
            }
        }
    }

    fn next_event(&mut self) -> Result<TunnelEvent> {
        let event = if let Some(event) = self.queued.pop_front() {
            event
        } else {
            self.read_event()?
        };
        if matches!(event, TunnelEvent::Closed(_)) {
            if let TunnelEvent::Closed(connection_id) = &event {
                self.known.remove(connection_id);
            }
        }
        Ok(event)
    }

    fn read_event(&mut self) -> Result<TunnelEvent> {
        loop {
            let packet = read_tunnel_frame(self.stream)?;
            match packet.packet_type {
                TUNNEL_PACKET_OPEN => {
                    if packet.connection_id == 0 {
                        bail!("peer requested zero tunnel connection ID");
                    }
                    self.known.insert(packet.connection_id);
                    write_tunnel_frame(
                        self.stream,
                        packet.connection_id,
                        TUNNEL_PACKET_ACK,
                        &[],
                        false,
                    )?;
                    return Ok(TunnelEvent::Opened);
                }
                TUNNEL_PACKET_ACK => {
                    return Ok(TunnelEvent::Ack(packet.connection_id));
                }
                TUNNEL_PACKET_PING => {
                    write_tunnel_frame(
                        self.stream,
                        packet.connection_id,
                        TUNNEL_PACKET_PING,
                        &packet.payload,
                        false,
                    )?;
                }
                TUNNEL_PACKET_CLOSE => {
                    return Ok(TunnelEvent::Closed(packet.connection_id));
                }
                TUNNEL_PACKET_DATA | TUNNEL_PACKET_DATA_COMPRESSED => {
                    if !self.known.contains(&packet.connection_id) {
                        continue;
                    }
                    return Ok(TunnelEvent::Data(packet));
                }
                other => eprintln!("ignoring tunnel packet type {other}"),
            }
        }
    }

    fn send_data(&mut self, connection_id: u32, payload: &[u8]) -> Result<()> {
        if !self.known.contains(&connection_id) {
            return Ok(());
        }
        write_tunnel_frame(
            self.stream,
            connection_id,
            TUNNEL_PACKET_DATA,
            payload,
            false,
        )
    }

    fn send_close(&mut self, connection_id: u32) -> Result<()> {
        if self.known.remove(&connection_id) {
            write_tunnel_frame(self.stream, connection_id, TUNNEL_PACKET_CLOSE, &[], false)?;
        }
        Ok(())
    }
}

#[derive(Clone)]
pub struct SyncNode {
    root: PathBuf,
    key: ShareKey,
    identity: PeerIdentity,
    metadata_public_key: Option<[u8; 32]>,
    signing_key: SigningKey,
    read_only: bool,
    selection: SyncSelection,
    trackers: Vec<String>,
    acl_hash: [u8; 20],
    acl: AclState,
}

impl SyncNode {
    pub fn new(
        root: impl Into<PathBuf>,
        key: ShareKey,
        device_name: impl Into<String>,
    ) -> Result<Self> {
        let device_name = device_name.into();
        let peer_id = stable_peer_id(&key, &device_name);
        Self::new_with_peer_id(root, key, device_name, peer_id)
    }

    pub fn new_with_peer_id(
        root: impl Into<PathBuf>,
        key: ShareKey,
        device_name: impl Into<String>,
        peer_id: [u8; 20],
    ) -> Result<Self> {
        let root = root.into();
        if !root.is_dir() {
            bail!("sync root is not a directory: {}", root.display());
        }
        let read_only = matches!(key.key_type, 'B' | 'E' | 'F');
        // A read-only share key carries no Ed25519 seed, but the official
        // read-only peer still advertises a real `pk` and signs the entries it
        // relays with it; the receiver verifies against that advertised key.
        // Advertising the zero key instead makes every relayed entry look like
        // `bad signature` to the receiving peer, so such a node keeps one
        // generated identity beside its sync state and reuses it across runs.
        let signing_key = key
            .ed25519_signing_key()
            .unwrap_or_else(|_| persistent_identity_key(&root));
        let public_key = key
            .ed25519_public_key()
            .unwrap_or_else(|_| signing_key.verifying_key().to_bytes());
        let identity = PeerIdentity::from_keys(device_name, key.share_id(), public_key, peer_id);
        let metadata_public_key = Some(public_key);
        Ok(Self {
            root,
            key,
            identity,
            metadata_public_key,
            signing_key,
            read_only,
            selection: SyncSelection::all(),
            trackers: Vec::new(),
            acl_hash: empty_hash(),
            acl: AclState::default(),
        })
    }

    pub fn with_selection(mut self, selection: SyncSelection) -> Self {
        self.selection = selection;
        self
    }

    pub fn selection(&self) -> &SyncSelection {
        &self.selection
    }

    pub fn with_trackers(mut self, trackers: impl IntoIterator<Item = impl Into<String>>) -> Self {
        self.trackers = trackers.into_iter().map(Into::into).collect();
        self
    }

    pub fn with_acl_state(mut self, acl: AclState) -> Self {
        self.acl_hash = acl.hash();
        self.acl = acl;
        self
    }

    pub fn acl_state(&self) -> &AclState {
        &self.acl
    }

    /// The bytes served to a peer for one file.
    ///
    /// Inside an encrypted folder the wire carries AES-transformed content
    /// while the torrent advertises the *plaintext* piece hashes; the receiver
    /// decrypts these bytes and compares them against those hashes. Serving the
    /// plaintext here is what made an encrypted-only peer reject the download
    /// (its piece hash check failed) even though the metadata verified.
    fn wire_content(
        &self,
        metadata: &FileMetadata,
        content: &[u8],
        encrypted_wire: bool,
    ) -> Result<Vec<u8>> {
        if !encrypted_wire || content.is_empty() || !self.key.can_encrypt() {
            return Ok(content.to_vec());
        }
        crate::encrypted_folder::encrypt_content(
            &self.key.encryption_key()?,
            &metadata.piece_hashes,
            PIECE_LENGTH as usize,
            content,
        )
    }

    fn sign_metadata(&self, metadata: &mut FileMetadata) -> Result<()> {
        // A read-only folder relays the writer's signed entries and announces
        // the writer's public key, so it must not overwrite that signature with
        // its own; only entries it originates itself need signing. Such a node
        // rebuilds its entries from the stored canonical form, which is what
        // makes the writer's signature still cover them.
        if self.read_only && !metadata.signature.is_empty() {
            return Ok(());
        }
        if self.key.can_encrypt()
            && metadata.entry_type == EntryType::RegularFile
            && metadata.state == EntryState::Active
            && metadata.size > 0
        {
            let content = fs::read(self.root.join(metadata.wire_path_string()))
                .with_context(|| format!("read {}", metadata.wire_path_string()))?;
            metadata.prepare_encrypted_with_content(&self.key, &content)?;
        } else {
            metadata.prepare_encrypted(&self.key)?;
        }
        metadata.sign(&self.signing_key)
    }

    /// Verify the `data` field of one file and return the bytes to store.
    ///
    /// Inside an encrypted folder the wire carries ciphertext, so upstream
    /// hashes those bytes into `pieces` and ships the AES-wrapped SHA-1 of the
    /// plaintext in `epieces`. Both layers are checked: the ciphertext against
    /// `pieces`, then the decrypted bytes against `epieces`. The decrypted
    /// plaintext is what gets written to disk for a `D`/`E` folder; an
    /// encrypted-only (`F`) session has no content key and stores the
    /// ciphertext verbatim.
    /// Verify the `data` field of one file and return the bytes to store.
    ///
    /// `pieces` always describes the ciphertext of an encrypted folder, but the
    /// `data` body depends on the receiver: official client 3.1.2 sends the
    /// plaintext to a peer holding a content key and the ciphertext only to an
    /// encrypted-only peer. Both bodies are therefore accepted here — the
    /// ciphertext is checked against `pieces`, the plaintext against the
    /// AES-wrapped hashes in `epieces` — and the plaintext is returned whenever
    /// this session can derive it, so a `D`/`E` folder keeps decrypting what an
    /// `E` peer published.
    fn verified_content(
        &self,
        metadata: &FileMetadata,
        torrent: &crate::protocol::TorrentMetadata,
        wire_content: &[u8],
    ) -> Result<Vec<u8>> {
        // A plain folder, and an encrypted-only session that holds no content
        // key, both receive exactly the bytes `pieces` describes and store them
        // unchanged (`F` keeps the ciphertext).
        if metadata.encrypted_epart.is_none()
            || torrent.epieces.is_empty()
            || !self.key.can_encrypt()
        {
            torrent.verify(wire_content).with_context(|| {
                format!(
                    "verify received content for {}",
                    metadata.protocol_path_string()
                )
            })?;
            return Ok(wire_content.to_vec());
        }
        let content_key = self.key.encryption_key()?;
        let plaintext_hashes = encrypted_folder::decrypt_epieces(&content_key, &torrent.epieces)
            .context("decrypt encrypted torrent piece hashes")?;
        if plaintext_hashes.len() != torrent.piece_hashes.len() {
            bail!("encrypted torrent piece hash count mismatch");
        }
        let mut plaintext_torrent = torrent.clone();
        plaintext_torrent.piece_hashes = plaintext_hashes.clone();
        if plaintext_torrent.verify(wire_content).is_ok() {
            return Ok(wire_content.to_vec());
        }
        torrent.verify(wire_content).with_context(|| {
            format!(
                "verify received encrypted content for {}",
                metadata.protocol_path_string()
            )
        })?;
        let mut decrypted = wire_content.to_vec();
        encrypted_folder::decrypt_content(
            &content_key,
            &plaintext_hashes,
            torrent.piece_length as usize,
            &mut decrypted,
        )
        .context("decrypt received encrypted content")?;
        plaintext_torrent.verify(&decrypted).with_context(|| {
            format!(
                "verify received plaintext content for {}",
                metadata.protocol_path_string()
            )
        })?;
        Ok(decrypted)
    }

    fn metadata_content_key(&self, metadata: &FileMetadata) -> Result<Option<[u8; 16]>> {
        if metadata.encrypted_epart.is_some() {
            Ok(Some(self.key.encryption_key()?))
        } else {
            Ok(None)
        }
    }

    fn direct_info_hash_matches(
        &self,
        metadata: &FileMetadata,
        expected: &[u8; 20],
        encrypted_wire: bool,
    ) -> Result<bool> {
        if metadata.info_hash_for_wire(&self.identity.share_id, encrypted_wire) == *expected {
            return Ok(true);
        }
        if encrypted_wire || !self.key.can_encrypt() {
            return Ok(false);
        }
        let mut encrypted_metadata = metadata.clone();
        encrypted_metadata.prepare_encrypted(&self.key)?;
        Ok(encrypted_metadata.info_hash_for_wire(&self.identity.share_id, true) == *expected)
    }

    fn direct_request_signature_matches(
        &self,
        signature: &[u8],
        info_hash: &[u8; 20],
        relative_path: &str,
        local_metadata: &FileMetadata,
        remote_files: &HashMap<String, FileMetadata>,
    ) -> Result<bool> {
        if signature == local_metadata.signature_for_wire(&self.signing_key)? {
            return Ok(true);
        }

        Ok(remote_files.values().any(|remote_metadata| {
            let encrypted_wire = remote_metadata.protocol_path_string() == relative_path;
            if !encrypted_wire && remote_metadata.wire_path_string() != relative_path {
                return false;
            }
            if remote_metadata.signature.is_empty() || remote_metadata.signature != signature {
                return false;
            }
            self.direct_info_hash_matches(remote_metadata, info_hash, encrypted_wire)
                .unwrap_or(false)
        }))
    }

    pub fn announce_to_trackers(&self, port: u16, event: Option<&str>) -> Result<Vec<TrackerPeer>> {
        let info_hash: [u8; 20] = Sha1::digest(self.identity.share_id).into();
        let mut peers = Vec::new();
        let mut failures = Vec::new();
        for endpoint in &self.trackers {
            match TrackerClient::new(endpoint).announce(&TrackerRequest {
                info_hash,
                peer_id: self.identity.peer_id,
                port,
                uploaded: 0,
                downloaded: 0,
                left: 0,
                event: event.map(str::to_owned),
            }) {
                Ok(response) => peers.extend(
                    response
                        .peers
                        .into_iter()
                        .filter(|peer| peer.peer_id != Some(self.identity.peer_id)),
                ),
                Err(error) => failures.push(format!("{endpoint}: {error:#}")),
            }
        }
        if peers.is_empty() && !failures.is_empty() {
            bail!("all trackers failed: {}", failures.join("; "));
        }
        Ok(peers)
    }

    pub fn serve(&self, listen: &str) -> Result<()> {
        self.serve_with_discovery(listen, true)
    }

    pub fn serve_with_discovery(&self, listen: &str, discovery: bool) -> Result<()> {
        let listener = TcpListener::bind(listen).context("bind upstream peer listener")?;
        let address = listener
            .local_addr()
            .context("read upstream listener address")?;
        let _advertiser = discovery
            .then(|| {
                spawn_advertiser(
                    self.identity.peer_id,
                    address.port(),
                    vec![self.identity.share_id],
                )
            })
            .transpose()?;
        if !self.trackers.is_empty() {
            let sync = self.clone();
            let port = address.port();
            let seen = Arc::new(Mutex::new(HashSet::new()));
            thread::spawn(move || {
                let mut event = Some("started");
                loop {
                    match sync.announce_to_trackers(port, event) {
                        Ok(peers) => {
                            for peer in peers {
                                let identity = peer.peer_id.unwrap_or_else(|| {
                                    Sha1::digest(format!("tracker-peer:{}", peer.address)).into()
                                });
                                if !seen.lock().unwrap().insert(identity) {
                                    continue;
                                }
                                let candidate = sync.clone();
                                let address = peer.address;
                                thread::spawn(move || {
                                    if let Err(error) =
                                        candidate.connect_any_once(&address.to_string())
                                    {
                                        eprintln!("tracker peer {address} disconnected: {error:#}");
                                    }
                                });
                            }
                        }
                        Err(error) => eprintln!("tracker announce failed: {error:#}"),
                    }
                    event = None;
                    thread::sleep(Duration::from_secs(60));
                }
            });
        }
        loop {
            let (stream, peer) = listener.accept().context("accept upstream peer")?;
            let sync = self.clone();
            thread::spawn(move || {
                if let Err(error) = sync.serve_stream(stream) {
                    eprintln!("upstream peer {peer} disconnected: {error:#}");
                }
            });
        }
    }

    pub fn serve_once(&self, listen: &str) -> Result<()> {
        let listener = TcpListener::bind(listen).context("bind upstream peer listener")?;
        let (stream, peer) = listener.accept().context("accept upstream peer")?;
        eprintln!("accepted upstream peer {peer}");
        self.serve_stream(stream)
    }

    fn serve_stream(&self, mut stream: TcpStream) -> Result<()> {
        stream.set_read_timeout(Some(Duration::from_secs(30)))?;
        stream.set_write_timeout(Some(Duration::from_secs(30)))?;
        let mut preface = [0_u8; 1];
        let peeked = match stream.peek(&mut preface) {
            Ok(peeked) => peeked,
            Err(error)
                if error.kind() == std::io::ErrorKind::WouldBlock
                    || error.kind() == std::io::ErrorKind::TimedOut =>
            {
                return Ok(());
            }
            Err(error) => return Err(error.into()),
        };
        if peeked == 0 {
            return Ok(());
        }
        stream.set_read_timeout(Some(Duration::from_secs(5)))?;
        if preface[0] == srpeh::SRPEH_MAGIC[0] {
            let material = srpeh::server_handshake_material(&mut stream, &self.key)?;
            let peer_encrypted_only = material.peer_is_encrypted_only();
            stream.set_read_timeout(Some(Duration::from_millis(100)))?;
            let mut stream = material.server_stream(stream);
            return self.run_connection(&mut stream, false, peer_encrypted_only);
        }
        if preface[0] != 0x16 {
            exchange_tunnel_check(&mut stream.try_clone()?, self.identity.peer_id, false)?;
            let mut preface = [0_u8; 1];
            let peeked = stream.peek(&mut preface)?;
            if peeked == 0 {
                return Ok(());
            }
            if preface[0] == srpeh::SRPEH_MAGIC[0] {
                let material = srpeh::server_handshake_material(&mut stream, &self.key)?;
                let peer_encrypted_only = material.peer_is_encrypted_only();
                stream.set_read_timeout(Some(Duration::from_millis(100)))?;
                let mut stream = material.server_stream(stream);
                return self.run_connection(&mut stream, false, peer_encrypted_only);
            }
            if preface[0] != 0x16 {
                bail!("unknown encrypted tunnel preface 0x{:02x}", preface[0]);
            }
        }
        let mut stream = accept_psk(stream, &self.key)?;
        stream
            .get_ref()
            .set_read_timeout(Some(Duration::from_millis(100)))?;
        self.run_connection(&mut stream, false, false)
    }

    pub fn connect(&self, address: &str) -> Result<()> {
        let mut backoff = Duration::from_secs(1);
        loop {
            match self.connect_any_once(address) {
                Ok(()) => backoff = Duration::from_secs(1),
                Err(error) => {
                    eprintln!("upstream connection failed: {error:#}");
                    thread::sleep(backoff);
                    backoff = (backoff * 2).min(Duration::from_secs(60));
                    continue;
                }
            }
            thread::sleep(Duration::from_secs(1));
        }
    }

    pub fn connect_any_once(&self, address: &str) -> Result<()> {
        self.connect_srpeh_once(address).or_else(|srpeh_error| {
            self.connect_once(address).map_err(|tls_error| {
                anyhow::anyhow!("SRPEH: {srpeh_error:#}; TLS-PSK: {tls_error:#}")
            })
        })
    }

    pub fn connect_once(&self, address: &str) -> Result<()> {
        let stream = TcpStream::connect(address).context("connect upstream peer")?;
        stream.set_read_timeout(Some(Duration::from_secs(1)))?;
        stream.set_write_timeout(Some(Duration::from_secs(30)))?;
        let mut stream = connect_psk(stream, &self.key)?;
        stream
            .get_ref()
            .set_read_timeout(Some(Duration::from_millis(100)))?;
        self.run_connection(&mut stream, true, false)
    }

    pub fn connect_srpeh_once(&self, address: &str) -> Result<()> {
        let mut stream = TcpStream::connect(address).context("connect upstream SRPEH peer")?;
        stream.set_read_timeout(Some(Duration::from_secs(1)))?;
        stream.set_write_timeout(Some(Duration::from_secs(30)))?;
        let material = srpeh::client_handshake_material(&mut stream, &self.key)?;
        // The responder announces its own role in the SRPEH reply. An
        // encrypted-only responder has no content key, so it can only consume
        // the ciphertext body and must be addressed as encrypted-only even when
        // we ourselves hold the writable key.
        let peer_encrypted_only = material.peer_is_encrypted_only();
        stream.set_read_timeout(Some(Duration::from_millis(100)))?;
        let mut stream = material.client_stream(stream);
        self.run_connection(&mut stream, true, peer_encrypted_only)
    }

    fn start_merge_session<S: Read + Write>(
        &self,
        mux: &mut TunnelMux<'_, S>,
        relay_identity: Option<[u8; 32]>,
    ) -> Result<u32> {
        let connection_id = mux.open_session()?;
        // While relaying, announce the writer's public key instead of this
        // node's own: the peer was handed the writer's signed entries and
        // verifies them against exactly that key.
        let identity = match relay_identity {
            Some(public_key) => self.identity.id_message_with_key(public_key),
            None => self.identity.id_message(),
        };
        write_peer_message_uncompressed(mux, connection_id, &identity)?;
        Ok(connection_id)
    }

    fn send_state_notify_on<S: Read + Write>(
        &self,
        mux: &mut TunnelMux<'_, S>,
        connection_id: u32,
        root_hash: [u8; 20],
        files: &[LocalFile],
    ) -> Result<()> {
        write_peer_message(
            mux,
            connection_id,
            &state_notify_message(root_hash, files, self.acl_hash),
        )
    }

    /// `peer_encrypted_only` marks a peer that declared the encrypted share
    /// type during the handshake. Such a peer holds no Ed25519 key and cannot
    /// decrypt, so every file published to it must use the encrypted wire form.
    pub fn run_connection<S: Read + Write>(
        &self,
        stream: &mut S,
        initiator: bool,
        peer_encrypted_only: bool,
    ) -> Result<()> {
        let mut sync_state = SyncStateStore::load(&self.root)?;
        let mut local_files = self.scan_files(&mut sync_state)?;
        // A read-only folder relays the writer's own signed entries to an
        // encrypted-only peer, which cannot write or decrypt and so can never
        // turn the relay into a divergent tree. That identity is learned from
        // the peer's `id` message and remembered in the sync state.
        let mut relay_identity = if self.read_only && peer_encrypted_only {
            sync_state.writer_public_key()
        } else {
            None
        };
        let mut published_files = match relay_identity {
            Some(_) => relay_files(&self.root, &sync_state),
            None => {
                if self.read_only {
                    Vec::new()
                } else {
                    local_files.clone()
                }
            }
        };
        let mut local_tree = build_tree(&published_files, false)?;
        let mut root_hash = local_tree.root_hash;
        let mut local_paths = top_level_paths(&published_files);
        let mut remote_paths = BTreeSet::new();
        let mut remote_files: HashMap<String, FileMetadata> = HashMap::new();
        let mut remote_roots: HashMap<u32, [u8; 20]> = HashMap::new();
        let mut pending_have_pieces: HashSet<u32> = HashSet::new();
        let mut remote_public_keys: HashMap<u32, [u8; 32]> = HashMap::new();
        let mut remote_public_key: Option<[u8; 32]> = None;
        let mut downloads: HashMap<u32, DownloadSession> = HashMap::new();
        let mut uploads: HashMap<u32, UploadSession> = HashMap::new();
        let mut wire_buffers: HashMap<u32, Vec<u8>> = HashMap::new();
        let mut reconciled_versions: HashMap<String, [u8; 20]> = HashMap::new();
        let mut merge_connections = HashSet::new();
        let mut sent_get_root = false;
        let mut sent_get_nodes = false;
        let mut requested_get_files: BTreeSet<String> = BTreeSet::new();
        let mut sent_file_manifest = false;
        let mut received_files = false;
        let mut merge_in_flight: Option<u32> = None;
        let mut acl_merge_pending = false;
        let mut merge_request_at = Some(
            Instant::now()
                + if initiator {
                    Duration::ZERO
                } else {
                    MERGE_NEGOTIATION_DELAY
                },
        );
        let mut merge_root_deadline = None;
        let mut merge_cooldown_until: Option<Instant> = None;
        let mut settle_deadline = None;
        let mut idle_deadline = Instant::now() + Duration::from_secs(PEER_IDLE_SECONDS);
        let mut next_local_scan = Instant::now() + Duration::from_secs(1);

        exchange_tunnel_check(stream, self.identity.peer_id, initiator)?;
        let mut mux = TunnelMux::new(stream);
        let own_merge_connection = establish_tunnel(&mut mux, initiator)?;
        let mut merge_connection = own_merge_connection;
        merge_connections.insert(merge_connection);
        // While relaying, this connection must also announce the writer's key:
        // the peer verifies the relayed entries against whatever `pk` arrived
        // last, so sending our own key here would undo the relay identity.
        let announced = match relay_identity {
            Some(public_key) => self.identity.id_message_with_key(public_key),
            None => self.identity.id_message(),
        };
        write_peer_message_uncompressed(&mut mux, merge_connection, &announced)?;

        loop {
            if let Some(deadline) = merge_root_deadline {
                if Instant::now() >= deadline {
                    merge_root_deadline = None;
                    merge_in_flight = None;
                    sent_get_root = false;
                    merge_request_at = Some(Instant::now());
                }
            }
            if merge_request_at.is_some_and(|deadline| Instant::now() >= deadline)
                && merge_in_flight.is_none()
                && !sent_get_root
                && !sent_get_nodes
                && merge_cooldown_until.is_none_or(|deadline| Instant::now() >= deadline)
            {
                merge_request_at = None;
                if !mux.known.contains(&merge_connection) {
                    merge_connection = self.start_merge_session(&mut mux, relay_identity)?;
                }
                sent_get_nodes = false;
                sent_file_manifest = false;
                requested_get_files.clear();
                reconciled_versions.clear();
                send_get_root(
                    &mut mux,
                    merge_connection,
                    root_hash,
                    self.acl_hash,
                    active_size(&published_files),
                )?;
                sent_get_root = true;
                merge_in_flight = Some(merge_connection);
                merge_root_deadline = Some(Instant::now() + MERGE_ROOT_RETRY);
            }
            if let Some(deadline) = settle_deadline {
                if Instant::now() >= deadline && downloads.is_empty() && uploads.is_empty() {
                    break;
                }
            }
            if Instant::now() >= idle_deadline && uploads.is_empty() {
                break;
            }
            if self.has_missing_tracked_path(&sync_state)? {
                next_local_scan = Instant::now();
            }
            if Instant::now() >= next_local_scan {
                let refreshed_files = self.scan_files(&mut sync_state)?;
                let refreshed_published_files = match relay_identity {
                    Some(_) => relay_files(&self.root, &sync_state),
                    None => {
                        if self.read_only {
                            Vec::new()
                        } else {
                            refreshed_files.clone()
                        }
                    }
                };
                let refreshed_tree = build_tree(&refreshed_published_files, false)?;
                let refreshed_root = refreshed_tree.root_hash;
                let refreshed_paths = top_level_paths(&refreshed_published_files);
                if refreshed_root != root_hash {
                    let changed_paths = changed_local_paths(&local_files, &refreshed_files);
                    let stale_downloads = downloads
                        .iter()
                        .filter_map(|(connection_id, download)| {
                            changed_paths
                                .contains(&download.path)
                                .then_some(*connection_id)
                        })
                        .collect::<Vec<_>>();
                    for connection_id in stale_downloads {
                        downloads.remove(&connection_id);
                        mux.send_close(connection_id)?;
                    }
                    let stale_uploads = uploads
                        .iter()
                        .filter_map(|(connection_id, upload)| {
                            changed_paths
                                .contains(&upload.metadata.wire_path_string())
                                .then_some(*connection_id)
                        })
                        .collect::<Vec<_>>();
                    for connection_id in stale_uploads {
                        uploads.remove(&connection_id);
                        mux.send_close(connection_id)?;
                    }
                    if (merge_in_flight.is_some()
                        || sent_get_root
                        || sent_get_nodes
                        || sent_file_manifest)
                        && mux.known.contains(&merge_connection)
                    {
                        mux.send_close(merge_connection)?;
                    }
                    merge_cooldown_until = None;
                    for connection_id in merge_connections.clone() {
                        if mux.known.contains(&connection_id) {
                            self.send_state_notify_on(
                                &mut mux,
                                connection_id,
                                refreshed_root,
                                &refreshed_published_files,
                            )?;
                        }
                    }
                    merge_request_at = Some(Instant::now() + MERGE_NEGOTIATION_DELAY);
                    settle_deadline =
                        Some(Instant::now() + Duration::from_secs(SYNC_SETTLE_SECONDS));
                }
                local_files = refreshed_files;
                published_files = refreshed_published_files;
                local_tree = refreshed_tree;
                root_hash = refreshed_root;
                local_paths = refreshed_paths;
                next_local_scan = Instant::now() + Duration::from_secs(1);
            }
            let event = match mux.next_event() {
                Ok(event) => event,
                Err(error) if is_timeout(&error) => continue,
                Err(error) if is_clean_tunnel_eof(&error) => {
                    if (received_files || (!self.read_only && !local_files.is_empty()))
                        && downloads.is_empty()
                        && uploads.is_empty()
                    {
                        return Ok(());
                    }
                    if downloads.is_empty() && uploads.is_empty() {
                        bail!("peer disconnected before synchronization completed");
                    }
                    bail!(
                        "peer disconnected with {} incomplete download(s) and {} upload(s)",
                        downloads.len(),
                        uploads.len()
                    );
                }
                Err(error) => return Err(error),
            };
            idle_deadline = Instant::now() + Duration::from_secs(PEER_IDLE_SECONDS);
            let packet = match event {
                TunnelEvent::Data(packet) => packet,
                TunnelEvent::Opened => continue,
                TunnelEvent::Ack(_) => continue,
                TunnelEvent::Closed(connection_id) => {
                    wire_buffers.remove(&connection_id);
                    if merge_in_flight == Some(connection_id) {
                        merge_in_flight = None;
                        sent_get_root = false;
                        sent_get_nodes = false;
                        sent_file_manifest = false;
                        requested_get_files.clear();
                        reconciled_versions.clear();
                        merge_cooldown_until = Some(Instant::now() + Duration::from_secs(2));
                    }
                    if let Some(download) = downloads.remove(&connection_id) {
                        let target = safe_target(&self.root, &download.path)?;
                        let metadata_changed =
                            remote_files.get(&download.path).is_some_and(|metadata| {
                                metadata.metadata_hash() != download.metadata_hash
                            });
                        let type_changed =
                            remote_files.get(&download.path).is_some_and(|metadata| {
                                (metadata.entry_type == EntryType::RegularFile && target.is_dir())
                                    || (metadata.entry_type == EntryType::Directory
                                        && target.is_file())
                            });
                        if !metadata_changed && !type_changed {
                            bail!(
                                "peer closed download connection for {} before content completed",
                                download.path
                            );
                        }
                    }
                    uploads.remove(&connection_id);
                    if received_files && downloads.is_empty() && uploads.is_empty() {
                        settle_deadline =
                            Some(Instant::now() + Duration::from_secs(SYNC_SETTLE_SECONDS));
                    }
                    continue;
                }
            };
            if !mux.known.contains(&packet.connection_id) {
                wire_buffers.remove(&packet.connection_id);
                continue;
            }
            let wire_buffer = wire_buffers.entry(packet.connection_id).or_default();
            wire_buffer.extend_from_slice(&packet.payload);
            let payloads = take_complete_wire_payloads(wire_buffer)?;
            if payloads.is_empty() {
                continue;
            }
            for payload in payloads {
                match payload {
                    WirePayload::DirectHandshake(magic) => {
                        mux.send_data(packet.connection_id, &magic)?;
                    }
                    WirePayload::Direct(frame) => {
                        let direct_message = decode_direct_torrent(&frame)?;
                        if direct_message.as_dict()?.contains_key(&b"data"[..]) {
                            self.apply_content_response(
                                &mut mux,
                                packet.connection_id,
                                &direct_message,
                                &remote_files,
                                &mut downloads,
                                &mut sync_state,
                            )?;
                            if received_files && downloads.is_empty() && uploads.is_empty() {
                                settle_deadline =
                                    Some(Instant::now() + Duration::from_secs(SYNC_SETTLE_SECONDS));
                            }
                        } else {
                            self.respond_direct_request(
                                &mut mux,
                                packet.connection_id,
                                &direct_message,
                                frame
                                    .get(..DIRECT_TORRENT_MAGIC_V2.len())
                                    .unwrap_or(DIRECT_TORRENT_MAGIC_V3),
                                &local_files,
                                &remote_files,
                                &mut downloads,
                                &mut uploads,
                            )?;
                        }
                    }
                    WirePayload::Peer(payload) => {
                        if !payload.starts_with(b"d") {
                            self.handle_bit_torrent_message(
                                &mut mux,
                                packet.connection_id,
                                &payload,
                                &mut downloads,
                                &mut uploads,
                                &remote_files,
                                &mut sync_state,
                            )?;
                            if received_files && downloads.is_empty() && uploads.is_empty() {
                                settle_deadline =
                                    Some(Instant::now() + Duration::from_secs(SYNC_SETTLE_SECONDS));
                            }
                            continue;
                        }
                        let message = decode(&payload).context("decode PeerMessage")?;
                        if message.as_dict()?.contains_key(&b"data"[..]) {
                            self.apply_content_response(
                                &mut mux,
                                packet.connection_id,
                                &message,
                                &remote_files,
                                &mut downloads,
                                &mut sync_state,
                            )?;
                            if received_files && downloads.is_empty() && uploads.is_empty() {
                                settle_deadline =
                                    Some(Instant::now() + Duration::from_secs(SYNC_SETTLE_SECONDS));
                            }
                            continue;
                        }
                        if !message.as_dict()?.contains_key(&b"m"[..])
                            && message.get(b"f").is_ok()
                            && message.get(b"i").is_ok()
                            && message.get(b"sig").is_ok()
                        {
                            self.respond_direct_request(
                                &mut mux,
                                packet.connection_id,
                                &message,
                                DIRECT_TORRENT_MAGIC_V3,
                                &local_files,
                                &remote_files,
                                &mut downloads,
                                &mut uploads,
                            )?;
                            continue;
                        }
                        let message_type = message
                            .get(b"m")?
                            .as_bytes()
                            .context("PeerMessage has no type")?;
                        match message_type {
                            b"id" => {
                                // A read-only peer holds no Ed25519 key, so the
                                // official client omits `pk` entirely. Keep the
                                // connection and record the same "cannot sign"
                                // sentinel the rest of the code already uses for
                                // a peer that has no metadata signing identity.
                                let public_key = crate::protocol::peer_identity_key(&message)?;
                                let remote_share_id: [u8; 20] =
                                    message.get(b"share")?.as_bytes()?.try_into().map_err(
                                        |_| anyhow::anyhow!("peer share ID is not 20 bytes"),
                                    )?;
                                if remote_share_id != self.identity.share_id {
                                    bail!("peer share ID does not match the configured share");
                                }
                                remote_public_keys.insert(packet.connection_id, public_key);
                                // A signing-capable peer supersedes the sentinel;
                                // never overwrite a real key with a zero one.
                                if !crate::protocol::peer_key_cannot_sign(&public_key)
                                    || remote_public_key.is_none()
                                {
                                    remote_public_key = Some(public_key);
                                }
                                // A read-only folder answers a later
                                // encrypted-only peer with the writer's own
                                // identity, so remember it as soon as a signing
                                // peer announces one.
                                if self.read_only
                                    && !crate::protocol::peer_key_cannot_sign(&public_key)
                                    && sync_state.remember_writer_public_key(&public_key)
                                {
                                    sync_state.save()?;
                                    relay_identity = Some(public_key);
                                    published_files = relay_files(&self.root, &sync_state);
                                    local_tree = build_tree(&published_files, false)?;
                                    root_hash = local_tree.root_hash;
                                    local_paths = top_level_paths(&published_files);
                                    sent_file_manifest = false;
                                    requested_get_files.clear();
                                    if mux.known.contains(&merge_connection) {
                                        mux.send_close(merge_connection)?;
                                    }
                                    merge_request_at = Some(Instant::now());
                                }
                                merge_connections.insert(packet.connection_id);
                            }
                            b"get_root" => {
                                merge_request_at = None;
                                merge_root_deadline = None;
                                if merge_in_flight.is_some_and(|connection_id| {
                                    connection_id != packet.connection_id
                                }) {
                                    if mux.known.contains(&merge_connection) {
                                        mux.send_close(merge_connection)?;
                                    }
                                    merge_in_flight = None;
                                    sent_get_root = false;
                                    sent_get_nodes = false;
                                    sent_file_manifest = false;
                                    requested_get_files.clear();
                                    reconciled_versions.clear();
                                }
                                let remote_time = message
                                    .get(b"time")
                                    .ok()
                                    .and_then(|value| value.as_int().ok());
                                write_peer_message(
                                    &mut mux,
                                    packet.connection_id,
                                    &root_message(
                                        root_hash,
                                        remote_time,
                                        self.acl_hash,
                                        active_size(&published_files),
                                    ),
                                )?;
                            }
                            b"root" => {
                                if packet.connection_id != merge_connection
                                    || !merge_connections.contains(&packet.connection_id)
                                {
                                    continue;
                                }
                                merge_root_deadline = None;
                                let remote_root = message
                                    .get(b"hash")
                                    .ok()
                                    .and_then(|value| value.as_bytes().ok())
                                    .and_then(|bytes| <[u8; 20]>::try_from(bytes).ok())
                                    .unwrap_or(root_hash);
                                remote_roots.insert(packet.connection_id, remote_root);
                                let remote_acl_hash = message
                                    .get(b"acl_hash")
                                    .ok()
                                    .and_then(|value| value.as_bytes().ok())
                                    .and_then(|bytes| <[u8; 20]>::try_from(bytes).ok())
                                    .unwrap_or_else(empty_hash);
                                if remote_acl_hash != self.acl_hash && !acl_merge_pending {
                                    write_peer_message(
                                        &mut mux,
                                        packet.connection_id,
                                        &get_acl_nodes_message(self.acl_hash),
                                    )?;
                                    acl_merge_pending = true;
                                } else if remote_root != root_hash && !sent_get_nodes {
                                    sent_file_manifest = false;
                                    requested_get_files.clear();
                                    reconciled_versions.clear();
                                    remote_files.clear();
                                    send_get_nodes(
                                        &mut mux,
                                        packet.connection_id,
                                        &BTreeSet::new(),
                                    )?;
                                    sent_get_nodes = true;
                                } else {
                                    write_peer_message(
                                        &mut mux,
                                        packet.connection_id,
                                        &get_have_pieces_message(),
                                    )?;
                                    sent_get_root = false;
                                }
                            }
                            b"get_nodes" => {
                                let mut response_nodes = BTreeMap::new();
                                for path in requested_paths_from_node_request(&message)? {
                                    let node = local_tree.node(&path).with_context(|| {
                                        format!("local node is unavailable: {path}")
                                    })?;
                                    response_nodes.insert(node_path_key(&path), node);
                                }
                                if !response_nodes.is_empty() {
                                    write_peer_message(
                                        &mut mux,
                                        packet.connection_id,
                                        &nodes_message_many(
                                            response_nodes,
                                            message
                                                .get(b"offset")
                                                .ok()
                                                .and_then(|value| value.as_int().ok())
                                                .unwrap_or(0),
                                        ),
                                    )?;
                                }
                            }
                            b"get_acl_nodes" => {
                                write_peer_message(
                                    &mut mux,
                                    packet.connection_id,
                                    &acl_nodes_message(self.acl_hash, Vec::new()),
                                )?;
                            }
                            b"acl_nodes" => {
                                write_peer_message(
                                    &mut mux,
                                    packet.connection_id,
                                    &get_acl_entries_message(self.acl_hash, 0),
                                )?;
                            }
                            b"get_acl_entries" => {
                                let offset = message
                                    .get(b"offset")
                                    .ok()
                                    .and_then(|value| value.as_int().ok())
                                    .unwrap_or(0);
                                let entries = self
                                    .acl
                                    .wire_entries()
                                    .into_iter()
                                    .skip(offset.max(0) as usize)
                                    .take(256)
                                    .collect::<Vec<_>>();
                                write_peer_message(
                                    &mut mux,
                                    packet.connection_id,
                                    &acl_entries_message(self.acl_hash, entries, offset),
                                )?;
                            }
                            b"acl_entries" => {
                                parse_entries(message.get(b"entries")?)?;
                                write_peer_message(
                                    &mut mux,
                                    packet.connection_id,
                                    &acl_entries_accepted_message(self.acl_hash),
                                )?;
                            }
                            b"acl_entries_accepted" => {
                                if acl_merge_pending {
                                    acl_merge_pending = false;
                                    if !sent_get_nodes {
                                        send_get_nodes(
                                            &mut mux,
                                            packet.connection_id,
                                            &BTreeSet::new(),
                                        )?;
                                        sent_get_nodes = true;
                                    }
                                }
                            }
                            b"nodes" => {
                                let discovered_paths = node_top_level_paths(&message)?;
                                if packet.connection_id != merge_connection
                                    || !merge_connections.contains(&packet.connection_id)
                                {
                                    continue;
                                }
                                if sent_file_manifest {
                                    continue;
                                }
                                remote_paths.extend(discovered_paths);
                                let desired_paths =
                                    local_paths.union(&remote_paths).cloned().collect();
                                if !sent_file_manifest {
                                    self.send_files(
                                        &mut mux,
                                        packet.connection_id,
                                        &published_files,
                                        &[],
                                        self.wire_is_encrypted(
                                            remote_public_keys.get(&packet.connection_id),
                                            peer_encrypted_only,
                                        ),
                                    )?;
                                    if requested_get_files != desired_paths {
                                        send_get_files(
                                            &mut mux,
                                            packet.connection_id,
                                            &desired_paths,
                                        )?;
                                        requested_get_files = desired_paths;
                                    }
                                    pending_have_pieces.insert(packet.connection_id);
                                    sent_file_manifest = true;
                                    sent_get_root = false;
                                }
                            }
                            b"get_files" | b"get_files_next" => {
                                let paths = requested_paths(&message)?;
                                self.send_files(
                                    &mut mux,
                                    packet.connection_id,
                                    &local_files,
                                    &paths,
                                    self.wire_is_encrypted(
                                        remote_public_keys.get(&packet.connection_id),
                                        peer_encrypted_only,
                                    ),
                                )?;
                            }
                            b"files" => {
                                if !merge_connections.contains(&packet.connection_id) {
                                    continue;
                                }
                                merge_connection = packet.connection_id;
                                let list = message.get(b"files")?.as_list()?;
                                let mut refreshed_remote_files = HashMap::new();
                                // A read-only peer cannot sign, so fall back to
                                // our own key (the writer's) to verify metadata,
                                // exactly as the local-key path already does.
                                let metadata_public_key = remote_public_keys
                                    .get(&packet.connection_id)
                                    .copied()
                                    .filter(|public_key| {
                                        !crate::protocol::peer_key_cannot_sign(public_key)
                                    })
                                    .or(remote_public_key
                                        .filter(|key| !crate::protocol::peer_key_cannot_sign(key)))
                                    .or(self.metadata_public_key)
                                    .context("peer sent file metadata before its identity")?;
                                for value in list {
                                    let metadata = parse_file_with_key(
                                        value,
                                        &metadata_public_key,
                                        Some(&self.key),
                                    )?;
                                    let path = metadata.wire_path_string();
                                    if self.selection.allows_path(&path) {
                                        refreshed_remote_files.insert(path, metadata);
                                    }
                                }
                                remote_files.extend(refreshed_remote_files);
                                if pending_have_pieces.remove(&packet.connection_id) {
                                    if let Some(remote_root) =
                                        remote_roots.get(&packet.connection_id).copied()
                                    {
                                        match peer_have_pieces_message(
                                            remote_root,
                                            &remote_files,
                                            &published_files,
                                        ) {
                                            Ok(message) => write_peer_message(
                                                &mut mux,
                                                packet.connection_id,
                                                &message,
                                            )?,
                                            Err(_) => {
                                                pending_have_pieces.insert(packet.connection_id);
                                            }
                                        }
                                    } else {
                                        pending_have_pieces.insert(packet.connection_id);
                                    }
                                }
                                for (path, metadata) in &remote_files {
                                    let metadata_hash = metadata.metadata_hash();
                                    if reconciled_versions.get(path) == Some(&metadata_hash) {
                                        continue;
                                    }
                                    let stale_connections = downloads
                                        .iter()
                                        .filter_map(|(connection_id, download)| {
                                            (download.path == *path
                                                && download.metadata_hash != metadata_hash)
                                                .then_some(*connection_id)
                                        })
                                        .collect::<Vec<_>>();
                                    for connection_id in stale_connections {
                                        downloads.remove(&connection_id);
                                        mux.send_close(connection_id)?;
                                    }
                                    let mut local = local_files
                                        .iter()
                                        .find(|file| file.metadata.wire_path_string() == *path)
                                        .cloned();
                                    if let Some(entry) = local.as_mut() {
                                        let target = safe_target(&self.root, path)?;
                                        if entry.metadata.state == EntryState::Active
                                            && !target.exists()
                                        {
                                            let mut tombstone =
                                                entry.metadata.tombstone(unix_time());
                                            self.sign_metadata(&mut tombstone)?;
                                            entry.metadata = tombstone;
                                            entry.content.clear();
                                        } else if entry.metadata.state == EntryState::Deleted
                                            && target.exists()
                                        {
                                            let (metadata, content) = if target.is_dir() {
                                                (
                                                    FileMetadata::from_directory(
                                                        &target,
                                                        path,
                                                        self.identity.peer_id,
                                                        unix_time(),
                                                    )?,
                                                    Vec::new(),
                                                )
                                            } else {
                                                let metadata = FileMetadata::from_path(
                                                    &target,
                                                    path,
                                                    self.identity.peer_id,
                                                )?;
                                                let content = fs::read(&target)?;
                                                metadata.verify_content(&content)?;
                                                (metadata, content)
                                            };
                                            entry.metadata = metadata;
                                            entry.content = content;
                                            self.sign_metadata(&mut entry.metadata)?;
                                        }
                                    }
                                    reconciled_versions.insert(path.clone(), metadata_hash);
                                    let reconciliation = local
                                        .as_ref()
                                        .map(|local| file_reconciliation(metadata, local))
                                        .unwrap_or(FileReconciliation::RemoteWins);
                                    if metadata.state == EntryState::Active
                                        && local.as_ref().is_some_and(|local| {
                                            local.metadata.state == EntryState::Active
                                                && local.metadata.file_hash == metadata.file_hash
                                                && local.metadata.metadata_hash()
                                                    != metadata.metadata_hash()
                                        })
                                    {
                                        if let Some(local) = local.as_ref() {
                                            if metadata_wins(metadata, &local.metadata) {
                                                self.adopt_remote_metadata(
                                                    metadata,
                                                    local,
                                                    &mut sync_state,
                                                )?;
                                            }
                                        }
                                        continue;
                                    }
                                    match reconciliation {
                                        FileReconciliation::Equal => {
                                            if let Some(local) = local.as_ref() {
                                                self.adopt_remote_metadata(
                                                    metadata,
                                                    local,
                                                    &mut sync_state,
                                                )?;
                                            }
                                            continue;
                                        }
                                        FileReconciliation::LocalWins => {
                                            let pending = downloads
                                                .iter()
                                                .filter_map(|(connection_id, download)| {
                                                    (download.path == *path)
                                                        .then_some(*connection_id)
                                                })
                                                .collect::<Vec<_>>();
                                            for connection_id in pending {
                                                downloads.remove(&connection_id);
                                                mux.send_close(connection_id)?;
                                            }
                                            continue;
                                        }
                                        FileReconciliation::RemoteWins
                                        | FileReconciliation::Conflict => {}
                                    }
                                    if metadata.state == EntryState::Deleted {
                                        self.apply_remote_deletion(
                                            metadata,
                                            local.as_ref(),
                                            &mut sync_state,
                                        )?;
                                        continue;
                                    }
                                    if metadata.entry_type == EntryType::Directory {
                                        self.apply_remote_directory(
                                            metadata,
                                            local.as_ref(),
                                            &mut sync_state,
                                        )?;
                                        continue;
                                    }
                                    if downloads.values().any(|pending| pending.path == *path) {
                                        continue;
                                    }
                                    let mut conflict_target = None;
                                    let target = safe_target(&self.root, path)?;
                                    let preserve_target = reconciliation
                                        == FileReconciliation::Conflict
                                        || local.as_ref().is_some_and(|entry| {
                                            entry.metadata.entry_type != metadata.entry_type
                                        });
                                    if reconciliation == FileReconciliation::Conflict
                                        && !target.exists()
                                        && local.as_ref().is_some_and(|entry| {
                                            entry.metadata.state == EntryState::Deleted
                                        })
                                    {
                                        conflict_target = Some(self.next_conflict_path(&target)?);
                                    }
                                    if metadata.entry_type == EntryType::RegularFile
                                        && metadata.size == 0
                                        && metadata.file_hash == [0; 20]
                                        && metadata.piece_count == 0
                                    {
                                        let torrent = parse_torrent_info(&metadata.torrent_info())?;
                                        self.apply_remote_to(
                                            metadata,
                                            &torrent,
                                            &[],
                                            conflict_target,
                                            preserve_target,
                                            &mut sync_state,
                                        )?;
                                        sync_state.save()?;
                                        if downloads.is_empty() && uploads.is_empty() {
                                            settle_deadline = Some(
                                                Instant::now()
                                                    + Duration::from_secs(SYNC_SETTLE_SECONDS),
                                            );
                                        }
                                        continue;
                                    }
                                    let connection_id = mux.open_session()?;
                                    // Request the name the responder can
                                    // actually look up: only an
                                    // encrypted-only peer holds the encrypted
                                    // tree, every other peer publishes the
                                    // plaintext one.
                                    let login = metadata.direct_login(
                                        &self.identity.share_id,
                                        &self.identity.peer_id,
                                        &self.signing_key,
                                        metadata.encrypted_epart.is_some()
                                            || self.key.is_encrypted_only(),
                                        peer_encrypted_only,
                                    )?;
                                    mux.send_data(connection_id, &login)?;
                                    downloads.insert(
                                        connection_id,
                                        DownloadSession::with_conflict_target(
                                            path.clone(),
                                            metadata_hash,
                                            conflict_target,
                                            preserve_target,
                                        ),
                                    );
                                }
                                sync_state.save()?;
                                received_files = true;
                                if downloads.is_empty() && uploads.is_empty() {
                                    settle_deadline = Some(
                                        Instant::now() + Duration::from_secs(SYNC_SETTLE_SECONDS),
                                    );
                                }
                            }
                            b"get_have_pieces" => {
                                let remote_root = remote_roots
                                    .get(&packet.connection_id)
                                    .copied()
                                    .unwrap_or(root_hash);
                                if remote_root == root_hash {
                                    write_peer_message(
                                        &mut mux,
                                        packet.connection_id,
                                        &have_pieces_message(root_hash, &published_files),
                                    )?;
                                } else if let Ok(message) = peer_have_pieces_message(
                                    remote_root,
                                    &remote_files,
                                    &published_files,
                                ) {
                                    write_peer_message(&mut mux, packet.connection_id, &message)?;
                                } else {
                                    pending_have_pieces.insert(packet.connection_id);
                                }
                            }
                            b"state_notify" => {
                                merge_connections.insert(packet.connection_id);
                                if state_notify_requires_reconcile(
                                    &message,
                                    root_hash,
                                    self.acl_hash,
                                )? {
                                    if merge_in_flight.is_some()
                                        || sent_get_root
                                        || sent_get_nodes
                                        || sent_file_manifest
                                    {
                                        if mux.known.contains(&merge_connection) {
                                            mux.send_close(merge_connection)?;
                                        }
                                        sent_get_nodes = false;
                                        sent_file_manifest = false;
                                        requested_get_files.clear();
                                        reconciled_versions.clear();
                                        merge_cooldown_until = None;
                                    }
                                    merge_request_at =
                                        Some(Instant::now() + MERGE_NEGOTIATION_DELAY);
                                }
                            }
                            b"have_pieces" => {
                                if !merge_connections.contains(&packet.connection_id) {
                                    continue;
                                }
                                merge_connections.remove(&packet.connection_id);
                                if merge_in_flight == Some(packet.connection_id)
                                    || merge_connection == packet.connection_id
                                {
                                    merge_in_flight = None;
                                    sent_get_root = false;
                                    sent_get_nodes = false;
                                    sent_file_manifest = false;
                                    requested_get_files.clear();
                                    reconciled_versions.clear();
                                    merge_cooldown_until =
                                        Some(Instant::now() + Duration::from_secs(2));
                                }
                                mux.send_close(packet.connection_id)?;
                            }
                            b"not_master" => {
                                merge_in_flight = None;
                                sent_get_root = false;
                                sent_get_nodes = false;
                                sent_file_manifest = false;
                                requested_get_files.clear();
                                reconciled_versions.clear();
                                merge_cooldown_until = None;
                                merge_request_at = Some(Instant::now() + MERGE_NEGOTIATION_DELAY);
                            }
                            other => {
                                eprintln!(
                                    "ignoring PeerMessage type {}",
                                    String::from_utf8_lossy(other)
                                );
                            }
                        }
                    }
                }
            }
        }
        Ok(())
    }

    fn apply_content_response<S: Read + Write>(
        &self,
        mux: &mut TunnelMux<'_, S>,
        connection_id: u32,
        message: &Value,
        remote_files: &HashMap<String, FileMetadata>,
        downloads: &mut HashMap<u32, DownloadSession>,
        sync_state: &mut SyncStateStore,
    ) -> Result<()> {
        let (wire_content, torrent) = parse_content(message)?;
        let torrent_hash = torrent_file_hash(&torrent)?;
        let path = downloads
            .get(&connection_id)
            .map(|download| download.path.clone())
            .context("content on a connection with no download session")?;
        let metadata = remote_files
            .get(&path)
            .context("content for unknown remote file")?
            .clone();
        if metadata.file_hash != torrent_hash {
            bail!("remote metadata and torrent hash differ for {path}");
        }
        let content = self.verified_content(&metadata, &torrent, &wire_content)?;
        let conflict_target = downloads
            .get(&connection_id)
            .and_then(|download| download.conflict_target.clone());
        let preserve_target = downloads
            .get(&connection_id)
            .is_some_and(|download| download.preserve_target);
        self.apply_remote_to(
            &metadata,
            &torrent,
            &content,
            conflict_target,
            preserve_target,
            sync_state,
        )?;
        sync_state.save()?;
        downloads.remove(&connection_id);
        mux.send_close(connection_id)?;
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    fn respond_direct_request<S: Read + Write>(
        &self,
        mux: &mut TunnelMux<'_, S>,
        connection_id: u32,
        direct_message: &Value,
        ident_magic: &[u8],
        local_files: &[LocalFile],
        remote_files: &HashMap<String, FileMetadata>,
        downloads: &mut HashMap<u32, DownloadSession>,
        uploads: &mut HashMap<u32, UploadSession>,
    ) -> Result<()> {
        let relative_path = String::from_utf8(direct_message.get(b"f")?.as_bytes()?.to_vec())
            .context("DirectTorrent path is not UTF-8")?;
        let info_hash: [u8; 20] = direct_message
            .get(b"i")?
            .as_bytes()?
            .try_into()
            .map_err(|_| anyhow::anyhow!("DirectTorrent info hash is not 20 bytes"))?;
        let signature = direct_message.get(b"sig")?.as_bytes()?;
        if let Some(download) = downloads.get_mut(&connection_id) {
            let expected_path = &download.path;
            let metadata = remote_files
                .get(expected_path)
                .context("DirectTorrent response for unknown download")?;
            let encrypted_wire = metadata.protocol_path_string() == relative_path;
            if !encrypted_wire && metadata.wire_path_string() != relative_path {
                bail!("DirectTorrent response identity mismatch for {relative_path}");
            }
            if !self.direct_info_hash_matches(metadata, &info_hash, encrypted_wire)? {
                bail!("DirectTorrent response identity mismatch for {relative_path}");
            }
            if signature != metadata.signature {
                bail!("DirectTorrent response signature differs for {relative_path}");
            }
            download.phase = DownloadPhase::LoginAccepted;
            self.start_v2_metadata_download(mux, connection_id, download, metadata)?;
            return Ok(());
        }
        let file = local_files
            .iter()
            .find(|file| {
                file.metadata.protocol_path_string() == relative_path
                    || file.metadata.wire_path_string() == relative_path
            })
            .with_context(|| format!("DirectTorrent request for unknown file {relative_path}"))?;
        let encrypted_wire = file.metadata.protocol_path_string() == relative_path;
        if !encrypted_wire && file.metadata.wire_path_string() != relative_path {
            bail!("DirectTorrent request identity mismatch for {relative_path}");
        }
        // A read-only node relays only the ciphertext form; the plaintext body
        // stays something only the writable holder authorizes.
        if self.read_only && !encrypted_wire {
            bail!("read-only node only serves the encrypted wire form");
        }
        if !self.direct_info_hash_matches(&file.metadata, &info_hash, encrypted_wire)? {
            bail!("DirectTorrent info hash mismatch for {relative_path}");
        }
        if let Ok(peer_id) = direct_message.get(b"p") {
            if peer_id.as_bytes()?.len() != 20 {
                bail!("DirectTorrent peer ID is not 20 bytes");
            }
        }
        if let Ok(share_id) = direct_message.get(b"s") {
            if share_id.as_bytes()? != self.identity.share_id {
                bail!("DirectTorrent share ID mismatch for {relative_path}");
            }
        }
        if !self.direct_request_signature_matches(
            signature,
            &info_hash,
            &relative_path,
            &file.metadata,
            remote_files,
        )? {
            bail!("DirectTorrent request signature differs for {relative_path}");
        }
        let ciphertext = self.wire_content(&file.metadata, &file.content, true)?;
        // A `D`/`E` receiver decrypts locally, so it consumes the *plaintext*
        // over the piece protocol and validates it against the plaintext hashes
        // carried (AES-wrapped) by `epieces`; an encrypted-only `F` receiver has
        // no content key and consumes the ciphertext. The published torrent
        // info keeps describing the ciphertext either way, because that is the
        // form `file_hash` was derived from.
        let served = if encrypted_wire {
            ciphertext.clone()
        } else {
            file.content.clone()
        };
        if ident_magic == DIRECT_TORRENT_MAGIC_V2 {
            let login = crate::protocol::encode_direct_torrent(direct_message)?;
            mux.send_data(connection_id, &login)?;
        } else {
            let content_key = self.metadata_content_key(&file.metadata)?;
            let content = file.metadata.content_message_for_wire(
                &served,
                &ciphertext,
                content_key.as_ref(),
            )?;
            let response = crate::protocol::encode_direct_torrent_body(&content)?;
            mux.send_data(connection_id, &response)?;
        }
        uploads.insert(
            connection_id,
            UploadSession {
                metadata: file.metadata.clone(),
                content: served,
                torrent_content: ciphertext,
                remote_metadata_id: None,
            },
        );
        Ok(())
    }

    /// The torrent info this upload must publish through `ut_metadata`.
    fn upload_torrent_info(&self, upload: &UploadSession) -> Result<Value> {
        let content_key = self.metadata_content_key(&upload.metadata)?;
        upload
            .metadata
            .torrent_info_for_content(&upload.torrent_content, content_key.as_ref())
    }

    fn start_v2_metadata_download<S: Read + Write>(
        &self,
        mux: &mut TunnelMux<'_, S>,
        connection_id: u32,
        download: &mut DownloadSession,
        metadata: &FileMetadata,
    ) -> Result<()> {
        if !matches!(
            download.phase,
            DownloadPhase::LoginSent | DownloadPhase::LoginAccepted
        ) {
            return Ok(());
        }
        let metadata_size = expected_torrent_info_size_for_shape(
            metadata.size,
            metadata.piece_count,
            metadata.encrypted_epart.is_some(),
        )?;
        download.phase = DownloadPhase::MetadataDownloading;
        download.metadata_size = metadata_size;
        let handshake = Value::dict([
            (
                b"m".to_vec(),
                Value::dict([(
                    b"ut_metadata".to_vec(),
                    Value::Int(LOCAL_UT_METADATA_ID as i64),
                )]),
            ),
            (b"metadata_size".to_vec(), Value::Int(metadata_size as i64)),
            (b"reqq".to_vec(), Value::Int(1024)),
            (b"max_req".to_vec(), Value::Int(134_217_728)),
        ]);
        let mut payload = vec![0x00];
        payload.extend_from_slice(&encode(&handshake));
        write_bit_torrent_message(mux, connection_id, 0x14, &payload)?;
        write_bit_torrent_message(mux, connection_id, 0x0f, &[])?;
        write_bit_torrent_message(mux, connection_id, 0x02, &[])?;
        Ok(())
    }

    fn request_v2_metadata<S: Read + Write>(
        &self,
        mux: &mut TunnelMux<'_, S>,
        connection_id: u32,
        download: &mut DownloadSession,
    ) -> Result<()> {
        let remote_id = download
            .remote_metadata_id
            .context("metadata extension was not negotiated")?;
        let count = download.metadata_size.div_ceil(METADATA_PIECE_SIZE);
        for piece in 0..count {
            let request = Value::dict([
                (b"msg_type".to_vec(), Value::Int(0)),
                (b"piece".to_vec(), Value::Int(piece as i64)),
            ]);
            let mut payload = vec![remote_id];
            payload.extend_from_slice(&encode(&request));
            write_bit_torrent_message(mux, connection_id, 0x14, &payload)?;
        }
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    fn handle_bit_torrent_message<S: Read + Write>(
        &self,
        mux: &mut TunnelMux<'_, S>,
        connection_id: u32,
        payload: &[u8],
        downloads: &mut HashMap<u32, DownloadSession>,
        uploads: &mut HashMap<u32, UploadSession>,
        remote_files: &HashMap<String, FileMetadata>,
        sync_state: &mut SyncStateStore,
    ) -> Result<()> {
        let opcode = *payload.first().context("empty BitTorrent message")?;
        if let Some(upload) = uploads.get_mut(&connection_id) {
            if matches!(opcode, 0x02 | 0x06 | 0x14) {
                return self.handle_upload_message(mux, connection_id, payload, upload);
            }
        }
        match opcode {
            0x0e | 0x0f | 0x01 | 0x02 | 0x03 | 0x04 | 0x05 | 0x06 | 0x08 | 0x09 | 0x0a | 0x0d
            | 0x11 => {}
            0x14 => {
                let extension_id = *payload.get(1).context("truncated extension message")?;
                if extension_id == 0 {
                    let (handshake, _) = decode_prefix_wire(&payload[2..])
                        .context("decode BitTorrent extension handshake")?;
                    let metadata_id = handshake.get(b"m")?.get(b"ut_metadata")?.as_int()?;
                    let metadata_id = u8::try_from(metadata_id)
                        .map_err(|_| anyhow::anyhow!("invalid ut_metadata extension ID"))?;
                    let metadata_size = handshake
                        .get(b"metadata_size")
                        .ok()
                        .and_then(|value| value.as_int().ok())
                        .unwrap_or(0);
                    let download = downloads
                        .get_mut(&connection_id)
                        .context("extension handshake on a connection with no download session")?;
                    download.remote_metadata_id = Some(metadata_id);
                    if metadata_size > 0 {
                        download.metadata_size = metadata_size as usize;
                    }
                    self.request_v2_metadata(mux, connection_id, download)?;
                } else {
                    let (header, consumed) =
                        decode_prefix_wire(&payload[2..]).context("decode ut_metadata header")?;
                    let message_type = header.get(b"msg_type")?.as_int()?;
                    if message_type != 1 {
                        return Ok(());
                    }
                    let piece = usize::try_from(header.get(b"piece")?.as_int()?)
                        .map_err(|_| anyhow::anyhow!("invalid metadata piece index"))?;
                    let download = downloads
                        .get_mut(&connection_id)
                        .context("metadata on a connection with no download session")?;
                    download
                        .metadata_parts
                        .insert(piece, payload[2 + consumed..].to_vec());
                    if download.metadata_complete() {
                        let mut metadata_bytes = Vec::with_capacity(download.metadata_size);
                        for index in 0..download.metadata_size.div_ceil(METADATA_PIECE_SIZE) {
                            let part = download
                                .metadata_parts
                                .get(&index)
                                .with_context(|| format!("missing metadata piece {index}"))?;
                            metadata_bytes.extend_from_slice(part);
                        }
                        metadata_bytes.truncate(download.metadata_size);
                        let info = decode(&metadata_bytes).context("decode torrent info")?;
                        let torrent = parse_torrent_info(&info)?;
                        let expected = remote_files
                            .get(&download.path)
                            .context("metadata for unknown remote file")?;
                        let torrent_hash = torrent_file_hash(&torrent)?;
                        if torrent_hash != expected.file_hash {
                            bail!(
                                "torrent identity mismatch for {}: torrent={} metadata={}",
                                download.path,
                                hex::encode(torrent_hash),
                                hex::encode(expected.file_hash)
                            );
                        }
                        download.content = vec![0; torrent.size as usize];
                        download.torrent = Some(torrent);
                        download.phase = DownloadPhase::PiecesDownloading;
                        write_bit_torrent_message(mux, connection_id, 0x0f, &[])?;
                        write_bit_torrent_message(mux, connection_id, 0x02, &[])?;
                        self.request_v2_pieces(mux, connection_id, download)?;
                    }
                }
            }
            0x07 => {
                if payload.len() < 9 {
                    bail!("truncated BitTorrent piece message");
                }
                let index = u32::from_be_bytes(payload[1..5].try_into()?);
                let begin = u32::from_be_bytes(payload[5..9].try_into()?);
                let data = &payload[9..];
                let download = downloads
                    .get_mut(&connection_id)
                    .context("piece on a connection with no download session")?;
                let torrent = download
                    .torrent
                    .as_ref()
                    .context("piece before torrent metadata")?;
                let offset = index as usize * torrent.piece_length as usize + begin as usize;
                if offset.checked_add(data.len()).context("piece overflow")?
                    > download.content.len()
                {
                    bail!("piece outside downloaded file");
                }
                download.content[offset..offset + data.len()].copy_from_slice(data);
                download.received_blocks.insert((index, begin));
                let complete = download
                    .requested_blocks
                    .keys()
                    .all(|key| download.received_blocks.contains(key));
                if complete {
                    let path = download.path.clone();
                    let torrent = download.torrent.clone().unwrap();
                    let wire_content = std::mem::take(&mut download.content);
                    let conflict_target = download.conflict_target.clone();
                    let preserve_target = download.preserve_target;
                    let metadata = remote_files
                        .get(&path)
                        .context("content for unknown remote file")?
                        .clone();
                    downloads.remove(&connection_id);
                    let content = self.verified_content(&metadata, &torrent, &wire_content)?;
                    self.apply_remote_to(
                        &metadata,
                        &torrent,
                        &content,
                        conflict_target,
                        preserve_target,
                        sync_state,
                    )?;
                    sync_state.save()?;
                    mux.send_close(connection_id)?;
                }
            }
            _ => {}
        }
        Ok(())
    }

    fn handle_upload_message<S: Read + Write>(
        &self,
        mux: &mut TunnelMux<'_, S>,
        connection_id: u32,
        payload: &[u8],
        upload: &mut UploadSession,
    ) -> Result<()> {
        let opcode = *payload.first().context("empty BitTorrent message")?;
        match opcode {
            0x02 => write_bit_torrent_message(mux, connection_id, 0x0f, &[]),
            0x06 => {
                let body = payload.get(1..13).context("truncated piece request")?;
                let index = u32::from_be_bytes(body[0..4].try_into()?);
                let begin = u32::from_be_bytes(body[4..8].try_into()?);
                let length = u32::from_be_bytes(body[8..12].try_into()?);
                if length == 0 || length > 64 * 1024 {
                    bail!("invalid requested piece block length {length}");
                }
                let start = usize::try_from(begin)?
                    .checked_add(
                        usize::try_from(index)?
                            .checked_mul(usize::try_from(PIECE_LENGTH)?)
                            .context("piece offset overflow")?,
                    )
                    .context("piece offset overflow")?;
                let end = start
                    .checked_add(usize::try_from(length)?)
                    .context("piece block overflow")?;
                if end > upload.content.len() {
                    bail!("piece request outside upload content");
                }
                let mut response = Vec::with_capacity(8 + length as usize);
                response.extend_from_slice(&index.to_be_bytes());
                response.extend_from_slice(&begin.to_be_bytes());
                response.extend_from_slice(&upload.content[start..end]);
                write_bit_torrent_message(mux, connection_id, 0x07, &response)
            }
            0x14 => {
                let extension_id = *payload.get(1).context("truncated extension message")?;
                if extension_id == 0 {
                    let (handshake, _) = decode_prefix_wire(&payload[2..])
                        .context("decode upload extension handshake")?;
                    let remote_metadata_id = handshake.get(b"m")?.get(b"ut_metadata")?.as_int()?;
                    upload.remote_metadata_id =
                        Some(u8::try_from(remote_metadata_id).map_err(|_| {
                            anyhow::anyhow!("invalid remote metadata extension ID")
                        })?);
                    let metadata = encode(&self.upload_torrent_info(upload)?);
                    let response = Value::dict([
                        (
                            b"m".to_vec(),
                            Value::dict([(
                                b"ut_metadata".to_vec(),
                                Value::Int(LOCAL_UT_METADATA_ID as i64),
                            )]),
                        ),
                        (b"metadata_size".to_vec(), Value::Int(metadata.len() as i64)),
                        (b"reqq".to_vec(), Value::Int(1024)),
                        (b"max_req".to_vec(), Value::Int(134_217_728)),
                    ]);
                    let mut response_payload = vec![0_u8];
                    response_payload.extend_from_slice(&encode(&response));
                    write_bit_torrent_message(mux, connection_id, 0x14, &response_payload)?;
                    write_bit_torrent_message(
                        mux,
                        connection_id,
                        0x05,
                        &piece_bitfield(upload.metadata.piece_hashes.len()),
                    )?;
                    write_bit_torrent_message(mux, connection_id, 0x0f, &[])?;
                    return Ok(());
                }
                let (header, _consumed) =
                    decode_prefix_wire(&payload[2..]).context("decode upload metadata header")?;
                let message_type = header.get(b"msg_type")?.as_int()?;
                let piece = usize::try_from(header.get(b"piece")?.as_int()?)
                    .map_err(|_| anyhow::anyhow!("invalid metadata piece index"))?;
                if message_type != 0 {
                    return Ok(());
                }
                let metadata = encode(&self.upload_torrent_info(upload)?);
                let start = piece
                    .checked_mul(METADATA_PIECE_SIZE)
                    .context("metadata piece offset overflow")?;
                if start >= metadata.len() {
                    bail!("metadata piece {piece} is out of range");
                }
                let end = (start + METADATA_PIECE_SIZE).min(metadata.len());
                let remote_metadata_id = upload
                    .remote_metadata_id
                    .context("metadata request before extension handshake")?;
                let response = Value::dict([
                    (b"msg_type".to_vec(), Value::Int(1)),
                    (b"piece".to_vec(), Value::Int(piece as i64)),
                    (b"total_size".to_vec(), Value::Int(metadata.len() as i64)),
                ]);
                let mut response_payload = vec![remote_metadata_id];
                response_payload.extend_from_slice(&encode(&response));
                response_payload.extend_from_slice(&metadata[start..end]);
                write_bit_torrent_message(mux, connection_id, 0x14, &response_payload)?;
                Ok(())
            }
            _ => Ok(()),
        }
    }

    fn request_v2_pieces<S: Read + Write>(
        &self,
        mux: &mut TunnelMux<'_, S>,
        connection_id: u32,
        download: &mut DownloadSession,
    ) -> Result<()> {
        const BLOCK_SIZE: u32 = 16 * 1024;
        let torrent = download
            .torrent
            .as_ref()
            .context("piece requests before torrent metadata")?;
        let piece_length = u32::try_from(torrent.piece_length)?;
        for index in 0..torrent.piece_hashes.len() as u32 {
            let mut begin = 0;
            while begin < piece_length {
                let remaining = torrent
                    .size
                    .saturating_sub(index as u64 * piece_length as u64 + begin as u64);
                if remaining == 0 {
                    break;
                }
                let length = BLOCK_SIZE.min(remaining as u32);
                let key = (index, begin);
                if download
                    .requested_blocks
                    .insert(key, length as usize)
                    .is_none()
                {
                    let mut body = Vec::with_capacity(13);
                    body.extend_from_slice(&index.to_be_bytes());
                    body.extend_from_slice(&begin.to_be_bytes());
                    body.extend_from_slice(&length.to_be_bytes());
                    write_bit_torrent_message(mux, connection_id, 0x06, &body)?;
                }
                begin += length;
            }
        }
        Ok(())
    }

    fn scan_files(&self, sync_state: &mut SyncStateStore) -> Result<Vec<LocalFile>> {
        let mut paths = Vec::new();
        collect_files(&self.root, &self.root, &self.selection, &mut paths)?;
        paths.sort();
        let mut files = Vec::new();
        let mut present = BTreeSet::new();
        for relative in paths {
            present.insert(relative.clone());
            let absolute = self.root.join(&relative);
            let previous = sync_state.get(&relative).cloned();
            let (mut metadata, content) = if absolute.is_dir() {
                (
                    FileMetadata::from_directory(
                        &absolute,
                        &relative,
                        self.identity.peer_id,
                        unix_time(),
                    )?,
                    Vec::new(),
                )
            } else {
                let metadata =
                    FileMetadata::from_path(&absolute, &relative, self.identity.peer_id)?;
                let content =
                    fs::read(&absolute).with_context(|| format!("read {}", absolute.display()))?;
                metadata.verify_content(&content)?;
                (metadata, content)
            };
            // A read-only folder stores what the writer published, so its
            // entries keep the writer's canonical `main` and signature. Only
            // the piece hashes are recomputed from the bytes on disk, which is
            // what lets this node later relay the ciphertext form.
            if self.read_only {
                if let Some(authored) = previous
                    .as_ref()
                    .filter(|record| record.wire_main.is_some())
                {
                    if let Ok(mut restored) = state_record_metadata(authored, &relative) {
                        if restored.entry_type == EntryType::RegularFile {
                            restored.piece_hashes = sha1_pieces(&content);
                        }
                        let fingerprint = local_fingerprint(&restored);
                        sync_state.insert_local(&restored, &fingerprint);
                        files.push(LocalFile {
                            metadata: restored,
                            content,
                            baseline: previous,
                        });
                        continue;
                    }
                }
            }
            let fingerprint = local_fingerprint(&metadata);
            if let Some(previous) = &previous {
                if previous.state == EntryState::Deleted.wire_value() as u8 {
                    metadata.otime = next_local_otime(previous.otime);
                    metadata.write_times = previous.write_times + 1;
                } else if fingerprint == previous.local_fingerprint {
                    metadata.owner = decode_owner(&previous.owner);
                    metadata.otime = previous.otime;
                    metadata.write_times = previous.write_times;
                } else {
                    metadata.otime = next_local_otime(previous.otime);
                    metadata.write_times = previous.write_times + 1;
                }
            }
            self.sign_metadata(&mut metadata)?;
            sync_state.insert_local(&metadata, &fingerprint);
            files.push(LocalFile {
                metadata,
                content,
                baseline: previous,
            });
        }

        let missing: Vec<(String, StateRecord)> = if self.read_only {
            Vec::new()
        } else {
            sync_state
                .entries()
                .filter(|(path, record)| {
                    self.selection.allows_path(path)
                        && !present.contains(*path)
                        && record.state == 1
                })
                .map(|(path, record)| ((*path).clone(), record.clone()))
                .collect()
        };
        for (path, previous) in missing {
            let mut metadata = state_record_metadata(&previous, &path)?;
            let fingerprint = local_fingerprint(&metadata);
            metadata = metadata.tombstone(unix_time());
            self.sign_metadata(&mut metadata)?;
            sync_state.insert_local(&metadata, &fingerprint);
            files.push(LocalFile {
                metadata,
                content: Vec::new(),
                baseline: Some(previous),
            });
        }
        let mut included: BTreeSet<String> = files
            .iter()
            .map(|file| file.metadata.wire_path_string())
            .collect();
        let retained_tombstones: Vec<(String, StateRecord)> = if self.read_only {
            Vec::new()
        } else {
            sync_state
                .entries()
                .filter(|(path, record)| {
                    self.selection.allows_path(path)
                        && record.state == EntryState::Deleted.wire_value() as u8
                        && included.insert((*path).clone())
                })
                .map(|(path, record)| ((*path).clone(), record.clone()))
                .collect()
        };
        for (path, previous) in retained_tombstones {
            let metadata = state_record_metadata(&previous, &path)?;
            files.push(LocalFile {
                metadata,
                content: Vec::new(),
                baseline: Some(previous),
            });
        }
        files.sort_by_key(|left| left.metadata.relative_path.clone());
        sync_state.save()?;
        Ok(files)
    }

    fn has_missing_tracked_path(&self, sync_state: &SyncStateStore) -> Result<bool> {
        if self.read_only {
            return Ok(false);
        }
        for (path, record) in sync_state.entries() {
            if self.selection.allows_path(path)
                && record.state == EntryState::Active.wire_value() as u8
                && !safe_target(&self.root, path)?.exists()
            {
                return Ok(true);
            }
        }
        Ok(false)
    }

    /// Whether file content must travel encrypted to this peer.
    ///
    /// Official client 3.1.2 keeps the folder's ciphertext form on the wire for
    /// *every* peer of an encrypt-capable share: it sends the same encrypted
    /// bytes to a read-only `E` peer (which decrypts them locally) as to an
    /// encrypted-only `F` peer (which stores them verbatim). Sending plaintext
    /// instead made the peer reject the download, because `pieces` inside the
    /// torrent advertises the SHA-1 of the ciphertext. A peer that cannot
    /// advertise a signing key is treated as encrypted-only for the same
    /// reason.
    /// Whether the `data` body sent to this peer carries ciphertext.
    ///
    /// Official client 3.1.2 sends the *plaintext* body to a peer that holds a
    /// content key (a `D`/`E` reader decrypts locally and stores plaintext) and
    /// the *ciphertext* body only to an encrypted-only peer that cannot decrypt
    /// (an `F` reader stores the ciphertext verbatim). Either way `pieces`
    /// describes the ciphertext; see `content_message_for_wire`.
    fn wire_is_encrypted(
        &self,
        remote_public_key: Option<&[u8; 32]>,
        peer_encrypted_only: bool,
    ) -> bool {
        peer_encrypted_only || remote_public_key.is_none_or(crate::protocol::peer_key_cannot_sign)
    }

    fn send_files<S: Read + Write>(
        &self,
        mux: &mut TunnelMux<'_, S>,
        connection_id: u32,
        files: &[LocalFile],
        paths: &[String],
        encrypted_wire: bool,
    ) -> Result<()> {
        // A read-only node only ever publishes the ciphertext relay form, so a
        // plaintext request stays unanswered.
        if self.read_only && !encrypted_wire {
            return Ok(());
        }
        let selected: Vec<&LocalFile> = files
            .iter()
            .filter(|file| {
                let wire_path = if encrypted_wire {
                    file.metadata.protocol_path_string()
                } else {
                    file.metadata.wire_path_string()
                };
                // An encrypted-only peer holds the plaintext tree but not the
                // encrypted names, so it asks for files by their plaintext path
                // while expecting the encrypted wire form back. Accept either
                // name rather than only the one we happen to publish.
                let plain_path = file.metadata.wire_path_string();
                paths.is_empty()
                    || paths.iter().any(|path| {
                        path_matches_request(&wire_path, path)
                            || (encrypted_wire && path_matches_request(&plain_path, path))
                    })
            })
            .collect();
        // While relaying, publish the writer's signed entry verbatim: its
        // `main` is the stored canonical form and its signature already
        // verifies against the writer's public key the peer was told to use.
        // Re-signing here would silently swap in this node's own key.
        if self.read_only && encrypted_wire {
            let relayed = selected
                .iter()
                .map(|file| {
                    let main = file
                        .metadata
                        .main_for_wire(true)
                        .context("relayed entry has no stored wire form")?;
                    let mut fields = BTreeMap::new();
                    if file.metadata.entry_type == EntryType::RegularFile
                        && file.metadata.state == EntryState::Active
                    {
                        fields.insert(
                            b"have".to_vec(),
                            Value::Int(file.metadata.piece_hashes.len() as i64),
                        );
                    }
                    fields.insert(b"main".to_vec(), main);
                    fields.insert(
                        b"sig".to_vec(),
                        Value::bytes(file.metadata.signature.clone()),
                    );
                    Ok(Value::Dict(fields))
                })
                .collect::<Result<Vec<_>>>()?;
            return write_peer_message(
                mux,
                connection_id,
                &Value::dict([
                    (b"files".to_vec(), Value::List(relayed)),
                    (b"m".to_vec(), Value::bytes(b"files")),
                ]),
            );
        }
        let signed = selected
            .iter()
            .map(|file| {
                file.metadata.signed_file_for_wire(
                    encrypted_wire,
                    &self.signing_key,
                    file.metadata.piece_hashes.len() as i64,
                )
            })
            .collect::<Result<Vec<_>>>()?;
        write_peer_message(
            mux,
            connection_id,
            &Value::dict([
                (b"files".to_vec(), Value::List(signed)),
                (b"m".to_vec(), Value::bytes(b"files")),
            ]),
        )
    }

    fn apply_remote_to(
        &self,
        metadata: &FileMetadata,
        torrent: &TorrentMetadata,
        content: &[u8],
        conflict_target: Option<PathBuf>,
        preserve_target: bool,
        sync_state: &mut SyncStateStore,
    ) -> Result<()> {
        let torrent_hash = torrent_file_hash(torrent)?;
        if torrent_hash != metadata.file_hash {
            bail!(
                "torrent identity mismatch for {}: torrent={} metadata={}",
                metadata.wire_path_string(),
                hex::encode(torrent_hash),
                hex::encode(metadata.file_hash)
            );
        }
        let relative = metadata.wire_path_string();
        let target = match conflict_target {
            Some(target) => target,
            None => safe_target(&self.root, &relative)?,
        };
        if preserve_target && target.exists() {
            let unchanged = fs::read(&target)
                .map(|current| current == content)
                .unwrap_or(false);
            if !unchanged {
                self.preserve_conflict_sibling(&target, sync_state)?;
            }
        }
        if let Some(parent) = target.parent() {
            fs::create_dir_all(parent)?;
        }
        let temporary = target.with_file_name(format!(
            ".{}.rustsync-tmp-{}",
            target
                .file_name()
                .and_then(|name| name.to_str())
                .unwrap_or("file"),
            std::process::id()
        ));
        fs::write(&temporary, content).with_context(|| format!("write {}", temporary.display()))?;
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&temporary, fs::Permissions::from_mode(metadata.mode))?;
        filetime::set_file_mtime(
            &temporary,
            filetime::FileTime::from_unix_time(metadata.mtime_seconds, 0),
        )?;
        fs::rename(&temporary, &target).with_context(|| format!("commit {}", target.display()))?;
        if target == safe_target(&self.root, &relative)? {
            sync_state.insert(metadata, &local_fingerprint(metadata));
        } else {
            let conflict_relative = target
                .strip_prefix(&self.root)
                .context("conflict target escaped sync root")?
                .to_string_lossy()
                .replace('\\', "/");
            let mut conflict_metadata =
                FileMetadata::from_path(&target, &conflict_relative, self.identity.peer_id)?;
            conflict_metadata.otime = unix_time();
            conflict_metadata.write_times = 2;
            self.sign_metadata(&mut conflict_metadata)?;
            sync_state.insert_local(&conflict_metadata, &local_fingerprint(&conflict_metadata));
        }
        Ok(())
    }

    fn apply_remote_deletion(
        &self,
        metadata: &FileMetadata,
        local: Option<&LocalFile>,
        sync_state: &mut SyncStateStore,
    ) -> Result<()> {
        let path = metadata.wire_path_string();
        let target = safe_target(&self.root, &path)?;
        let reconciliation = local
            .map(|local| file_reconciliation(metadata, local))
            .unwrap_or(FileReconciliation::RemoteWins);
        match reconciliation {
            FileReconciliation::LocalWins => return Ok(()),
            FileReconciliation::Equal | FileReconciliation::RemoteWins => {
                remove_path(&target)?;
            }
            FileReconciliation::Conflict => self.archive_path(&target, "conflict")?,
        }
        if target.exists() {
            remove_path(&target)?;
        }
        sync_state.insert(metadata, &local_fingerprint(metadata));
        Ok(())
    }

    fn apply_remote_directory(
        &self,
        metadata: &FileMetadata,
        local: Option<&LocalFile>,
        sync_state: &mut SyncStateStore,
    ) -> Result<()> {
        let path = metadata.wire_path_string();
        let target = safe_target(&self.root, &path)?;
        let reconciliation = local
            .map(|entry| file_reconciliation(metadata, entry))
            .unwrap_or(FileReconciliation::RemoteWins);
        if reconciliation == FileReconciliation::LocalWins {
            return Ok(());
        }
        if target.exists() && !target.is_dir() {
            self.preserve_conflict_sibling(&target, sync_state)?;
        }
        fs::create_dir_all(&target).with_context(|| format!("create {}", target.display()))?;
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&target, fs::Permissions::from_mode(metadata.mode))?;
        sync_state.insert(metadata, &local_fingerprint(metadata));
        Ok(())
    }

    fn adopt_remote_metadata(
        &self,
        metadata: &FileMetadata,
        local: &LocalFile,
        sync_state: &mut SyncStateStore,
    ) -> Result<()> {
        if !metadata_wins(metadata, &local.metadata)
            && metadata.metadata_hash() != local.metadata.metadata_hash()
        {
            return Ok(());
        }
        let target = safe_target(&self.root, &metadata.wire_path_string())?;
        if target.exists() {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&target, fs::Permissions::from_mode(metadata.mode))?;
            filetime::set_file_mtime(
                &target,
                filetime::FileTime::from_unix_time(metadata.mtime_seconds, 0),
            )?;
        }
        sync_state.insert(metadata, &local_fingerprint(metadata));
        Ok(())
    }

    fn archive_path(&self, path: &Path, reason: &str) -> Result<()> {
        if !path.exists() {
            return Ok(());
        }
        let archive = self.root.join(".sync").join("Archive");
        fs::create_dir_all(&archive).with_context(|| format!("create {}", archive.display()))?;
        let name = path
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("entry");
        let mut destination = archive.join(format!("{}-{reason}-{name}", unix_time()));
        let mut suffix = 1;
        while destination.exists() {
            destination = archive.join(format!("{}-{reason}-{name}-{suffix}", unix_time()));
            suffix += 1;
        }
        fs::rename(path, &destination)
            .with_context(|| format!("archive {} as {}", path.display(), destination.display()))
    }

    fn preserve_conflict_sibling(
        &self,
        target: &Path,
        sync_state: &mut SyncStateStore,
    ) -> Result<()> {
        if !target.exists() {
            return Ok(());
        }
        let destination = self.next_conflict_path(target)?;
        fs::rename(target, &destination).with_context(|| {
            format!(
                "preserve conflict {} as {}",
                target.display(),
                destination.display()
            )
        })?;
        let relative = destination
            .strip_prefix(&self.root)
            .context("conflict target escaped sync root")?
            .to_string_lossy()
            .replace('\\', "/");
        let mut metadata = if destination.is_dir() {
            FileMetadata::from_directory(
                &destination,
                &relative,
                self.identity.peer_id,
                unix_time(),
            )?
        } else {
            FileMetadata::from_path(&destination, &relative, self.identity.peer_id)?
        };
        metadata.otime = unix_time();
        metadata.write_times = sync_state
            .get(&relative)
            .map(|record| record.write_times + 1)
            .unwrap_or(2);
        self.sign_metadata(&mut metadata)?;
        sync_state.insert_local(&metadata, &local_fingerprint(&metadata));
        sync_state.save()?;
        Ok(())
    }

    fn next_conflict_path(&self, target: &Path) -> Result<PathBuf> {
        let original_name = target
            .file_name()
            .and_then(|name| name.to_str())
            .context("conflict target has no UTF-8 file name")?;
        let parent = target.parent().context("conflict target has no parent")?;
        let mut destination = parent.join(format!("{original_name}.Conflict"));
        let mut suffix = 2;
        while destination.exists() {
            destination = parent.join(format!("{original_name}.Conflict{suffix}"));
            suffix += 1;
        }
        Ok(destination)
    }
}

pub fn random_peer_id() -> [u8; 20] {
    use rand::RngCore;
    let mut value = [0_u8; 20];
    rand::thread_rng().fill_bytes(&mut value);
    value
}

fn random_connection_id() -> u32 {
    use rand::RngCore;
    loop {
        let value = rand::thread_rng().next_u32();
        if value != 0 {
            return value;
        }
    }
}

fn tunnel_check_message(method: &[u8], peer_id: [u8; 20]) -> Value {
    Value::dict([
        (b"encryption_required".to_vec(), Value::Int(1)),
        (b"ifp".to_vec(), Value::Int(100)),
        (b"m".to_vec(), Value::bytes(method)),
        (b"p".to_vec(), Value::bytes(peer_id)),
        (b"v".to_vec(), Value::bytes(b"3.1.2")),
    ])
}

fn exchange_tunnel_check<S: Read + Write>(
    stream: &mut S,
    peer_id: [u8; 20],
    initiator: bool,
) -> Result<()> {
    if initiator {
        write_bencode_frame_uncompressed(
            stream,
            &tunnel_check_message(b"tunnel_connect", peer_id),
        )?;
    }
    let remote = read_bencode_frame(stream)?;
    let expected_method = if initiator {
        b"tunnel_accept".as_slice()
    } else {
        b"tunnel_connect".as_slice()
    };
    let remote_method = remote
        .get(b"m")?
        .as_bytes()
        .context("tunnel check has no method")?;
    if remote_method != expected_method {
        bail!(
            "unexpected tunnel check method {}",
            String::from_utf8_lossy(remote_method)
        );
    }
    validate_tunnel_check(&remote)?;
    if !initiator {
        write_bencode_frame_uncompressed(stream, &tunnel_check_message(b"tunnel_accept", peer_id))?;
    }
    Ok(())
}

fn validate_tunnel_check(message: &Value) -> Result<()> {
    if message.get(b"encryption_required")?.as_int()? != 1 {
        bail!("peer does not require tunnel encryption");
    }
    if message.get(b"ifp")?.as_int()? != 100 {
        bail!("unsupported tunnel interface priority");
    }
    if message.get(b"p")?.as_bytes()?.len() != 20 {
        bail!("tunnel check peer ID is not 20 bytes");
    }
    if message.get(b"v")?.as_bytes()? != b"3.1.2" {
        bail!("unsupported upstream peer protocol version");
    }
    Ok(())
}

fn establish_tunnel<S: Read + Write>(mux: &mut TunnelMux<'_, S>, _initiator: bool) -> Result<u32> {
    mux.open_session()
}

fn write_peer_message<S: Read + Write>(
    mux: &mut TunnelMux<'_, S>,
    connection_id: u32,
    value: &Value,
) -> Result<()> {
    let mut frame = Vec::new();
    write_bencode_frame(&mut frame, value)?;
    mux.send_data(connection_id, &frame)
}

fn write_bit_torrent_message<S: Read + Write>(
    mux: &mut TunnelMux<'_, S>,
    connection_id: u32,
    opcode: u8,
    payload: &[u8],
) -> Result<()> {
    let mut body = Vec::with_capacity(1 + payload.len());
    body.push(opcode);
    body.extend_from_slice(payload);
    let mut frame = Vec::with_capacity(4 + body.len());
    frame.extend_from_slice(&(body.len() as u32).to_be_bytes());
    frame.extend_from_slice(&body);
    mux.send_data(connection_id, &frame)
}

fn wire_frame_length(payload: &[u8]) -> Option<usize> {
    if payload.len() >= DIRECT_TORRENT_MAGIC_V2.len()
        && (payload.starts_with(DIRECT_TORRENT_MAGIC_V2)
            || payload.starts_with(DIRECT_TORRENT_MAGIC_V3))
    {
        if payload.len() == DIRECT_TORRENT_MAGIC_V2.len() {
            return Some(payload.len());
        }
        if payload.len() < DIRECT_TORRENT_MAGIC_V2.len() + 4 {
            return None;
        }
        if payload[DIRECT_TORRENT_MAGIC_V2.len()..DIRECT_TORRENT_MAGIC_V2.len() + 4]
            == DIRECT_TORRENT_MAGIC_V2[..4]
            || payload[DIRECT_TORRENT_MAGIC_V3.len()..DIRECT_TORRENT_MAGIC_V3.len() + 4]
                == DIRECT_TORRENT_MAGIC_V3[..4]
        {
            return Some(DIRECT_TORRENT_MAGIC_V2.len());
        }
    }
    if payload.starts_with(DIRECT_TORRENT_MAGIC_V2) || payload.starts_with(DIRECT_TORRENT_MAGIC_V3)
    {
        if payload.len() < 24 {
            return None;
        }
        let length = u32::from_be_bytes(payload[20..24].try_into().ok()?) as usize;
        return 24usize.checked_add(length);
    }
    if payload.len() < 4 {
        return None;
    }
    let length = u32::from_be_bytes(payload[..4].try_into().ok()?) as usize;
    4usize.checked_add(length)
}

fn take_complete_wire_payloads(buffer: &mut Vec<u8>) -> Result<Vec<WirePayload>> {
    let mut payloads = Vec::new();
    while let Some(length) = wire_frame_length(buffer) {
        if buffer.len() < length {
            break;
        }
        let bytes: Vec<u8> = buffer.drain(..length).collect();
        payloads.push(read_wire_payload_bytes(&bytes)?);
    }
    Ok(payloads)
}

fn write_peer_message_uncompressed<S: Read + Write>(
    mux: &mut TunnelMux<'_, S>,
    connection_id: u32,
    value: &Value,
) -> Result<()> {
    let mut frame = Vec::new();
    write_bencode_frame_uncompressed(&mut frame, value)?;
    mux.send_data(connection_id, &frame)
}

fn send_get_root<S: Read + Write>(
    mux: &mut TunnelMux<'_, S>,
    connection_id: u32,
    root_hash: [u8; 20],
    acl_hash: [u8; 20],
    active_size: u64,
) -> Result<()> {
    write_peer_message(
        mux,
        connection_id,
        &Value::dict([
            (b"acl_hash".to_vec(), Value::bytes(acl_hash)),
            (b"active_size".to_vec(), Value::Int(active_size as i64)),
            (b"exclusive_merge_connection".to_vec(), Value::Int(0)),
            (b"extra".to_vec(), Value::Dict(BTreeMap::new())),
            (b"force_full_merge".to_vec(), Value::Int(0)),
            (b"hash".to_vec(), Value::bytes(root_hash)),
            (b"m".to_vec(), Value::bytes(b"get_root")),
            (b"time".to_vec(), Value::Int(unix_time())),
        ]),
    )
}

fn send_get_files<S: Read + Write>(
    mux: &mut TunnelMux<'_, S>,
    connection_id: u32,
    paths: &BTreeSet<String>,
) -> Result<()> {
    let mut requested = Vec::with_capacity(paths.len());
    for path in paths {
        requested.push(Value::bytes(format!("/{path}//")));
    }
    write_peer_message(
        mux,
        connection_id,
        &Value::dict([
            (b"m".to_vec(), Value::bytes(b"get_files")),
            (b"paths".to_vec(), Value::List(requested)),
        ]),
    )
}

fn root_message(
    root_hash: [u8; 20],
    remote_time: Option<i64>,
    acl_hash: [u8; 20],
    active_size: u64,
) -> Value {
    Value::dict([
        (b"acl_hash".to_vec(), Value::bytes(acl_hash)),
        (b"active_size".to_vec(), Value::Int(active_size as i64)),
        (b"exclusive_merge_connection".to_vec(), Value::Int(0)),
        (b"extra".to_vec(), Value::Dict(BTreeMap::new())),
        (b"force_full_merge".to_vec(), Value::Int(0)),
        (b"hash".to_vec(), Value::bytes(root_hash)),
        (b"m".to_vec(), Value::bytes(b"root")),
        (b"time".to_vec(), Value::Int(unix_time())),
        (
            b"your_time".to_vec(),
            Value::Int(remote_time.unwrap_or_else(unix_time)),
        ),
    ])
}

fn send_get_nodes<S: Read + Write>(
    mux: &mut TunnelMux<'_, S>,
    connection_id: u32,
    paths: &BTreeSet<String>,
) -> Result<()> {
    let mut requested = vec![Value::dict([(b"path".to_vec(), Value::bytes(b"/"))])];
    requested.extend(
        paths
            .iter()
            .map(|path| Value::dict([(b"path".to_vec(), Value::bytes(format!("/{path}")))])),
    );
    write_peer_message(
        mux,
        connection_id,
        &Value::dict([
            (b"m".to_vec(), Value::bytes(b"get_nodes")),
            (b"paths".to_vec(), Value::List(requested)),
        ]),
    )
}

fn nodes_message_many(nodes: BTreeMap<Vec<u8>, Value>, offset: i64) -> Value {
    Value::dict([
        (b"m".to_vec(), Value::bytes(b"nodes")),
        (b"nodes".to_vec(), Value::Dict(nodes)),
        (b"offset".to_vec(), Value::Int(offset)),
    ])
}

fn node_path_key(path: &str) -> Vec<u8> {
    if path.is_empty() || path == "/" {
        b"/".to_vec()
    } else {
        format!("/{path}").into_bytes()
    }
}

fn have_pieces_message(root_hash: [u8; 20], files: &[LocalFile]) -> Value {
    let bitlist = have_pieces_bitlist(files);
    let hash = have_pieces_hash(root_hash, &bitlist);
    Value::dict([
        (b"bitlist".to_vec(), Value::bytes(bitlist)),
        (b"hash".to_vec(), Value::bytes(hash)),
        (b"m".to_vec(), Value::bytes(b"have_pieces")),
        (b"prev_hash".to_vec(), Value::bytes([0_u8; 20])),
    ])
}

fn peer_have_pieces_message(
    root_hash: [u8; 20],
    remote_files: &HashMap<String, FileMetadata>,
    local_files: &[LocalFile],
) -> Result<Value> {
    let mut remote_entries = remote_files.values().cloned().collect::<Vec<_>>();
    remote_entries.sort_by(|left, right| left.relative_path.iter().cmp(right.relative_path.iter()));
    let remote_tree = build_file_tree(&remote_entries)?;
    if remote_tree.root_hash != root_hash {
        bail!(
            "remote tree root mismatch: expected {}, got {}",
            hex::encode(root_hash),
            hex::encode(remote_tree.root_hash)
        );
    }

    let ordered_entries = tree_metadata_entries(&remote_entries)?;
    let bitlist = have_pieces_bitlist_for_tree(&ordered_entries, local_files);
    let hash = have_pieces_hash(root_hash, &bitlist);
    Ok(Value::dict([
        (b"bitlist".to_vec(), Value::bytes(bitlist)),
        (b"hash".to_vec(), Value::bytes(hash)),
        (b"m".to_vec(), Value::bytes(b"have_pieces")),
        (b"prev_hash".to_vec(), Value::bytes([0_u8; 20])),
    ]))
}

fn get_have_pieces_message() -> Value {
    Value::dict([
        (b"m".to_vec(), Value::bytes(b"get_have_pieces")),
        (b"prev_hash".to_vec(), Value::bytes([0_u8; 20])),
    ])
}

fn have_pieces_bitlist(files: &[LocalFile]) -> Vec<u8> {
    files
        .iter()
        .map(|file| {
            let complete = file.metadata.state == EntryState::Active
                && (file.metadata.entry_type == EntryType::Directory
                    || file.metadata.size == file.content.len() as u64);
            if complete {
                1
            } else {
                2
            }
        })
        .collect()
}

fn tree_metadata_entries(entries: &[FileMetadata]) -> Result<Vec<FileMetadata>> {
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

    fn collect(node: &TreeNode, output: &mut Vec<FileMetadata>) {
        if let Some(metadata) = metadata_for_node(node) {
            output.push(metadata.clone());
        }
        for child in node.children.values() {
            collect(child, output);
        }
    }

    let mut root = TreeNode::default();
    for metadata in entries {
        insert(&mut root, metadata)?;
    }
    let mut output = Vec::new();
    for child in root.children.values() {
        collect(child, &mut output);
    }
    Ok(output)
}

fn have_pieces_bitlist_for_tree(entries: &[FileMetadata], local_files: &[LocalFile]) -> Vec<u8> {
    let local_by_path = local_files
        .iter()
        .map(|file| (file.metadata.wire_path_string(), file))
        .collect::<HashMap<_, _>>();
    entries
        .iter()
        .map(|metadata| {
            let complete = local_by_path
                .get(&metadata.wire_path_string())
                .is_some_and(|file| {
                    file.metadata.state == EntryState::Active
                        && file.metadata.entry_type == metadata.entry_type
                        && (metadata.entry_type == EntryType::Directory
                            || file.metadata.size == file.content.len() as u64)
                });
            if complete {
                1
            } else {
                2
            }
        })
        .collect()
}

fn have_pieces_hash(root_hash: [u8; 20], bitlist: &[u8]) -> [u8; 20] {
    if bitlist.is_empty() {
        Sha1::digest([]).into()
    } else {
        let mut input = Vec::with_capacity(root_hash.len() + bitlist.len());
        input.extend_from_slice(&root_hash);
        input.extend_from_slice(bitlist);
        Sha1::digest(input).into()
    }
}

fn piece_bitfield(piece_count: usize) -> Vec<u8> {
    let mut bitfield = vec![0_u8; piece_count.div_ceil(8)];
    for index in 0..piece_count {
        bitfield[index / 8] |= 1_u8 << (7 - index % 8);
    }
    bitfield
}

fn state_notify_message(root_hash: [u8; 20], files: &[LocalFile], acl_hash: [u8; 20]) -> Value {
    let bitlist = have_pieces_bitlist(files);
    Value::dict([
        (b"acl_hash".to_vec(), Value::bytes(acl_hash)),
        (
            b"active_size".to_vec(),
            Value::Int(active_size(files) as i64),
        ),
        (
            b"have_pieces_hash".to_vec(),
            Value::bytes(have_pieces_hash(root_hash, &bitlist)),
        ),
        (b"m".to_vec(), Value::bytes(b"state_notify")),
        (b"tree_hash".to_vec(), Value::bytes(root_hash)),
    ])
}

fn active_size(files: &[LocalFile]) -> u64 {
    files
        .iter()
        .filter(|file| file.metadata.state == EntryState::Active)
        .map(|file| file.metadata.size)
        .sum()
}

fn state_notify_requires_reconcile(
    message: &Value,
    local_root: [u8; 20],
    local_acl_hash: [u8; 20],
) -> Result<bool> {
    let remote_root: [u8; 20] = message
        .get(b"tree_hash")?
        .as_bytes()?
        .try_into()
        .map_err(|_| anyhow::anyhow!("state_notify tree hash is not 20 bytes"))?;
    let remote_acl_hash = message
        .get(b"acl_hash")
        .ok()
        .and_then(|value| value.as_bytes().ok())
        .and_then(|bytes| <[u8; 20]>::try_from(bytes).ok());
    Ok(remote_root != local_root || remote_acl_hash.unwrap_or_else(empty_hash) != local_acl_hash)
}

/// SHA-1 of every 32 KiB piece of `content`.
fn sha1_pieces(content: &[u8]) -> Vec<[u8; 20]> {
    content
        .chunks(PIECE_LENGTH as usize)
        .map(|chunk| Sha1::digest(chunk).into())
        .collect()
}

/// The entries a read-only folder relays, rebuilt from its own stored state.
///
/// Verified against official client 3.1.2: a read-only `E` folder answers an
/// encrypted-only `F` peer with the *writer's* identity and the writer's
/// signed entry forwarded verbatim (its `owner` stays the writer's peer ID and
/// the signature still verifies against the writer's public key, which is
/// public material derived from the writable key). The entries are therefore
/// taken straight from the stored records rather than from a fresh scan, which
/// would re-sign them under this node's own key and be rejected.
fn relay_files(root: &Path, sync_state: &SyncStateStore) -> Vec<LocalFile> {
    let mut files = Vec::new();
    for (path, record) in sync_state.entries() {
        if record.state != EntryState::Active.wire_value() as u8 || record.wire_main.is_none() {
            continue;
        }
        let Ok(mut metadata) = state_record_metadata(record, path) else {
            continue;
        };
        let Ok(target) = safe_target(root, path) else {
            continue;
        };
        let Ok(content) = fs::read(&target) else {
            continue;
        };
        if metadata.entry_type == EntryType::RegularFile {
            metadata.piece_hashes = sha1_pieces(&content);
        }
        files.push(LocalFile {
            metadata,
            content,
            baseline: Some(record.clone()),
        });
    }
    files.sort_by_key(|file| file.metadata.relative_path.clone());
    files
}

fn build_tree(files: &[LocalFile], encrypted: bool) -> Result<FileTree> {
    build_file_tree(
        &files
            .iter()
            .map(|file| {
                let mut metadata = file.metadata.clone();
                if encrypted {
                    metadata.relative_path = metadata
                        .encrypted_path
                        .clone()
                        .unwrap_or(metadata.relative_path);
                } else {
                    metadata.encrypted_path = None;
                    metadata.encrypted_epart = None;
                    metadata.encrypted_main = None;
                }
                metadata
            })
            .collect::<Vec<_>>(),
    )
}

fn top_level_paths(files: &[LocalFile]) -> BTreeSet<String> {
    files
        .iter()
        .filter_map(|file| file.metadata.relative_path.first().cloned())
        .collect()
}

fn changed_local_paths(previous: &[LocalFile], current: &[LocalFile]) -> BTreeSet<String> {
    let previous = previous
        .iter()
        .map(|file| {
            (
                file.metadata.wire_path_string(),
                file.metadata.metadata_hash(),
            )
        })
        .collect::<HashMap<_, _>>();
    let current = current
        .iter()
        .map(|file| {
            (
                file.metadata.wire_path_string(),
                file.metadata.metadata_hash(),
            )
        })
        .collect::<HashMap<_, _>>();
    previous
        .keys()
        .chain(current.keys())
        .filter(|path| previous.get(*path) != current.get(*path))
        .cloned()
        .collect()
}

fn node_top_level_paths(message: &Value) -> Result<BTreeSet<String>> {
    let mut paths = BTreeSet::new();
    for node in message.get(b"nodes")?.as_dict()?.values() {
        let children = node.get(b"children").ok();
        let Some(children) = children else {
            continue;
        };
        for name in children.as_dict()?.keys() {
            let name = String::from_utf8(name.clone()).context("node path is not UTF-8")?;
            if name.is_empty() || name == "." || name == ".." || name == ".sync" {
                bail!("unsafe top-level node path {name}");
            }
            paths.insert(name);
        }
    }
    Ok(paths)
}

fn path_matches_request(file_path: &str, requested_path: &str) -> bool {
    requested_path.is_empty()
        || file_path == requested_path
        || file_path.starts_with(&format!("{requested_path}/"))
}

fn requested_paths(message: &Value) -> Result<Vec<String>> {
    message
        .get(b"paths")?
        .as_list()?
        .iter()
        .map(|value| {
            let raw = value.as_bytes()?;
            let text = String::from_utf8(raw.to_vec())?;
            Ok(text.trim_matches('/').to_owned())
        })
        .collect()
}

fn requested_paths_from_node_request(message: &Value) -> Result<Vec<String>> {
    message
        .get(b"paths")?
        .as_list()?
        .iter()
        .map(|value| {
            let path = value.get(b"path")?.as_bytes()?;
            let text = String::from_utf8(path.to_vec()).context("node path is not UTF-8")?;
            Ok(text.trim_matches('/').to_owned())
        })
        .collect()
}

fn metadata_wins(remote: &FileMetadata, local: &FileMetadata) -> bool {
    write_version_wins(remote, local)
}

fn normalized_write_times(metadata: &FileMetadata) -> i64 {
    metadata.write_times & 0x3
}

fn write_version_wins(remote: &FileMetadata, local: &FileMetadata) -> bool {
    let remote_wire = normalized_write_times(remote);
    let local_wire = normalized_write_times(local);
    // `write_times` only travels as a two-bit wire version, and upstream omits
    // it entirely for entries it did not version. A zero counter therefore
    // means "unknown", not "oldest", so the timestamps have to decide. When
    // both sides do carry a counter, equal wire versions are indistinguishable
    // on the wire and only a differing pair is a real ordering.
    if remote.write_times != local.write_times
        && remote.write_times != 0
        && local.write_times != 0
        && remote_wire != local_wire
        && remote.owner == local.owner
    {
        return remote.write_times > local.write_times;
    }
    (remote.time_seconds, remote.otime, &remote.owner)
        > (local.time_seconds, local.otime, &local.owner)
}

fn file_reconciliation(remote: &FileMetadata, local: &LocalFile) -> FileReconciliation {
    if remote.entry_type != local.metadata.entry_type {
        return FileReconciliation::Conflict;
    }
    if remote.state == EntryState::Deleted
        && local.metadata.state == EntryState::Deleted
        && remote.file_hash == local.metadata.file_hash
    {
        return FileReconciliation::Equal;
    }
    if local.metadata.state == EntryState::Deleted
        && remote.state == EntryState::Active
        && remote.file_hash == local.metadata.file_hash
    {
        if metadata_wins(remote, &local.metadata) {
            return FileReconciliation::RemoteWins;
        }
        return FileReconciliation::LocalWins;
    }
    if remote.state == EntryState::Deleted
        && local.metadata.state == EntryState::Active
        && remote.file_hash == local.metadata.file_hash
    {
        return if metadata_wins(remote, &local.metadata) {
            FileReconciliation::RemoteWins
        } else {
            FileReconciliation::LocalWins
        };
    }
    if remote.metadata_hash() == local.metadata.metadata_hash() {
        return FileReconciliation::Equal;
    }
    if remote.state == EntryState::Active
        && local.metadata.state == EntryState::Active
        && remote.owner == local.metadata.owner
        && remote.write_times != local.metadata.write_times
    {
        return if write_version_wins(remote, &local.metadata) {
            FileReconciliation::RemoteWins
        } else {
            FileReconciliation::LocalWins
        };
    }
    let current_fingerprint = local_fingerprint(&local.metadata);
    let Some(record) = local.baseline.as_ref() else {
        return FileReconciliation::Conflict;
    };
    let local_recreated = record.state == EntryState::Deleted.wire_value() as u8
        && local.metadata.state == EntryState::Active;
    let remote_recreated = record.state == EntryState::Deleted.wire_value() as u8
        && local.metadata.state == EntryState::Deleted
        && remote.state == EntryState::Active;
    if remote_recreated {
        return FileReconciliation::RemoteWins;
    }
    if local_recreated {
        return if metadata_wins(remote, &local.metadata) {
            FileReconciliation::RemoteWins
        } else if metadata_wins(&local.metadata, remote) {
            FileReconciliation::LocalWins
        } else {
            FileReconciliation::Conflict
        };
    }
    let baseline_metadata_hash = if record.sync_metadata_hash.is_empty() {
        &record.metadata_hash
    } else {
        &record.sync_metadata_hash
    };
    let sync_fingerprint = if record.sync_fingerprint.is_empty() {
        &record.local_fingerprint
    } else {
        &record.sync_fingerprint
    };
    let sync_file_hash = if record.sync_file_hash.is_empty() {
        &record.file_hash
    } else {
        &record.sync_file_hash
    };
    let local_unchanged = *sync_fingerprint == current_fingerprint
        && *sync_file_hash == hex::encode(local.metadata.file_hash)
        && *baseline_metadata_hash == hex::encode(local.metadata.metadata_hash());
    let remote_unchanged = *sync_file_hash == hex::encode(remote.file_hash)
        && *baseline_metadata_hash == hex::encode(remote.metadata_hash());
    if local_unchanged {
        FileReconciliation::RemoteWins
    } else if remote_unchanged {
        FileReconciliation::LocalWins
    } else {
        FileReconciliation::Conflict
    }
}

fn remove_path(path: &Path) -> Result<()> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error).with_context(|| format!("stat {}", path.display())),
    };
    if metadata.is_dir() {
        fs::remove_dir_all(path).with_context(|| format!("remove {}", path.display()))
    } else {
        fs::remove_file(path).with_context(|| format!("remove {}", path.display()))
    }
}

fn torrent_file_hash(torrent: &TorrentMetadata) -> Result<[u8; 20]> {
    torrent.file_hash()
}

fn safe_target(root: &Path, relative: &str) -> Result<PathBuf> {
    if relative.is_empty()
        || relative.starts_with('/')
        || relative
            .split('/')
            .any(|part| part.is_empty() || part == "." || part == ".." || part == ".sync")
    {
        bail!("unsafe remote file path {relative}");
    }
    Ok(root.join(relative))
}

fn collect_files(
    root: &Path,
    current: &Path,
    selection: &SyncSelection,
    output: &mut Vec<String>,
) -> Result<()> {
    for item in fs::read_dir(current).with_context(|| format!("read {}", current.display()))? {
        let item = item?;
        let path = item.path();
        let name = item.file_name();
        if name == ".sync" {
            continue;
        }
        if item.file_type()?.is_symlink() {
            bail!("symlinks are not supported: {}", path.display());
        }
        let metadata = fs::symlink_metadata(&path)?;
        let relative = path
            .strip_prefix(root)?
            .to_string_lossy()
            .replace('\\', "/");
        if metadata.is_dir() {
            if !selection.allows_traversal(&relative, true) {
                continue;
            }
            if selection.allows_path(&relative) {
                output.push(relative);
            }
            collect_files(root, &path, selection, output)?;
        } else if metadata.is_file() && selection.allows_path(&relative) {
            output.push(relative);
        }
    }
    Ok(())
}

fn decode_owner(value: &str) -> [u8; 20] {
    hex::decode(value)
        .ok()
        .and_then(|value| value.try_into().ok())
        .unwrap_or([0_u8; 20])
}

fn state_record_metadata(record: &StateRecord, path: &str) -> Result<FileMetadata> {
    let entry_type = match record.entry_type {
        1 => EntryType::RegularFile,
        2 => EntryType::Directory,
        value => bail!("unsupported stored entry type {value}"),
    };
    let state = match record.state {
        1 => EntryState::Active,
        2 => EntryState::Deleted,
        value => bail!("unsupported stored entry state {value}"),
    };
    let file_hash: [u8; 20] = hex::decode(&record.file_hash)
        .context("decode stored file hash")?
        .try_into()
        .map_err(|_| anyhow::anyhow!("stored file hash is not 20 bytes"))?;
    let mut metadata = FileMetadata {
        relative_path: path.split('/').map(str::to_owned).collect(),
        entry_type,
        size: record.size,
        mode: record.perm,
        mtime_seconds: record.mtime,
        time_seconds: record.time,
        state,
        file_hash,
        piece_count: record.npieces,
        piece_hashes: Vec::new(),
        random_prefix: Vec::new(),
        owner: decode_owner(&record.owner),
        otime: record.otime,
        write_times: record.write_times,
        signature: hex::decode(&record.signature).unwrap_or_default(),
        encrypted_path: None,
        encrypted_epart: None,
        encrypted_main: None,
    };
    if let Some(encoded) = &record.wire_main {
        let main = decode(&hex::decode(encoded).context("decode stored encrypted main")?)
            .context("parse stored encrypted main")?;
        metadata
            .restore_encrypted_main(main)
            .context("restore stored encrypted main")?;
    }
    Ok(metadata)
}

/// The Ed25519 identity of a peer whose share key carries no seed.
///
/// Stored next to the sync state so the same `pk` is advertised on every run:
/// a rotating identity would invalidate the metadata this peer published
/// earlier. The file holds a raw 32-byte seed and is created on first use.
fn persistent_identity_key(root: &Path) -> SigningKey {
    let path = root.join(".sync").join("rustsync-identity.key");
    if let Ok(bytes) = fs::read(&path) {
        if let Ok(seed) = <[u8; 32]>::try_from(bytes.as_slice()) {
            return SigningKey::from_bytes(&seed);
        }
    }
    let mut seed = [0_u8; 32];
    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut seed);
    let key = SigningKey::from_bytes(&seed);
    if let Some(parent) = path.parent() {
        let _ = fs::create_dir_all(parent);
    }
    let _ = fs::write(&path, seed);
    key
}

fn unix_time() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

fn next_local_otime(previous_otime: i64) -> i64 {
    unix_time().max(previous_otime.saturating_add(1))
}

fn is_timeout(error: &anyhow::Error) -> bool {
    error.chain().any(|cause| {
        cause.downcast_ref::<std::io::Error>().is_some_and(|error| {
            error.kind() == std::io::ErrorKind::WouldBlock
                || error.kind() == std::io::ErrorKind::TimedOut
        })
    })
}

fn is_clean_tunnel_eof(error: &anyhow::Error) -> bool {
    error.downcast_ref::<std::io::Error>().is_some_and(|error| {
        error.kind() == std::io::ErrorKind::UnexpectedEof
            && error.to_string() == TUNNEL_EOF_AT_FRAME_BOUNDARY
    })
}

fn stable_peer_id(key: &ShareKey, device_name: &str) -> [u8; 20] {
    let mut hasher = Sha1::new();
    hasher.update(b"rustsync peer id\0");
    hasher.update(key.share_id());
    hasher.update(device_name.as_bytes());
    hasher.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::{parse_torrent_info, verify_file_signature, EntryState, TorrentMetadata};
    use tempfile::tempdir;

    fn test_sync(root: &Path) -> SyncNode {
        let key =
            ShareKey::parse(&format!("A{}", crate::secret::encode_base32(&[7_u8; 20]))).unwrap();
        SyncNode::new(root, key, "compat-test").unwrap()
    }

    #[test]
    fn read_only_share_key_constructs_a_non_signing_sync_node() {
        let root = tempdir().unwrap();
        let key = ShareKey::generate_read_write()
            .read_only_link_key()
            .unwrap();
        // The share key itself carries no Ed25519 seed, so it can never sign.
        assert!(key.ed25519_signing_key().is_err());
        let sync = SyncNode::new(root.path(), key, "read-only-test").unwrap();
        assert!(sync.read_only);
        // The node still advertises a real, non-zero `pk`: the official
        // read-only peer does the same, and a relayed entry is verified against
        // exactly that advertised key. Advertising the zero key instead made
        // every relay look like `bad signature` to the receiving peer.
        let advertised = sync
            .metadata_public_key
            .expect("read-only node advertises a pk");
        assert_ne!(advertised, [0_u8; 32]);
        assert_eq!(advertised, sync.identity.identity_key);
    }

    #[test]
    fn read_only_identity_is_stable_across_nodes() {
        // A rotating identity would invalidate metadata this peer published
        // earlier, so the same root must reuse the same `pk` across restarts.
        let root = tempdir().unwrap();
        let key = ShareKey::generate_read_write()
            .read_only_link_key()
            .unwrap();
        let first = SyncNode::new(root.path(), key.clone(), "stable-test").unwrap();
        let second = SyncNode::new(root.path(), key, "stable-test").unwrap();
        assert_eq!(
            first.metadata_public_key, second.metadata_public_key,
            "the read-only identity must persist across runs"
        );
    }

    fn remote_metadata(relative: &str, content: &[u8]) -> (FileMetadata, TorrentMetadata) {
        let source = tempfile::NamedTempFile::new().unwrap();
        fs::write(source.path(), content).unwrap();
        let mut metadata = FileMetadata::from_path(source.path(), relative, [4_u8; 20]).unwrap();
        metadata.otime = 700;
        metadata.write_times = 3;
        metadata.sign(&SigningKey::from_bytes(&[9_u8; 32])).unwrap();
        let torrent = parse_torrent_info(&metadata.torrent_info()).unwrap();
        (metadata, torrent)
    }

    fn remote_directory_metadata(relative: &str) -> FileMetadata {
        let source = tempdir().unwrap();
        FileMetadata::from_directory(source.path(), relative, [4_u8; 20], 700).unwrap()
    }

    fn establish_base(
        sync: &SyncNode,
        state: &mut SyncStateStore,
        name: &str,
        content: &[u8],
    ) -> FileMetadata {
        fs::write(sync.root.join(name), content).unwrap();
        let metadata = sync
            .scan_files(state)
            .unwrap()
            .into_iter()
            .find(|file| file.metadata.wire_path_string() == name)
            .unwrap()
            .metadata;
        state.insert(&metadata, &local_fingerprint(&metadata));
        state.save().unwrap();
        metadata
    }

    fn local_file_from_bytes(
        root: &Path,
        name: &str,
        content: &[u8],
        baseline: Option<StateRecord>,
    ) -> LocalFile {
        let path = root.join(name);
        fs::write(&path, content).unwrap();
        let metadata = FileMetadata::from_path(&path, name, [3_u8; 20]).unwrap();
        LocalFile {
            metadata,
            content: content.to_vec(),
            baseline,
        }
    }

    fn local_file_from_metadata(metadata: FileMetadata, content: Vec<u8>) -> LocalFile {
        LocalFile {
            metadata,
            content,
            baseline: None,
        }
    }

    fn hash_from_hex(value: &str) -> [u8; 20] {
        hex::decode(value).unwrap().try_into().unwrap()
    }

    #[test]
    fn direct_request_accepts_signature_from_advertised_remote_metadata() {
        let root = tempdir().unwrap();
        let sync = test_sync(root.path());
        let mut local = local_file_from_bytes(root.path(), "conflict.bin", b"same", None).metadata;
        local.sign(&sync.signing_key).unwrap();

        let mut remote = local.clone();
        remote.otime += 1;
        remote.write_times += 1;
        remote.sign(&sync.signing_key).unwrap();
        assert_ne!(local.signature, remote.signature);

        let remote_files = HashMap::from([(remote.wire_path_string(), remote.clone())]);
        let info_hash = local.info_hash_for_wire(&sync.identity.share_id, false);

        assert!(sync
            .direct_request_signature_matches(
                &remote.signature,
                &info_hash,
                "conflict.bin",
                &local,
                &remote_files,
            )
            .unwrap());
        assert!(sync
            .direct_request_signature_matches(
                &local.signature,
                &info_hash,
                "conflict.bin",
                &local,
                &remote_files,
            )
            .unwrap());
        assert!(!sync
            .direct_request_signature_matches(
                &[0_u8; 64],
                &info_hash,
                "conflict.bin",
                &local,
                &remote_files,
            )
            .unwrap());
        assert!(!sync
            .direct_request_signature_matches(
                &remote.signature,
                &[0_u8; 20],
                "conflict.bin",
                &local,
                &remote_files,
            )
            .unwrap());
    }

    #[test]
    fn concatenated_direct_handshake_and_login_are_both_consumed() {
        let login = crate::protocol::encode_direct_torrent(&Value::dict([
            (b"f".to_vec(), Value::bytes("file")),
            (b"i".to_vec(), Value::bytes([1_u8; 20])),
            (b"sig".to_vec(), Value::bytes([2_u8; 64])),
        ]))
        .unwrap();
        let mut wire = DIRECT_TORRENT_MAGIC_V2.to_vec();
        wire.extend_from_slice(&login);
        let payloads = take_complete_wire_payloads(&mut wire).unwrap();
        assert!(wire.is_empty());
        assert_eq!(
            payloads,
            vec![
                WirePayload::DirectHandshake(DIRECT_TORRENT_MAGIC_V2.try_into().unwrap()),
                WirePayload::Direct(login),
            ]
        );
    }

    #[test]
    fn have_pieces_uses_per_file_status_and_tree_root() {
        let root = tempdir().unwrap();
        fs::write(root.path().join("present"), b"x").unwrap();
        let present =
            FileMetadata::from_path(&root.path().join("present"), "present", [3; 20]).unwrap();
        let missing =
            FileMetadata::from_path(&root.path().join("present"), "missing", [3; 20]).unwrap();
        let deleted = missing.tombstone(10);
        let directory =
            FileMetadata::from_directory(root.path(), "directory", [3; 20], 10).unwrap();
        let files = vec![
            local_file_from_metadata(directory, Vec::new()),
            local_file_from_metadata(present, b"x".to_vec()),
            local_file_from_metadata(missing, Vec::new()),
            local_file_from_metadata(deleted, Vec::new()),
        ];
        assert_eq!(have_pieces_bitlist(&files), vec![1, 1, 2, 2]);

        let root_hash = hash_from_hex("2ac82ab802e3c38591e965910354a54f1f2f1cca");
        assert_eq!(
            have_pieces_hash(root_hash, &[1, 2, 2]),
            hash_from_hex("99bceb78a48ea461656fb87756aeb1cf7be70111")
        );
    }

    #[test]
    fn have_pieces_includes_directories_and_empty_files() {
        let root = tempdir().unwrap();
        fs::create_dir(root.path().join("nested")).unwrap();
        fs::write(root.path().join("nested/empty.bin"), b"").unwrap();
        let directory =
            FileMetadata::from_directory(&root.path().join("nested"), "nested", [3; 20], 10)
                .unwrap();
        let empty = FileMetadata::from_path(
            &root.path().join("nested/empty.bin"),
            "nested/empty.bin",
            [3; 20],
        )
        .unwrap();
        let missing = FileMetadata::from_path(
            &root.path().join("nested/empty.bin"),
            "nested/missing.bin",
            [3; 20],
        )
        .unwrap();
        let deleted = missing.tombstone(20);
        let files = vec![
            local_file_from_metadata(directory, Vec::new()),
            local_file_from_metadata(empty, Vec::new()),
            local_file_from_metadata(missing, b"x".to_vec()),
            local_file_from_metadata(deleted, Vec::new()),
        ];
        assert_eq!(have_pieces_bitlist(&files), vec![1, 1, 2, 2]);
    }

    #[test]
    fn scan_files_orders_nodes_like_component_wise_tree_walk() {
        let root = tempdir().unwrap();
        fs::create_dir(root.path().join("a")).unwrap();
        fs::write(root.path().join("a/b"), b"nested").unwrap();
        fs::write(root.path().join("a.txt"), b"top").unwrap();

        let files = test_sync(root.path())
            .scan_files(&mut SyncStateStore::load(root.path()).unwrap())
            .unwrap();

        assert_eq!(
            files
                .iter()
                .map(|file| file.metadata.wire_path_string())
                .collect::<Vec<_>>(),
            vec!["a", "a/b", "a.txt"]
        );
    }

    #[test]
    fn selection_does_not_tombstone_unselected_tracked_paths() {
        let root = tempdir().unwrap();
        let included = root.path().join("included.txt");
        let ignored = root.path().join("ignored.txt");
        fs::write(&included, b"included").unwrap();
        fs::write(&ignored, b"ignored").unwrap();
        let selection = SyncSelection::new(Vec::<String>::new(), ["ignored.txt"]).unwrap();
        let sync = test_sync(root.path()).with_selection(selection);
        let mut state = SyncStateStore::load(root.path()).unwrap();
        for (path, absolute) in [
            ("included.txt", included.as_path()),
            ("ignored.txt", ignored.as_path()),
        ] {
            let mut metadata =
                FileMetadata::from_path(absolute, path, sync.identity.peer_id).unwrap();
            metadata.sign(&sync.signing_key).unwrap();
            let fingerprint = local_fingerprint(&metadata);
            state.insert_local(&metadata, &fingerprint);
        }
        state.save().unwrap();
        drop(state);
        fs::remove_file(included).unwrap();
        fs::remove_file(ignored).unwrap();

        let files = sync
            .scan_files(&mut SyncStateStore::load(root.path()).unwrap())
            .unwrap();
        let paths = files
            .iter()
            .map(|file| file.metadata.wire_path_string())
            .collect::<Vec<_>>();
        assert!(paths.contains(&"included.txt".to_owned()));
        assert!(!paths.contains(&"ignored.txt".to_owned()));
    }

    #[test]
    fn have_pieces_hash_matches_empty_and_single_file_vectors() {
        assert_eq!(
            have_pieces_hash([0; 20], &[]),
            hash_from_hex("da39a3ee5e6b4b0d3255bfef95601890afd80709")
        );
        let root_hash = hash_from_hex("83fc92028111bd27121027558ed5d1b79e06ab6c");
        assert_eq!(
            have_pieces_hash(root_hash, &[1]),
            hash_from_hex("b4123ce099bbefee3dd7317bb9233e1df02ed849")
        );
    }

    #[test]
    fn changed_local_paths_tracks_content_and_type_changes() {
        let (old_metadata, _) = remote_metadata("changed.bin", b"old");
        let (new_metadata, _) = remote_metadata("changed.bin", b"new");
        let directory_metadata = remote_directory_metadata("type-change");
        let (removed_metadata, _) = remote_metadata("removed.bin", b"removed");
        let previous = vec![
            local_file_from_metadata(old_metadata, b"old".to_vec()),
            local_file_from_metadata(removed_metadata, b"removed".to_vec()),
        ];
        let current = vec![
            local_file_from_metadata(new_metadata, b"new".to_vec()),
            local_file_from_metadata(directory_metadata, Vec::new()),
        ];

        assert_eq!(
            changed_local_paths(&previous, &current),
            BTreeSet::from([
                "changed.bin".to_owned(),
                "removed.bin".to_owned(),
                "type-change".to_owned(),
            ])
        );
    }

    #[test]
    fn get_have_pieces_uses_zero_previous_hash() {
        let message = get_have_pieces_message();
        assert_eq!(
            message.get(b"m").unwrap().as_bytes().unwrap(),
            b"get_have_pieces"
        );
        assert_eq!(
            message.get(b"prev_hash").unwrap().as_bytes().unwrap(),
            [0_u8; 20]
        );
    }

    #[test]
    fn changed_state_notify_reconciles_even_during_pending_requests() {
        let local_root = [1_u8; 20];
        let remote_root = [2_u8; 20];
        let unchanged = state_notify_message(local_root, &[], empty_hash());
        let changed = state_notify_message(remote_root, &[], empty_hash());
        let acl_changed = state_notify_message(local_root, &[], [3_u8; 20]);

        assert!(!state_notify_requires_reconcile(&unchanged, local_root, empty_hash()).unwrap());
        assert!(state_notify_requires_reconcile(&changed, local_root, empty_hash()).unwrap());
        assert!(state_notify_requires_reconcile(&acl_changed, local_root, empty_hash()).unwrap());
    }

    #[test]
    fn acl_state_hash_is_carried_by_sync_node() {
        let root = tempdir().unwrap();
        let mut acl = AclState::default();
        acl.insert(crate::acl::AclEntry::new(
            1, 10, 1, [1_u8; 20], 11, [2_u8; 20],
        ));
        let expected = acl.hash();
        let sync = test_sync(root.path()).with_acl_state(acl.clone());

        assert_eq!(sync.acl_state(), &acl);
        assert_eq!(sync.acl_hash, expected);
    }

    #[test]
    fn upstream_merge_messages_include_acl_and_merge_fields() {
        let message = root_message([4_u8; 20], Some(99), [5_u8; 20], 123);
        assert_eq!(message.get(b"m").unwrap().as_bytes().unwrap(), b"root");
        assert_eq!(
            message.get(b"acl_hash").unwrap().as_bytes().unwrap(),
            [5_u8; 20]
        );
        assert_eq!(message.get(b"active_size").unwrap().as_int().unwrap(), 123);
        assert_eq!(
            message
                .get(b"exclusive_merge_connection")
                .unwrap()
                .as_int()
                .unwrap(),
            0
        );

        let notify = state_notify_message([4_u8; 20], &[], [5_u8; 20]);
        assert_eq!(
            notify.get(b"acl_hash").unwrap().as_bytes().unwrap(),
            [5_u8; 20]
        );
        assert_eq!(notify.get(b"active_size").unwrap().as_int().unwrap(), 0);
    }

    fn baseline_record(metadata: &FileMetadata) -> StateRecord {
        StateRecord {
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
            file_hash: hex::encode(metadata.file_hash),
            signature: hex::encode(&metadata.signature),
            local_fingerprint: local_fingerprint(metadata),
            sync_file_hash: hex::encode(metadata.file_hash),
            sync_fingerprint: local_fingerprint(metadata),
            sync_metadata_hash: hex::encode(metadata.metadata_hash()),
            wire_main: metadata
                .encrypted_main
                .as_ref()
                .map(|main| hex::encode(encode(main))),
        }
    }

    #[test]
    fn read_only_node_relays_the_writers_signed_entry() {
        // A read-only `E` folder holds no Ed25519 seed, so it cannot sign the
        // entries it relays. Verified against official client 3.1.2: it answers
        // an encrypted-only `F` peer with the *writer's* signed entry forwarded
        // verbatim. This test pins that behaviour at the unit level.
        let root = tempdir().unwrap();
        let writer_key = ShareKey::generate_encrypt_capable_read_write();
        let writer_signing = writer_key.ed25519_signing_key().unwrap();
        let writer_public = writer_key.ed25519_public_key().unwrap();
        let content = b"relay-payload".repeat(40);
        fs::write(root.path().join("relay.bin"), &content).unwrap();

        let mut metadata =
            FileMetadata::from_path(&root.path().join("relay.bin"), "relay.bin", [0x21; 20])
                .unwrap();
        metadata
            .prepare_encrypted_with_content(&writer_key, &content)
            .unwrap();
        metadata.sign(&writer_signing).unwrap();
        let writer_signature = metadata.signature.clone();
        let writer_main = metadata.main();
        assert!(metadata.encrypted_main.is_some());
        assert!(!writer_signature.is_empty());

        let mut state = SyncStateStore::load(root.path()).unwrap();
        state.insert_local(&metadata, &local_fingerprint(&metadata));
        state.save().unwrap();
        // The store holds an exclusive lock while open, so it must be released
        // before the node reopens the same state file.
        drop(state);

        let read_only = SyncNode::new(
            root.path(),
            writer_key.read_only_link_key().unwrap(),
            "relay-test",
        )
        .unwrap();
        assert!(read_only.read_only);

        // A rescan must keep the writer's canonical form and signature instead
        // of re-signing the entry under this node's own identity.
        let mut state = SyncStateStore::load(root.path()).unwrap();
        let files = read_only.scan_files(&mut state).unwrap();
        let scanned = files
            .iter()
            .find(|file| file.metadata.wire_path_string() == "relay.bin")
            .expect("relay file is scanned");
        assert_eq!(scanned.metadata.signature, writer_signature);
        assert_eq!(scanned.metadata.encrypted_main.as_ref(), Some(&writer_main));
        verify_file_signature(
            &writer_public,
            &scanned.metadata.main(),
            &scanned.metadata.signature,
        )
        .unwrap();

        // The relayed entry handed to the peer carries the same signature and
        // still verifies against the writer's public key.
        let relayed = relay_files(root.path(), &state);
        let entry = relayed
            .iter()
            .find(|file| file.metadata.wire_path_string() == "relay.bin")
            .expect("relay entry is rebuilt from stored state");
        assert_eq!(entry.metadata.signature, writer_signature);
        assert_eq!(entry.metadata.encrypted_main.as_ref(), Some(&writer_main));
        verify_file_signature(
            &writer_public,
            &entry.metadata.main(),
            &entry.metadata.signature,
        )
        .unwrap();
    }

    #[test]
    fn read_only_node_without_a_stored_writer_form_signs_itself() {
        // Without a stored canonical form there is nothing to relay, so the
        // node signs the entry under its own persistent identity rather than
        // publishing an unsigned object.
        let root = tempdir().unwrap();
        let writer_key = ShareKey::generate_encrypt_capable_read_write();
        let content = b"fresh-read-only-content";
        fs::write(root.path().join("fresh.bin"), content).unwrap();

        let read_only = SyncNode::new(
            root.path(),
            writer_key.read_only_link_key().unwrap(),
            "relay-fresh",
        )
        .unwrap();
        let mut state = SyncStateStore::load(root.path()).unwrap();
        let files = read_only.scan_files(&mut state).unwrap();
        let scanned = files
            .iter()
            .find(|file| file.metadata.wire_path_string() == "fresh.bin")
            .expect("fresh file is scanned");
        assert!(!scanned.metadata.signature.is_empty());
        assert!(scanned.metadata.encrypted_main.is_some());
        verify_file_signature(
            &read_only.identity.identity_key,
            &scanned.metadata.main(),
            &scanned.metadata.signature,
        )
        .unwrap();
    }

    #[test]
    fn local_create_update_delete_and_recreation_are_tracked() {
        let root = tempdir().unwrap();
        let sync = test_sync(root.path());
        let mut state = SyncStateStore::load(root.path()).unwrap();
        assert!(sync.scan_files(&mut state).unwrap().is_empty());

        fs::write(root.path().join("file.txt"), b"created").unwrap();
        let created = sync
            .scan_files(&mut state)
            .unwrap()
            .into_iter()
            .next()
            .unwrap();
        assert_eq!(created.metadata.state, EntryState::Active);
        assert_eq!(created.metadata.wire_path_string(), "file.txt");
        let base = created.metadata.clone();
        state.insert(&base, &local_fingerprint(&base));
        state.save().unwrap();

        fs::write(root.path().join("file.txt"), b"updated").unwrap();
        let updated = sync
            .scan_files(&mut state)
            .unwrap()
            .into_iter()
            .next()
            .unwrap();
        assert_ne!(updated.metadata.file_hash, base.file_hash);
        assert_eq!(
            file_reconciliation(&base, &updated),
            FileReconciliation::LocalWins
        );

        fs::remove_file(root.path().join("file.txt")).unwrap();
        let deleted = sync
            .scan_files(&mut state)
            .unwrap()
            .into_iter()
            .next()
            .unwrap();
        assert_eq!(deleted.metadata.state, EntryState::Deleted);
        assert_eq!(
            deleted.metadata.write_times,
            updated.metadata.write_times + 1
        );
        assert_eq!(
            file_reconciliation(&updated.metadata, &deleted),
            FileReconciliation::LocalWins
        );
        let retained = sync.scan_files(&mut state).unwrap();
        assert_eq!(retained.len(), 1);
        assert_eq!(retained[0].metadata.state, EntryState::Deleted);

        fs::write(root.path().join("file.txt"), b"recreated").unwrap();
        let recreated = sync
            .scan_files(&mut state)
            .unwrap()
            .into_iter()
            .next()
            .unwrap();
        assert_eq!(recreated.metadata.state, EntryState::Active);
        assert_eq!(
            recreated.metadata.write_times,
            deleted.metadata.write_times + 1
        );
        assert_ne!(recreated.metadata.file_hash, deleted.metadata.file_hash);
        assert_eq!(
            file_reconciliation(&base, &recreated),
            FileReconciliation::LocalWins
        );
    }

    #[test]
    fn local_metadata_updates_keep_otime_monotonic_after_future_mtime() {
        let root = tempdir().unwrap();
        let sync = test_sync(root.path());
        let mut state = SyncStateStore::load(root.path()).unwrap();
        let target = root.path().join("metadata.txt");
        let future_mtime = 2_000_000_000_i64;
        fs::write(&target, b"first").unwrap();
        filetime::set_file_mtime(&target, filetime::FileTime::from_unix_time(future_mtime, 0))
            .unwrap();

        let first = sync
            .scan_files(&mut state)
            .unwrap()
            .into_iter()
            .next()
            .unwrap();
        assert_eq!(first.metadata.mtime_seconds, future_mtime);

        fs::write(&target, b"second").unwrap();
        filetime::set_file_mtime(
            &target,
            filetime::FileTime::from_unix_time(future_mtime - 100, 0),
        )
        .unwrap();
        let second = sync
            .scan_files(&mut state)
            .unwrap()
            .into_iter()
            .next()
            .unwrap();

        assert!(second.metadata.otime > first.metadata.otime);
        assert!(metadata_wins(&second.metadata, &first.metadata));
        assert_eq!(
            file_reconciliation(&first.metadata, &second),
            FileReconciliation::LocalWins
        );
    }

    #[test]
    fn same_content_metadata_update_is_applied_without_replacing_content() {
        let root = tempdir().unwrap();
        let sync = test_sync(root.path());
        let mut state = SyncStateStore::load(root.path()).unwrap();
        let base = establish_base(&sync, &mut state, "metadata.txt", b"unchanged");
        let local = sync
            .scan_files(&mut state)
            .unwrap()
            .into_iter()
            .find(|file| file.metadata.wire_path_string() == "metadata.txt")
            .unwrap();
        let mut remote = base;
        remote.mode = 0o640;
        remote.mtime_seconds = 1_900_000_000;
        remote.time_seconds = 1_900_000_001;
        remote.write_times += 1;
        remote.sign(&SigningKey::from_bytes(&[9_u8; 32])).unwrap();

        assert_eq!(remote.file_hash, local.metadata.file_hash);
        assert_ne!(remote.metadata_hash(), local.metadata.metadata_hash());
        sync.adopt_remote_metadata(&remote, &local, &mut state)
            .unwrap();

        let target = root.path().join("metadata.txt");
        assert_eq!(fs::read(&target).unwrap(), b"unchanged");
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            fs::metadata(&target).unwrap().permissions().mode() & 0o7777,
            remote.mode
        );
        assert_eq!(
            filetime::FileTime::from_last_modification_time(&fs::metadata(&target).unwrap())
                .unix_seconds(),
            remote.mtime_seconds
        );
        let record = state.get("metadata.txt").unwrap();
        assert_eq!(
            record.sync_metadata_hash,
            hex::encode(remote.metadata_hash())
        );
        assert_eq!(record.sync_file_hash, hex::encode(remote.file_hash));
    }

    #[test]
    fn same_content_directory_metadata_update_is_applied_without_replacing_children() {
        let root = tempdir().unwrap();
        let sync = test_sync(root.path());
        let mut state = SyncStateStore::load(root.path()).unwrap();
        let directory = root.path().join("metadata-dir");
        fs::create_dir(&directory).unwrap();
        fs::write(directory.join("child.txt"), b"unchanged-child").unwrap();
        let local = sync
            .scan_files(&mut state)
            .unwrap()
            .into_iter()
            .find(|file| file.metadata.wire_path_string() == "metadata-dir")
            .unwrap();
        let mut remote = local.metadata.clone();
        remote.mode = 0o700;
        remote.mtime_seconds = 1_900_000_010;
        remote.time_seconds = 1_900_000_011;
        remote.write_times += 1;
        remote.sign(&SigningKey::from_bytes(&[9_u8; 32])).unwrap();

        assert_eq!(remote.file_hash, local.metadata.file_hash);
        assert_ne!(remote.metadata_hash(), local.metadata.metadata_hash());
        sync.adopt_remote_metadata(&remote, &local, &mut state)
            .unwrap();

        assert_eq!(
            fs::read(directory.join("child.txt")).unwrap(),
            b"unchanged-child"
        );
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            fs::metadata(&directory).unwrap().permissions().mode() & 0o7777,
            remote.mode
        );
        assert_eq!(
            filetime::FileTime::from_last_modification_time(&fs::metadata(&directory).unwrap())
                .unix_seconds(),
            remote.mtime_seconds
        );
    }

    #[test]
    fn synchronized_deletion_allows_remote_recreation_from_tombstone() {
        let root = tempdir().unwrap();
        let sync = test_sync(root.path());
        let mut state = SyncStateStore::load(root.path()).unwrap();
        let base = establish_base(&sync, &mut state, "file.txt", b"base");
        let deleted = base.tombstone(1234);
        fs::remove_file(root.path().join("file.txt")).unwrap();
        state.insert(&deleted, &local_fingerprint(&deleted));
        state.save().unwrap();

        let local = sync
            .scan_files(&mut state)
            .unwrap()
            .into_iter()
            .find(|file| file.metadata.wire_path_string() == "file.txt")
            .unwrap();
        assert_eq!(local.metadata.state, EntryState::Deleted);
        assert_eq!(
            file_reconciliation(&base, &local),
            FileReconciliation::LocalWins
        );

        let recreated = FileMetadata {
            state: EntryState::Active,
            file_hash: [7_u8; 20],
            owner: [0_u8; 20],
            write_times: deleted.write_times,
            ..base
        };
        assert_eq!(
            file_reconciliation(&recreated, &local),
            FileReconciliation::RemoteWins
        );
    }

    #[test]
    fn remote_create_update_delete_apply_to_local_tree() {
        let root = tempdir().unwrap();
        let sync = test_sync(root.path());
        let mut state = SyncStateStore::load(root.path()).unwrap();
        sync.scan_files(&mut state).unwrap();

        let (created, created_torrent) = remote_metadata("remote.txt", b"remote-created");
        sync.apply_remote_to(
            &created,
            &created_torrent,
            b"remote-created",
            None,
            false,
            &mut state,
        )
        .unwrap();
        assert_eq!(
            fs::read(root.path().join("remote.txt")).unwrap(),
            b"remote-created"
        );

        let (updated, updated_torrent) = remote_metadata("remote.txt", b"remote-updated");
        sync.apply_remote_to(
            &updated,
            &updated_torrent,
            b"remote-updated",
            None,
            false,
            &mut state,
        )
        .unwrap();
        assert_eq!(
            fs::read(root.path().join("remote.txt")).unwrap(),
            b"remote-updated"
        );
        assert!(!root.path().join("remote.txt.Conflict").exists());

        let deleted = updated.tombstone(1234);
        let local = sync
            .scan_files(&mut state)
            .unwrap()
            .into_iter()
            .next()
            .unwrap();
        sync.apply_remote_deletion(&deleted, Some(&local), &mut state)
            .unwrap();
        assert!(!root.path().join("remote.txt").exists());
        assert_eq!(
            state.get("remote.txt").unwrap().state,
            EntryState::Deleted.wire_value() as u8
        );

        let local_tombstone = sync
            .scan_files(&mut state)
            .unwrap()
            .into_iter()
            .find(|file| file.metadata.wire_path_string() == "remote.txt")
            .unwrap();
        assert_eq!(local_tombstone.metadata.state, EntryState::Deleted);
        let (recreated, recreated_torrent) = remote_metadata("remote.txt", b"remote-recreated");
        assert_eq!(
            file_reconciliation(&recreated, &local_tombstone),
            FileReconciliation::RemoteWins
        );
        sync.apply_remote_to(
            &recreated,
            &recreated_torrent,
            b"remote-recreated",
            None,
            false,
            &mut state,
        )
        .unwrap();
        assert_eq!(
            fs::read(root.path().join("remote.txt")).unwrap(),
            b"remote-recreated"
        );
        assert!(!root.path().join("remote.txt.Conflict").exists());
    }

    #[test]
    fn remote_delete_conflicts_with_local_edit_and_archives_data() {
        let root = tempdir().unwrap();
        let sync = test_sync(root.path());
        let mut state = SyncStateStore::load(root.path()).unwrap();
        let base = establish_base(&sync, &mut state, "file.txt", b"base");
        fs::write(root.path().join("file.txt"), b"local-edit").unwrap();
        let local = sync
            .scan_files(&mut state)
            .unwrap()
            .into_iter()
            .find(|file| file.metadata.wire_path_string() == "file.txt")
            .unwrap();
        let deleted = base.tombstone(1234);
        sync.apply_remote_deletion(&deleted, Some(&local), &mut state)
            .unwrap();
        assert!(!root.path().join("file.txt").exists());
        assert_eq!(
            state.get("file.txt").unwrap().state,
            EntryState::Deleted.wire_value() as u8
        );
        let archived = fs::read_dir(root.path().join(".sync").join("Archive"))
            .unwrap()
            .filter_map(|entry| entry.ok())
            .any(|entry| fs::read(entry.path()).unwrap() == b"local-edit");
        assert!(archived);
    }

    #[test]
    fn remote_delete_missing_target_is_idempotent() {
        let root = tempdir().unwrap();
        let sync = test_sync(root.path());
        let mut state = SyncStateStore::load(root.path()).unwrap();
        let base = establish_base(&sync, &mut state, "gone.txt", b"base");
        fs::remove_file(root.path().join("gone.txt")).unwrap();
        let deleted = base.tombstone(1234);
        sync.apply_remote_deletion(&deleted, None, &mut state)
            .unwrap();
        assert_eq!(
            state.get("gone.txt").unwrap().state,
            EntryState::Deleted.wire_value() as u8
        );
    }

    #[test]
    fn adopting_equal_tombstone_with_missing_target_is_idempotent() {
        let root = tempdir().unwrap();
        let sync = test_sync(root.path());
        let mut state = SyncStateStore::load(root.path()).unwrap();
        let source = root.path().join("gone.txt");
        fs::write(&source, b"gone").unwrap();
        let active = FileMetadata::from_path(&source, "gone.txt", [3_u8; 20]).unwrap();
        fs::remove_file(source).unwrap();
        let tombstone = active.tombstone(1234);
        let local = local_file_from_metadata(tombstone.clone(), Vec::new());
        sync.adopt_remote_metadata(&tombstone, &local, &mut state)
            .unwrap();
        assert_eq!(
            state.get("gone.txt").unwrap().state,
            EntryState::Deleted.wire_value() as u8
        );
    }

    #[test]
    fn simultaneous_deletions_do_not_resurrect_stale_active_metadata() {
        let root = tempdir().unwrap();
        let path = root.path().join("gone.txt");
        fs::write(&path, b"base").unwrap();
        let active = FileMetadata::from_path(&path, "gone.txt", [3_u8; 20]).unwrap();
        let mut local_tombstone = active.tombstone(2000);
        local_tombstone
            .sign(&SigningKey::from_bytes(&[4_u8; 32]))
            .unwrap();
        let local = LocalFile {
            metadata: local_tombstone.clone(),
            content: Vec::new(),
            baseline: Some(baseline_record(&active)),
        };
        let mut stale_remote = active.clone();
        stale_remote.time_seconds = 1000;
        assert_eq!(
            file_reconciliation(&stale_remote, &local),
            FileReconciliation::LocalWins
        );

        let mut remote_tombstone = active.tombstone(1500);
        remote_tombstone.time_seconds = 1500;
        assert_eq!(
            file_reconciliation(&remote_tombstone, &local),
            FileReconciliation::Equal
        );

        let mut recreated = stale_remote;
        recreated.write_times = local_tombstone.write_times + 1;
        assert_eq!(
            file_reconciliation(&recreated, &local),
            FileReconciliation::RemoteWins
        );
    }

    #[test]
    fn wire_version_wrap_uses_time_to_accept_remote_tombstone() {
        let root = tempdir().unwrap();
        let path = root.path().join("wrapped.txt");
        fs::write(&path, b"base").unwrap();
        let active = FileMetadata::from_path(&path, "wrapped.txt", [3_u8; 20]).unwrap();
        let mut local_metadata = active.clone();
        local_metadata.write_times = 4;
        local_metadata.time_seconds = 1_000;
        let local = LocalFile {
            metadata: local_metadata,
            content: b"base".to_vec(),
            baseline: Some(baseline_record(&active)),
        };
        let mut remote = active.tombstone(2_000);
        remote.write_times = 4;

        assert_eq!(
            normalized_write_times(&remote),
            normalized_write_times(&local.metadata)
        );
        assert_eq!(
            file_reconciliation(&remote, &local),
            FileReconciliation::RemoteWins
        );
    }

    #[test]
    fn omitted_upstream_write_times_use_time_to_accept_remote_tombstone() {
        let root = tempdir().unwrap();
        let path = root.path().join("upstream-delete.txt");
        fs::write(&path, b"base").unwrap();
        let active = FileMetadata::from_path(&path, "upstream-delete.txt", [3_u8; 20]).unwrap();
        let local_metadata = FileMetadata {
            write_times: 3,
            time_seconds: 1_000,
            ..active.clone()
        };
        let local = LocalFile {
            metadata: local_metadata,
            content: b"base".to_vec(),
            baseline: Some(baseline_record(&active)),
        };
        let mut remote = active.tombstone(2_000);
        remote.write_times = 0;

        assert_eq!(normalized_write_times(&remote), 0);
        assert_eq!(
            file_reconciliation(&remote, &local),
            FileReconciliation::RemoteWins
        );
    }

    #[test]
    fn write_times_from_other_owner_do_not_block_remote_tombstone() {
        let root = tempdir().unwrap();
        let path = root.path().join("other-owner-delete.txt");
        fs::write(&path, b"base").unwrap();
        let active = FileMetadata::from_path(&path, "other-owner-delete.txt", [3_u8; 20]).unwrap();
        let local_metadata = FileMetadata {
            write_times: 3,
            time_seconds: 1_000,
            ..active.clone()
        };
        let local = LocalFile {
            metadata: local_metadata,
            content: b"base".to_vec(),
            baseline: Some(baseline_record(&active)),
        };
        let mut remote = active.tombstone(2_000);
        remote.owner = [9_u8; 20];
        remote.write_times = 2;

        assert_ne!(remote.owner, local.metadata.owner);
        assert_eq!(
            file_reconciliation(&remote, &local),
            FileReconciliation::RemoteWins
        );
    }

    #[test]
    fn remote_update_conflicts_with_local_edit_and_keeps_both_values() {
        let root = tempdir().unwrap();
        let sync = test_sync(root.path());
        let mut state = SyncStateStore::load(root.path()).unwrap();
        establish_base(&sync, &mut state, "file.txt", b"base");
        fs::write(root.path().join("file.txt"), b"local-edit").unwrap();
        sync.scan_files(&mut state).unwrap();
        let (remote, torrent) = remote_metadata("file.txt", b"remote-edit");
        sync.apply_remote_to(&remote, &torrent, b"remote-edit", None, true, &mut state)
            .unwrap();
        assert_eq!(
            fs::read(root.path().join("file.txt")).unwrap(),
            b"remote-edit"
        );
        assert_eq!(
            fs::read(root.path().join("file.txt.Conflict")).unwrap(),
            b"local-edit"
        );
    }

    #[test]
    fn remote_update_replaces_unchanged_local_without_false_conflict() {
        let root = tempdir().unwrap();
        let sync = test_sync(root.path());
        let mut state = SyncStateStore::load(root.path()).unwrap();
        establish_base(&sync, &mut state, "file.txt", b"base");
        sync.scan_files(&mut state).unwrap();
        let (remote, torrent) = remote_metadata("file.txt", b"remote-edit");
        sync.apply_remote_to(&remote, &torrent, b"remote-edit", None, false, &mut state)
            .unwrap();
        assert_eq!(
            fs::read(root.path().join("file.txt")).unwrap(),
            b"remote-edit"
        );
        assert!(!root.path().join("file.txt.Conflict").exists());
    }

    #[test]
    fn directory_and_file_type_changes_preserve_the_other_value() {
        let root = tempdir().unwrap();
        let sync = test_sync(root.path());
        let mut state = SyncStateStore::load(root.path()).unwrap();
        establish_base(&sync, &mut state, "entry", b"local-file");
        let local = sync
            .scan_files(&mut state)
            .unwrap()
            .into_iter()
            .next()
            .unwrap();
        let directory = remote_directory_metadata("entry");
        assert_eq!(
            file_reconciliation(&directory, &local),
            FileReconciliation::Conflict
        );
        sync.apply_remote_directory(&directory, Some(&local), &mut state)
            .unwrap();
        assert!(root.path().join("entry").is_dir());
        assert_eq!(
            fs::read(root.path().join("entry.Conflict")).unwrap(),
            b"local-file"
        );

        let root = tempdir().unwrap();
        let sync = test_sync(root.path());
        let mut state = SyncStateStore::load(root.path()).unwrap();
        fs::create_dir(root.path().join("entry")).unwrap();
        fs::write(root.path().join("entry").join("nested"), b"nested").unwrap();
        let local = sync
            .scan_files(&mut state)
            .unwrap()
            .into_iter()
            .next()
            .unwrap();
        let (remote, torrent) = remote_metadata("entry", b"remote-file");
        assert_eq!(
            file_reconciliation(&remote, &local),
            FileReconciliation::Conflict
        );
        sync.apply_remote_to(&remote, &torrent, b"remote-file", None, true, &mut state)
            .unwrap();
        assert_eq!(fs::read(root.path().join("entry")).unwrap(), b"remote-file");
        assert_eq!(
            fs::read(root.path().join("entry.Conflict").join("nested")).unwrap(),
            b"nested"
        );
    }

    #[test]
    fn node_paths_are_discovered_from_top_level_children() {
        let root = Value::dict([
            (
                b"children".to_vec(),
                Value::dict([
                    (b"alpha".to_vec(), Value::bytes([1_u8; 20])),
                    (b"beta".to_vec(), Value::bytes([2_u8; 20])),
                ]),
            ),
            (b"file".to_vec(), Value::bytes([0_u8; 20])),
            (b"offset".to_vec(), Value::Int(0)),
        ]);
        let message = Value::dict([
            (b"m".to_vec(), Value::bytes(b"nodes")),
            (b"nodes".to_vec(), Value::dict([(b"/".to_vec(), root)])),
        ]);
        assert_eq!(
            node_top_level_paths(&message).unwrap(),
            ["alpha".to_owned(), "beta".to_owned()]
                .into_iter()
                .collect()
        );
    }

    #[test]
    fn file_requests_match_exact_and_descendant_paths() {
        assert!(path_matches_request("origin/file.bin", "origin"));
        assert!(path_matches_request("origin/file.bin", "origin/file.bin"));
        assert!(!path_matches_request("origin-other/file.bin", "origin"));
        assert!(path_matches_request("any/file.bin", ""));
    }

    #[test]
    fn reconciliation_tracks_remote_local_and_concurrent_changes() {
        let root = tempdir().unwrap();
        let unchanged = local_file_from_bytes(root.path(), "file", b"base", None);
        let baseline = baseline_record(&unchanged.metadata);

        let remote = FileMetadata {
            file_hash: [9_u8; 20],
            ..unchanged.metadata.clone()
        };
        let remote_wins = LocalFile {
            baseline: Some(baseline.clone()),
            ..local_file_from_bytes(root.path(), "file", b"base", None)
        };
        assert_eq!(
            file_reconciliation(&remote, &remote_wins),
            FileReconciliation::RemoteWins
        );

        let local_wins = LocalFile {
            metadata: FileMetadata {
                file_hash: [8_u8; 20],
                ..unchanged.metadata.clone()
            },
            baseline: Some(baseline.clone()),
            content: b"local".to_vec(),
        };
        assert_eq!(
            file_reconciliation(&unchanged.metadata, &local_wins),
            FileReconciliation::LocalWins
        );

        let conflict = LocalFile {
            metadata: FileMetadata {
                file_hash: [8_u8; 20],
                ..unchanged.metadata.clone()
            },
            baseline: Some(baseline),
            content: b"local".to_vec(),
        };
        assert_eq!(
            file_reconciliation(&remote, &conflict),
            FileReconciliation::Conflict
        );
    }

    #[test]
    fn wire_frames_reassemble_across_tunnel_payloads() {
        let mut peer_frame = Vec::new();
        peer_frame.extend_from_slice(&[0, 0, 0, 6]);
        peer_frame.extend_from_slice(b"abcdef");
        assert_eq!(wire_frame_length(&peer_frame[..3]), None);
        assert_eq!(wire_frame_length(&peer_frame), Some(peer_frame.len()));

        let value = Value::dict([(b"m".to_vec(), Value::bytes(b"id"))]);
        let body = encode(&value);
        let mut direct = DIRECT_TORRENT_MAGIC_V2.to_vec();
        direct.extend_from_slice(&(body.len() as u32).to_be_bytes());
        direct.extend_from_slice(&body);
        assert_eq!(wire_frame_length(&direct[..23]), None);
        assert_eq!(wire_frame_length(&direct), Some(direct.len()));
    }

    #[test]
    fn tunnel_close_drops_late_inbound_and_outbound_frames() {
        let mut output = Vec::new();
        {
            let mut stream = std::io::Cursor::new(&mut output);
            let mut mux = TunnelMux::new(&mut stream);
            mux.known.insert(77);
            mux.send_close(77).unwrap();
            mux.send_data(77, b"late").unwrap();
        }
        assert_eq!(
            output,
            write_tunnel_frame_bytes(77, TUNNEL_PACKET_CLOSE, &[], false)
        );

        let mut input = write_tunnel_frame_bytes(88, TUNNEL_PACKET_DATA, b"stale", false);
        input.extend(write_tunnel_frame_bytes(
            99,
            TUNNEL_PACKET_DATA,
            b"current",
            false,
        ));
        let mut stream = std::io::Cursor::new(input);
        let mut mux = TunnelMux::new(&mut stream);
        mux.known.insert(99);
        let TunnelEvent::Data(packet) = mux.next_event().unwrap() else {
            panic!("expected current tunnel data");
        };
        assert_eq!(packet.connection_id, 99);
        assert_eq!(packet.payload, b"current");
    }

    fn write_tunnel_frame_bytes(
        connection_id: u32,
        packet_type: u8,
        payload: &[u8],
        compressed: bool,
    ) -> Vec<u8> {
        let mut frame = Vec::new();
        write_tunnel_frame(&mut frame, connection_id, packet_type, payload, compressed).unwrap();
        frame
    }

    #[test]
    fn conflict_siblings_use_incrementing_upstream_names() {
        let root = tempdir().unwrap();
        let key =
            ShareKey::parse(&format!("A{}", crate::secret::encode_base32(&[7_u8; 20]))).unwrap();
        let sync = SyncNode::new(root.path(), key, "conflict-test").unwrap();
        let mut state = SyncStateStore::load(root.path()).unwrap();

        fs::write(root.path().join("file.txt"), b"first").unwrap();
        sync.preserve_conflict_sibling(&root.path().join("file.txt"), &mut state)
            .unwrap();
        assert_eq!(
            fs::read(root.path().join("file.txt.Conflict")).unwrap(),
            b"first"
        );

        fs::write(root.path().join("file.txt"), b"second").unwrap();
        sync.preserve_conflict_sibling(&root.path().join("file.txt"), &mut state)
            .unwrap();
        assert_eq!(
            fs::read(root.path().join("file.txt.Conflict2")).unwrap(),
            b"second"
        );
    }
}
