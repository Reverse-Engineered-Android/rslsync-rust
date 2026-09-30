use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};
use rustsync::apply::{apply_manifest_with_policy, ApplyPolicy, ConflictPolicy};
use rustsync::client::RemoteClient;
use rustsync::discovery::LanPing;
use rustsync::encrypted::{decrypt_tree, encrypt_tree};
use rustsync::operations::{
    ApplyRequest, DecryptTreeRequest, EncodePingRequest, EncryptTreeRequest, GenerateKeyRequest,
    InspectKeyRequest, PullRequest, ScanRequest, TrackerAnnounceRequest,
};
use rustsync::peer::{pull, random_peer_id, serve_once};
use rustsync::permissions::PermissionPolicy;
use rustsync::scan::{manifest_path, scan_root_with_selection};
use rustsync::secret::ShareKey;
use rustsync::selective::SyncSelection;
use rustsync::server::{ServerOptions, WebServer};
use rustsync::sync_session::SyncNode;
use rustsync::tracker::{TrackerClient, TrackerRequest, TrackerServer};
use std::fs;
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;

#[derive(Debug, Parser)]
#[command(version, about)]
struct Cli {
    /// Send one-shot CLI operations to a rustsync REST server.
    #[arg(long)]
    server: Option<String>,
    /// Bearer token for the REST server.
    #[arg(long)]
    server_token: Option<String>,
    /// Password used to log in to the REST server.
    #[arg(long)]
    server_password: Option<String>,
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Serve the embedded REST API and web interface.
    ServeUi {
        #[arg(long, default_value = "127.0.0.1:8787")]
        listen: String,
        #[arg(long, default_value = ".rustsync-server/state.json")]
        state: PathBuf,
    },
    /// Scan a directory and write a deterministic JSON manifest.
    Scan {
        root: PathBuf,
        #[arg(short, long)]
        output: Option<PathBuf>,
        #[arg(long)]
        include: Option<String>,
        #[arg(long)]
        exclude: Option<String>,
    },
    /// Verify a manifest and atomically copy its entries from source to target.
    Apply {
        source: PathBuf,
        target: PathBuf,
        #[arg(short, long)]
        manifest: Option<PathBuf>,
        #[arg(long, default_value = "overwrite")]
        conflict: String,
        #[arg(long, default_value = "preserve")]
        permissions: String,
    },
    /// Generate an upstream-compatible B/read-only or A/read-write share key.
    GenerateKey {
        /// Generate a writable A key instead of a read-only B key.
        #[arg(long)]
        read_write: bool,
    },
    /// Validate an upstream key and print non-secret compatibility metadata.
    InspectKey { key: String },
    /// Encode an upstream LAN discovery ping packet as hexadecimal.
    EncodePing {
        #[arg(long)]
        peer_id: String,
        #[arg(long)]
        port: u16,
        #[arg(long = "share-id", required = true)]
        share_ids: Vec<String>,
    },
    /// Serve the native rustsync manifest/piece protocol once.
    Serve {
        root: PathBuf,
        #[arg(long, default_value = "127.0.0.1:0")]
        listen: String,
        #[arg(long)]
        key: String,
    },
    /// Pull a tree through the native rustsync protocol.
    Pull {
        address: String,
        target: PathBuf,
        #[arg(long)]
        key: String,
    },
    /// Serve upstream client 3.1.2 SRPEH/Bencode with legacy TLS-PSK fallback.
    ServeUpstream {
        root: PathBuf,
        #[arg(long, default_value = "127.0.0.1:0")]
        listen: String,
        #[arg(long)]
        key: String,
        #[arg(long, default_value = "rustsync")]
        device_name: String,
        #[arg(long)]
        peer_id: Option<String>,
        #[arg(long)]
        no_discovery: bool,
        #[arg(long)]
        include: Option<String>,
        #[arg(long)]
        exclude: Option<String>,
        /// HTTP tracker URLs used for peer discovery.
        #[arg(long)]
        tracker: Vec<String>,
    },
    /// Continuously connect to an upstream peer and resynchronize.
    ConnectUpstream {
        root: PathBuf,
        address: String,
        #[arg(long)]
        key: String,
        #[arg(long, default_value = "rustsync")]
        device_name: String,
        #[arg(long)]
        peer_id: Option<String>,
        #[arg(long)]
        include: Option<String>,
        #[arg(long)]
        exclude: Option<String>,
        /// HTTP tracker URLs used for peer discovery.
        #[arg(long)]
        tracker: Vec<String>,
    },
    /// Encrypt a directory into a self-contained authenticated vault.
    EncryptTree {
        source: PathBuf,
        destination: PathBuf,
        #[arg(long)]
        passphrase: String,
    },
    /// Decrypt an authenticated encrypted vault into a directory.
    DecryptTree {
        source: PathBuf,
        destination: PathBuf,
        #[arg(long)]
        passphrase: String,
    },
    /// Announce to an HTTP tracker and print returned peers as JSON.
    TrackerAnnounce {
        #[arg(long)]
        url: String,
        #[arg(long)]
        info_hash: String,
        #[arg(long)]
        peer_id: String,
        #[arg(long)]
        port: u16,
    },
    /// Serve a minimal independent HTTP tracker.
    TrackerServe {
        #[arg(long, default_value = "127.0.0.1:0")]
        listen: String,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let server = cli
        .server
        .or_else(|| std::env::var("RUSTSYNC_SERVER").ok())
        .filter(|value| !value.trim().is_empty());
    let server_token = cli
        .server_token
        .or_else(|| std::env::var("RUSTSYNC_SERVER_TOKEN").ok())
        .filter(|value| !value.trim().is_empty());
    let server_password = cli
        .server_password
        .or_else(|| std::env::var("RUSTSYNC_SERVER_PASSWORD").ok())
        .filter(|value| !value.trim().is_empty());
    if let Some(server) = server {
        let mut client = RemoteClient::new(&server, server_token, server_password)?;
        return run_remote(&mut client, cli.command);
    }
    match cli.command {
        Command::ServeUi { listen, state } => {
            let server = WebServer::bind(ServerOptions::new(listen, state))?;
            eprintln!(
                "rustsync server listening on http://{}",
                server.local_addr()?
            );
            server.serve_forever()?;
        }
        Command::Scan {
            root,
            output,
            include,
            exclude,
        } => {
            let selection = SyncSelection::from_csv(include.as_deref(), exclude.as_deref())?;
            let manifest = scan_root_with_selection(&root, &selection)?;
            let destination = output.unwrap_or_else(|| manifest_path(&root));
            let json = serde_json::to_vec_pretty(&manifest)?;
            fs::write(&destination, json)
                .with_context(|| format!("write {}", destination.display()))?;
            println!("{} {}", manifest.root_hash, destination.display());
        }
        Command::Apply {
            source,
            target,
            manifest,
            conflict,
            permissions,
        } => {
            let conflict = match conflict.as_str() {
                "overwrite" => ConflictPolicy::Overwrite,
                "preserve" => ConflictPolicy::Preserve,
                value => bail!("conflict policy must be overwrite or preserve, got {value}"),
            };
            let permissions = match permissions.as_str() {
                "preserve" => PermissionPolicy::Preserve,
                "ignore" => PermissionPolicy::Ignore,
                "check" => PermissionPolicy::CheckOnly,
                value => bail!("permissions must be preserve, ignore, or check, got {value}"),
            };
            let path = manifest.unwrap_or_else(|| manifest_path(&source));
            let manifest: rustsync::Manifest = serde_json::from_slice(
                &fs::read(&path).with_context(|| format!("read {}", path.display()))?,
            )?;
            apply_manifest_with_policy(
                &source,
                &target,
                &manifest,
                ApplyPolicy {
                    conflict,
                    permissions,
                },
            )?;
            println!("{} {}", manifest.root_hash, target.display());
        }
        Command::GenerateKey { read_write } => {
            let key = if read_write {
                ShareKey::generate_read_write()
            } else {
                ShareKey::generate_read_only()
            };
            println!("{}", key.render());
        }
        Command::InspectKey { key } => {
            let parsed = ShareKey::parse(&key)?;
            println!("type={}", parsed.key_type);
            println!("share_id={}", hex::encode(parsed.share_id()));
            println!("tls_identity={}", parsed.tls_identity());
            println!("tls_psk_available={}", parsed.tls_psk().is_ok());
        }
        Command::EncodePing {
            peer_id,
            port,
            share_ids,
        } => {
            let peer_id = parse_fixed_20(&peer_id, "peer ID")?;
            let shares = share_ids
                .iter()
                .map(|value| parse_fixed_20(value, "share ID"))
                .collect::<Result<Vec<_>>>()?;
            let ping = LanPing {
                peer_id,
                port,
                shares,
            };
            println!("{}", hex::encode(ping.encode()));
        }
        Command::Serve { root, listen, key } => {
            let key = ShareKey::parse(&key)?;
            let listener = TcpListener::bind(&listen).with_context(|| format!("bind {listen}"))?;
            let address = listener.local_addr()?;
            eprintln!("listening on {address}");
            let peer = serve_once(&listener, &root, &key, random_peer_id())?;
            println!("served {peer}");
        }
        Command::Pull {
            address,
            target,
            key,
        } => {
            let key = ShareKey::parse(&key)?;
            let stream =
                TcpStream::connect(&address).with_context(|| format!("connect {address}"))?;
            let manifest = pull(stream, &target, &key, random_peer_id())?;
            println!("{} {}", manifest.root_hash, target.display());
        }
        Command::ServeUpstream {
            root,
            listen,
            key,
            device_name,
            peer_id,
            no_discovery,
            include,
            exclude,
            tracker,
        } => {
            let peer_id = peer_id
                .map(|value| parse_fixed_20(&value, "peer ID"))
                .transpose()?
                .unwrap_or_else(rustsync::sync_session::random_peer_id);
            let sync =
                SyncNode::new_with_peer_id(root, ShareKey::parse(&key)?, device_name, peer_id)?;
            sync.with_selection(SyncSelection::from_csv(
                include.as_deref(),
                exclude.as_deref(),
            )?)
            .with_trackers(tracker)
            .serve_with_discovery(&listen, !no_discovery)?;
        }
        Command::ConnectUpstream {
            root,
            address,
            key,
            device_name,
            peer_id,
            include,
            exclude,
            tracker,
        } => {
            let peer_id = peer_id
                .map(|value| parse_fixed_20(&value, "peer ID"))
                .transpose()?
                .unwrap_or_else(rustsync::sync_session::random_peer_id);
            let sync =
                SyncNode::new_with_peer_id(root, ShareKey::parse(&key)?, device_name, peer_id)?;
            sync.with_selection(SyncSelection::from_csv(
                include.as_deref(),
                exclude.as_deref(),
            )?)
            .with_trackers(tracker)
            .connect(&address)?;
        }
        Command::EncryptTree {
            source,
            destination,
            passphrase,
        } => {
            let manifest = encrypt_tree(&source, &destination, passphrase.as_bytes())?;
            println!("{} {}", manifest.files.len(), destination.display());
        }
        Command::DecryptTree {
            source,
            destination,
            passphrase,
        } => {
            let manifest = decrypt_tree(&source, &destination, passphrase.as_bytes())?;
            println!("{} {}", manifest.files.len(), destination.display());
        }
        Command::TrackerAnnounce {
            url,
            info_hash,
            peer_id,
            port,
        } => {
            let response = TrackerClient::new(url).announce(&TrackerRequest {
                info_hash: parse_fixed_20(&info_hash, "info hash")?,
                peer_id: parse_fixed_20(&peer_id, "peer ID")?,
                port,
                uploaded: 0,
                downloaded: 0,
                left: 0,
                event: Some("started".into()),
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
            println!(
                "{}",
                serde_json::json!({
                    "interval": response.interval,
                    "warning": response.warning,
                    "peers": peers,
                })
            );
        }
        Command::TrackerServe { listen } => {
            let server = TrackerServer::bind(&listen)?;
            eprintln!("tracker listening on {}", server.local_addr()?);
            server.serve_forever()?;
        }
    }
    Ok(())
}

fn run_remote(client: &mut RemoteClient, command: Command) -> Result<()> {
    match command {
        Command::ServeUi { .. } => bail!("serve-ui always runs on the local host"),
        Command::Scan {
            root,
            output,
            include,
            exclude,
        } => {
            let response: rustsync::operations::ScanResponse = client.call(
                "POST",
                "/api/v1/operations/scan",
                Some(&ScanRequest {
                    root,
                    output,
                    include,
                    exclude,
                }),
            )?;
            println!(
                "{} {}",
                response.summary.root_hash,
                response.summary.output.unwrap_or_default().display()
            );
        }
        Command::Apply {
            source,
            target,
            manifest,
            conflict,
            permissions,
        } => {
            let response: rustsync::operations::ApplyResponse = client.call(
                "POST",
                "/api/v1/operations/apply",
                Some(&ApplyRequest {
                    source,
                    target,
                    manifest,
                    conflict: Some(conflict),
                    permissions: Some(permissions),
                }),
            )?;
            println!("{} {}", response.root_hash, response.target.display());
        }
        Command::Pull {
            address,
            target,
            key,
        } => {
            let response: rustsync::operations::PullResponse = client.call(
                "POST",
                "/api/v1/operations/pull",
                Some(&PullRequest {
                    address,
                    target,
                    key,
                }),
            )?;
            println!("{} {}", response.root_hash, response.target.display());
        }
        Command::GenerateKey { read_write } => {
            let response: rustsync::operations::GenerateKeyResponse = client.call(
                "POST",
                "/api/v1/operations/keys/generate",
                Some(&GenerateKeyRequest { read_write }),
            )?;
            println!("{}", response.key);
        }
        Command::InspectKey { key } => {
            let response: serde_json::Value = client.call(
                "POST",
                "/api/v1/operations/keys/inspect",
                Some(&InspectKeyRequest { key }),
            )?;
            println!("{}", serde_json::to_string_pretty(&response)?);
        }
        Command::EncodePing {
            peer_id,
            port,
            share_ids,
        } => {
            let response: rustsync::operations::EncodePingResponse = client.call(
                "POST",
                "/api/v1/operations/ping/encode",
                Some(&EncodePingRequest {
                    peer_id,
                    port,
                    share_ids,
                }),
            )?;
            println!("{}", response.packet_hex);
        }
        Command::EncryptTree {
            source,
            destination,
            passphrase,
        } => {
            let response: rustsync::operations::VaultResponse = client.call(
                "POST",
                "/api/v1/operations/vault/encrypt",
                Some(&EncryptTreeRequest {
                    source,
                    destination,
                    passphrase,
                }),
            )?;
            println!("{} {}", response.file_count, response.destination.display());
        }
        Command::DecryptTree {
            source,
            destination,
            passphrase,
        } => {
            let response: rustsync::operations::VaultResponse = client.call(
                "POST",
                "/api/v1/operations/vault/decrypt",
                Some(&DecryptTreeRequest {
                    source,
                    destination,
                    passphrase,
                }),
            )?;
            println!("{} {}", response.file_count, response.destination.display());
        }
        Command::TrackerAnnounce {
            url,
            info_hash,
            peer_id,
            port,
        } => {
            let response: serde_json::Value = client.call(
                "POST",
                "/api/v1/operations/tracker/announce",
                Some(&TrackerAnnounceRequest {
                    url,
                    info_hash,
                    peer_id,
                    port,
                    uploaded: 0,
                    downloaded: 0,
                    left: 0,
                    event: Some("started".into()),
                }),
            )?;
            println!("{}", serde_json::to_string_pretty(&response)?);
        }
        Command::Serve { .. }
        | Command::ServeUpstream { .. }
        | Command::ConnectUpstream { .. }
        | Command::TrackerServe { .. } => {
            bail!("long-running listeners are managed locally; run this command without --server")
        }
    }
    Ok(())
}

fn parse_fixed_20(value: &str, label: &str) -> Result<[u8; 20]> {
    let bytes = hex::decode(value).with_context(|| format!("decode {label}"))?;
    bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("{label} must be exactly 20 bytes"))
}
