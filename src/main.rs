use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};
use rustsync::apply::{apply_manifest, ConflictPolicy};
use rustsync::discovery::LanPing;
use rustsync::peer::{pull, random_peer_id, serve_once};
use rustsync::scan::{manifest_path, scan_root};
use rustsync::secret::ShareKey;
use rustsync::sync_session::SyncNode;
use std::fs;
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;

#[derive(Debug, Parser)]
#[command(version, about)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Scan a directory and write a deterministic JSON manifest.
    Scan {
        root: PathBuf,
        #[arg(short, long)]
        output: Option<PathBuf>,
    },
    /// Verify a manifest and atomically copy its entries from source to target.
    Apply {
        source: PathBuf,
        target: PathBuf,
        #[arg(short, long)]
        manifest: Option<PathBuf>,
        #[arg(long, default_value = "overwrite")]
        conflict: String,
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
    },
}

fn main() -> Result<()> {
    match Cli::parse().command {
        Command::Scan { root, output } => {
            let manifest = scan_root(&root)?;
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
        } => {
            let policy = match conflict.as_str() {
                "overwrite" => ConflictPolicy::Overwrite,
                "preserve" => ConflictPolicy::Preserve,
                value => bail!("conflict policy must be overwrite or preserve, got {value}"),
            };
            let path = manifest.unwrap_or_else(|| manifest_path(&source));
            let manifest: rustsync::Manifest = serde_json::from_slice(
                &fs::read(&path).with_context(|| format!("read {}", path.display()))?,
            )?;
            apply_manifest(&source, &target, &manifest, policy)?;
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
        } => {
            let peer_id = peer_id
                .map(|value| parse_fixed_20(&value, "peer ID"))
                .transpose()?
                .unwrap_or_else(rustsync::sync_session::random_peer_id);
            let sync =
                SyncNode::new_with_peer_id(root, ShareKey::parse(&key)?, device_name, peer_id)?;
            sync.serve_with_discovery(&listen, !no_discovery)?;
        }
        Command::ConnectUpstream {
            root,
            address,
            key,
            device_name,
            peer_id,
        } => {
            let peer_id = peer_id
                .map(|value| parse_fixed_20(&value, "peer ID"))
                .transpose()?
                .unwrap_or_else(rustsync::sync_session::random_peer_id);
            let sync =
                SyncNode::new_with_peer_id(root, ShareKey::parse(&key)?, device_name, peer_id)?;
            sync.connect(&address)?;
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
