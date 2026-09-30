use crate::apply::{apply_manifest, ConflictPolicy};
use crate::model::{Manifest, PIECE_SIZE};
use crate::scan::scan_root;
use crate::secret::ShareKey;
use anyhow::{bail, Context, Result};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Seek, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::time::Duration;

const PROTOCOL: &str = "rustsync/1";
const MAX_FRAME: usize = 64 * 1024 * 1024;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct Hello {
    protocol: String,
    peer_id: String,
    share_id: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
enum Message {
    Hello(Hello),
    Manifest(Manifest),
    WantPiece {
        path: String,
        index: u64,
    },
    Piece {
        path: String,
        index: u64,
        data: Vec<u8>,
    },
    Done,
    Error {
        message: String,
    },
}

pub fn random_peer_id() -> [u8; 20] {
    let mut peer_id = [0_u8; 20];
    rand::thread_rng().fill_bytes(&mut peer_id);
    peer_id
}

pub fn serve_once(
    listener: &TcpListener,
    root: &Path,
    key: &ShareKey,
    peer_id: [u8; 20],
) -> Result<SocketAddr> {
    let (stream, peer_address) = listener.accept().context("accept peer")?;
    handle_client(stream, root, key, peer_id).with_context(|| format!("serve {peer_address}"))?;
    Ok(peer_address)
}

pub fn handle_client(
    stream: TcpStream,
    root: &Path,
    key: &ShareKey,
    peer_id: [u8; 20],
) -> Result<()> {
    stream.set_read_timeout(Some(Duration::from_secs(30)))?;
    stream.set_write_timeout(Some(Duration::from_secs(30)))?;
    let mut reader = stream.try_clone()?;
    let mut writer = stream;
    let share_id = hex::encode(key.share_id());
    receive_hello(&mut reader, &share_id)?;
    send_message(
        &mut writer,
        &Message::Hello(Hello {
            protocol: PROTOCOL.into(),
            peer_id: hex::encode(peer_id),
            share_id,
        }),
    )?;
    let manifest = scan_root(root)?;
    send_message(&mut writer, &Message::Manifest(manifest))?;
    loop {
        match receive_message(&mut reader)? {
            Message::WantPiece { path, index } => {
                let data = read_piece(root, &path, index)?;
                send_message(&mut writer, &Message::Piece { path, index, data })?;
            }
            Message::Done => return Ok(()),
            Message::Error { message } => bail!("peer reported error: {message}"),
            _ => bail!("unexpected client message"),
        }
    }
}

pub fn pull(
    stream: TcpStream,
    target_root: &Path,
    key: &ShareKey,
    peer_id: [u8; 20],
) -> Result<Manifest> {
    stream.set_read_timeout(Some(Duration::from_secs(30)))?;
    stream.set_write_timeout(Some(Duration::from_secs(30)))?;
    let mut reader = stream.try_clone()?;
    let mut writer = stream;
    let share_id = hex::encode(key.share_id());
    send_message(
        &mut writer,
        &Message::Hello(Hello {
            protocol: PROTOCOL.into(),
            peer_id: hex::encode(peer_id),
            share_id: share_id.clone(),
        }),
    )?;
    receive_hello(&mut reader, &share_id)?;
    let manifest = match receive_message(&mut reader)? {
        Message::Manifest(manifest) => manifest,
        Message::Error { message } => bail!("remote error: {message}"),
        _ => bail!("remote did not send a manifest"),
    };
    manifest.validate()?;
    let staging = staging_path(target_root)?;
    fs::create_dir_all(&staging)?;
    let result = (|| -> Result<Manifest> {
        for entry in manifest
            .entries
            .iter()
            .filter(|entry| matches!(entry.kind, crate::model::EntryKind::Directory))
        {
            let local = staging.join(&entry.path);
            fs::create_dir_all(&local)?;
        }
        for entry in manifest
            .entries
            .iter()
            .filter(|entry| matches!(entry.kind, crate::model::EntryKind::File))
        {
            let local = staging.join(&entry.path);
            if let Some(parent) = local.parent() {
                fs::create_dir_all(parent)?;
            }
            let mut output = OpenOptions::new()
                .create(true)
                .truncate(true)
                .write(true)
                .open(&local)?;
            for index in 0..entry.pieces.len() as u64 {
                send_message(
                    &mut writer,
                    &Message::WantPiece {
                        path: entry.path.clone(),
                        index,
                    },
                )?;
                let data = match receive_message(&mut reader)? {
                    Message::Piece { data, .. } => data,
                    Message::Error { message } => bail!("remote error: {message}"),
                    _ => bail!("unexpected response to piece request"),
                };
                output.write_all(&data)?;
            }
            output.flush()?;
            output.sync_all()?;
            crate::apply::restore_metadata(&local, entry)?;
        }
        for entry in manifest
            .entries
            .iter()
            .filter(|entry| matches!(entry.kind, crate::model::EntryKind::Directory))
        {
            crate::apply::restore_metadata(&staging.join(&entry.path), entry)?;
        }
        let local_manifest = scan_root(&staging)?;
        if local_manifest != manifest {
            bail!("received manifest does not match reconstructed staging tree");
        }
        send_message(&mut writer, &Message::Done)?;
        apply_manifest(&staging, target_root, &manifest, ConflictPolicy::Overwrite)?;
        Ok(manifest)
    })();
    let cleanup = fs::remove_dir_all(&staging);
    result.and_then(|manifest| {
        cleanup.context("remove staging directory")?;
        Ok(manifest)
    })
}

fn staging_path(target_root: &Path) -> Result<PathBuf> {
    let parent = target_root.parent().unwrap_or_else(|| Path::new("."));
    let name = target_root
        .file_name()
        .map(|value| value.to_string_lossy().into_owned())
        .unwrap_or_else(|| "target".into());
    let mut suffix = [0_u8; 8];
    rand::thread_rng().fill_bytes(&mut suffix);
    Ok(parent.join(format!(".{name}.rustsync-staging-{}", hex::encode(suffix))))
}

fn read_piece(root: &Path, path: &str, index: u64) -> Result<Vec<u8>> {
    crate::model::validate_relative_path(path)?;
    let local = root.join(path);
    let mut file = File::open(&local).with_context(|| format!("open {}", local.display()))?;
    file.seek(std::io::SeekFrom::Start(
        index
            .checked_mul(PIECE_SIZE as u64)
            .context("piece offset overflow")?,
    ))?;
    let mut data = vec![0_u8; PIECE_SIZE];
    let mut filled = 0;
    while filled < data.len() {
        let count = file.read(&mut data[filled..])?;
        if count == 0 {
            break;
        }
        filled += count;
    }
    data.truncate(filled);
    Ok(data)
}

fn receive_hello(stream: &mut TcpStream, expected_share: &str) -> Result<()> {
    match receive_message(stream)? {
        Message::Hello(hello) => {
            if hello.protocol != PROTOCOL {
                bail!("unsupported peer protocol {}", hello.protocol);
            }
            if hello.share_id != expected_share {
                bail!("share ID mismatch");
            }
            if hex::decode(hello.peer_id)?.len() != 20 {
                bail!("invalid peer ID");
            }
            Ok(())
        }
        _ => bail!("expected peer hello"),
    }
}

fn send_message(stream: &mut TcpStream, message: &Message) -> Result<()> {
    let payload = serde_json::to_vec(message)?;
    if payload.len() > MAX_FRAME {
        bail!("peer frame is too large");
    }
    stream.write_all(&(payload.len() as u32).to_be_bytes())?;
    stream.write_all(&payload)?;
    stream.flush()?;
    Ok(())
}

fn receive_message(stream: &mut TcpStream) -> Result<Message> {
    let mut length = [0_u8; 4];
    stream.read_exact(&mut length)?;
    let length = u32::from_be_bytes(length) as usize;
    if length > MAX_FRAME {
        bail!("peer frame exceeds {MAX_FRAME} bytes");
    }
    let mut payload = vec![0_u8; length];
    stream.read_exact(&mut payload)?;
    Ok(serde_json::from_slice(&payload)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::secret::ShareKey;
    use std::io::Write;
    use tempfile::tempdir;

    #[test]
    fn native_round_trip_reconstructs_tree() {
        let source = tempdir().unwrap();
        let target = tempdir().unwrap();
        fs::create_dir(source.path().join("dir")).unwrap();
        File::create(source.path().join("dir/file.bin"))
            .unwrap()
            .write_all(&vec![42_u8; PIECE_SIZE + 17])
            .unwrap();
        let key = ShareKey::generate_read_only();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server_key = key.clone();
        let server_root = source.path().to_path_buf();
        let server = std::thread::spawn(move || {
            serve_once(&listener, &server_root, &server_key, random_peer_id()).unwrap();
        });
        let stream = TcpStream::connect(address).unwrap();
        let manifest = pull(
            stream,
            target.path().join("target").as_path(),
            &key,
            random_peer_id(),
        )
        .unwrap();
        server.join().unwrap();
        assert_eq!(manifest, scan_root(source.path()).unwrap());
        assert_eq!(
            fs::read(target.path().join("target/dir/file.bin"))
                .unwrap()
                .len(),
            PIECE_SIZE + 17
        );
    }
}
