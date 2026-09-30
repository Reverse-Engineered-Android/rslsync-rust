use crate::bencode::{decode, Value};
use anyhow::{bail, Context, Result};
use std::collections::{BTreeMap, HashMap};
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TrackerPeer {
    pub address: SocketAddr,
    pub peer_id: Option<[u8; 20]>,
}

#[derive(Clone, Debug)]
pub struct TrackerRequest {
    pub info_hash: [u8; 20],
    pub peer_id: [u8; 20],
    pub port: u16,
    pub uploaded: u64,
    pub downloaded: u64,
    pub left: u64,
    pub event: Option<String>,
}

#[derive(Clone, Debug)]
pub struct TrackerResponse {
    pub interval: u64,
    pub peers: Vec<TrackerPeer>,
    pub warning: Option<String>,
}

#[derive(Clone, Debug)]
pub struct TrackerClient {
    endpoint: String,
    timeout: Duration,
}

impl TrackerClient {
    pub fn new(endpoint: impl Into<String>) -> Self {
        Self {
            endpoint: endpoint.into(),
            timeout: Duration::from_secs(5),
        }
    }

    pub fn with_timeout(endpoint: impl Into<String>, timeout: Duration) -> Self {
        Self {
            endpoint: endpoint.into(),
            timeout,
        }
    }

    pub fn announce(&self, request: &TrackerRequest) -> Result<TrackerResponse> {
        let (host, port, path) = parse_http_endpoint(&self.endpoint)?;
        let mut query = vec![
            format!("info_hash={}", percent_encode(&request.info_hash)),
            format!("peer_id={}", percent_encode(&request.peer_id)),
            format!("port={}", request.port),
            format!("uploaded={}", request.uploaded),
            format!("downloaded={}", request.downloaded),
            format!("left={}", request.left),
            "compact=1".to_owned(),
        ];
        if let Some(event) = &request.event {
            query.push(format!("event={}", percent_encode(event.as_bytes())));
        }
        let query = query.join("&");
        let mut stream = TcpStream::connect((host.as_str(), port))
            .with_context(|| format!("connect tracker {host}:{port}"))?;
        stream.set_read_timeout(Some(self.timeout))?;
        stream.set_write_timeout(Some(self.timeout))?;
        let request =
            format!("GET {path}?{query} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n");
        stream.write_all(request.as_bytes())?;
        let mut response = Vec::new();
        stream.read_to_end(&mut response)?;
        parse_tracker_http_response(&response)
    }
}

#[derive(Default)]
struct TrackerRegistry {
    peers: BTreeMap<[u8; 20], (SocketAddr, Instant)>,
}

impl TrackerRegistry {
    fn announce(
        &mut self,
        _info_hash: [u8; 20],
        peer_id: [u8; 20],
        address: SocketAddr,
        ttl: Duration,
        event: Option<&str>,
    ) -> Vec<TrackerPeer> {
        self.peers.retain(|_, (_, seen)| seen.elapsed() < ttl);
        if event == Some("stopped") {
            self.peers.remove(&peer_id);
            return Vec::new();
        }
        self.peers.insert(peer_id, (address, Instant::now()));
        self.peers
            .iter()
            .filter(|(id, _)| **id != peer_id)
            .map(|(id, (address, _))| TrackerPeer {
                address: *address,
                peer_id: Some(*id),
            })
            .filter(|peer| {
                // The compact response is share-scoped in a real tracker; the
                // key is retained in the registry to allow one server to serve
                // several shares without exposing unrelated peers.
                self.peers.contains_key(&peer.peer_id.unwrap())
            })
            .collect()
    }
}

pub struct TrackerServer {
    listener: TcpListener,
    registry: Arc<Mutex<HashMap<[u8; 20], TrackerRegistry>>>,
    ttl: Duration,
}

impl TrackerServer {
    pub fn bind(address: &str) -> Result<Self> {
        let listener = TcpListener::bind(address).context("bind tracker")?;
        Ok(Self {
            listener,
            registry: Arc::new(Mutex::new(HashMap::new())),
            ttl: Duration::from_secs(30 * 60),
        })
    }

    pub fn local_addr(&self) -> Result<SocketAddr> {
        Ok(self.listener.local_addr()?)
    }

    pub fn serve_forever(&self) -> Result<()> {
        for stream in self.listener.incoming() {
            let stream = stream.context("accept tracker request")?;
            let registry = Arc::clone(&self.registry);
            let ttl = self.ttl;
            thread::spawn(move || {
                if let Err(error) = handle_tracker_connection(stream, registry, ttl) {
                    eprintln!("tracker request failed: {error:#}");
                }
            });
        }
        Ok(())
    }
}

fn handle_tracker_connection(
    mut stream: TcpStream,
    registry: Arc<Mutex<HashMap<[u8; 20], TrackerRegistry>>>,
    ttl: Duration,
) -> Result<()> {
    stream.set_read_timeout(Some(Duration::from_secs(5)))?;
    stream.set_write_timeout(Some(Duration::from_secs(5)))?;
    let mut request = Vec::new();
    let mut buffer = [0_u8; 1024];
    loop {
        let count = stream.read(&mut buffer)?;
        request.extend_from_slice(&buffer[..count]);
        if request.windows(4).any(|window| window == b"\r\n\r\n") || count == 0 {
            break;
        }
    }
    let text = std::str::from_utf8(&request).context("tracker request is not UTF-8")?;
    let first = text
        .lines()
        .next()
        .context("tracker request has no status line")?;
    let target = first
        .split_whitespace()
        .nth(1)
        .context("tracker request has no target")?;
    let query = target
        .split_once('?')
        .map(|(_, query)| query)
        .unwrap_or_default();
    let params = parse_query(query);
    let info_hash = parse_hash_param(&params, "info_hash")?;
    let peer_id = parse_hash_param(&params, "peer_id")?;
    let port = params
        .get("port")
        .map(|value| std::str::from_utf8(value))
        .transpose()
        .context("tracker port is not UTF-8")?
        .context("tracker request has no port")?
        .parse::<u16>()
        .context("tracker port is invalid")?;
    let event = params
        .get("event")
        .map(|value| std::str::from_utf8(value))
        .transpose()
        .context("tracker event is not UTF-8")?
        .filter(|value| !value.is_empty());
    if !matches!(event, None | Some("started" | "completed" | "stopped")) {
        bail!("tracker event is invalid");
    }
    let source_ip = stream.peer_addr()?.ip();
    let address = SocketAddr::new(source_ip, port);
    let response = registry
        .lock()
        .unwrap()
        .entry(info_hash)
        .or_default()
        .announce(info_hash, peer_id, address, ttl, event);
    let compact = response
        .iter()
        .flat_map(|peer| compact_peer(peer.address))
        .collect::<Vec<_>>();
    let body = crate::bencode::encode(&Value::dict([
        (b"interval".to_vec(), Value::Int(120)),
        (b"peers".to_vec(), Value::Bytes(compact)),
    ]));
    let response = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    stream.write_all(response.as_bytes())?;
    stream.write_all(&body)?;
    Ok(())
}

pub fn parse_tracker_http_response(response: &[u8]) -> Result<TrackerResponse> {
    let split = response
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .context("tracker response has no HTTP body")?;
    let headers = std::str::from_utf8(&response[..split])?;
    let status = headers.lines().next().unwrap_or_default();
    if !status.contains(" 200 ") && !status.ends_with(" 200") {
        bail!("tracker returned HTTP failure: {status}");
    }
    let body = &response[split + 4..];
    let value = decode(body).context("decode tracker response")?;
    let interval = value
        .get(b"interval")
        .ok()
        .and_then(|value| value.as_int().ok())
        .unwrap_or(300)
        .max(1) as u64;
    let warning = value
        .get(b"warning message")
        .ok()
        .and_then(|value| String::from_utf8(value.as_bytes().unwrap_or_default().to_vec()).ok());
    if let Ok(reason) = value.get(b"failure reason") {
        let reason = String::from_utf8_lossy(reason.as_bytes().unwrap_or_default());
        bail!("tracker failure: {reason}");
    }
    let raw_peers = value.get(b"peers")?;
    let mut peers = Vec::new();
    if let Value::Bytes(raw) = raw_peers {
        if raw.len() % 6 != 0 {
            bail!("compact tracker peer list has invalid length");
        }
        for chunk in raw.chunks_exact(6) {
            let address = SocketAddr::from((
                <[u8; 4]>::try_from(&chunk[..4]).unwrap(),
                u16::from_be_bytes([chunk[4], chunk[5]]),
            ));
            peers.push(TrackerPeer {
                address,
                peer_id: None,
            });
        }
    } else {
        for value in raw_peers.as_list()? {
            let ip = String::from_utf8(value.get(b"ip")?.as_bytes()?.to_vec())?;
            let port = value.get(b"port")?.as_int()? as u16;
            let peer_id = value
                .get(b"peer id")
                .ok()
                .and_then(|value| <[u8; 20]>::try_from(value.as_bytes().unwrap_or_default()).ok());
            peers.push(TrackerPeer {
                address: SocketAddr::new(ip.parse()?, port),
                peer_id,
            });
        }
    }
    Ok(TrackerResponse {
        interval,
        peers,
        warning,
    })
}

fn parse_http_endpoint(endpoint: &str) -> Result<(String, u16, String)> {
    let endpoint = endpoint
        .strip_prefix("http://")
        .context("tracker endpoint must use http://")?;
    let (authority, path) = endpoint.split_once('/').unwrap_or((endpoint, ""));
    let (host, port) = authority
        .rsplit_once(':')
        .map(|(host, port)| (host.to_owned(), port.parse().unwrap_or(80)))
        .unwrap_or((authority.to_owned(), 80));
    Ok((host, port, format!("/{path}")))
}

fn parse_query(query: &str) -> HashMap<String, Vec<u8>> {
    query
        .split('&')
        .filter_map(|part| part.split_once('='))
        .map(|(key, value)| (percent_decode(key), percent_decode_bytes(value)))
        .collect()
}

fn parse_hash_param(params: &HashMap<String, Vec<u8>>, key: &str) -> Result<[u8; 20]> {
    let value = params.get(key).context("tracker request has no hash")?;
    value
        .as_slice()
        .try_into()
        .map_err(|_| anyhow::anyhow!("tracker {key} is not 20 bytes"))
}

fn percent_encode(value: &[u8]) -> String {
    let mut output = String::with_capacity(value.len() * 3);
    for byte in value {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'~') {
            output.push(*byte as char);
        } else {
            output.push_str(&format!("%{byte:02X}"));
        }
    }
    output
}

fn percent_decode(value: &str) -> String {
    String::from_utf8(percent_decode_bytes(value)).unwrap_or_default()
}

fn percent_decode_bytes(value: &str) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(value.len());
    let input = value.as_bytes();
    let mut index = 0;
    while index < input.len() {
        if input[index] == b'%' && index + 2 < input.len() {
            if let Ok(byte) = u8::from_str_radix(&value[index + 1..index + 3], 16) {
                bytes.push(byte);
                index += 3;
                continue;
            }
        }
        if input[index] == b'+' {
            bytes.push(b' ');
        } else {
            bytes.push(input[index]);
        }
        index += 1;
    }
    bytes
}

fn compact_peer(address: SocketAddr) -> Vec<u8> {
    match address {
        SocketAddr::V4(value) => {
            let mut output = value.ip().octets().to_vec();
            output.extend_from_slice(&value.port().to_be_bytes());
            output
        }
        SocketAddr::V6(_) => Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_compact_tracker_response() {
        let mut peers = [127_u8, 0, 0, 1, 0x16, 0x33].to_vec();
        peers.extend_from_slice(&[10, 0, 0, 2, 0x12, 0x34]);
        let body = crate::bencode::encode(&Value::dict([
            (b"interval".to_vec(), Value::Int(60)),
            (b"peers".to_vec(), Value::Bytes(peers)),
        ]));
        let mut response =
            format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n", body.len()).into_bytes();
        response.extend_from_slice(&body);
        let parsed = parse_tracker_http_response(&response).unwrap();
        assert_eq!(parsed.interval, 60);
        assert_eq!(parsed.peers.len(), 2);
        assert_eq!(parsed.peers[0].address.port(), 5683);
    }

    #[test]
    fn tracker_hashes_do_not_require_utf8() {
        let params = parse_query("info_hash=%FF%FE&peer_id=%80%81");
        assert_eq!(params["info_hash"], vec![0xff, 0xfe]);
        assert!(parse_hash_param(&params, "info_hash").is_err());
        assert!(parse_hash_param(&params, "peer_id").is_err());
    }

    #[test]
    fn stopped_announce_removes_only_that_peer() {
        let mut registry = TrackerRegistry::default();
        let first = [1_u8; 20];
        let second = [2_u8; 20];
        let ttl = Duration::from_secs(60);
        assert!(registry
            .announce(
                [3_u8; 20],
                first,
                "127.0.0.1:1001".parse().unwrap(),
                ttl,
                None
            )
            .is_empty());
        assert_eq!(
            registry
                .announce(
                    [3_u8; 20],
                    second,
                    "127.0.0.1:1002".parse().unwrap(),
                    ttl,
                    None
                )
                .len(),
            1
        );
        assert!(registry
            .announce(
                [3_u8; 20],
                first,
                "127.0.0.1:1001".parse().unwrap(),
                ttl,
                Some("stopped")
            )
            .is_empty());
        assert_eq!(
            registry
                .announce(
                    [3_u8; 20],
                    first,
                    "127.0.0.1:1001".parse().unwrap(),
                    ttl,
                    None
                )
                .len(),
            1
        );
    }

    #[test]
    fn tracker_server_round_trip() {
        let server = TrackerServer::bind("127.0.0.1:0").unwrap();
        let address = server.local_addr().unwrap();
        thread::spawn(move || server.serve_forever().unwrap());
        let client = TrackerClient::new(format!("http://{address}/announce"));
        let response = client
            .announce(&TrackerRequest {
                info_hash: [7; 20],
                peer_id: [8; 20],
                port: 1234,
                uploaded: 0,
                downloaded: 0,
                left: 1,
                event: Some("started".into()),
            })
            .unwrap();
        assert_eq!(response.interval, 120);
    }
}
