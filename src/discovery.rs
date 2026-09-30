use anyhow::{bail, Context, Result};
use std::collections::BTreeMap;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4, UdpSocket};
use std::thread::{self, JoinHandle};
use std::time::Duration;

pub const DISCOVERY_MAGIC: &[u8] = b"RESSN\0";
pub const DEFAULT_DISCOVERY_PORT: u16 = 3838;
pub const DEFAULT_MULTICAST: &str = "239.192.0.0:3838";
pub const DEFAULT_BROADCAST: &str = "255.255.255.255:3838";
pub const DEFAULT_LOOPBACK: &str = "127.0.0.1:3838";

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LanPing {
    pub peer_id: [u8; 20],
    pub port: u16,
    pub shares: Vec<[u8; 20]>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Bencode {
    Bytes(Vec<u8>),
    Int(i64),
    List(Vec<Bencode>),
    Dict(BTreeMap<Vec<u8>, Bencode>),
}

impl LanPing {
    pub fn encode(&self) -> Vec<u8> {
        let mut dict = BTreeMap::new();
        dict.insert(b"m".to_vec(), Bencode::Bytes(b"ping".to_vec()));
        dict.insert(b"peer".to_vec(), Bencode::Bytes(self.peer_id.to_vec()));
        dict.insert(b"port".to_vec(), Bencode::Int(self.port.into()));
        dict.insert(
            b"shares".to_vec(),
            Bencode::List(
                self.shares
                    .iter()
                    .map(|share| Bencode::Bytes(share.to_vec()))
                    .collect(),
            ),
        );
        let mut output = DISCOVERY_MAGIC.to_vec();
        output.extend(encode(&Bencode::Dict(dict)));
        output
    }

    pub fn decode(data: &[u8]) -> Result<Self> {
        let payload = data
            .strip_prefix(DISCOVERY_MAGIC)
            .context("missing RESSN discovery magic")?;
        let (value, consumed) = decode_at(payload)?;
        if consumed != payload.len() {
            bail!("trailing bytes in discovery packet");
        }
        let dict = match value {
            Bencode::Dict(dict) => dict,
            _ => bail!("discovery payload is not a dictionary"),
        };
        if get_bytes(&dict, b"m")? != b"ping" {
            bail!("only LAN ping is supported");
        }
        let peer_id = fixed_20(get_bytes(&dict, b"peer")?)?;
        let port = match dict.get(b"port".as_slice()) {
            Some(Bencode::Int(value)) if *value > 0 && *value <= i64::from(u16::MAX) => {
                *value as u16
            }
            _ => bail!("invalid ping port"),
        };
        let shares = match dict.get(b"shares".as_slice()) {
            Some(Bencode::List(items)) => items
                .iter()
                .map(|item| match item {
                    Bencode::Bytes(value) => fixed_20(value),
                    _ => bail!("share is not a byte string"),
                })
                .collect::<Result<Vec<_>>>()?,
            _ => bail!("missing share list"),
        };
        Ok(Self {
            peer_id,
            port,
            shares,
        })
    }

    pub fn endpoint(&self, source: SocketAddr) -> SocketAddr {
        SocketAddr::new(source.ip(), self.port)
    }
}

pub fn spawn_advertiser(
    peer_id: [u8; 20],
    port: u16,
    shares: Vec<[u8; 20]>,
) -> Result<JoinHandle<()>> {
    let multicast_socket = UdpSocket::bind(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0))
        .context("bind upstream LAN discovery sender")?;
    multicast_socket
        .set_broadcast(true)
        .context("enable upstream LAN discovery broadcast")?;
    let loopback_socket = UdpSocket::bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0))
        .context("bind upstream loopback discovery sender")?;
    let packet = LanPing {
        peer_id,
        port,
        shares,
    }
    .encode();
    let destinations: [(SocketAddr, bool); 3] = [
        (
            DEFAULT_MULTICAST
                .parse()
                .context("parse upstream multicast endpoint")?,
            false,
        ),
        (
            DEFAULT_BROADCAST
                .parse()
                .context("parse upstream broadcast endpoint")?,
            false,
        ),
        (
            DEFAULT_LOOPBACK
                .parse()
                .context("parse upstream loopback endpoint")?,
            true,
        ),
    ];
    Ok(thread::spawn(move || loop {
        for (destination, loopback) in destinations {
            let socket = if loopback {
                &loopback_socket
            } else {
                &multicast_socket
            };
            if let Err(error) = socket.send_to(&packet, destination) {
                eprintln!(
                    "upstream discovery send to {} failed: {}",
                    destination, error
                );
            }
        }
        thread::sleep(Duration::from_secs(1));
    }))
}

fn get_bytes<'a>(dict: &'a BTreeMap<Vec<u8>, Bencode>, key: &[u8]) -> Result<&'a [u8]> {
    match dict.get(key) {
        Some(Bencode::Bytes(value)) => Ok(value),
        _ => bail!("missing byte-string field"),
    }
}

fn fixed_20(value: &[u8]) -> Result<[u8; 20]> {
    value
        .try_into()
        .map_err(|_| anyhow::anyhow!("expected a 20-byte identifier"))
}

pub fn encode(value: &Bencode) -> Vec<u8> {
    let mut output = Vec::new();
    encode_into(value, &mut output);
    output
}

fn encode_into(value: &Bencode, output: &mut Vec<u8>) {
    match value {
        Bencode::Bytes(bytes) => {
            output.extend_from_slice(bytes.len().to_string().as_bytes());
            output.push(b':');
            output.extend_from_slice(bytes);
        }
        Bencode::Int(value) => {
            output.push(b'i');
            output.extend_from_slice(value.to_string().as_bytes());
            output.push(b'e');
        }
        Bencode::List(items) => {
            output.push(b'l');
            for item in items {
                encode_into(item, output);
            }
            output.push(b'e');
        }
        Bencode::Dict(items) => {
            output.push(b'd');
            for (key, item) in items {
                encode_into(&Bencode::Bytes(key.clone()), output);
                encode_into(item, output);
            }
            output.push(b'e');
        }
    }
}

fn decode_at(data: &[u8]) -> Result<(Bencode, usize)> {
    let first = *data.first().context("empty bencode value")?;
    match first {
        b'i' => {
            let end = data
                .iter()
                .position(|byte| *byte == b'e')
                .context("unterminated integer")?;
            let value = std::str::from_utf8(&data[1..end])?.parse::<i64>()?;
            Ok((Bencode::Int(value), end + 1))
        }
        b'l' => {
            let mut cursor = 1;
            let mut values = Vec::new();
            while data.get(cursor) != Some(&b'e') {
                let (value, used) = decode_at(&data[cursor..])?;
                values.push(value);
                cursor += used;
            }
            Ok((Bencode::List(values), cursor + 1))
        }
        b'd' => {
            let mut cursor = 1;
            let mut values = BTreeMap::new();
            while data.get(cursor) != Some(&b'e') {
                let (key, key_used) = decode_at(&data[cursor..])?;
                let key = match key {
                    Bencode::Bytes(value) => value,
                    _ => bail!("bencode dictionary key is not a byte string"),
                };
                cursor += key_used;
                let (value, value_used) = decode_at(&data[cursor..])?;
                cursor += value_used;
                values.insert(key, value);
            }
            Ok((Bencode::Dict(values), cursor + 1))
        }
        b'0'..=b'9' => {
            let colon = data
                .iter()
                .position(|byte| *byte == b':')
                .context("unterminated string")?;
            let length = std::str::from_utf8(&data[..colon])?.parse::<usize>()?;
            let start = colon + 1;
            let end = start
                .checked_add(length)
                .context("string length overflow")?;
            if end > data.len() {
                bail!("truncated bencode string");
            }
            Ok((Bencode::Bytes(data[start..end].to_vec()), end))
        }
        _ => bail!("invalid bencode value"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matches_ressn_wire_shape() {
        let ping = LanPing {
            peer_id: [0x20; 20],
            port: 57301,
            shares: vec![[0x21; 20], [0x57; 20]],
        };
        let decoded = LanPing::decode(&ping.encode()).unwrap();
        assert_eq!(decoded, ping);
        let mut expected = b"RESSN\0d1:m4:ping4:peer20:".to_vec();
        expected.extend([0x20; 20]);
        expected.extend_from_slice(b"4:porti57301e6:sharesl20:");
        expected.extend([0x21; 20]);
        expected.extend_from_slice(b"20:");
        expected.extend([0x57; 20]);
        expected.extend_from_slice(b"ee");
        assert_eq!(ping.encode(), expected);
    }
}
