use crate::caller_error::invalid_request;
use crate::secret::ShareKey;
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SyncAccess {
    #[default]
    ReadWrite,
    ReadOnly,
    EncryptedOnly,
}

impl SyncAccess {
    pub fn from_key(key: &ShareKey) -> Self {
        match key.key_type {
            'A' | 'D' => Self::ReadWrite,
            'F' => Self::EncryptedOnly,
            _ => Self::ReadOnly,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::ReadWrite => "read-write",
            Self::ReadOnly => "read-only",
            Self::EncryptedOnly => "encrypted-only",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct SyncLink {
    pub key: String,
    pub access: SyncAccess,
    pub peers: Vec<String>,
    pub device_name: Option<String>,
}

impl SyncLink {
    pub fn parse(value: &str) -> Result<Self> {
        let value = value.trim();
        if value.is_empty() {
            return Err(invalid_request("sync link cannot be empty"));
        }
        if !value.contains("://") {
            let key = ShareKey::parse(value)?;
            return Ok(Self {
                key: key.render(),
                access: SyncAccess::from_key(&key),
                peers: Vec::new(),
                device_name: None,
            });
        }
        let (scheme, rest) = value
            .split_once("://")
            .context("sync link is missing ://")?;
        if scheme != "rustsync" {
            return Err(invalid_request(format!(
                "unsupported sync link scheme {scheme}"
            )));
        }
        let (authority, query) = match rest.split_once('?') {
            Some((authority, query)) => (authority, Some(query)),
            None => (rest, None),
        };
        let key_text = authority
            .split_once('@')
            .map(|(key, _endpoint)| key)
            .unwrap_or(authority);
        let key = ShareKey::parse(key_text)?;
        let mut peers = Vec::new();
        let mut device_name = None;
        let mut access = SyncAccess::from_key(&key);
        if let Some(query) = query {
            for part in query.split('&').filter(|part| !part.is_empty()) {
                let (name, value) = part.split_once('=').unwrap_or((part, ""));
                match name {
                    "peer" | "peers" => {
                        for peer in value.split(',') {
                            let peer = percent_decode(peer)?;
                            if !peer.trim().is_empty() {
                                peers.push(peer.trim().to_owned());
                            }
                        }
                    }
                    "device" => device_name = Some(percent_decode(value)?),
                    "access" => {
                        access = match value {
                            "read-write" | "rw" => SyncAccess::ReadWrite,
                            "read-only" | "ro" => SyncAccess::ReadOnly,
                            "encrypted-only" | "encrypted" => SyncAccess::EncryptedOnly,
                            other => {
                                return Err(invalid_request(format!(
                                    "unsupported sync link access {other}"
                                )))
                            }
                        };
                    }
                    _ => {}
                }
            }
        }
        let key_access = SyncAccess::from_key(&key);
        if access != key_access {
            return Err(invalid_request(
                "sync link access does not match its share key",
            ));
        }
        Ok(Self {
            key: key.render(),
            access: key_access,
            peers,
            device_name,
        })
    }

    pub fn render(&self) -> String {
        let link = format!("rustsync://{}", self.key);
        let mut query = Vec::new();
        query.push(format!("access={}", self.access.as_str()));
        for peer in &self.peers {
            query.push(format!("peer={}", percent_encode(peer)));
        }
        if let Some(device_name) = self
            .device_name
            .as_deref()
            .filter(|device_name| !device_name.trim().is_empty())
        {
            query.push(format!("device={}", percent_encode(device_name)));
        }
        format!("{link}?{}", query.join("&"))
    }
}

fn percent_encode(value: &str) -> String {
    let mut output = String::new();
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'~') {
            output.push(byte as char);
        } else {
            output.push_str(&format!("%{byte:02X}"));
        }
    }
    output
}

fn percent_decode(value: &str) -> Result<String> {
    let bytes = value.as_bytes();
    let mut output = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%' {
            let end = (index + 3).min(bytes.len());
            let hex = value
                .get(index + 1..end)
                .context("truncated percent escape in sync link")?;
            output
                .push(u8::from_str_radix(hex, 16).context("invalid percent escape in sync link")?);
            index = end;
        } else {
            output.push(bytes[index]);
            index += 1;
        }
    }
    String::from_utf8(output).context("sync link query is not UTF-8")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn raw_key_and_uri_round_trip() {
        let key = ShareKey::generate_read_write();
        let link = SyncLink {
            key: key.render(),
            access: SyncAccess::ReadWrite,
            peers: vec!["127.0.0.1:22000".to_owned()],
            device_name: Some("desktop".to_owned()),
        };
        let parsed = SyncLink::parse(&link.render()).unwrap();
        assert_eq!(parsed, link);
        assert_eq!(
            SyncLink::parse(&key.render()).unwrap().access,
            SyncAccess::ReadWrite
        );
    }

    #[test]
    fn rejects_access_that_disagrees_with_key_type() {
        let key = ShareKey::generate_read_only();
        let link = format!("rustsync://{}?access=read-write", key.render());
        assert!(SyncLink::parse(&link).is_err());
    }
}
