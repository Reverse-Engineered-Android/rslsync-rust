use anyhow::{bail, Context, Result};
use ed25519_dalek::SigningKey;
use rand::RngCore;
use sha1::{Digest, Sha1};
use tiny_keccak::{Hasher as KeccakHasher, Keccak};

const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ShareKeyFamily {
    Standard,
    EncryptCapable,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ShareKey {
    pub key_type: char,
    pub body: Vec<u8>,
}

/// A share key the caller supplied that this implementation deliberately
/// rejects: an Advanced Folder key, an unknown key type, a malformed body, or
/// a role that cannot be derived from the given key. These are caller errors,
/// not server faults, so the HTTP layer maps them to 400 instead of 500.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InvalidKeyError {
    message: String,
}

impl InvalidKeyError {
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }

    pub fn message(&self) -> &str {
        &self.message
    }
}

impl std::fmt::Display for InvalidKeyError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl std::error::Error for InvalidKeyError {}

/// Build an `InvalidKeyError` and wrap it into the `anyhow` error the rest of
/// the crate propagates, so `downcast_ref` can recover it at the HTTP edge.
fn invalid_key(message: impl Into<String>) -> anyhow::Error {
    anyhow::Error::new(InvalidKeyError::new(message))
}

/// Recover a caller-supplied-key rejection from a propagated error chain.
pub fn invalid_key_error(error: &anyhow::Error) -> Option<&InvalidKeyError> {
    error.downcast_ref::<InvalidKeyError>()
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
pub struct DerivedShareKeys {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub read_write: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub read_only: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub encrypted: Option<String>,
}

impl ShareKey {
    pub fn parse(value: &str) -> Result<Self> {
        let value = value.trim();
        let mut chars = value.chars();
        let key_type = chars.next().context("empty share key")?;
        if matches!(key_type, 'G' | 'H') {
            return Err(invalid_key("Advanced Folder keys are not supported"));
        }
        if !matches!(key_type, 'A' | 'B' | 'D' | 'E' | 'F') {
            return Err(invalid_key(format!(
                "unsupported Standard Folder key type {key_type}"
            )));
        }
        let body_text: String = chars.collect();
        let body = decode_base32(&body_text).map_err(|error| invalid_key(format!("{error:#}")))?;
        let expected_len = if key_type == 'E' { 36 } else { 20 };
        if body.len() != expected_len {
            return Err(invalid_key(format!(
                "{key_type} share key body must be {expected_len} bytes, got {}",
                body.len()
            )));
        }
        Ok(Self { key_type, body })
    }

    pub fn from_read_only(value: &str) -> Result<Self> {
        let key = Self::parse(value)?;
        if !matches!(key.key_type, 'B' | 'E' | 'F') {
            return Err(invalid_key(
                "read-only compatibility requires a B, E, or F key",
            ));
        }
        Ok(key)
    }

    pub fn family(&self) -> ShareKeyFamily {
        match self.key_type {
            'D' | 'E' | 'F' => ShareKeyFamily::EncryptCapable,
            _ => ShareKeyFamily::Standard,
        }
    }

    pub fn is_read_write(&self) -> bool {
        matches!(self.key_type, 'A' | 'D')
    }

    pub fn is_encrypted_only(&self) -> bool {
        self.key_type == 'F'
    }

    pub fn can_encrypt(&self) -> bool {
        matches!(self.key_type, 'D' | 'E')
    }

    pub fn encryption_key(&self) -> Result<[u8; 16]> {
        match self.key_type {
            'D' => Ok(keccak_256(&self.body)[..16].try_into().unwrap()),
            'E' => Ok(self.body[20..36].try_into().unwrap()),
            'F' => bail!("encrypted-only keys cannot decrypt file content"),
            other => bail!("{other} keys have no encryption capability"),
        }
    }

    pub fn share_id(&self) -> [u8; 20] {
        if self.family() == ShareKeyFamily::EncryptCapable {
            keccak_256(&self.access_key())[..20].try_into().unwrap()
        } else {
            Sha1::digest(self.access_key()).into()
        }
    }

    pub fn tls_identity(&self) -> String {
        encode_base32(&self.share_id())
    }

    pub fn tls_psk(&self) -> Result<Vec<u8>> {
        match self.key_type {
            'A' | 'B' | 'F' => Ok(self.access_key().to_vec()),
            'D' | 'E' => Ok(self.read_only_link_key()?.body),
            other => bail!("{other} keys have no upstream authentication key"),
        }
    }

    /// The share type an encrypted-only peer declares in the SRPEH handshake.
    ///
    /// Verified against official client 3.1.2: a peer holding only the
    /// encrypted key announces `type=4`, while `D`/`E` peers omit the field.
    pub const ENCRYPTED_SHARE_TYPE: i64 = 4;

    /// The SRP password for a handshake in which the peer declared `share_type`.
    ///
    /// The declared type selects the password: an encrypted-only peer
    /// authenticates with the 20-byte access key (the `F` body), whereas the
    /// ordinary `D`/`E` roles use the 36-byte read-only body. Serving the wrong
    /// password for the declared type fails the client proof, which is why the
    /// field cannot be ignored.
    pub fn tls_psk_for_share_type(&self, share_type: Option<i64>) -> Result<Vec<u8>> {
        match share_type {
            Some(Self::ENCRYPTED_SHARE_TYPE) => {
                if self.family() != ShareKeyFamily::EncryptCapable {
                    bail!("{} keys cannot serve an encrypted-only peer", self.key_type);
                }
                Ok(self.access_key().to_vec())
            }
            Some(other) => bail!("unsupported SRPEH share type {other}"),
            None => self.tls_psk(),
        }
    }

    /// The share type this key's own role must declare during a handshake.
    pub fn srpeh_share_type(&self) -> Option<i64> {
        self.is_encrypted_only()
            .then_some(Self::ENCRYPTED_SHARE_TYPE)
    }

    pub fn ed25519_signing_key(&self) -> Result<SigningKey> {
        match self.key_type {
            'A' | 'D' => Ok(SigningKey::from_bytes(&ed25519_seed(&self.body))),
            _ => bail!("{} keys cannot sign file metadata", self.key_type),
        }
    }

    pub fn ed25519_public_key(&self) -> Result<[u8; 32]> {
        match self.key_type {
            'A' | 'D' => Ok(self.ed25519_signing_key()?.verifying_key().to_bytes()),
            _ => bail!("{} keys do not expose an Ed25519 public key", self.key_type),
        }
    }

    pub fn generate_read_only() -> Self {
        Self {
            key_type: 'B',
            body: random_bytes(20),
        }
    }

    pub fn generate_read_write() -> Self {
        Self::generate_encrypt_capable_read_write()
    }

    pub fn generate_standard_read_write() -> Self {
        Self {
            key_type: 'A',
            body: random_bytes(20),
        }
    }

    pub fn generate_encrypt_capable_read_write() -> Self {
        Self {
            key_type: 'D',
            body: random_bytes(20),
        }
    }

    pub fn read_only_link_key(&self) -> Result<Self> {
        match self.key_type {
            'A' => Ok(Self {
                key_type: 'B',
                body: self.access_key().to_vec(),
            }),
            'D' => Ok(Self {
                key_type: 'E',
                body: self
                    .encrypted_key()
                    .context("D key has no encrypted key")?
                    .body
                    .iter()
                    .copied()
                    .chain(keccak_256(&self.body)[..16].iter().copied())
                    .collect(),
            }),
            'B' | 'E' | 'F' => Ok(self.clone()),
            other => Err(invalid_key(format!(
                "{other} keys have no read-only compatibility key"
            ))),
        }
    }

    pub fn encrypted_link_key(&self) -> Result<Self> {
        match self.key_type {
            'D' | 'E' | 'F' => Ok(Self {
                key_type: 'F',
                body: self.access_key().to_vec(),
            }),
            'A' | 'B' => Err(invalid_key(format!(
                "{} keys have no upstream encrypted key",
                self.key_type
            ))),
            other => Err(invalid_key(format!(
                "{other} keys have no upstream encrypted key"
            ))),
        }
    }

    pub fn derived_keys(&self) -> DerivedShareKeys {
        let read_write = self.is_read_write().then(|| self.render());
        let read_only = (!self.is_encrypted_only())
            .then(|| self.read_only_link_key().ok().map(|key| key.render()))
            .flatten();
        let encrypted = self.encrypted_link_key().ok().map(|key| key.render());
        DerivedShareKeys {
            read_write,
            read_only,
            encrypted,
        }
    }

    pub fn render(&self) -> String {
        format!("{}{}", self.key_type, encode_base32(&self.body))
    }

    fn access_key(&self) -> [u8; 20] {
        match self.key_type {
            'A' => Sha1::digest(self.ed25519_public_key().unwrap()).into(),
            'B' | 'F' => self.body[..20].try_into().unwrap(),
            'D' => self.encrypted_key().unwrap().body[..20].try_into().unwrap(),
            'E' => self.body[..20].try_into().unwrap(),
            _ => unreachable!(),
        }
    }

    fn encrypted_key(&self) -> Result<Self> {
        match self.key_type {
            'D' => Ok(Self {
                key_type: 'F',
                body: keccak_256(&self.ed25519_public_key()?).to_vec()[..20].to_vec(),
            }),
            'E' | 'F' => Ok(Self {
                key_type: 'F',
                body: self.body[..20].to_vec(),
            }),
            other => Err(invalid_key(format!(
                "{other} keys have no upstream encrypted key"
            ))),
        }
    }
}

fn ed25519_seed(body: &[u8]) -> [u8; 32] {
    let mut seed = [0_u8; 32];
    seed[..20].copy_from_slice(body);
    seed
}

fn random_bytes(len: usize) -> Vec<u8> {
    let mut body = vec![0_u8; len];
    rand::thread_rng().fill_bytes(&mut body);
    body
}

fn keccak_256(input: &[u8]) -> [u8; 32] {
    let mut hasher = Keccak::v256();
    hasher.update(input);
    let mut output = [0_u8; 32];
    hasher.finalize(&mut output);
    output
}

pub fn encode_base32(input: &[u8]) -> String {
    let mut output = String::with_capacity((input.len() * 8).div_ceil(5));
    let mut accumulator = 0_u32;
    let mut bits = 0_u32;
    for byte in input {
        accumulator = (accumulator << 8) | u32::from(*byte);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            output.push(ALPHABET[((accumulator >> bits) & 31) as usize] as char);
        }
    }
    if bits > 0 {
        output.push(ALPHABET[((accumulator << (5 - bits)) & 31) as usize] as char);
    }
    output
}

pub fn decode_base32(input: &str) -> Result<Vec<u8>> {
    let mut output = Vec::with_capacity(input.len() * 5 / 8);
    let mut accumulator = 0_u32;
    let mut bits = 0_u32;
    for character in input.bytes() {
        let value = ALPHABET
            .iter()
            .position(|candidate| *candidate == character)
            .with_context(|| format!("invalid base32 character {}", character as char))?;
        accumulator = (accumulator << 5) | value as u32;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            output.push((accumulator >> bits) as u8);
        }
    }
    if bits > 0 && (accumulator & ((1 << bits) - 1)) != 0 {
        return Err(invalid_key("non-zero base32 padding bits"));
    }
    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;

    const D_KEY: &str = "DJMJ5MWYMBKS5SCWMBRQ7LXBGZAQGLSAQ";
    const E_KEY: &str = "EH5L5UOAVPTVUQTRQRVGFD5XGUQB5B6ZDZR47LKBWQANFZSCU5CTMTFG3CI";
    const F_KEY: &str = "FH5L5UOAVPTVUQTRQRVGFD5XGUQB5B6ZD";

    #[test]
    fn base32_round_trip() {
        let value = [
            0_u8, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19,
        ];
        assert_eq!(decode_base32(&encode_base32(&value)).unwrap(), value);
    }

    #[test]
    fn official_d_ef_keys_and_share_id_match() {
        let d = ShareKey::parse(D_KEY).unwrap();
        assert_eq!(
            d.ed25519_public_key().unwrap().as_slice(),
            &hex::decode("a47d3e6199ca4332314adcefb56e057fc9d52999e84ade89ceebfd0fd9645651")
                .unwrap()
        );
        assert_eq!(
            d.share_id(),
            hex::decode("d9c0ea752a4abdadcd2d5979b4e288560bcdb61d")
                .unwrap()
                .as_slice()
        );
        assert_eq!(d.read_only_link_key().unwrap().render(), E_KEY);
        assert_eq!(d.encrypted_link_key().unwrap().render(), F_KEY);
        assert_eq!(ShareKey::parse(E_KEY).unwrap().share_id(), d.share_id());
        assert_eq!(ShareKey::parse(F_KEY).unwrap().share_id(), d.share_id());
        let e = ShareKey::parse(E_KEY).unwrap();
        assert_eq!(d.tls_psk().unwrap().len(), 36);
        assert_eq!(d.tls_psk().unwrap().as_slice(), e.body.as_slice());
        assert_eq!(e.tls_psk().unwrap().as_slice(), e.body.as_slice());
        assert_eq!(
            ShareKey::parse(F_KEY).unwrap().tls_psk().unwrap()[..20],
            ShareKey::parse(F_KEY).unwrap().body[..]
        );
    }

    #[test]
    fn official_a_b_family_matches_sha1_domain() {
        let a = ShareKey::parse("AJMJ5MWYMBKS5SCWMBRQ7LXBGZAQGLSAQ").unwrap();
        assert_eq!(
            a.share_id(),
            hex::decode("dc18d6f848d777fda73a720785c87e3d690cceee")
                .unwrap()
                .as_slice()
        );
        let b = a.read_only_link_key().unwrap();
        assert_eq!(b.render(), "BPFFEO6MQCDNHCB4BJFSNAPTXIX6OMXYU");
        assert_eq!(b.share_id(), a.share_id());
        assert_eq!(a.tls_psk().unwrap(), a.access_key().to_vec());
        assert_eq!(a.tls_psk().unwrap().len(), 20);
        assert_eq!(b.tls_psk().unwrap(), b.access_key().to_vec());
        assert_eq!(b.tls_psk().unwrap().len(), 20);
        assert!(a.encrypted_link_key().is_err());
    }

    #[test]
    fn advanced_folder_keys_are_explicitly_rejected() {
        for prefix in ['G', 'H'] {
            let value = format!("{prefix}{}", encode_base32(&[1_u8; 32]));
            let error = ShareKey::parse(&value).unwrap_err().to_string();
            assert!(error.contains("Advanced Folder keys are not supported"));
        }
    }

    #[test]
    fn generated_encrypt_capable_key_exposes_all_three_roles() {
        let key = ShareKey::generate_read_write();
        assert_eq!(key.key_type, 'D');
        let derived = key.derived_keys();
        assert_eq!(derived.read_write.as_deref(), Some(key.render().as_str()));
        assert!(derived.read_only.unwrap().starts_with('E'));
        assert!(derived.encrypted.unwrap().starts_with('F'));

        let read_only = key.read_only_link_key().unwrap();
        let read_only_derived = read_only.derived_keys();
        assert!(read_only_derived.read_write.is_none());
        assert_eq!(
            read_only_derived.read_only.as_deref(),
            Some(read_only.render().as_str())
        );
        assert!(read_only_derived.encrypted.unwrap().starts_with('F'));

        let encrypted = key.encrypted_link_key().unwrap();
        let encrypted_derived = encrypted.derived_keys();
        assert!(encrypted_derived.read_write.is_none());
        assert!(encrypted_derived.read_only.is_none());
        assert_eq!(
            encrypted_derived.encrypted.as_deref(),
            Some(encrypted.render().as_str())
        );
    }
}
