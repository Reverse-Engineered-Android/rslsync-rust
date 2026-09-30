use anyhow::{bail, Context, Result};
use ed25519_dalek::SigningKey;
use rand::RngCore;
use sha1::{Digest, Sha1};

const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ShareKey {
    pub key_type: char,
    pub body: [u8; 20],
    pub read_only_psk: Option<[u8; 20]>,
}

impl ShareKey {
    pub fn parse(value: &str) -> Result<Self> {
        let mut chars = value.chars();
        let key_type = chars.next().context("empty share key")?;
        if !matches!(key_type, 'A' | 'B' | 'D' | 'E') {
            bail!("unsupported share key type {key_type}");
        }
        let body_text: String = chars.collect();
        let body = decode_base32(&body_text)?
            .try_into()
            .map_err(|_| anyhow::anyhow!("share key body is not 20 bytes"))?;
        let public_key: Option<[u8; 32]> = match key_type {
            'A' | 'D' => {
                let signing_key = SigningKey::from_bytes(&ed25519_seed(body));
                Some(signing_key.verifying_key().to_bytes())
            }
            _ => None,
        };
        let read_only_psk = match key_type {
            'A' | 'D' => public_key.map(|public_key| {
                let mut hasher = Sha1::new();
                hasher.update(public_key);
                hasher.finalize().into()
            }),
            'B' | 'E' => Some(body),
            _ => None,
        };
        Ok(Self {
            key_type,
            body,
            read_only_psk,
        })
    }

    pub fn from_read_only(value: &str) -> Result<Self> {
        let key = Self::parse(value)?;
        if !matches!(key.key_type, 'B' | 'E') {
            bail!("read-only compatibility requires a B or E key");
        }
        Ok(key)
    }

    pub fn share_id(&self) -> [u8; 20] {
        let source = self.read_only_psk.unwrap_or(self.body);
        let mut hasher = Sha1::new();
        hasher.update(source);
        hasher.finalize().into()
    }

    pub fn tls_identity(&self) -> String {
        encode_base32(&self.share_id())
    }

    pub fn tls_psk(&self) -> Result<[u8; 20]> {
        self.read_only_psk
            .context("share key has no TLS-PSK material")
    }

    pub fn ed25519_signing_key(&self) -> Result<SigningKey> {
        match self.key_type {
            'A' | 'D' => Ok(SigningKey::from_bytes(&ed25519_seed(self.body))),
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
        let body = random_body();
        Self {
            key_type: 'B',
            body,
            read_only_psk: Some(body),
        }
    }

    pub fn generate_read_write() -> Self {
        let body = random_body();
        let signing_key = SigningKey::from_bytes(&ed25519_seed(body));
        let public_key = signing_key.verifying_key().to_bytes();
        Self {
            key_type: 'A',
            body,
            read_only_psk: Some(Sha1::digest(public_key).into()),
        }
    }

    pub fn read_only_link_key(&self) -> Result<Self> {
        let body = self
            .read_only_psk
            .context("share key has no read-only compatibility key")?;
        let key_type = if self.key_type == 'D' { 'E' } else { 'B' };
        Ok(Self {
            key_type,
            body,
            read_only_psk: Some(body),
        })
    }

    pub fn render(&self) -> String {
        format!("{}{}", self.key_type, encode_base32(&self.body))
    }
}

fn ed25519_seed(body: [u8; 20]) -> [u8; 32] {
    let mut seed = [0_u8; 32];
    seed[..20].copy_from_slice(&body);
    seed
}

fn random_body() -> [u8; 20] {
    let mut body = [0_u8; 20];
    rand::thread_rng().fill_bytes(&mut body);
    body
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
        bail!("non-zero base32 padding bits");
    }
    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base32_round_trip() {
        let value = [
            0_u8, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19,
        ];
        assert_eq!(decode_base32(&encode_base32(&value)).unwrap(), value);
    }

    #[test]
    fn b_key_has_upstream_tls_material() {
        let key = ShareKey::generate_read_only();
        assert_eq!(key.share_id().len(), 20);
        assert_eq!(key.tls_identity().len(), 32);
        assert_eq!(key.tls_psk().unwrap(), key.body);
    }

    #[test]
    fn generated_read_write_key_is_signable_and_derives_read_only_material() {
        let key = ShareKey::generate_read_write();
        assert_eq!(key.key_type, 'A');
        assert!(key.ed25519_public_key().is_ok());
        assert!(key.ed25519_signing_key().is_ok());
        assert_eq!(
            key.tls_psk().unwrap(),
            Sha1::digest(key.ed25519_public_key().unwrap()).as_slice()
        );
        assert_eq!(
            ShareKey::parse(&key.render()).unwrap().tls_psk().unwrap(),
            key.tls_psk().unwrap()
        );
        let read_only = key.read_only_link_key().unwrap();
        assert_eq!(read_only.key_type, 'B');
        assert_eq!(read_only.share_id(), key.share_id());
        assert!(read_only.ed25519_signing_key().is_err());
    }

    #[test]
    fn a_key_derives_b_key_and_signing_identity() {
        let body = [
            20_u8, 19, 18, 17, 16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1,
        ];
        let key = ShareKey::parse(&format!("A{}", encode_base32(&body))).unwrap();
        let public_key = key.ed25519_public_key().unwrap();
        let expected_psk: [u8; 20] = Sha1::digest(public_key).into();
        assert_eq!(key.tls_psk().unwrap(), expected_psk);
        assert_eq!(key.share_id(), Sha1::digest(expected_psk).as_slice());
        assert_eq!(
            key.ed25519_signing_key()
                .unwrap()
                .verifying_key()
                .to_bytes(),
            public_key
        );
    }

    #[test]
    fn b_and_e_keys_use_decoded_body_as_tls_psk() {
        for key_type in ['B', 'E'] {
            let body = [7_u8; 20];
            let key = ShareKey::parse(&format!("{key_type}{}", encode_base32(&body))).unwrap();
            assert_eq!(key.tls_psk().unwrap(), body);
            assert_eq!(key.share_id(), Sha1::digest(body).as_slice());
        }
    }
}
