use crate::bencode::{encode, Value};
use anyhow::{bail, Context, Result};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use sha1::{Digest, Sha1};
use std::collections::BTreeMap;

/// Signed folder access-control entry.
///
/// The field names follow the upstream merge-controller vocabulary (`type`,
/// `t`, `s`, `o`, `ot`, `issuer`, and `sig`) while the validation rules are
/// kept explicit so a malformed entry cannot become a write authorization.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AclEntry {
    pub entry_type: u8,
    pub time: i64,
    pub state: u8,
    pub owner: [u8; 20],
    pub owner_time: i64,
    pub issuer: [u8; 20],
    pub signature: Vec<u8>,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct AclState {
    pub entries: Vec<AclEntry>,
}

impl AclEntry {
    pub fn new(
        entry_type: u8,
        time: i64,
        state: u8,
        owner: [u8; 20],
        owner_time: i64,
        issuer: [u8; 20],
    ) -> Self {
        Self {
            entry_type,
            time,
            state,
            owner,
            owner_time,
            issuer,
            signature: Vec::new(),
        }
    }

    pub fn signed_body(&self) -> Value {
        Value::dict([
            (b"issuer".to_vec(), Value::bytes(self.issuer)),
            (b"o".to_vec(), Value::bytes(self.owner)),
            (b"ot".to_vec(), Value::Int(self.owner_time)),
            (b"s".to_vec(), Value::Int(i64::from(self.state))),
            (b"t".to_vec(), Value::Int(self.time)),
            (b"type".to_vec(), Value::Int(i64::from(self.entry_type))),
        ])
    }

    pub fn sign(&mut self, signing_key: &SigningKey) -> Result<()> {
        self.signature = signing_key
            .sign(&Sha1::digest(encode(&self.signed_body())))
            .to_bytes()
            .to_vec();
        Ok(())
    }

    pub fn verify(&self, public_key: &[u8; 32]) -> Result<()> {
        if self.signature.len() != 64 {
            bail!("ACL signature must be 64 bytes");
        }
        let public = VerifyingKey::from_bytes(public_key).context("invalid ACL public key")?;
        let signature = Signature::from_slice(&self.signature).context("invalid ACL signature")?;
        public
            .verify(&Sha1::digest(encode(&self.signed_body())), &signature)
            .context("invalid ACL entry signature")
    }

    pub fn wire_value(&self) -> Value {
        let mut fields = match self.signed_body() {
            Value::Dict(fields) => fields,
            _ => BTreeMap::new(),
        };
        fields.insert(b"sig".to_vec(), Value::bytes(self.signature.clone()));
        Value::Dict(fields)
    }

    pub fn parse(value: &Value) -> Result<Self> {
        let body = value.get(b"entry").unwrap_or(value);
        let entry_type = body.get(b"type")?.as_int()?;
        let time = body.get(b"t")?.as_int()?;
        let state = body.get(b"s")?.as_int()?;
        let owner = value
            .get(b"o")
            .or_else(|_| body.get(b"o"))?
            .as_bytes()?
            .try_into()
            .map_err(|_| anyhow::anyhow!("ACL owner is not 20 bytes"))?;
        let owner_time = value.get(b"ot").or_else(|_| body.get(b"ot"))?.as_int()?;
        let issuer = value
            .get(b"issuer")
            .or_else(|_| body.get(b"issuer"))?
            .as_bytes()?
            .try_into()
            .map_err(|_| anyhow::anyhow!("ACL issuer is not 20 bytes"))?;
        let signature = value.get(b"sig")?.as_bytes()?.to_vec();
        let entry_type = u8::try_from(entry_type).context("ACL type does not fit u8")?;
        let state = u8::try_from(state).context("ACL state does not fit u8")?;
        Ok(Self {
            entry_type,
            time,
            state,
            owner,
            owner_time,
            issuer,
            signature,
        })
    }
}

impl AclState {
    pub fn insert(&mut self, entry: AclEntry) {
        self.entries.push(entry);
        self.entries.sort_by(|left, right| {
            left.issuer
                .cmp(&right.issuer)
                .then(left.owner.cmp(&right.owner))
                .then(left.time.cmp(&right.time))
                .then(left.entry_type.cmp(&right.entry_type))
        });
    }

    pub fn hash(&self) -> [u8; 20] {
        let mut values = self
            .entries
            .iter()
            .map(AclEntry::wire_value)
            .collect::<Vec<_>>();
        values.sort_by_key(encode);
        let payload = encode(&Value::List(values));
        Sha1::digest(payload).into()
    }

    pub fn wire_entries(&self) -> Vec<Value> {
        self.entries.iter().map(AclEntry::wire_value).collect()
    }
}

pub fn empty_hash() -> [u8; 20] {
    AclState::default().hash()
}

pub fn parse_entries(value: &Value) -> Result<Vec<AclEntry>> {
    value.as_list()?.iter().map(AclEntry::parse).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;

    #[test]
    fn signed_acl_entries_round_trip_and_verify() {
        let signing_key = SigningKey::from_bytes(&[7_u8; 32]);
        let mut entry = AclEntry::new(1, 12, 1, [2_u8; 20], 11, [3_u8; 20]);
        entry.sign(&signing_key).unwrap();
        let value = entry.wire_value();
        let parsed = AclEntry::parse(&value).unwrap();
        parsed
            .verify(&signing_key.verifying_key().to_bytes())
            .unwrap();
        assert_eq!(parsed, entry);
    }

    #[test]
    fn acl_hash_is_order_stable() {
        let mut state = AclState::default();
        state.insert(AclEntry::new(1, 1, 1, [2; 20], 1, [3; 20]));
        state.insert(AclEntry::new(1, 0, 1, [1; 20], 1, [3; 20]));
        let first = state.hash();
        state.entries.reverse();
        assert_eq!(state.hash(), first);
    }
}
