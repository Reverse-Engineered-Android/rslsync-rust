use anyhow::{bail, Context, Result};
use std::collections::BTreeMap;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Value {
    Bytes(Vec<u8>),
    Int(i64),
    List(Vec<Value>),
    Dict(BTreeMap<Vec<u8>, Value>),
}

impl Value {
    pub fn bytes(value: impl Into<Vec<u8>>) -> Self {
        Self::Bytes(value.into())
    }

    pub fn dict(entries: impl IntoIterator<Item = (impl Into<Vec<u8>>, Value)>) -> Self {
        Self::Dict(
            entries
                .into_iter()
                .map(|(key, value)| (key.into(), value))
                .collect(),
        )
    }

    pub fn as_bytes(&self) -> Result<&[u8]> {
        match self {
            Self::Bytes(value) => Ok(value),
            _ => bail!("bencode value is not a byte string"),
        }
    }

    pub fn as_int(&self) -> Result<i64> {
        match self {
            Self::Int(value) => Ok(*value),
            _ => bail!("bencode value is not an integer"),
        }
    }

    pub fn as_list(&self) -> Result<&[Value]> {
        match self {
            Self::List(value) => Ok(value),
            _ => bail!("bencode value is not a list"),
        }
    }

    pub fn as_dict(&self) -> Result<&BTreeMap<Vec<u8>, Value>> {
        match self {
            Self::Dict(value) => Ok(value),
            _ => bail!("bencode value is not a dictionary"),
        }
    }

    pub fn get(&self, key: &[u8]) -> Result<&Value> {
        self.as_dict()?
            .get(key)
            .with_context(|| format!("missing bencode key {}", String::from_utf8_lossy(key)))
    }
}

pub fn encode(value: &Value) -> Vec<u8> {
    let mut output = Vec::new();
    encode_into(value, &mut output);
    output
}

fn encode_into(value: &Value, output: &mut Vec<u8>) {
    match value {
        Value::Bytes(bytes) => {
            output.extend_from_slice(bytes.len().to_string().as_bytes());
            output.push(b':');
            output.extend_from_slice(bytes);
        }
        Value::Int(value) => {
            output.push(b'i');
            output.extend_from_slice(value.to_string().as_bytes());
            output.push(b'e');
        }
        Value::List(values) => {
            output.push(b'l');
            for value in values {
                encode_into(value, output);
            }
            output.push(b'e');
        }
        Value::Dict(values) => {
            output.push(b'd');
            for (key, value) in values {
                encode_into(&Value::Bytes(key.clone()), output);
                encode_into(value, output);
            }
            output.push(b'e');
        }
    }
}

pub fn decode(input: &[u8]) -> Result<Value> {
    let (value, consumed) = decode_at(input, 0)?;
    if consumed != input.len() {
        bail!("trailing bytes after bencode value");
    }
    Ok(value)
}

pub fn decode_prefix(input: &[u8]) -> Result<(Value, usize)> {
    decode_at(input, 0)
}

pub fn decode_prefix_wire(input: &[u8]) -> Result<(Value, usize)> {
    decode_at_mode(input, 0, false)
}

fn decode_at(input: &[u8], offset: usize) -> Result<(Value, usize)> {
    decode_at_mode(input, offset, true)
}

fn decode_at_mode(input: &[u8], offset: usize, strict: bool) -> Result<(Value, usize)> {
    let marker = *input.get(offset).context("truncated bencode value")?;
    match marker {
        b'i' => {
            let end = input[offset..]
                .iter()
                .position(|byte| *byte == b'e')
                .map(|index| offset + index)
                .context("unterminated bencode integer")?;
            let raw = std::str::from_utf8(&input[offset + 1..end])
                .context("bencode integer is not ASCII")?;
            if raw.is_empty() || (raw.len() > 1 && raw.starts_with('0')) || raw == "-0" {
                bail!("non-canonical bencode integer");
            }
            Ok((Value::Int(raw.parse()?), end + 1))
        }
        b'l' => {
            let mut cursor = offset + 1;
            let mut values = Vec::new();
            while input.get(cursor) != Some(&b'e') {
                let (value, next) = decode_at_mode(input, cursor, strict)?;
                values.push(value);
                cursor = next;
            }
            Ok((Value::List(values), cursor + 1))
        }
        b'd' => {
            let mut cursor = offset + 1;
            let mut values = BTreeMap::new();
            let mut previous = None;
            while input.get(cursor) != Some(&b'e') {
                let (key, next) = decode_at_mode(input, cursor, strict)?;
                let key = match key {
                    Value::Bytes(key) => key,
                    _ => bail!("bencode dictionary key is not a byte string"),
                };
                if strict && previous.as_ref().is_some_and(|value| value >= &key) {
                    bail!("bencode dictionary keys are not strictly sorted");
                }
                previous = Some(key.clone());
                let (value, next_value) = decode_at_mode(input, next, strict)?;
                values.insert(key, value);
                cursor = next_value;
            }
            Ok((Value::Dict(values), cursor + 1))
        }
        b'0'..=b'9' => {
            let colon = input[offset..]
                .iter()
                .position(|byte| *byte == b':')
                .map(|index| offset + index)
                .context("unterminated bencode byte string")?;
            let raw = std::str::from_utf8(&input[offset..colon])
                .context("bencode byte length is not ASCII")?;
            if raw.len() > 1 && raw.starts_with('0') {
                bail!("non-canonical bencode byte length");
            }
            let length: usize = raw.parse().context("invalid bencode byte length")?;
            let start = colon + 1;
            let end = start
                .checked_add(length)
                .context("bencode length overflow")?;
            let bytes = input
                .get(start..end)
                .context("truncated bencode byte string")?;
            Ok((Value::Bytes(bytes.to_vec()), end))
        }
        _ => bail!("invalid bencode marker 0x{marker:02x}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_dictionary_encoding_and_strict_decode() {
        let value = Value::dict([
            (b"z".to_vec(), Value::Int(2)),
            (b"a".to_vec(), Value::bytes(b"x")),
        ]);
        assert_eq!(encode(&value), b"d1:a1:x1:zi2ee");
        assert_eq!(decode(b"d1:a1:x1:zi2ee").unwrap(), value);
        assert!(decode(b"d1:zi2e1:a1:xe").is_err());
        assert!(decode(b"i03e").is_err());
    }
}
