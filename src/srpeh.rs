use crate::bencode::{decode, encode, Value};
use crate::secret::ShareKey;
use anyhow::{bail, Context, Result};
use openssl::bn::{BigNum, BigNumContext};
use openssl::symm::{Cipher, Crypter, Mode};
use rand::RngCore;
use sha1::{Digest, Sha1};
use std::collections::VecDeque;
use std::io::{Read, Write};

pub const SRPEH_MAGIC: &[u8] = b"RESSN\0";
const MAX_SRPEH_FRAME: usize = 16 * 1024;
const SRP_MODULUS_HEX: &str = "d77946826e811914b39401d56a0a7843a8e7575d738c672a090ab1187d690dc43872fc06a7b6a43f3b95beaec7df04b9d242ebdc481111283216ce816e004b786c5fce856780d41837d95ad787a50bbe90bd3a9c98ac0f5fc0de744b1cde1891690894bc1f65e00de15b4b2aa6d87100c9ecc2527e45eb849deb14bb2049b163ea04187fd27c1bd9c7958cd40ce7067a9c024f9b7c5a0b4f5003686161f0605b";
const SRP_GENERATOR: &[u8] = &[2];

struct SrpParams {
    modulus: BigNum,
    modulus_bytes: Vec<u8>,
    generator: Vec<u8>,
    salt: Vec<u8>,
}

impl SrpParams {
    fn new(salt: &[u8]) -> Result<Self> {
        if salt.len() != 16 {
            bail!("SRPEH salt must be 16 bytes");
        }
        let modulus_bytes = hex::decode(SRP_MODULUS_HEX).context("decode SRP modulus")?;
        let modulus = BigNum::from_slice(&modulus_bytes)?;
        Ok(Self {
            modulus,
            modulus_bytes,
            generator: SRP_GENERATOR.to_vec(),
            salt: salt.to_vec(),
        })
    }

    fn proof_prefix(&self, username: &[u8]) -> Vec<u8> {
        let n_hash = Sha1::digest(&self.modulus_bytes);
        let g_hash = Sha1::digest(&self.generator);
        let mut output = Vec::with_capacity(60);
        for (left, right) in n_hash.into_iter().zip(g_hash) {
            output.push(left ^ right);
        }
        output.extend_from_slice(&Sha1::digest(username));
        output.extend_from_slice(&self.salt);
        output
    }

    fn multiplier(&self) -> Result<BigNum> {
        let mut input = self.modulus_bytes.clone();
        input.extend_from_slice(&left_pad(&self.generator, self.modulus_bytes.len()));
        Ok(BigNum::from_slice(&Sha1::digest(input))?)
    }

    fn password_exponent(&self, username: &[u8], password: &[u8]) -> Result<BigNum> {
        let inner = Sha1::digest([username, b":", password].concat());
        let mut input = self.salt.clone();
        input.extend_from_slice(&inner);
        Ok(BigNum::from_slice(&Sha1::digest(input))?)
    }

    fn verifier(&self, username: &[u8], password: &[u8]) -> Result<BigNum> {
        let exponent = self.password_exponent(username, password)?;
        mod_exp(&self.generator_value()?, &exponent, &self.modulus)
    }

    fn generator_value(&self) -> Result<BigNum> {
        Ok(BigNum::from_slice(&self.generator)?)
    }

    fn encode_public(&self, value: &BigNum) -> Result<Vec<u8>> {
        let bytes = value.to_vec();
        if bytes.len() > self.modulus_bytes.len() {
            bail!("SRP public value exceeds modulus");
        }
        Ok(bytes)
    }
}

pub struct SrpClient {
    params: SrpParams,
    username: Vec<u8>,
    password: Vec<u8>,
    secret: BigNum,
    public: Vec<u8>,
    proof_input: Vec<u8>,
}

impl SrpClient {
    pub fn new(username: &[u8], password: &[u8], salt: &[u8]) -> Result<Self> {
        let params = SrpParams::new(salt)?;
        let mut seed = [0_u8; 32];
        rand::thread_rng().fill_bytes(&mut seed);
        let secret = BigNum::from_slice(&seed)?;
        let public_value = mod_exp(&params.generator_value()?, &secret, &params.modulus)?;
        let public = params.encode_public(&public_value)?;
        let mut proof_input = params.proof_prefix(username);
        proof_input.extend_from_slice(&public);
        Ok(Self {
            params,
            username: username.to_vec(),
            password: password.to_vec(),
            secret,
            public,
            proof_input,
        })
    }

    pub fn public(&self) -> &[u8] {
        &self.public
    }

    pub fn proof(&self, server_public: &[u8]) -> Result<([u8; 40], [u8; 20])> {
        let key = self.session_key(server_public)?;
        let mut proof_input = self.proof_input.clone();
        proof_input.extend_from_slice(server_public);
        proof_input.extend_from_slice(&key);
        let client_proof: [u8; 20] = Sha1::digest(proof_input).into();
        Ok((key, client_proof))
    }

    pub fn verify_server(
        &self,
        server_public: &[u8],
        server_proof: &[u8],
        key: &[u8; 40],
        client_proof: &[u8; 20],
    ) -> Result<()> {
        let mut server_input = self.public.clone();
        server_input.extend_from_slice(client_proof);
        server_input.extend_from_slice(key);
        let expected_server_proof: [u8; 20] = Sha1::digest(server_input).into();
        if server_proof != expected_server_proof {
            bail!("SRPEH server proof mismatch");
        }
        let _ = server_public;
        Ok(())
    }

    fn session_key(&self, server_public: &[u8]) -> Result<[u8; 40]> {
        let public = BigNum::from_slice(server_public)?;
        if is_zero(&public) || public.ucmp(&self.params.modulus) != std::cmp::Ordering::Less {
            bail!("invalid SRP server public value");
        }
        let n_len = self.params.modulus_bytes.len();
        let u_input = [
            left_pad(&self.public, n_len),
            left_pad(server_public, n_len),
        ]
        .concat();
        let u = BigNum::from_slice(&Sha1::digest(u_input))?;
        let x = self
            .params
            .password_exponent(&self.username, &self.password)?;
        let gx = mod_exp(&self.params.generator_value()?, &x, &self.params.modulus)?;
        let k_gx = mod_mul(&self.params.multiplier()?, &gx, &self.params.modulus)?;
        let base = add_mod(
            &public,
            &negate_mod(&k_gx, &self.params.modulus)?,
            &self.params.modulus,
        )?;
        if is_zero(&base) {
            bail!("invalid SRP client base");
        }
        let mut context = BigNumContext::new()?;
        let mut product = BigNum::new()?;
        product.checked_mul(&u, &x, &mut context)?;
        let mut exponent = BigNum::new()?;
        exponent.checked_add(&product, &self.secret)?;
        let shared = mod_exp(&base, &exponent, &self.params.modulus)?;
        mgf1_sha1(&shared.to_vec(), 40)
    }
}

pub struct SrpServer {
    params: SrpParams,
    verifier: BigNum,
    secret: BigNum,
    public: Vec<u8>,
    proof_prefix: Vec<u8>,
}

impl SrpServer {
    pub fn new(username: &[u8], password: &[u8], salt: &[u8]) -> Result<Self> {
        let params = SrpParams::new(salt)?;
        let verifier = params.verifier(username, password)?;
        let mut seed = [0_u8; 32];
        rand::thread_rng().fill_bytes(&mut seed);
        let secret = BigNum::from_slice(&seed)?;
        let k = params.multiplier()?;
        let blinded = mod_mul(&k, &verifier, &params.modulus)?;
        let random = mod_exp(&params.generator_value()?, &secret, &params.modulus)?;
        let public_value = add_mod(&blinded, &random, &params.modulus)?;
        let public = params.encode_public(&public_value)?;
        Ok(Self {
            proof_prefix: params.proof_prefix(username),
            params,
            verifier,
            secret,
            public,
        })
    }

    pub fn public(&self) -> &[u8] {
        &self.public
    }

    pub fn finish(
        &self,
        client_public: &[u8],
        client_proof: &[u8],
    ) -> Result<([u8; 40], [u8; 20])> {
        let key = self.session_key(client_public)?;
        let expected: [u8; 20] = Sha1::digest(
            [
                self.proof_prefix.as_slice(),
                client_public,
                self.public.as_slice(),
                key.as_slice(),
            ]
            .concat(),
        )
        .into();
        if client_proof != expected {
            bail!("SRPEH client proof mismatch");
        }
        let proof: [u8; 20] =
            Sha1::digest([client_public, client_proof, key.as_slice()].concat()).into();
        Ok((key, proof))
    }

    fn session_key(&self, client_public: &[u8]) -> Result<[u8; 40]> {
        let public = BigNum::from_slice(client_public)?;
        if is_zero(&public) || public.ucmp(&self.params.modulus) != std::cmp::Ordering::Less {
            bail!("invalid SRP client public value");
        }
        let n_len = self.params.modulus_bytes.len();
        let u_input = [
            left_pad(client_public, n_len),
            left_pad(&self.public, n_len),
        ]
        .concat();
        let u = BigNum::from_slice(&Sha1::digest(u_input))?;
        let vu = mod_exp(&self.verifier, &u, &self.params.modulus)?;
        let base = mod_mul(&public, &vu, &self.params.modulus)?;
        let one = BigNum::from_u32(1)?;
        if base.ucmp(&one) != std::cmp::Ordering::Greater {
            bail!("invalid SRP server base");
        }
        let shared = mod_exp(&base, &self.secret, &self.params.modulus)?;
        mgf1_sha1(&shared.to_vec(), 40)
    }
}

#[derive(Clone, Debug)]
pub struct HandshakeMaterial {
    pub session_key: [u8; 40],
    pub client_nonce: [u8; 16],
    pub server_nonce: [u8; 16],
}

impl HandshakeMaterial {
    pub fn client_stream<S: Read + Write>(self, stream: S) -> EncryptedStream<S> {
        EncryptedStream::new(
            stream,
            CipherState::new(
                self.session_key[20..36].try_into().unwrap(),
                self.server_nonce,
                u32::from_be_bytes(self.session_key[36..40].try_into().unwrap()) as u64,
            ),
            CipherState::new(
                self.session_key[0..16].try_into().unwrap(),
                self.client_nonce,
                u32::from_be_bytes(self.session_key[16..20].try_into().unwrap()) as u64,
            ),
        )
    }

    pub fn server_stream<S: Read + Write>(self, stream: S) -> EncryptedStream<S> {
        EncryptedStream::new(
            stream,
            CipherState::new(
                self.session_key[0..16].try_into().unwrap(),
                self.client_nonce,
                u32::from_be_bytes(self.session_key[16..20].try_into().unwrap()) as u64,
            ),
            CipherState::new(
                self.session_key[20..36].try_into().unwrap(),
                self.server_nonce,
                u32::from_be_bytes(self.session_key[36..40].try_into().unwrap()) as u64,
            ),
        )
    }
}

struct CipherState {
    cipher: Cipher,
    key: [u8; 16],
    nonce: [u8; 16],
    offset: u64,
    keystream: Vec<u8>,
    keystream_offset: usize,
}

impl CipherState {
    fn new(key: [u8; 16], nonce: [u8; 16], offset: u64) -> Self {
        Self {
            cipher: Cipher::aes_128_ecb(),
            key,
            nonce,
            offset,
            keystream: Vec::new(),
            keystream_offset: 0,
        }
    }

    fn apply(&mut self, input: &mut [u8]) -> std::io::Result<()> {
        let mut input_offset = 0;
        while input_offset < input.len() {
            if self.keystream_offset == self.keystream.len() {
                self.generate_keystream();
            }
            let count = input
                .len()
                .saturating_sub(input_offset)
                .min(self.keystream.len() - self.keystream_offset);
            for index in 0..count {
                input[input_offset + index] ^= self.keystream[self.keystream_offset + index];
            }
            input_offset += count;
            self.keystream_offset += count;
        }
        Ok(())
    }

    fn generate_keystream(&mut self) {
        const BLOCKS_PER_BATCH: usize = 4096;
        let mut input = Vec::with_capacity(BLOCKS_PER_BATCH * 16);
        let mut offset = self.offset;
        for _ in 0..BLOCKS_PER_BATCH {
            let mut block = self.nonce;
            let low = offset as u32;
            let high = (offset >> 32) as u32;
            for (target, value) in block[0..4].iter_mut().zip(low.to_le_bytes()) {
                *target ^= value;
            }
            for (target, value) in block[4..8].iter_mut().zip(high.to_le_bytes()) {
                *target ^= value;
            }
            input.extend_from_slice(&block);
            offset = offset.wrapping_add(16);
        }
        let mut crypter = Crypter::new(self.cipher, Mode::Encrypt, &self.key, None)
            .expect("construct fixed AES-128 stream cipher");
        crypter.pad(false);
        self.keystream
            .resize(input.len() + self.cipher.block_size(), 0);
        let count = crypter
            .update(&input, &mut self.keystream)
            .expect("expand upstream SRPEH keystream");
        let mut tail = [0_u8; 16];
        let final_count = crypter
            .finalize(&mut tail)
            .expect("finish upstream SRPEH keystream");
        assert_eq!(final_count, 0);
        self.keystream.truncate(count);
        self.keystream_offset = 0;
        self.offset = offset;
    }
}

pub struct EncryptedStream<S> {
    stream: S,
    read_cipher: CipherState,
    write_cipher: CipherState,
    pending: VecDeque<u8>,
}

impl<S> EncryptedStream<S> {
    fn new(stream: S, read_cipher: CipherState, write_cipher: CipherState) -> Self {
        Self {
            stream,
            read_cipher,
            write_cipher,
            pending: VecDeque::new(),
        }
    }
}

impl<S: Read> Read for EncryptedStream<S> {
    fn read(&mut self, output: &mut [u8]) -> std::io::Result<usize> {
        if output.is_empty() {
            return Ok(0);
        }
        if self.pending.is_empty() {
            let mut input = [0_u8; 16 * 1024];
            let count = self.stream.read(&mut input)?;
            if count == 0 {
                return Ok(0);
            }
            self.read_cipher.apply(&mut input[..count])?;
            self.pending.extend(&input[..count]);
        }
        let count = output.len().min(self.pending.len());
        for (target, value) in output.iter_mut().zip(self.pending.drain(..count)) {
            *target = value;
        }
        Ok(count)
    }
}

impl<S: Write> Write for EncryptedStream<S> {
    fn write(&mut self, input: &[u8]) -> std::io::Result<usize> {
        if input.is_empty() {
            return Ok(0);
        }
        let mut output = input.to_vec();
        self.write_cipher.apply(&mut output)?;
        self.stream.write_all(&output)?;
        Ok(input.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.stream.flush()
    }
}

pub fn client_handshake<S: Read + Write>(stream: &mut S, key: &ShareKey) -> Result<[u8; 40]> {
    Ok(client_handshake_material(stream, key)?.session_key)
}

pub fn client_handshake_material<S: Read + Write>(
    stream: &mut S,
    key: &ShareKey,
) -> Result<HandshakeMaterial> {
    client_handshake_material_inner(stream, key, None)
}

pub fn client_handshake_material_with_type<S: Read + Write>(
    stream: &mut S,
    key: &ShareKey,
    share_type: i64,
) -> Result<HandshakeMaterial> {
    client_handshake_material_inner(stream, key, Some(share_type))
}

fn client_handshake_material_inner<S: Read + Write>(
    stream: &mut S,
    key: &ShareKey,
    share_type: Option<i64>,
) -> Result<HandshakeMaterial> {
    let username = key.share_id();
    let password = key.tls_psk()?;
    let client_nonce = random_16();
    let mut fields = vec![
        (b"nonce".to_vec(), Value::bytes(client_nonce.to_vec())),
        (b"share".to_vec(), Value::bytes(username.to_vec())),
    ];
    if let Some(share_type) = share_type {
        fields.push((b"type".to_vec(), Value::Int(share_type)));
    }
    let request = Value::dict(fields);
    write_prefixed_frame(stream, SRPEH_MAGIC, &encode(&request))?;
    let response = read_frame(stream)?;
    let response = decode(&response)?;
    let server_public = response.get(b"pub")?.as_bytes()?.to_vec();
    let salt = response.get(b"salt")?.as_bytes()?.to_vec();
    let client = SrpClient::new(&username, &password, &salt)?;
    let (key, client_proof) = client.proof(&server_public)?;
    let client_response = Value::dict([
        (b"pub".to_vec(), Value::bytes(client.public().to_vec())),
        (b"resp".to_vec(), Value::bytes(client_proof.to_vec())),
    ]);
    write_frame(stream, &encode(&client_response))?;
    let final_response = read_frame(stream)?;
    let final_response = decode(&final_response)?;
    let server_nonce: [u8; 16] = final_response
        .get(b"nonce")?
        .as_bytes()?
        .try_into()
        .map_err(|_| anyhow::anyhow!("invalid SRPEH server nonce length"))?;
    let server_proof = final_response.get(b"resp")?.as_bytes()?;
    let server_proof: [u8; 20] = server_proof
        .try_into()
        .map_err(|_| anyhow::anyhow!("invalid SRPEH server proof length"))?;
    client.verify_server(&server_public, &server_proof, &key, &client_proof)?;
    Ok(HandshakeMaterial {
        session_key: key,
        client_nonce,
        server_nonce,
    })
}

pub fn server_handshake<S: Read + Write>(stream: &mut S, key: &ShareKey) -> Result<[u8; 40]> {
    Ok(server_handshake_material(stream, key)?.session_key)
}

pub fn server_handshake_material<S: Read + Write>(
    stream: &mut S,
    key: &ShareKey,
) -> Result<HandshakeMaterial> {
    let mut magic = [0_u8; 6];
    stream.read_exact(&mut magic)?;
    if magic != SRPEH_MAGIC {
        bail!("invalid SRPEH request magic");
    }
    let request = decode(&read_frame(stream)?)?;
    let nonce = request.get(b"nonce")?.as_bytes()?;
    if nonce.len() != 16 {
        bail!("invalid SRPEH nonce length");
    }
    let username = request.get(b"share")?.as_bytes()?.to_vec();
    if username != key.share_id() {
        bail!("SRPEH share ID mismatch");
    }
    let password = key.tls_psk()?;
    let salt = random_16();
    let server = SrpServer::new(&username, &password, &salt)?;
    let response = Value::dict([
        (b"pub".to_vec(), Value::bytes(server.public().to_vec())),
        (b"salt".to_vec(), Value::bytes(salt.to_vec())),
    ]);
    write_frame(stream, &encode(&response))?;
    let client_response = decode(&read_frame(stream)?)?;
    let client_public = client_response.get(b"pub")?.as_bytes()?.to_vec();
    let client_proof = client_response.get(b"resp")?.as_bytes()?;
    let client_proof: [u8; 20] = client_proof
        .try_into()
        .map_err(|_| anyhow::anyhow!("invalid SRPEH client proof length"))?;
    let (derived, server_proof) = server.finish(&client_public, &client_proof)?;
    let server_nonce = random_16();
    let final_response = Value::dict([
        (b"nonce".to_vec(), Value::bytes(server_nonce.to_vec())),
        (b"resp".to_vec(), Value::bytes(server_proof.to_vec())),
    ]);
    write_frame(stream, &encode(&final_response))?;
    let client_nonce: [u8; 16] = request
        .get(b"nonce")?
        .as_bytes()?
        .try_into()
        .map_err(|_| anyhow::anyhow!("invalid SRPEH client nonce length"))?;
    Ok(HandshakeMaterial {
        session_key: derived,
        client_nonce,
        server_nonce,
    })
}

pub struct FramedStream<S> {
    stream: S,
    pending: VecDeque<u8>,
}

impl<S> FramedStream<S> {
    pub fn new(stream: S) -> Self {
        Self {
            stream,
            pending: VecDeque::new(),
        }
    }
}

impl<S: Read> Read for FramedStream<S> {
    fn read(&mut self, output: &mut [u8]) -> std::io::Result<usize> {
        if output.is_empty() {
            return Ok(0);
        }
        if self.pending.is_empty() {
            let mut length = [0_u8; 4];
            self.stream.read_exact(&mut length)?;
            let length = u32::from_be_bytes(length) as usize;
            if length > MAX_SRPEH_FRAME {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "SRPEH frame exceeds limit",
                ));
            }
            let mut payload = vec![0_u8; length];
            self.stream.read_exact(&mut payload)?;
            self.pending.extend(payload);
        }
        let count = output.len().min(self.pending.len());
        for (target, value) in output.iter_mut().zip(self.pending.drain(..count)) {
            *target = value;
        }
        Ok(count)
    }
}

impl<S: Write> Write for FramedStream<S> {
    fn write(&mut self, input: &[u8]) -> std::io::Result<usize> {
        if input.is_empty() {
            return Ok(0);
        }
        write_frame(&mut self.stream, input).map_err(|error| {
            let io_error = error.chain().find_map(|cause| {
                cause
                    .downcast_ref::<std::io::Error>()
                    .map(|error| std::io::Error::new(error.kind(), error.to_string()))
            });
            io_error.unwrap_or_else(|| {
                std::io::Error::new(std::io::ErrorKind::InvalidData, error.to_string())
            })
        })?;
        Ok(input.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.stream.flush()
    }
}

fn random_16() -> [u8; 16] {
    let mut value = [0_u8; 16];
    rand::thread_rng().fill_bytes(&mut value);
    value
}

fn left_pad(value: &[u8], length: usize) -> Vec<u8> {
    let mut output = vec![0_u8; length.saturating_sub(value.len())];
    output.extend_from_slice(value);
    output
}

fn add_mod(left: &BigNum, right: &BigNum, modulus: &BigNum) -> Result<BigNum> {
    let mut output = BigNum::new()?;
    let mut context = BigNumContext::new()?;
    output.mod_add(left, right, modulus, &mut context)?;
    Ok(output)
}

fn negate_mod(value: &BigNum, modulus: &BigNum) -> Result<BigNum> {
    if is_zero(value) {
        Ok(BigNum::from_slice(&value.to_vec())?)
    } else {
        let mut output = BigNum::new()?;
        let mut context = BigNumContext::new()?;
        output.mod_sub(modulus, value, modulus, &mut context)?;
        Ok(output)
    }
}

fn mod_exp(value: &BigNum, exponent: &BigNum, modulus: &BigNum) -> Result<BigNum> {
    let mut output = BigNum::new()?;
    let mut context = BigNumContext::new()?;
    output.mod_exp(value, exponent, modulus, &mut context)?;
    Ok(output)
}

fn mod_mul(left: &BigNum, right: &BigNum, modulus: &BigNum) -> Result<BigNum> {
    let mut output = BigNum::new()?;
    let mut context = BigNumContext::new()?;
    output.mod_mul(left, right, modulus, &mut context)?;
    Ok(output)
}

fn is_zero(value: &BigNum) -> bool {
    value.to_vec().iter().all(|byte| *byte == 0)
}

fn mgf1_sha1(seed: &[u8], length: usize) -> Result<[u8; 40]> {
    if length != 40 {
        bail!("unsupported MGF1 output length");
    }
    let mut output = [0_u8; 40];
    let mut offset = 0;
    let mut counter = 0_u32;
    while offset < output.len() {
        let mut input = seed.to_vec();
        input.extend_from_slice(&counter.to_be_bytes());
        let digest = Sha1::digest(input);
        let count = (output.len() - offset).min(digest.len());
        output[offset..offset + count].copy_from_slice(&digest[..count]);
        offset += count;
        counter = counter.wrapping_add(1);
    }
    Ok(output)
}

fn write_prefixed_frame<S: Write>(stream: &mut S, prefix: &[u8], payload: &[u8]) -> Result<()> {
    let mut frame = prefix.to_vec();
    frame.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    frame.extend_from_slice(payload);
    stream.write_all(&frame)?;
    stream.flush()?;
    Ok(())
}

fn write_frame<S: Write>(stream: &mut S, payload: &[u8]) -> Result<()> {
    if payload.len() > MAX_SRPEH_FRAME {
        bail!("SRPEH frame is too large");
    }
    let mut frame = Vec::with_capacity(4 + payload.len());
    frame.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    frame.extend_from_slice(payload);
    stream.write_all(&frame)?;
    stream.flush()?;
    Ok(())
}

fn read_frame<S: Read>(stream: &mut S) -> Result<Vec<u8>> {
    let mut length = [0_u8; 4];
    stream.read_exact(&mut length)?;
    let length = u32::from_be_bytes(length) as usize;
    if length > MAX_SRPEH_FRAME {
        bail!("SRPEH frame exceeds limit");
    }
    let mut payload = vec![0_u8; length];
    stream.read_exact(&mut payload)?;
    Ok(payload)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn srp_client_and_server_agree() {
        let username = [7_u8; 20];
        let password = [9_u8; 20];
        let salt = [3_u8; 16];
        let client = SrpClient::new(&username, &password, &salt).unwrap();
        let server = SrpServer::new(&username, &password, &salt).unwrap();
        let (client_key, client_proof) = client.proof(server.public()).unwrap();
        let (server_key, server_proof) = server.finish(client.public(), &client_proof).unwrap();
        assert_eq!(client_key, server_key);
        client
            .verify_server(server.public(), &server_proof, &client_key, &client_proof)
            .unwrap();
    }

    #[test]
    fn srp_rejects_wrong_password() {
        let username = [7_u8; 20];
        let salt = [3_u8; 16];
        let client = SrpClient::new(&username, &[9_u8; 20], &salt).unwrap();
        let server = SrpServer::new(&username, &[8_u8; 20], &salt).unwrap();
        let (_, client_proof) = client.proof(server.public()).unwrap();
        assert!(server.finish(client.public(), &client_proof).is_err());
    }

    #[test]
    fn srpeh_stream_cipher_uses_directional_split_material() {
        let mut session_key = [0_u8; 40];
        for (index, value) in session_key.iter_mut().enumerate() {
            *value = index as u8;
        }
        session_key[16..20].copy_from_slice(&0x12345678_u32.to_be_bytes());
        session_key[36..40].copy_from_slice(&0x9abcdef0_u32.to_be_bytes());
        let material = HandshakeMaterial {
            session_key,
            client_nonce: [0x10; 16],
            server_nonce: [0x20; 16],
        };
        let mut client = std::io::Cursor::new(Vec::new());
        let mut server = std::io::Cursor::new(Vec::new());
        {
            let mut stream = FramedStream::new(material.clone().server_stream(&mut client));
            stream.write_all(b"server-to-client").unwrap();
        }
        {
            let mut stream = FramedStream::new(material.client_stream(&mut server));
            stream.write_all(b"client-to-server").unwrap();
        }
        assert_ne!(client.into_inner(), server.into_inner());
    }

    #[test]
    fn srpeh_aes_counter_matches_fips_vector_at_zero() {
        let key = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f,
        ];
        let nonce = [
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd,
            0xee, 0xff,
        ];
        let mut cipher = CipherState::new(key, nonce, 0);
        let mut plaintext = [0_u8; 16];
        cipher.apply(&mut plaintext).unwrap();
        assert_eq!(
            plaintext,
            [
                0x69, 0xc4, 0xe0, 0xd8, 0x6a, 0x7b, 0x04, 0x30, 0xd8, 0xcd, 0xb7, 0x80, 0x70, 0xb4,
                0xc5, 0x5a
            ]
        );
    }

    #[test]
    fn srpeh_directions_map_session_key_nonce_and_counter() {
        let mut session_key = [0_u8; 40];
        for (index, value) in session_key.iter_mut().enumerate() {
            *value = index as u8;
        }
        session_key[16..20].copy_from_slice(&0x12345678_u32.to_be_bytes());
        session_key[36..40].copy_from_slice(&0x9abcdef0_u32.to_be_bytes());
        let material = HandshakeMaterial {
            session_key,
            client_nonce: [0x10; 16],
            server_nonce: [0x20; 16],
        };

        let client = material
            .clone()
            .client_stream(std::io::Cursor::new(Vec::new()));
        assert_eq!(
            client.read_cipher.key,
            <[u8; 16]>::try_from(&session_key[20..36]).unwrap()
        );
        assert_eq!(client.read_cipher.nonce, [0x20; 16]);
        assert_eq!(client.read_cipher.offset, 0x9abcdef0);
        assert_eq!(
            client.write_cipher.key,
            <[u8; 16]>::try_from(&session_key[0..16]).unwrap()
        );
        assert_eq!(client.write_cipher.nonce, [0x10; 16]);
        assert_eq!(client.write_cipher.offset, 0x12345678);

        let server = material.server_stream(std::io::Cursor::new(Vec::new()));
        assert_eq!(
            server.read_cipher.key,
            <[u8; 16]>::try_from(&session_key[0..16]).unwrap()
        );
        assert_eq!(server.read_cipher.nonce, [0x10; 16]);
        assert_eq!(server.read_cipher.offset, 0x12345678);
        assert_eq!(
            server.write_cipher.key,
            <[u8; 16]>::try_from(&session_key[20..36]).unwrap()
        );
        assert_eq!(server.write_cipher.nonce, [0x20; 16]);
        assert_eq!(server.write_cipher.offset, 0x9abcdef0);
    }

    #[test]
    fn srpeh_cipher_continues_across_partial_buffers() {
        let mut state = CipherState::new([7; 16], [9; 16], 0x1234);
        let mut left = vec![0xa5; 37];
        let mut right = left.clone();
        state.apply(&mut left).unwrap();
        let mut split = CipherState::new([7; 16], [9; 16], 0x1234);
        split.apply(&mut right[..13]).unwrap();
        split.apply(&mut right[13..]).unwrap();
        assert_eq!(left, right);
    }

    #[test]
    fn framed_stream_preserves_would_block_error_kind() {
        struct BlockingWriter;

        impl Write for BlockingWriter {
            fn write(&mut self, _input: &[u8]) -> std::io::Result<usize> {
                Err(std::io::Error::from(std::io::ErrorKind::WouldBlock))
            }

            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }

        let mut stream = FramedStream::new(BlockingWriter);
        let error = stream.write_all(b"payload").unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::WouldBlock);
    }
}
