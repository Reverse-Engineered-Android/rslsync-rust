use anyhow::{bail, Context, Result};
use openssl::symm::{Cipher, Crypter, Mode};
use sha1::{Digest, Sha1};

pub const ENCRYPTION_KEY_LEN: usize = 16;
pub const NONCE_LEN: usize = 16;
pub const WRAPPED_PREFIX_LEN: usize = 8;

pub fn wrapped_value(
    content_key: &[u8; ENCRYPTION_KEY_LEN],
    plaintext: &[u8],
    prefix_context: &[u8],
) -> Result<Vec<u8>> {
    if plaintext.is_empty() {
        bail!("wrapped metadata plaintext cannot be empty");
    }
    let mut prefix_hasher = Sha1::new();
    prefix_hasher.update(plaintext);
    prefix_hasher.update(prefix_context);
    prefix_hasher.update(content_key);
    let prefix = prefix_hasher.finalize();

    let mut iv = [0_u8; NONCE_LEN];
    iv[..WRAPPED_PREFIX_LEN].copy_from_slice(&prefix[..WRAPPED_PREFIX_LEN]);
    let ciphertext = encrypt_blocks(content_key, &padded_plaintext(plaintext), &iv)?;

    let mut output = Vec::with_capacity(WRAPPED_PREFIX_LEN + ciphertext.len());
    output.extend_from_slice(&prefix[..WRAPPED_PREFIX_LEN]);
    output.extend_from_slice(&ciphertext);
    Ok(output)
}

pub fn unwrap_value(content_key: &[u8; ENCRYPTION_KEY_LEN], wrapped: &[u8]) -> Result<Vec<u8>> {
    let prefix = wrapped
        .get(..WRAPPED_PREFIX_LEN)
        .context("wrapped metadata is missing its prefix")?;
    let ciphertext = &wrapped[WRAPPED_PREFIX_LEN..];
    if ciphertext.is_empty() || !ciphertext.len().is_multiple_of(16) {
        bail!("wrapped metadata ciphertext has an invalid length");
    }
    let mut iv = [0_u8; NONCE_LEN];
    iv[..WRAPPED_PREFIX_LEN].copy_from_slice(prefix);
    decrypt_blocks(content_key, ciphertext, &iv)
}

fn padded_plaintext(plaintext: &[u8]) -> Vec<u8> {
    let padding = 16 - (plaintext.len() % 16);
    let mut padded = plaintext.to_vec();
    padded.extend(std::iter::repeat_n(padding as u8, padding));
    padded
}

fn encrypt_blocks(
    content_key: &[u8; ENCRYPTION_KEY_LEN],
    padded: &[u8],
    iv: &[u8; NONCE_LEN],
) -> Result<Vec<u8>> {
    let mut crypter = Crypter::new(Cipher::aes_128_cbc(), Mode::Encrypt, content_key, Some(iv))
        .context("create wrapped metadata encryptor")?;
    crypter.pad(false);
    let mut ciphertext = vec![0_u8; padded.len() + 16];
    let mut count = crypter
        .update(padded, &mut ciphertext)
        .context("encrypt wrapped metadata")?;
    count += crypter
        .finalize(&mut ciphertext[count..])
        .context("finish wrapped metadata encryption")?;
    ciphertext.truncate(count);
    Ok(ciphertext)
}

fn decrypt_blocks(
    content_key: &[u8; ENCRYPTION_KEY_LEN],
    ciphertext: &[u8],
    iv: &[u8; NONCE_LEN],
) -> Result<Vec<u8>> {
    if ciphertext.is_empty() || !ciphertext.len().is_multiple_of(16) {
        bail!("wrapped metadata ciphertext has an invalid length");
    }
    let mut crypter = Crypter::new(Cipher::aes_128_cbc(), Mode::Decrypt, content_key, Some(iv))
        .context("create wrapped metadata decryptor")?;
    crypter.pad(false);
    let mut padded = vec![0_u8; ciphertext.len() + 16];
    let mut count = crypter
        .update(ciphertext, &mut padded)
        .context("decrypt wrapped metadata")?;
    count += crypter
        .finalize(&mut padded[count..])
        .context("finish wrapped metadata decryption")?;
    padded.truncate(count);
    let padding = *padded.last().context("wrapped metadata has no padding")? as usize;
    if padding == 0 || padding > 16 || padded.len() < padding {
        bail!("wrapped metadata has invalid padding");
    }
    if !padded[padded.len() - padding..]
        .iter()
        .all(|byte| *byte as usize == padding)
    {
        bail!("wrapped metadata has invalid padding bytes");
    }
    Ok(padded[..padded.len() - padding].to_vec())
}

/// Trailing AES block of the previous component's wrapped bytes. Resilio Sync
/// chains encrypted path components in CBC order, so every component below the
/// share root is encrypted with the previous component's last block as IV and
/// carries no `SHA1`-derived prefix of its own.
fn chained_iv(previous: &[u8]) -> Result<[u8; NONCE_LEN]> {
    let block = previous
        .get(previous.len().saturating_sub(NONCE_LEN)..)
        .filter(|block| block.len() == NONCE_LEN)
        .context("wrapped path component is too short to chain")?;
    Ok(block.try_into().unwrap())
}

pub fn encrypt_path_component(
    content_key: &[u8; ENCRYPTION_KEY_LEN],
    component: &str,
    previous: Option<&[u8]>,
) -> Result<Vec<u8>> {
    match previous {
        None => wrapped_value(content_key, component.as_bytes(), b""),
        Some(previous) => {
            let iv = chained_iv(previous)?;
            encrypt_blocks(content_key, &padded_plaintext(component.as_bytes()), &iv)
        }
    }
}

pub fn decrypt_path_component(
    content_key: &[u8; ENCRYPTION_KEY_LEN],
    wrapped: &[u8],
    previous: Option<&[u8]>,
) -> Result<Vec<u8>> {
    match previous {
        None => unwrap_value(content_key, wrapped),
        Some(previous) => {
            let iv = chained_iv(previous)?;
            decrypt_blocks(content_key, wrapped, &iv)
        }
    }
}

/// Wrap a whole share-relative path. The first component (the share root
/// entry) is self-contained; every following component is chained to the
/// previous one.
pub fn wrap_path(
    content_key: &[u8; ENCRYPTION_KEY_LEN],
    components: &[String],
) -> Result<Vec<String>> {
    let mut output = Vec::with_capacity(components.len());
    let mut previous: Option<Vec<u8>> = None;
    for component in components {
        let wrapped = encrypt_path_component(content_key, component, previous.as_deref())?;
        previous = Some(wrapped.clone());
        output.push(crate::secret::encode_base32(&wrapped));
    }
    Ok(output)
}

pub fn unwrap_path(
    content_key: &[u8; ENCRYPTION_KEY_LEN],
    components: &[String],
) -> Result<Vec<String>> {
    let mut output = Vec::with_capacity(components.len());
    let mut previous: Option<Vec<u8>> = None;
    for component in components {
        let wrapped = crate::secret::decode_base32(component).context("decode encrypted path")?;
        let plaintext = decrypt_path_component(content_key, &wrapped, previous.as_deref())
            .context("decrypt encrypted path")?;
        previous = Some(wrapped);
        output.push(String::from_utf8(plaintext).context("encrypted path plaintext is not UTF-8")?);
    }
    Ok(output)
}

pub fn wrap_path_component(
    content_key: &[u8; ENCRYPTION_KEY_LEN],
    component: &str,
) -> Result<String> {
    Ok(crate::secret::encode_base32(&encrypt_path_component(
        content_key,
        component,
        None,
    )?))
}

pub fn unwrap_path_component(
    content_key: &[u8; ENCRYPTION_KEY_LEN],
    component: &str,
) -> Result<String> {
    let wrapped = crate::secret::decode_base32(component).context("decode encrypted path")?;
    let plaintext =
        decrypt_path_component(content_key, &wrapped, None).context("decrypt encrypted path")?;
    String::from_utf8(plaintext).context("encrypted path plaintext is not UTF-8")
}

/// Wire permissions used by the encrypted `main` dictionary. Resilio Sync
/// always publishes `0644` there and keeps the real mode inside `epart`.
pub const ENCRYPTED_WIRE_MODE: u32 = 0o644;

/// Real modes are folded to one of two values before they are protected:
/// an entry with any execute bit becomes `0755`, everything else `0644`.
pub fn normalize_mode(mode: u32) -> u32 {
    if mode & 0o111 != 0 {
        0o755
    } else {
        ENCRYPTED_WIRE_MODE
    }
}

pub fn protected_metadata(
    mtime_seconds: Option<i64>,
    mode: u32,
    entry_type: i64,
    write_times: i64,
) -> Vec<u8> {
    let mut output = Vec::new();
    output.push(b'd');
    if let Some(mtime_seconds) = mtime_seconds {
        output.extend_from_slice(b"5:mtimei");
        output.extend_from_slice(mtime_seconds.to_string().as_bytes());
        output.push(b'e');
    }
    output.extend_from_slice(b"4:permi");
    output.extend_from_slice(i64::from(mode).to_string().as_bytes());
    output.extend_from_slice(b"e4:typei");
    output.extend_from_slice(entry_type.to_string().as_bytes());
    output.extend_from_slice(b"e");
    if write_times & 0x3 != 0 {
        output.extend_from_slice(b"11:write_timesi");
        output.extend_from_slice((write_times & 0x3).to_string().as_bytes());
        output.push(b'e');
    }
    output.push(b'e');
    output
}

pub fn encrypt_epart(
    content_key: &[u8; ENCRYPTION_KEY_LEN],
    mtime_seconds: Option<i64>,
    time_seconds: i64,
    mode: u32,
    entry_type: i64,
    write_times: i64,
) -> Result<Vec<u8>> {
    let protected = protected_metadata(mtime_seconds, mode, entry_type, write_times);
    wrapped_value(
        content_key,
        &protected,
        &(time_seconds as u32).to_le_bytes(),
    )
}

pub fn decrypt_epart(content_key: &[u8; ENCRYPTION_KEY_LEN], epart: &[u8]) -> Result<Vec<u8>> {
    unwrap_value(content_key, epart)
}

/// Wire length of an `epieces` field carrying `piece_count` SHA-1 hashes.
///
/// The plaintext is `piece_count * 20` bytes followed by PKCS#7-style padding
/// that always adds between 1 and 16 bytes (a full block when the hashes
/// already fill whole blocks), and the field is prefixed with a 16-byte nonce.
pub fn encrypted_epieces_len(piece_count: usize) -> usize {
    let plaintext = piece_count.saturating_mul(20);
    NONCE_LEN + plaintext + (16 - (plaintext % 16))
}

pub fn encrypt_epieces(
    content_key: &[u8; ENCRYPTION_KEY_LEN],
    piece_hashes: &[[u8; 20]],
) -> Result<Vec<u8>> {
    let mut plaintext =
        Vec::with_capacity(piece_hashes.len().saturating_mul(20).next_multiple_of(16));
    for piece_hash in piece_hashes {
        plaintext.extend_from_slice(piece_hash);
    }
    let padding = 16 - (plaintext.len() % 16);
    plaintext.extend(std::iter::repeat_n(padding as u8, padding));

    let mut iv_hasher = Sha1::new();
    iv_hasher.update(&plaintext);
    iv_hasher.update(content_key);
    let iv_digest = iv_hasher.finalize();
    let iv: [u8; NONCE_LEN] = iv_digest[..NONCE_LEN].try_into().unwrap();

    let mut crypter = Crypter::new(Cipher::aes_128_cbc(), Mode::Encrypt, content_key, Some(&iv))
        .context("create epieces encryptor")?;
    crypter.pad(false);
    let mut ciphertext = vec![0_u8; plaintext.len() + 16];
    let mut count = crypter
        .update(&plaintext, &mut ciphertext)
        .context("encrypt epieces")?;
    count += crypter
        .finalize(&mut ciphertext[count..])
        .context("finish epieces encryption")?;
    ciphertext.truncate(count);

    let mut output = Vec::with_capacity(NONCE_LEN + ciphertext.len());
    output.extend_from_slice(&iv);
    output.extend_from_slice(&ciphertext);
    Ok(output)
}

pub fn decrypt_epieces(
    content_key: &[u8; ENCRYPTION_KEY_LEN],
    epieces: &[u8],
) -> Result<Vec<[u8; 20]>> {
    if epieces.len() <= NONCE_LEN || !(epieces.len() - NONCE_LEN).is_multiple_of(16) {
        bail!("epieces has an invalid length");
    }
    let iv: &[u8; NONCE_LEN] = epieces[..NONCE_LEN]
        .try_into()
        .context("epieces IV is not 16 bytes")?;
    let ciphertext = &epieces[NONCE_LEN..];
    let mut crypter = Crypter::new(Cipher::aes_128_cbc(), Mode::Decrypt, content_key, Some(iv))
        .context("create epieces decryptor")?;
    crypter.pad(false);
    let mut plaintext = vec![0_u8; ciphertext.len() + 16];
    let mut count = crypter
        .update(ciphertext, &mut plaintext)
        .context("decrypt epieces")?;
    count += crypter
        .finalize(&mut plaintext[count..])
        .context("finish epieces decryption")?;
    plaintext.truncate(count);

    let padding = *plaintext.last().context("epieces has no padding")? as usize;
    if padding == 0
        || padding > 16
        || plaintext.len() < padding
        || !plaintext[plaintext.len() - padding..]
            .iter()
            .all(|byte| *byte as usize == padding)
    {
        bail!("epieces has invalid padding");
    }
    plaintext.truncate(plaintext.len() - padding);
    if !plaintext.len().is_multiple_of(20) {
        bail!("epieces plaintext is not divisible by 20");
    }
    // The length was checked to be a multiple of 20 above, so the remainder is
    // always empty; `as_chunks` yields the fixed-size arrays directly.
    Ok(plaintext.as_chunks::<20>().0.to_vec())
}

pub fn piece_nonce(
    content_key: &[u8; ENCRYPTION_KEY_LEN],
    plaintext_piece_sha1: &[u8; 20],
    piece_offset: u64,
) -> [u8; NONCE_LEN] {
    let mut hasher = Sha1::new();
    hasher.update(content_key);
    hasher.update(plaintext_piece_sha1);
    hasher.update(piece_offset.to_le_bytes());
    let digest = hasher.finalize();
    let mut nonce = [0_u8; NONCE_LEN];
    nonce.copy_from_slice(&digest[..NONCE_LEN]);
    nonce
}

pub fn transform_piece(
    content_key: &[u8; ENCRYPTION_KEY_LEN],
    plaintext_piece_sha1: &[u8; 20],
    piece_offset: u64,
    piece: &mut [u8],
) -> Result<()> {
    let base_nonce = piece_nonce(content_key, plaintext_piece_sha1, piece_offset);
    let cipher = Cipher::aes_128_ecb();
    for (block_index, block) in piece.chunks_mut(16).enumerate() {
        let absolute_offset = piece_offset + (block_index as u64) * 16;
        let mut counter = base_nonce;
        let counter_bytes = absolute_offset.to_le_bytes();
        for index in 0..8 {
            counter[index] ^= counter_bytes[index];
        }
        let mut crypter = Crypter::new(cipher, Mode::Encrypt, content_key, None)?;
        crypter.pad(false);
        let mut keystream = [0_u8; 32];
        let count = crypter.update(&counter, &mut keystream)?;
        let final_count = crypter.finalize(&mut keystream[count..])?;
        if count + final_count < 16 {
            bail!("AES keystream block produced an invalid length");
        }
        for (target, keystream_byte) in block.iter_mut().zip(keystream) {
            *target ^= keystream_byte;
        }
    }
    Ok(())
}

pub fn encrypt_content(
    content_key: &[u8; ENCRYPTION_KEY_LEN],
    plaintext_piece_sha1: &[[u8; 20]],
    piece_length: usize,
    plaintext: &[u8],
) -> Result<Vec<u8>> {
    if plaintext.len().div_ceil(piece_length) != plaintext_piece_sha1.len() {
        bail!("piece hash count does not match content length");
    }
    let mut output = plaintext.to_vec();
    for (index, chunk) in output.chunks_mut(piece_length).enumerate() {
        transform_piece(
            content_key,
            &plaintext_piece_sha1[index],
            (index * piece_length) as u64,
            chunk,
        )?;
    }
    Ok(output)
}

pub fn decrypt_content(
    content_key: &[u8; ENCRYPTION_KEY_LEN],
    plaintext_piece_sha1: &[[u8; 20]],
    piece_length: usize,
    ciphertext: &mut [u8],
) -> Result<()> {
    if ciphertext.len().div_ceil(piece_length) != plaintext_piece_sha1.len() {
        bail!("piece hash count does not match ciphertext length");
    }
    for (index, chunk) in ciphertext.chunks_mut(piece_length).enumerate() {
        transform_piece(
            content_key,
            &plaintext_piece_sha1[index],
            (index * piece_length) as u64,
            chunk,
        )?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const CONTENT_KEY: [u8; 16] = [
        0xcc, 0x79, 0xf5, 0xa8, 0x36, 0x80, 0x1a, 0x5c, 0xc8, 0x54, 0xe8, 0xa6, 0xc9, 0x94, 0xdb,
        0x12,
    ];

    #[test]
    fn encrypted_epieces_len_matches_encrypt_epieces_for_every_piece_count() {
        // Regression: the parser previously used `ceil(n*20/16)*16`, which
        // under-counts whenever the SHA-1 hashes already fill whole AES blocks,
        // because the padding then adds a full extra block.
        for piece_count in 0..=64 {
            let hashes: Vec<[u8; 20]> = (0..piece_count).map(|index| [index as u8; 20]).collect();
            let encoded = encrypt_epieces(&CONTENT_KEY, &hashes).unwrap();
            assert_eq!(
                encoded.len(),
                encrypted_epieces_len(piece_count),
                "piece_count={piece_count}"
            );
            if piece_count > 0 {
                assert_eq!(decrypt_epieces(&CONTENT_KEY, &encoded).unwrap(), hashes);
            }
        }
    }

    #[test]
    fn derives_official_piece_nonce() {
        assert_eq!(
            piece_nonce(
                &CONTENT_KEY,
                &[
                    0xe0, 0x99, 0x6a, 0x37, 0xc1, 0x3d, 0x44, 0xc3, 0xb0, 0x60, 0x74, 0x93, 0x9d,
                    0x43, 0xfa, 0x37, 0x59, 0xbd, 0x32, 0xc1,
                ],
                0,
            ),
            [
                0x81, 0xe3, 0x59, 0x31, 0x68, 0x02, 0x9e, 0xc2, 0xd8, 0x86, 0x65, 0xed, 0x80, 0x01,
                0x89, 0xd2,
            ]
        );
    }

    #[test]
    fn transforms_content_symmetrically() {
        let hash = [
            0xe0, 0x99, 0x6a, 0x37, 0xc1, 0x3d, 0x44, 0xc3, 0xb0, 0x60, 0x74, 0x93, 0x9d, 0x43,
            0xfa, 0x37, 0x59, 0xbd, 0x32, 0xc1,
        ];
        let plaintext = b"official encrypted folder fixture";
        let mut transformed = plaintext.to_vec();
        transform_piece(&CONTENT_KEY, &hash, 0, &mut transformed).unwrap();
        assert_ne!(transformed, plaintext);
        transform_piece(&CONTENT_KEY, &hash, 0, &mut transformed).unwrap();
        assert_eq!(transformed, plaintext);
    }

    #[test]
    fn matches_official_first_fixture_ciphertext() {
        let hash = [
            0xe0, 0x99, 0x6a, 0x37, 0xc1, 0x3d, 0x44, 0xc3, 0xb0, 0x60, 0x74, 0x93, 0x9d, 0x43,
            0xfa, 0x37, 0x59, 0xbd, 0x32, 0xc1,
        ];
        let mut transformed = b"first".to_vec();
        transform_piece(&CONTENT_KEY, &hash, 0, &mut transformed).unwrap();
        assert_eq!(transformed, vec![0x33, 0xc9, 0x6e, 0x7e, 0x9e]);
    }

    #[test]
    fn matches_official_wrapped_metadata_fixtures() {
        let protected = protected_metadata(Some(1790774110), 420, 1, 2);
        assert_eq!(
            protected,
            b"d5:mtimei1790774110e4:permi420e4:typei1e11:write_timesi2ee"
        );
        let epart = encrypt_epart(&CONTENT_KEY, Some(1790774110), 1790774110, 420, 1, 2).unwrap();
        assert_eq!(
            hex::encode(&epart),
            "4877baa041bd5a99795bd5cec6b1fd07e57e30754bb21d2965d300ff170c1ed3d9683b8e96a247d011ac5ecde716c795f3d34af0d703bf87805f34e21aad4fe9060d84836d152797"
        );
        assert_eq!(decrypt_epart(&CONTENT_KEY, &epart).unwrap(), protected);

        let encoded = wrap_path_component(&CONTENT_KEY, "sample.bin").unwrap();
        assert_eq!(encoded, "YBH7Z2MYKTYT5TTLVCWU5MFB3QXYP5IUWOR6KEA");
        assert_eq!(
            unwrap_path_component(&CONTENT_KEY, &encoded).unwrap(),
            "sample.bin"
        );
    }
}
