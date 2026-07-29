//! The `.usealed` envelope: streaming hybrid-post-quantum file encryption.
//!
//! Layout (version 1):
//! ```text
//! magic     8  bytes  "USEALED\x01"
//! xwing_ct  1120 bytes  X-Wing ciphertext (ML-KEM-768 || X25519)
//! salt      32 bytes    random HKDF salt
//! records   *           length-prefixed AES-256-GCM records
//! ```
//! `file_key = HKDF-SHA-256(ikm = X-Wing shared key, salt, info = "unichat-seal-v1 file-key")`.
//!
//! Each record is `u32-le ciphertext_len || ciphertext||tag`. Record 0 is the
//! encrypted metadata (filename, MIME type, exact plaintext size — so the
//! original name is protected, fixing PQSpread's filename leak); records 1..N
//! are 1 MiB plaintext chunks (the last may be shorter; an empty file still
//! has one empty final chunk).
//!
//! Tamper resistance:
//! - nonce(i) = counter i (unique per record under a per-file key);
//! - AAD(i) = SHA3-256(header) || u64-le i || final_flag — binding every record
//!   to this exact header, its position, and whether it is last. Reordering,
//!   truncation, extension, or cross-file splicing all fail authentication.
//! - The decrypted size must equal the size claimed in the metadata record.

use std::io::{Read, Write};

use zeroize::Zeroizing;

use super::aead::{AeadKey, TAG_SIZE};
use super::kdf::hkdf_sha256_32;
use super::xwing::{self, XWingPrivate, XWingPublic};
use super::{CryptoError, Result};

pub const MAGIC: [u8; 8] = *b"USEALED\x01";
pub const SALT_SIZE: usize = 32;
pub const CHUNK_SIZE: usize = 1 << 20; // 1 MiB plaintext per record
const HKDF_INFO: &[u8] = b"unichat-seal-v1 file-key";
const HEADER_SIZE: usize = 8 + xwing::CIPHERTEXT_SIZE + SALT_SIZE;
const MAX_META_CT: usize = 4096;

/// File metadata carried encrypted inside record 0.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Metadata {
    pub filename: String,
    pub mime: String,
    pub size: u64,
}

impl Metadata {
    fn encode(&self) -> Result<Vec<u8>> {
        let name = self.filename.as_bytes();
        let mime = self.mime.as_bytes();
        if name.len() > 255 || mime.len() > 255 {
            return Err(CryptoError::Malformed("metadata field too long"));
        }
        let mut out = Vec::with_capacity(2 + name.len() + 2 + mime.len() + 8);
        out.extend_from_slice(&(name.len() as u16).to_le_bytes());
        out.extend_from_slice(name);
        out.extend_from_slice(&(mime.len() as u16).to_le_bytes());
        out.extend_from_slice(mime);
        out.extend_from_slice(&self.size.to_le_bytes());
        Ok(out)
    }

    fn decode(buf: &[u8]) -> Result<Self> {
        let take = |buf: &[u8], n: usize| -> Result<()> {
            if buf.len() < n {
                Err(CryptoError::Malformed("metadata truncated"))
            } else {
                Ok(())
            }
        };
        let mut pos = 0usize;
        take(buf, 2)?;
        let name_len = u16::from_le_bytes(buf[0..2].try_into().unwrap()) as usize;
        pos += 2;
        take(&buf[pos..], name_len)?;
        let filename = String::from_utf8(buf[pos..pos + name_len].to_vec())
            .map_err(|_| CryptoError::Malformed("metadata filename not UTF-8"))?;
        pos += name_len;
        take(&buf[pos..], 2)?;
        let mime_len = u16::from_le_bytes(buf[pos..pos + 2].try_into().unwrap()) as usize;
        pos += 2;
        take(&buf[pos..], mime_len)?;
        let mime = String::from_utf8(buf[pos..pos + mime_len].to_vec())
            .map_err(|_| CryptoError::Malformed("metadata mime not UTF-8"))?;
        pos += mime_len;
        take(&buf[pos..], 8)?;
        let size = u64::from_le_bytes(buf[pos..pos + 8].try_into().unwrap());
        pos += 8;
        if pos != buf.len() {
            return Err(CryptoError::Malformed("metadata has trailing bytes"));
        }
        Ok(Self {
            filename,
            mime,
            size,
        })
    }
}

fn record_aad(header_hash: &[u8; 32], index: u64, is_final: bool) -> [u8; 41] {
    let mut aad = [0u8; 41];
    aad[..32].copy_from_slice(header_hash);
    aad[32..40].copy_from_slice(&index.to_le_bytes());
    aad[40] = is_final as u8;
    aad
}

fn derive_key(
    ss: &Zeroizing<[u8; xwing::SHARED_KEY_SIZE]>,
    salt: &[u8; SALT_SIZE],
) -> Result<AeadKey> {
    let key = hkdf_sha256_32(ss.as_ref(), salt, HKDF_INFO)?;
    AeadKey::new(&key)
}

fn write_record(out: &mut impl Write, ct: &[u8]) -> Result<()> {
    out.write_all(&(ct.len() as u32).to_le_bytes())?;
    out.write_all(ct)?;
    Ok(())
}

/// Encrypt `input` for `recipient`, writing the envelope to `output`.
pub fn seal(
    recipient: &XWingPublic,
    meta: &Metadata,
    input: &mut impl Read,
    output: &mut impl Write,
) -> Result<()> {
    let (xwing_ct, ss) = recipient.encapsulate()?;
    let mut salt = [0u8; SALT_SIZE];
    super::random_bytes(&mut salt);

    let mut header = [0u8; HEADER_SIZE];
    header[..8].copy_from_slice(&MAGIC);
    header[8..8 + xwing::CIPHERTEXT_SIZE].copy_from_slice(&xwing_ct);
    header[8 + xwing::CIPHERTEXT_SIZE..].copy_from_slice(&salt);
    let header_hash = symcrypt::hash::sha3_256(&header);

    let key = derive_key(&ss, &salt)?;
    output.write_all(&header)?;

    // Record 0: metadata (never final — a data record always follows).
    let mut meta_buf = meta.encode()?;
    key.seal(0, &record_aad(&header_hash, 0, false), &mut meta_buf);
    write_record(output, &meta_buf)?;

    // Records 1..N: file chunks. Read one chunk ahead so the last chunk can be
    // flagged as final. Total bytes must match the declared size exactly.
    let mut index: u64 = 1;
    let mut total: u64 = 0;
    let mut current = read_full_chunk(input)?;
    loop {
        let next = read_full_chunk(input)?;
        let is_final = next.is_empty();
        total += current.len() as u64;
        let mut buf = std::mem::take(&mut current);
        key.seal(index, &record_aad(&header_hash, index, is_final), &mut buf);
        write_record(output, &buf)?;
        if is_final {
            break;
        }
        index += 1;
        current = next;
    }
    if total != meta.size {
        return Err(CryptoError::Malformed(
            "input size does not match declared metadata size",
        ));
    }
    output.flush()?;
    Ok(())
}

fn read_full_chunk(input: &mut impl Read) -> Result<Vec<u8>> {
    let mut buf = vec![0u8; CHUNK_SIZE];
    let mut filled = 0;
    while filled < CHUNK_SIZE {
        let n = input.read(&mut buf[filled..])?;
        if n == 0 {
            break;
        }
        filled += n;
    }
    buf.truncate(filled);
    Ok(buf)
}

/// Streaming decryptor. Construction authenticates and returns the metadata;
/// [`Opener::copy_to`] then decrypts the payload, failing closed on any
/// tampering, truncation, or size mismatch.
pub struct Opener<R: Read> {
    input: R,
    key: AeadKey,
    header_hash: [u8; 32],
    meta: Metadata,
}

impl<R: Read> Opener<R> {
    pub fn new(key_pair: &XWingPrivate, mut input: R) -> Result<Self> {
        let mut header = [0u8; HEADER_SIZE];
        input.read_exact(&mut header).map_err(|_| {
            CryptoError::Malformed("file too short for a .usealed header")
        })?;
        if header[..8] != MAGIC {
            return Err(CryptoError::UnsupportedFormat);
        }
        let header_hash = symcrypt::hash::sha3_256(&header);
        let xwing_ct: [u8; xwing::CIPHERTEXT_SIZE] =
            header[8..8 + xwing::CIPHERTEXT_SIZE].try_into().unwrap();
        let salt: [u8; SALT_SIZE] = header[8 + xwing::CIPHERTEXT_SIZE..].try_into().unwrap();

        let ss = key_pair.decapsulate(&xwing_ct)?;
        let key = derive_key(&ss, &salt)?;

        let mut meta_buf =
            read_record(&mut input, MAX_META_CT)?.ok_or(CryptoError::Malformed("missing metadata record"))?;
        key.open(0, &record_aad(&header_hash, 0, false), &mut meta_buf)?;
        let meta = Metadata::decode(&meta_buf)?;

        Ok(Self {
            input,
            key,
            header_hash,
            meta,
        })
    }

    pub fn metadata(&self) -> &Metadata {
        &self.meta
    }

    /// Decrypt all chunk records into `output`. Returns the number of plaintext
    /// bytes written. Any authentication failure aborts immediately; the caller
    /// must discard whatever was already written.
    ///
    /// The metadata record is authenticated before any chunk is processed, so
    /// its declared size fixes the expected chunk count — the final-record
    /// index is known up front and additionally enforced by the final flag in
    /// each chunk's AAD.
    pub fn copy_to(mut self, output: &mut impl Write) -> Result<u64> {
        let chunk = CHUNK_SIZE as u64;
        let expected_chunks = if self.meta.size == 0 {
            1
        } else {
            self.meta.size.div_ceil(chunk)
        };
        let mut total: u64 = 0;
        for index in 1..=expected_chunks {
            let is_final = index == expected_chunks;
            let mut buf = read_record(&mut self.input, CHUNK_SIZE + TAG_SIZE)?
                .ok_or(CryptoError::Malformed("envelope truncated before final chunk"))?;
            self.key
                .open(index, &record_aad(&self.header_hash, index, is_final), &mut buf)?;
            total += buf.len() as u64;
            if total > self.meta.size {
                return Err(CryptoError::Malformed("more data than metadata declared"));
            }
            output.write_all(&buf)?;
        }
        // Nothing may follow the authenticated final record.
        let mut trailing = [0u8; 1];
        if self.input.read(&mut trailing)? != 0 {
            return Err(CryptoError::Malformed("trailing data after final record"));
        }
        if total != self.meta.size {
            return Err(CryptoError::Malformed(
                "decrypted size does not match metadata",
            ));
        }
        output.flush()?;
        Ok(total)
    }
}

/// Read one `u32-le len || bytes` record. `Ok(None)` on clean EOF at a record
/// boundary.
fn read_record(input: &mut impl Read, max_len: usize) -> Result<Option<Vec<u8>>> {
    let mut len_buf = [0u8; 4];
    let mut filled = 0;
    while filled < 4 {
        let n = input.read(&mut len_buf[filled..])?;
        if n == 0 {
            if filled == 0 {
                return Ok(None);
            }
            return Err(CryptoError::Malformed("truncated record length"));
        }
        filled += n;
    }
    let len = u32::from_le_bytes(len_buf) as usize;
    if len < TAG_SIZE || len > max_len {
        return Err(CryptoError::Malformed("record length out of range"));
    }
    let mut buf = vec![0u8; len];
    input
        .read_exact(&mut buf)
        .map_err(|_| CryptoError::Malformed("truncated record body"))?;
    Ok(Some(buf))
}
