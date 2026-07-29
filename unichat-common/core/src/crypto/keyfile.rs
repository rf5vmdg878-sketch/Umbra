//! Key file formats.
//!
//! Public key (text, shareable):
//! `unichat-xwing-pub-v1:<base64 of 1216-byte X-Wing public key>`
//!
//! Secret key (binary, `.key`):
//! ```text
//! magic     8 bytes  "USEALKY\x01"
//! kdf_flag  1 byte   0 = plaintext seed, 1 = Argon2id + AES-256-GCM
//! [flag=1]  m_cost_kib u32-le || t_cost u32-le || p_cost u32-le || salt 16
//! payload   seed (32) if flag=0, else GCM(seed) || tag (48)
//! ```
//! With flag=1 the wrapping key is Argon2id(passphrase, salt, params); the GCM
//! nonce is zero (each derived key is used exactly once, for a unique salt)
//! and the AAD is the whole preamble, so KDF parameters and salt cannot be
//! tampered with — with the floor in [`kdf`] preventing parameter downgrade.

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use zeroize::Zeroizing;

use super::aead::{AeadKey, TAG_SIZE};
use super::kdf::{argon2id_32, Argon2Params, SALT_SIZE};
use super::xwing::{self, XWingPrivate};
use super::{CryptoError, Result};

pub const PUB_PREFIX: &str = "unichat-xwing-pub-v1:";
const SECRET_MAGIC: [u8; 8] = *b"USEALKY\x01";

pub fn encode_public(pk: &[u8; xwing::PUBLIC_KEY_SIZE]) -> String {
    format!("{}{}", PUB_PREFIX, B64.encode(pk))
}

pub fn decode_public(text: &str) -> Result<[u8; xwing::PUBLIC_KEY_SIZE]> {
    let body = text
        .trim()
        .strip_prefix(PUB_PREFIX)
        .ok_or(CryptoError::InvalidKey("missing unichat-xwing-pub-v1 prefix"))?;
    let bytes = B64
        .decode(body.trim())
        .map_err(|_| CryptoError::InvalidKey("public key is not valid base64"))?;
    bytes
        .as_slice()
        .try_into()
        .map_err(|_| CryptoError::InvalidKey("public key has wrong length"))
}

/// Serialize the 32-byte X-Wing seed, optionally wrapped under a passphrase.
pub fn encode_secret(
    key: &XWingPrivate,
    passphrase: Option<&Zeroizing<Vec<u8>>>,
) -> Result<Vec<u8>> {
    let mut out = Vec::with_capacity(9 + 12 + SALT_SIZE + 32 + TAG_SIZE);
    out.extend_from_slice(&SECRET_MAGIC);
    match passphrase {
        None => {
            out.push(0);
            out.extend_from_slice(key.seed().as_ref());
        }
        Some(pass) => {
            out.push(1);
            let params = Argon2Params::default();
            let mut salt = [0u8; SALT_SIZE];
            super::random_bytes(&mut salt);
            out.extend_from_slice(&params.m_cost_kib.to_le_bytes());
            out.extend_from_slice(&params.t_cost.to_le_bytes());
            out.extend_from_slice(&params.p_cost.to_le_bytes());
            out.extend_from_slice(&salt);
            let aad = out.clone();
            let wrap_key = argon2id_32(pass, &salt, params)?;
            let aead = AeadKey::new(&wrap_key)?;
            let mut seed_buf = key.seed().to_vec();
            aead.seal(0, &aad, &mut seed_buf);
            out.extend_from_slice(&seed_buf);
            seed_buf.iter_mut().for_each(|b| *b = 0);
        }
    }
    Ok(out)
}

/// True if this secret key file needs a passphrase to unlock.
pub fn secret_needs_passphrase(data: &[u8]) -> Result<bool> {
    if data.len() < 9 || data[..8] != SECRET_MAGIC {
        return Err(CryptoError::UnsupportedFormat);
    }
    match data[8] {
        0 => Ok(false),
        1 => Ok(true),
        _ => Err(CryptoError::UnsupportedFormat),
    }
}

pub fn decode_secret(
    data: &[u8],
    passphrase: Option<&Zeroizing<Vec<u8>>>,
) -> Result<XWingPrivate> {
    if data.len() < 9 || data[..8] != SECRET_MAGIC {
        return Err(CryptoError::UnsupportedFormat);
    }
    match data[8] {
        0 => {
            let seed_bytes: [u8; 32] = data[9..]
                .try_into()
                .map_err(|_| CryptoError::InvalidKey("secret key has wrong length"))?;
            let seed = Zeroizing::new(seed_bytes);
            XWingPrivate::from_seed(&seed)
        }
        1 => {
            let pass = passphrase.ok_or(CryptoError::WrongPassphrase)?;
            let preamble_len = 9 + 12 + SALT_SIZE;
            if data.len() != preamble_len + 32 + TAG_SIZE {
                return Err(CryptoError::InvalidKey("secret key has wrong length"));
            }
            let params = Argon2Params {
                m_cost_kib: u32::from_le_bytes(data[9..13].try_into().unwrap()),
                t_cost: u32::from_le_bytes(data[13..17].try_into().unwrap()),
                p_cost: u32::from_le_bytes(data[17..21].try_into().unwrap()),
            };
            let salt: [u8; SALT_SIZE] = data[21..21 + SALT_SIZE].try_into().unwrap();
            let aad = &data[..preamble_len];
            let wrap_key = argon2id_32(pass, &salt, params)?;
            let aead = AeadKey::new(&wrap_key)?;
            let mut buf = data[preamble_len..].to_vec();
            aead.open(0, aad, &mut buf)
                .map_err(|_| CryptoError::WrongPassphrase)?;
            let seed_bytes: [u8; 32] = buf
                .as_slice()
                .try_into()
                .map_err(|_| CryptoError::InvalidKey("unwrapped seed has wrong length"))?;
            let seed = Zeroizing::new(seed_bytes);
            buf.iter_mut().for_each(|b| *b = 0);
            XWingPrivate::from_seed(&seed)
        }
        _ => Err(CryptoError::UnsupportedFormat),
    }
}
