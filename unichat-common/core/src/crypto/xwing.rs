//! X-Wing hybrid KEM: ML-KEM-768 + X25519, per draft-connolly-cfrg-xwing-kem-06.
//!
//! The construction is composed entirely from SymCrypt primitives:
//! SHAKE-256 (key expansion), ML-KEM-768 (post-quantum KEM), Curve25519 ECDH
//! (classical KEM half), SHA3-256 (combiner). The hybrid stays secure if
//! either component is broken; no code path in this crate ever uses ML-KEM or
//! X25519 alone.
//!
//! Wire sizes (matching the draft and interoperable with other X-Wing
//! implementations):
//! - secret key:  32 bytes (seed)
//! - public key:  1216 bytes = ML-KEM-768 ek (1184) || X25519 pk (32)
//! - ciphertext:  1120 bytes = ML-KEM-768 ct (1088) || X25519 ephemeral pk (32)
//! - shared key:  32 bytes

use symcrypt::ecc::{CurveType, EcKey, EcKeyUsage};
use symcrypt::hash::sha3_256;
use zeroize::{Zeroize, Zeroizing};

use super::mlkem::{self, MlKem768Private, MlKem768Public};
use super::{CryptoError, Result};

pub const SECRET_KEY_SIZE: usize = 32;
pub const PUBLIC_KEY_SIZE: usize = 1216;
pub const CIPHERTEXT_SIZE: usize = 1120;
pub const SHARED_KEY_SIZE: usize = 32;

/// Domain-separation label from the X-Wing spec ("\.//^\").
const LABEL: &[u8; 6] = br"\.//^\";

const EXPANDED_SIZE: usize = mlkem::PRIVATE_SEED_SIZE + 32; // 96

/// X-Wing public (encapsulation) key.
pub struct XWingPublic {
    mlkem: MlKem768Public,
    pk_x: [u8; 32],
}

/// X-Wing private (decapsulation) key, expanded from a 32-byte seed.
pub struct XWingPrivate {
    seed: Zeroizing<[u8; SECRET_KEY_SIZE]>,
    mlkem: MlKem768Private,
    sk_x: Zeroizing<[u8; 32]>,
    public_bytes: [u8; PUBLIC_KEY_SIZE],
}

/// SHA3-256(ss_M || ss_X || ct_X || pk_X || label) — the X-Wing combiner.
fn combiner(ss_m: &[u8; 32], ss_x: &[u8], ct_x: &[u8; 32], pk_x: &[u8; 32]) -> Zeroizing<[u8; 32]> {
    let mut input = Zeroizing::new(Vec::with_capacity(32 + 32 + 32 + 32 + LABEL.len()));
    input.extend_from_slice(ss_m);
    input.extend_from_slice(ss_x);
    input.extend_from_slice(ct_x);
    input.extend_from_slice(pk_x);
    input.extend_from_slice(LABEL);
    Zeroizing::new(sha3_256(&input))
}

/// RFC 7748 clamping. X-Wing's expanded seed bytes are an unclamped scalar;
/// implementations clamp at point-multiplication time. SymCrypt instead
/// requires the canonical (clamped) form at key import. Clamping is
/// idempotent, so results match implementations that clamp late.
fn clamped(sk: &[u8; 32]) -> Zeroizing<[u8; 32]> {
    let mut out = Zeroizing::new(*sk);
    out[0] &= 248;
    out[31] &= 127;
    out[31] |= 64;
    out
}

fn x25519_public_from_private(sk: &[u8; 32]) -> Result<[u8; 32]> {
    let sk = clamped(sk);
    let key = EcKey::set_key_pair(CurveType::Curve25519, sk.as_ref(), None, EcKeyUsage::EcDh)?;
    let pk = key.export_public_key()?;
    pk.as_slice()
        .try_into()
        .map_err(|_| CryptoError::InvalidKey("unexpected X25519 public key size"))
}

fn x25519_agree(sk: &[u8; 32], peer_pk: &[u8; 32]) -> Result<Zeroizing<[u8; 32]>> {
    let sk = clamped(sk);
    let me = EcKey::set_key_pair(CurveType::Curve25519, sk.as_ref(), None, EcKeyUsage::EcDh)?;
    let peer = EcKey::set_public_key(CurveType::Curve25519, peer_pk.as_ref(), EcKeyUsage::EcDh)?;
    let mut ss = me.ecdh_secret_agreement(peer)?;
    let out: [u8; 32] = ss
        .as_slice()
        .try_into()
        .map_err(|_| CryptoError::InvalidKey("unexpected X25519 shared secret size"))?;
    ss.zeroize();
    Ok(Zeroizing::new(out))
}

impl XWingPrivate {
    /// Generate a fresh key from SymCrypt's DRBG.
    pub fn generate() -> Result<Self> {
        let mut seed = Zeroizing::new([0u8; SECRET_KEY_SIZE]);
        super::random_bytes(seed.as_mut());
        Self::from_seed(&seed)
    }

    /// Deterministically expand the 32-byte seed:
    /// expanded = SHAKE-256(seed, 96); ML-KEM seed (d||z) = expanded[0..64];
    /// X25519 secret = expanded[64..96].
    pub fn from_seed(seed: &Zeroizing<[u8; SECRET_KEY_SIZE]>) -> Result<Self> {
        let mut expanded = Zeroizing::new([0u8; EXPANDED_SIZE]);
        mlkem::shake256(seed.as_ref(), expanded.as_mut());

        let mut mlkem_seed = Zeroizing::new([0u8; mlkem::PRIVATE_SEED_SIZE]);
        mlkem_seed.copy_from_slice(&expanded[..mlkem::PRIVATE_SEED_SIZE]);
        let mut sk_x = Zeroizing::new([0u8; 32]);
        sk_x.copy_from_slice(&expanded[mlkem::PRIVATE_SEED_SIZE..]);

        let mlkem_key = MlKem768Private::from_seed(&mlkem_seed)?;
        let ek_m = mlkem_key.encapsulation_key_bytes()?;
        let pk_x = x25519_public_from_private(&sk_x)?;

        let mut public_bytes = [0u8; PUBLIC_KEY_SIZE];
        public_bytes[..mlkem::ENCAPS_KEY_SIZE].copy_from_slice(&ek_m);
        public_bytes[mlkem::ENCAPS_KEY_SIZE..].copy_from_slice(&pk_x);

        Ok(Self {
            seed: seed.clone(),
            mlkem: mlkem_key,
            sk_x,
            public_bytes,
        })
    }

    pub fn seed(&self) -> &Zeroizing<[u8; SECRET_KEY_SIZE]> {
        &self.seed
    }

    pub fn public_key_bytes(&self) -> &[u8; PUBLIC_KEY_SIZE] {
        &self.public_bytes
    }

    pub fn public_key(&self) -> Result<XWingPublic> {
        XWingPublic::from_bytes(&self.public_bytes)
    }

    pub fn decapsulate(
        &self,
        ct: &[u8; CIPHERTEXT_SIZE],
    ) -> Result<Zeroizing<[u8; SHARED_KEY_SIZE]>> {
        let ct_m: &[u8; mlkem::CIPHERTEXT_SIZE] =
            ct[..mlkem::CIPHERTEXT_SIZE].try_into().unwrap();
        let ct_x: &[u8; 32] = ct[mlkem::CIPHERTEXT_SIZE..].try_into().unwrap();
        let pk_x: &[u8; 32] = self.public_bytes[mlkem::ENCAPS_KEY_SIZE..]
            .try_into()
            .unwrap();

        let ss_m = self.mlkem.decapsulate(ct_m)?;
        let ss_x = x25519_agree(&self.sk_x, ct_x)?;
        Ok(combiner(&ss_m, ss_x.as_ref(), ct_x, pk_x))
    }
}

impl XWingPublic {
    pub fn from_bytes(pk: &[u8; PUBLIC_KEY_SIZE]) -> Result<Self> {
        let ek_m: &[u8; mlkem::ENCAPS_KEY_SIZE] =
            pk[..mlkem::ENCAPS_KEY_SIZE].try_into().unwrap();
        let pk_x: [u8; 32] = pk[mlkem::ENCAPS_KEY_SIZE..].try_into().unwrap();
        Ok(Self {
            mlkem: MlKem768Public::from_bytes(ek_m)?,
            pk_x,
        })
    }

    /// Encapsulate: fresh randomness for both halves comes from SymCrypt's DRBG.
    pub fn encapsulate(
        &self,
    ) -> Result<([u8; CIPHERTEXT_SIZE], Zeroizing<[u8; SHARED_KEY_SIZE]>)> {
        let (ct_m, ss_m) = self.mlkem.encapsulate()?;

        let eph = EcKey::generate_key_pair(CurveType::Curve25519, EcKeyUsage::EcDh)?;
        let ct_x: [u8; 32] = eph
            .export_public_key()?
            .as_slice()
            .try_into()
            .map_err(|_| CryptoError::InvalidKey("unexpected X25519 public key size"))?;
        let peer = EcKey::set_public_key(CurveType::Curve25519, &self.pk_x, EcKeyUsage::EcDh)?;
        let mut ss_x_vec = eph.ecdh_secret_agreement(peer)?;
        let ss_x: [u8; 32] = ss_x_vec
            .as_slice()
            .try_into()
            .map_err(|_| CryptoError::InvalidKey("unexpected X25519 shared secret size"))?;
        ss_x_vec.zeroize();

        let ss = combiner(&ss_m, &ss_x, &ct_x, &self.pk_x);
        let mut ss_x = ss_x;
        ss_x.zeroize();

        let mut ct = [0u8; CIPHERTEXT_SIZE];
        ct[..mlkem::CIPHERTEXT_SIZE].copy_from_slice(&ct_m);
        ct[mlkem::CIPHERTEXT_SIZE..].copy_from_slice(&ct_x);
        Ok((ct, ss))
    }
}
