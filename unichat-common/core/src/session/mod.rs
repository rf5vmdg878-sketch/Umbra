//! Session protocol (Phase 3): mutually authenticated, post-quantum,
//! forward-secret 1:1 channel — Ricochet's model, generalized to run over any
//! transport and made post-quantum.
//!
//! # Handshake (station-to-station over X-Wing + Ed25519)
//!
//! Each peer holds a long-term Ed25519 identity key (its address / root of
//! trust) and generates a **fresh ephemeral X-Wing keypair per session** for
//! forward secrecy. Authentication comes from Ed25519 signatures over the
//! transcript, binding each identity to its ephemeral key (defeats
//! man-in-the-middle / unknown-key-share).
//!
//! ```text
//! Initiator                                   Responder
//!   esk_I, epk_I = XWing.gen
//!   -- Init{magic,ver,id_pk_I,epk_I,nonce_I} -->
//!                                    esk_R, epk_R = XWing.gen
//!                                    (ct_R, ss_R) = encap(epk_I)
//!                                    sig_R = Sign(id_sk_R, H(ctx_R||T))
//!   <-- Resp{...,id_pk_R,epk_R,ct_R,nonce_R,sig_R} --
//!   ss_R = decap(esk_I, ct_R); verify sig_R
//!   (ct_I, ss_I) = encap(epk_R)
//!   sig_I = Sign(id_sk_I, H(ctx_I||T))
//!   -- Fin{ct_I,sig_I} -->
//!                                    ss_I = decap(esk_R, ct_I); verify sig_I
//! ```
//!
//! Both then derive directional AES-256-GCM keys:
//! `ikm = ss_R || ss_I`, `salt = SHA3-256(full transcript)`,
//! `k_i2r = HKDF(ikm, salt, "…i2r")`, `k_r2i = HKDF(ikm, salt, "…r2i")`.
//! Because both encapsulations feed `ikm`, the session key stays secret if
//! *either* ephemeral key is uncompromised, and secrecy survives compromise of
//! the long-term identity keys (forward secrecy). ML-KEM-768 + X25519 keeps
//! each half hybrid-secure.
//!
//! # Knock / approve (`ContactPolicy`)
//!
//! The handshake proves *who* the peer is; it does not grant access. After it
//! completes, the caller consults the contact list: a known **approved** peer
//! proceeds to chat; an unknown peer may send exactly one **contact request**
//! (nickname + short text) and nothing more until the user approves — the
//! Ricochet "nothing from strangers" rule.

use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::crypto::aead::AeadKey;
use crate::crypto::kdf::hkdf_sha256_32;
use crate::crypto::xwing::{self, XWingPrivate, XWingPublic};
use crate::crypto::{CryptoError, Result};
use crate::identity::{verify_detached, Identity, KeyBundle};

const MAGIC: [u8; 8] = *b"UNICHATS";
const VERSION: u8 = 1;

const ID_LEN: usize = 32;
const NONCE_LEN: usize = 32;
const SIG_LEN: usize = 64;
const EPK_LEN: usize = xwing::PUBLIC_KEY_SIZE; // 1216
const CT_LEN: usize = xwing::CIPHERTEXT_SIZE; // 1120

const INIT_LEN: usize = 8 + 1 + ID_LEN + EPK_LEN + NONCE_LEN;
const RESP_LEN: usize = 8 + 1 + ID_LEN + EPK_LEN + CT_LEN + NONCE_LEN + SIG_LEN;
const FIN_LEN: usize = CT_LEN + SIG_LEN;

const SIG_CTX_RESP: &[u8] = b"unichat-session-v1 responder\0";
const SIG_CTX_INIT: &[u8] = b"unichat-session-v1 initiator\0";
const HKDF_I2R: &[u8] = b"unichat-session-v1 i2r";
const HKDF_R2I: &[u8] = b"unichat-session-v1 r2i";

/// Largest application frame we will read (defends against memory-exhaustion
/// from a hostile peer). Plenty for chat and control messages.
const MAX_APP_FRAME: usize = 128 * 1024;

fn sha3(parts: &[&[u8]]) -> [u8; 32] {
    let mut buf = Vec::new();
    for p in parts {
        buf.extend_from_slice(p);
    }
    symcrypt::hash::sha3_256(&buf)
}

fn write_frame(w: &mut impl std::io::Write, payload: &[u8]) -> Result<()> {
    w.write_all(&(payload.len() as u32).to_le_bytes())?;
    w.write_all(payload)?;
    w.flush()?;
    Ok(())
}

fn read_frame(r: &mut impl std::io::Read, max: usize) -> Result<Vec<u8>> {
    let mut len = [0u8; 4];
    r.read_exact(&mut len)
        .map_err(|_| CryptoError::Handshake("connection closed during frame read"))?;
    let n = u32::from_le_bytes(len) as usize;
    if n > max {
        return Err(CryptoError::Protocol("frame exceeds maximum size"));
    }
    let mut buf = vec![0u8; n];
    r.read_exact(&mut buf)
        .map_err(|_| CryptoError::Handshake("connection closed mid-frame"))?;
    Ok(buf)
}

/// Absolute direction of a channel half (stable across both peers).
#[derive(Clone, Copy)]
enum Dir {
    I2R = 1,
    R2I = 2,
}

/// An established, encrypted, authenticated 1:1 channel.
pub struct SecureChannel<S> {
    stream: S,
    send_key: AeadKey,
    recv_key: AeadKey,
    send_dir: u8,
    recv_dir: u8,
    send_ctr: u64,
    recv_ctr: u64,
    peer_identity: [u8; 32],
    /// Secret keying material for sub-protocols (calls, bulk transfer) that want
    /// their own independent keys derived from this authenticated session.
    call_secret: Zeroizing<[u8; 32]>,
    is_initiator: bool,
}

fn app_aad(dir: u8, ctr: u64) -> [u8; 17] {
    let mut aad = [0u8; 17];
    aad[..8].copy_from_slice(b"UNICHATA");
    aad[8] = dir;
    aad[9..].copy_from_slice(&ctr.to_le_bytes());
    aad
}

impl<S: std::io::Read + std::io::Write> SecureChannel<S> {
    /// The peer's authenticated long-term identity public key.
    pub fn peer_identity(&self) -> &[u8; 32] {
        &self.peer_identity
    }

    /// Secret shared with the peer, for deriving keys for call/transfer
    /// sub-protocols that run over this session's stream.
    pub fn call_secret(&self) -> &Zeroizing<[u8; 32]> {
        &self.call_secret
    }

    /// Whether this side initiated the session (fixes directional key roles).
    pub fn is_initiator(&self) -> bool {
        self.is_initiator
    }

    /// Send one application message. Monotonic counter + direction are bound
    /// into the AEAD tag, so replay, reorder, and reflection all fail.
    pub fn send(&mut self, msg: &AppMsg) -> Result<()> {
        let mut buf = serde_json::to_vec(msg)
            .map_err(|_| CryptoError::Protocol("app message serialization failed"))?;
        if buf.len() > MAX_APP_FRAME - 64 {
            return Err(CryptoError::Protocol("app message too large"));
        }
        let aad = app_aad(self.send_dir, self.send_ctr);
        self.send_key.seal(self.send_ctr, &aad, &mut buf);
        self.send_ctr = self
            .send_ctr
            .checked_add(1)
            .ok_or(CryptoError::Protocol("session message counter exhausted"))?;
        write_frame(&mut self.stream, &buf)
    }

    /// Receive one application message. Returns `Ok(None)` on a clean peer
    /// disconnect at a frame boundary.
    pub fn recv(&mut self) -> Result<Option<AppMsg>> {
        let mut len = [0u8; 4];
        match self.stream.read_exact(&mut len) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
            Err(e) => return Err(CryptoError::Io(e)),
        }
        let n = u32::from_le_bytes(len) as usize;
        if n > MAX_APP_FRAME {
            return Err(CryptoError::Protocol("app frame exceeds maximum size"));
        }
        let mut buf = vec![0u8; n];
        self.stream.read_exact(&mut buf)?;
        let aad = app_aad(self.recv_dir, self.recv_ctr);
        self.recv_key.open(self.recv_ctr, &aad, &mut buf)?;
        self.recv_ctr = self
            .recv_ctr
            .checked_add(1)
            .ok_or(CryptoError::Protocol("session message counter exhausted"))?;
        let msg = serde_json::from_slice(&buf)
            .map_err(|_| CryptoError::Protocol("malformed app message"))?;
        Ok(Some(msg))
    }

    pub fn into_inner(self) -> S {
        self.stream
    }

    /// Verify a peer-supplied key bundle and confirm it belongs to the identity
    /// that was authenticated during the handshake. This binds the peer's
    /// long-term X-Wing key (needed for future offline sealing) to the live,
    /// session-authenticated Ed25519 identity — so a knock cannot smuggle in a
    /// bundle for someone else.
    pub fn verify_peer_bundle(&self, bundle_text: &str) -> Result<KeyBundle> {
        let bundle = KeyBundle::decode(bundle_text)?;
        if bundle.identity_pk() != &self.peer_identity {
            return Err(CryptoError::PeerAuth(
                "bundle identity does not match the authenticated peer",
            ));
        }
        Ok(bundle)
    }
}

/// Application-layer messages carried inside the encrypted channel.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub enum AppMsg {
    /// A knock from an unknown peer: introduce yourself, attach your signed
    /// key bundle (so approval can persist a full contact), and ask for
    /// approval.
    ContactRequest {
        nickname: String,
        text: String,
        bundle: String,
    },
    /// Response to a contact request. On acceptance the responder returns its
    /// own bundle so the initiator can persist the contact too.
    ContactResponse {
        accepted: bool,
        bundle: Option<String>,
    },
    /// A chat message (id lets the peer acknowledge).
    Chat { id: u32, text: String },
    /// Acknowledge a received chat message.
    ChatAck { id: u32 },
    /// Offer to send a file (E2E over this session).
    FileOffer { name: String, size: u64 },
    /// Accept or decline a file offer.
    FileAccept { accept: bool },
    /// One base64 chunk of the file (already inside the encrypted channel).
    FileChunk { index: u32, last: bool, data: String },
    /// A call is being requested through a relay: dial this call-id.
    CallOffer { call_id: String, video: bool },
    /// Accept or decline a call.
    CallAccept { accept: bool },
    /// Graceful goodbye.
    Bye,
}

fn derive_channel<S>(
    stream: S,
    ss_r: &Zeroizing<[u8; 32]>,
    ss_i: &Zeroizing<[u8; 32]>,
    transcript_hash: &[u8; 32],
    peer_identity: [u8; 32],
    is_initiator: bool,
) -> Result<SecureChannel<S>> {
    let mut ikm = Zeroizing::new([0u8; 64]);
    ikm[..32].copy_from_slice(ss_r.as_ref());
    ikm[32..].copy_from_slice(ss_i.as_ref());
    let k_i2r = hkdf_sha256_32(ikm.as_ref(), transcript_hash, HKDF_I2R)?;
    let k_r2i = hkdf_sha256_32(ikm.as_ref(), transcript_hash, HKDF_R2I)?;
    let call_secret = hkdf_sha256_32(ikm.as_ref(), transcript_hash, b"unichat-call-secret-v1")?;

    let (send_key, recv_key, send_dir, recv_dir) = if is_initiator {
        (
            AeadKey::new(&k_i2r)?,
            AeadKey::new(&k_r2i)?,
            Dir::I2R as u8,
            Dir::R2I as u8,
        )
    } else {
        (
            AeadKey::new(&k_r2i)?,
            AeadKey::new(&k_i2r)?,
            Dir::R2I as u8,
            Dir::I2R as u8,
        )
    };
    Ok(SecureChannel {
        stream,
        send_key,
        recv_key,
        send_dir,
        recv_dir,
        send_ctr: 0,
        recv_ctr: 0,
        peer_identity,
        call_secret,
        is_initiator,
    })
}

/// Run the initiator side of the handshake. `identity` and `xwing` are this
/// profile's long-term keys.
pub fn initiator_handshake<S: std::io::Read + std::io::Write>(
    mut stream: S,
    identity: &Identity,
    _xwing: &XWingPrivate,
) -> Result<SecureChannel<S>> {
    // Ephemeral key for forward secrecy.
    let esk_i = XWingPrivate::generate()?;
    let epk_i = esk_i.public_key_bytes();
    let id_pk_i = identity.public_bytes();
    let mut nonce_i = [0u8; NONCE_LEN];
    crate::crypto::random_bytes(&mut nonce_i);

    let mut init = Vec::with_capacity(INIT_LEN);
    init.extend_from_slice(&MAGIC);
    init.push(VERSION);
    init.extend_from_slice(&id_pk_i);
    init.extend_from_slice(epk_i);
    init.extend_from_slice(&nonce_i);
    write_frame(&mut stream, &init)?;

    // --- Resp ---
    let resp = read_frame(&mut stream, RESP_LEN)?;
    if resp.len() != RESP_LEN || resp[..8] != MAGIC || resp[8] != VERSION {
        return Err(CryptoError::Handshake("malformed Resp"));
    }
    let mut o = 9;
    let id_pk_r: [u8; 32] = resp[o..o + ID_LEN].try_into().unwrap();
    o += ID_LEN;
    let epk_r: [u8; EPK_LEN] = resp[o..o + EPK_LEN].try_into().unwrap();
    o += EPK_LEN;
    let ct_r: [u8; CT_LEN] = resp[o..o + CT_LEN].try_into().unwrap();
    o += CT_LEN;
    let _nonce_r = &resp[o..o + NONCE_LEN];
    o += NONCE_LEN;
    let sig_r: [u8; SIG_LEN] = resp[o..o + SIG_LEN].try_into().unwrap();

    // Responder signs the transcript up to (but excluding) its own signature.
    let resp_signed = &resp[..RESP_LEN - SIG_LEN];
    let digest_r = sha3(&[SIG_CTX_RESP, &init, resp_signed]);
    if !verify_detached(&id_pk_r, &digest_r, &sig_r) {
        return Err(CryptoError::PeerAuth("responder signature invalid"));
    }

    let ss_r = esk_i.decapsulate(&ct_r)?;

    // --- Fin ---
    let peer_xwing = XWingPublic::from_bytes(&epk_r)?;
    let (ct_i, ss_i) = peer_xwing.encapsulate()?;
    let digest_i = sha3(&[SIG_CTX_INIT, &init, &resp, &ct_i]);
    let sig_i = identity.sign_detached(&digest_i);

    let mut fin = Vec::with_capacity(FIN_LEN);
    fin.extend_from_slice(&ct_i);
    fin.extend_from_slice(&sig_i);
    write_frame(&mut stream, &fin)?;

    let transcript_hash = sha3(&[&init, &resp, &fin]);
    derive_channel(stream, &ss_r, &ss_i, &transcript_hash, id_pk_r, true)
}

/// Run the responder side of the handshake.
pub fn responder_handshake<S: std::io::Read + std::io::Write>(
    mut stream: S,
    identity: &Identity,
    _xwing: &XWingPrivate,
) -> Result<SecureChannel<S>> {
    // --- Init ---
    let init = read_frame(&mut stream, INIT_LEN)?;
    if init.len() != INIT_LEN || init[..8] != MAGIC {
        return Err(CryptoError::Handshake("malformed Init"));
    }
    if init[8] != VERSION {
        return Err(CryptoError::Handshake("unsupported protocol version"));
    }
    let mut o = 9;
    let id_pk_i: [u8; 32] = init[o..o + ID_LEN].try_into().unwrap();
    o += ID_LEN;
    let epk_i: [u8; EPK_LEN] = init[o..o + EPK_LEN].try_into().unwrap();
    // remaining bytes: nonce_i (unused beyond transcript binding)

    let esk_r = XWingPrivate::generate()?;
    let epk_r = esk_r.public_key_bytes();
    let id_pk_r = identity.public_bytes();
    let mut nonce_r = [0u8; NONCE_LEN];
    crate::crypto::random_bytes(&mut nonce_r);

    // Encapsulate to the initiator's ephemeral key.
    let peer_xwing = XWingPublic::from_bytes(&epk_i)?;
    let (ct_r, ss_r) = peer_xwing.encapsulate()?;

    let mut resp_signed = Vec::with_capacity(RESP_LEN - SIG_LEN);
    resp_signed.extend_from_slice(&MAGIC);
    resp_signed.push(VERSION);
    resp_signed.extend_from_slice(&id_pk_r);
    resp_signed.extend_from_slice(epk_r);
    resp_signed.extend_from_slice(&ct_r);
    resp_signed.extend_from_slice(&nonce_r);

    let digest_r = sha3(&[SIG_CTX_RESP, &init, &resp_signed]);
    let sig_r = identity.sign_detached(&digest_r);
    let mut resp = resp_signed;
    resp.extend_from_slice(&sig_r);
    write_frame(&mut stream, &resp)?;

    // --- Fin ---
    let fin = read_frame(&mut stream, FIN_LEN)?;
    if fin.len() != FIN_LEN {
        return Err(CryptoError::Handshake("malformed Fin"));
    }
    let ct_i: [u8; CT_LEN] = fin[..CT_LEN].try_into().unwrap();
    let sig_i: [u8; SIG_LEN] = fin[CT_LEN..].try_into().unwrap();

    let digest_i = sha3(&[SIG_CTX_INIT, &init, &resp, &ct_i]);
    if !verify_detached(&id_pk_i, &digest_i, &sig_i) {
        return Err(CryptoError::PeerAuth("initiator signature invalid"));
    }
    let ss_i = esk_r.decapsulate(&ct_i)?;

    let transcript_hash = sha3(&[&init, &resp, &fin]);
    derive_channel(stream, &ss_r, &ss_i, &transcript_hash, id_pk_i, false)
}
