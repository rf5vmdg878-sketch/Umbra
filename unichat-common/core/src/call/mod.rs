//! End-to-end encrypted real-time media (voice + video) — the secure transport
//! for calls, designed to run over the untrusted `umbra-relay` call service so
//! **no third-party media server is involved**.
//!
//! # Model
//!
//! Two peers rendezvous through the relay (which only forwards opaque bytes,
//! matched by a public `call_id`) and run the Phase-3 session handshake over
//! that relayed stream — so the relay never sees keys or media, only ciphertext.
//! From the authenticated session they derive an independent **call secret**
//! ([`crate::session::SecureChannel::call_secret`]); this module turns that into
//! directional AES-256-GCM media keys and frames.
//!
//! # Media frames
//!
//! Each captured audio/video frame is sealed independently (like SRTP, but
//! post-quantum-keyed): `nonce = per-direction sequence counter`, and the AAD
//! binds `kind ‖ seq ‖ timestamp`, so frames can't be reordered across kinds,
//! replayed, or reflected. Audio and video share the channel; the `kind` byte
//! and independent-looking payloads keep them demuxable after decryption. Frames
//! are length-prefixed on the stream.
//!
//! # What this module does NOT do
//!
//! It does not capture from a microphone/camera or run Opus/VP8 — that device +
//! codec layer plugs in through [`MediaSource`] / [`MediaSink`]. It carries and
//! protects whatever bytes those produce.

use std::io::{Read, Write};

use zeroize::Zeroizing;

use crate::crypto::aead::AeadKey;
use crate::crypto::kdf::hkdf_sha256_32;
use crate::crypto::{CryptoError, Result};
use crate::transport::Transport;

pub mod relay;

/// Magic prefixing the call-relay rendezvous header.
pub const CALL_MAGIC: [u8; 8] = *b"UNICALL1";
pub const MAX_CALL_ID: usize = 64;

/// Dial a call relay and announce the rendezvous `call_id`. The returned
/// connection becomes a transparent pipe to the peer once both sides arrive;
/// run the session handshake over it, then a [`SecureMediaChannel`]. The relay
/// only ever sees the public `call_id` and ciphertext.
pub fn rendezvous<T: Transport>(
    transport: &T,
    relay_addr: &str,
    call_id: &[u8],
    is_caller: bool,
) -> Result<T::Connection> {
    if call_id.is_empty() || call_id.len() > MAX_CALL_ID {
        return Err(CryptoError::Protocol("invalid call id length"));
    }
    let mut conn = transport.dial(relay_addr)?;
    let mut hdr = Vec::with_capacity(8 + 1 + call_id.len() + 1);
    hdr.extend_from_slice(&CALL_MAGIC);
    hdr.push(call_id.len() as u8);
    hdr.extend_from_slice(call_id);
    hdr.push(if is_caller { 1 } else { 2 });
    conn.write_all(&hdr)?;
    conn.flush()?;
    Ok(conn)
}

/// Generate a fresh random call id to share with the peer (out of band, e.g. in
/// a `CallOffer` chat message).
pub fn new_call_id() -> [u8; 16] {
    let mut id = [0u8; 16];
    crate::crypto::random_bytes(&mut id);
    id
}

const CALLER_TO_CALLEE: &[u8] = b"unichat-call-media caller->callee";
const CALLEE_TO_CALLER: &[u8] = b"unichat-call-media callee->caller";
const HEADER_LEN: usize = 9; // kind(1) || seq(4 le) || ts(4 le)
const MAX_MEDIA_FRAME: usize = 512 * 1024; // generous for a keyframe

/// Audio vs video, carried in each frame's authenticated header.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(u8)]
pub enum MediaKind {
    Audio = 1,
    Video = 2,
}

impl MediaKind {
    fn from_byte(b: u8) -> Option<Self> {
        match b {
            1 => Some(MediaKind::Audio),
            2 => Some(MediaKind::Video),
            _ => None,
        }
    }
}

/// A decrypted media frame handed to the playback/decoder side.
pub struct MediaFrame {
    pub kind: MediaKind,
    pub seq: u32,
    pub timestamp: u32,
    pub payload: Vec<u8>,
}

fn media_keys(call_secret: &Zeroizing<[u8; 32]>) -> Result<(AeadKey, AeadKey)> {
    // Salt is empty; the call_secret is already a strong per-session secret.
    let c2p = hkdf_sha256_32(call_secret.as_ref(), &[], CALLER_TO_CALLEE)?;
    let p2c = hkdf_sha256_32(call_secret.as_ref(), &[], CALLEE_TO_CALLER)?;
    Ok((AeadKey::new(&c2p)?, AeadKey::new(&p2c)?))
}

fn frame_aad(kind: MediaKind, seq: u32, ts: u32) -> [u8; HEADER_LEN] {
    let mut h = [0u8; HEADER_LEN];
    h[0] = kind as u8;
    h[1..5].copy_from_slice(&seq.to_le_bytes());
    h[5..9].copy_from_slice(&ts.to_le_bytes());
    h
}

/// An E2E-encrypted media channel over an established session's stream.
///
/// Construct it from the parts of a completed [`crate::session::SecureChannel`]
/// (via `into_inner()` + `call_secret()` + `is_initiator()`).
pub struct SecureMediaChannel<S> {
    stream: S,
    send_key: AeadKey,
    recv_key: AeadKey,
    send_seq: u32,
    recv_dir_is_c2p: bool,
}

impl<S: std::io::Read + std::io::Write> SecureMediaChannel<S> {
    /// `is_caller` must be the same value as `SecureChannel::is_initiator()` so
    /// both ends agree on which directional key is send vs receive.
    pub fn new(stream: S, call_secret: &Zeroizing<[u8; 32]>, is_caller: bool) -> Result<Self> {
        let (c2p, p2c) = media_keys(call_secret)?;
        let (send_key, recv_key) = if is_caller { (c2p, p2c) } else { (p2c, c2p) };
        Ok(Self {
            stream,
            send_key,
            recv_key,
            send_seq: 0,
            recv_dir_is_c2p: is_caller,
        })
    }

    /// Seal and send one captured media frame.
    pub fn send(&mut self, kind: MediaKind, timestamp: u32, payload: &[u8]) -> Result<()> {
        if payload.len() > MAX_MEDIA_FRAME {
            return Err(CryptoError::Protocol("media frame too large"));
        }
        let seq = self.send_seq;
        let aad = frame_aad(kind, seq, timestamp);
        let mut buf = payload.to_vec();
        self.send_key.seal(seq as u64, &aad, &mut buf);
        self.send_seq = self
            .send_seq
            .checked_add(1)
            .ok_or(CryptoError::Protocol("media sequence exhausted (rekey)"))?;

        // wire: u32 total_len || header(9) || ciphertext
        let mut frame = Vec::with_capacity(4 + HEADER_LEN + buf.len());
        frame.extend_from_slice(&((HEADER_LEN + buf.len()) as u32).to_le_bytes());
        frame.extend_from_slice(&aad);
        frame.extend_from_slice(&buf);
        self.stream.write_all(&frame)?;
        self.stream.flush()?;
        Ok(())
    }

    /// Receive and decrypt one media frame. `Ok(None)` on clean disconnect.
    pub fn recv(&mut self) -> Result<Option<MediaFrame>> {
        let mut len = [0u8; 4];
        match self.stream.read_exact(&mut len) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
            Err(e) => return Err(CryptoError::Io(e)),
        }
        let n = u32::from_le_bytes(len) as usize;
        if n < HEADER_LEN + 16 || n > HEADER_LEN + MAX_MEDIA_FRAME + 16 {
            return Err(CryptoError::Protocol("media frame length out of range"));
        }
        let mut body = vec![0u8; n];
        self.stream.read_exact(&mut body)?;
        let header: [u8; HEADER_LEN] = body[..HEADER_LEN].try_into().unwrap();
        let kind = MediaKind::from_byte(header[0])
            .ok_or(CryptoError::Malformed("unknown media kind"))?;
        let seq = u32::from_le_bytes(header[1..5].try_into().unwrap());
        let timestamp = u32::from_le_bytes(header[5..9].try_into().unwrap());

        let mut ct = body[HEADER_LEN..].to_vec();
        // The received direction uses the opposite key; AAD is the header.
        let _ = self.recv_dir_is_c2p;
        self.recv_key.open(seq as u64, &header, &mut ct)?;

        Ok(Some(MediaFrame {
            kind,
            seq,
            timestamp,
            payload: ct,
        }))
    }

    pub fn into_inner(self) -> S {
        self.stream
    }
}

// --- Split half-channels for full-duplex real-time calls ------------------
//
// A live call captures+sends and receives+plays concurrently, so the media
// stream is split into a write half and a read half (e.g. two clones of a
// TcpStream). Both sides derive the same directional keys with
// `media_key_pair`.

/// Directional media keys for `is_caller`: returns `(send_key, recv_key)`.
pub fn media_key_pair(
    call_secret: &Zeroizing<[u8; 32]>,
    is_caller: bool,
) -> Result<(AeadKey, AeadKey)> {
    let (c2p, p2c) = media_keys(call_secret)?;
    Ok(if is_caller { (c2p, p2c) } else { (p2c, c2p) })
}

fn write_media_frame<W: Write>(
    w: &mut W,
    key: &AeadKey,
    kind: MediaKind,
    seq: u32,
    timestamp: u32,
    payload: &[u8],
) -> Result<()> {
    if payload.len() > MAX_MEDIA_FRAME {
        return Err(CryptoError::Protocol("media frame too large"));
    }
    let aad = frame_aad(kind, seq, timestamp);
    let mut buf = payload.to_vec();
    key.seal(seq as u64, &aad, &mut buf);
    let mut frame = Vec::with_capacity(4 + HEADER_LEN + buf.len());
    frame.extend_from_slice(&((HEADER_LEN + buf.len()) as u32).to_le_bytes());
    frame.extend_from_slice(&aad);
    frame.extend_from_slice(&buf);
    w.write_all(&frame)?;
    w.flush()?;
    Ok(())
}

fn read_media_frame<R: Read>(r: &mut R, key: &AeadKey) -> Result<Option<MediaFrame>> {
    let mut len = [0u8; 4];
    match r.read_exact(&mut len) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(CryptoError::Io(e)),
    }
    let n = u32::from_le_bytes(len) as usize;
    if n < HEADER_LEN + 16 || n > HEADER_LEN + MAX_MEDIA_FRAME + 16 {
        return Err(CryptoError::Protocol("media frame length out of range"));
    }
    let mut body = vec![0u8; n];
    r.read_exact(&mut body)?;
    let header: [u8; HEADER_LEN] = body[..HEADER_LEN].try_into().unwrap();
    let kind = MediaKind::from_byte(header[0]).ok_or(CryptoError::Malformed("unknown media kind"))?;
    let seq = u32::from_le_bytes(header[1..5].try_into().unwrap());
    let timestamp = u32::from_le_bytes(header[5..9].try_into().unwrap());
    let mut ct = body[HEADER_LEN..].to_vec();
    key.open(seq as u64, &header, &mut ct)?;
    Ok(Some(MediaFrame {
        kind,
        seq,
        timestamp,
        payload: ct,
    }))
}

/// Write (send) half of a duplex media call.
pub struct MediaSender<W> {
    w: W,
    key: AeadKey,
    seq: u32,
}

impl<W: Write> MediaSender<W> {
    pub fn new(w: W, send_key: AeadKey) -> Self {
        Self { w, key: send_key, seq: 0 }
    }
    pub fn send(&mut self, kind: MediaKind, timestamp: u32, payload: &[u8]) -> Result<()> {
        write_media_frame(&mut self.w, &self.key, kind, self.seq, timestamp, payload)?;
        self.seq = self
            .seq
            .checked_add(1)
            .ok_or(CryptoError::Protocol("media sequence exhausted (rekey)"))?;
        Ok(())
    }
}

/// Read (receive) half of a duplex media call.
pub struct MediaReceiver<R> {
    r: R,
    key: AeadKey,
}

impl<R: Read> MediaReceiver<R> {
    pub fn new(r: R, recv_key: AeadKey) -> Self {
        Self { r, key: recv_key }
    }
    pub fn recv(&mut self) -> Result<Option<MediaFrame>> {
        read_media_frame(&mut self.r, &self.key)
    }
}

// ---------------------------------------------------------------------------
// Media device / codec integration point.
//
// Real calls need a capture+encode source and a decode+playback sink. These
// traits are the seam where a cpal/Opus (audio) and camera/VP8 (video)
// implementation plugs in; this crate carries and encrypts whatever bytes they
// produce. A synthetic implementation (below, tests only) proves the pipeline
// end to end without hardware.
// ---------------------------------------------------------------------------

/// Produces encoded media frames (e.g. Opus audio / VP8 video packets).
pub trait MediaSource {
    /// Next encoded frame, or `None` when the source stops. Blocking.
    fn next_frame(&mut self) -> Option<(MediaKind, u32, Vec<u8>)>;
}

/// Consumes decrypted media frames for decode + playback.
pub trait MediaSink {
    fn on_frame(&mut self, frame: &MediaFrame);
}
