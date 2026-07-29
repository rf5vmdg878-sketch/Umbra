//! Identity layer (Phase 2).
//!
//! - [`Identity`] — long-term Ed25519 signing key (the same key family as v3
//!   onion-service identities, which Phase 3's Tor transport will use).
//!   SymCrypt implements no EdDSA, so this uses the audited `ed25519-dalek`.
//! - [`KeyBundle`] — the shareable contact-exchange blob: identity public key
//!   + X-Wing public key + Ed25519 signature binding them. Decoding always
//!   verifies the signature; an unsigned or mis-signed bundle never becomes a
//!   contact (Ricochet's "nothing from strangers" rule, applied to key
//!   material).
//! - [`Contact`] — an approved/pending peer stored inside the encrypted
//!   profile (never in plaintext at rest — Cwtch's rule).
//! - [`Profile`] — display name + both key seeds + contacts.

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, Zeroizing};

use crate::crypto::xwing::{self, XWingPrivate, XWingPublic};
use crate::crypto::{CryptoError, Result};

/// Domain separator for bundle signatures — an Ed25519 signature made for any
/// other purpose can never validate a bundle, and vice versa.
const BUNDLE_DOMAIN: &[u8] = b"unichat-key-bundle-v1\0";

pub const BUNDLE_PREFIX: &str = "unichat-bundle-v1:";

/// Long-term Ed25519 identity key, held as its 32-byte seed.
pub struct Identity {
    signing: SigningKey,
}

impl Identity {
    pub fn generate() -> Self {
        let mut seed = Zeroizing::new([0u8; 32]);
        crate::crypto::random_bytes(seed.as_mut());
        Self::from_seed(&seed)
    }

    pub fn from_seed(seed: &Zeroizing<[u8; 32]>) -> Self {
        Self {
            signing: SigningKey::from_bytes(seed),
        }
    }

    pub fn public_bytes(&self) -> [u8; 32] {
        self.signing.verifying_key().to_bytes()
    }

    /// Detached Ed25519 signature over an arbitrary message (used by the
    /// session handshake to sign transcript digests).
    pub fn sign_detached(&self, msg: &[u8]) -> [u8; 64] {
        self.signing.sign(msg).to_bytes()
    }

    fn sign_bundle(&self, xwing_pk: &[u8; xwing::PUBLIC_KEY_SIZE]) -> [u8; 64] {
        let mut msg = Vec::with_capacity(BUNDLE_DOMAIN.len() + xwing_pk.len());
        msg.extend_from_slice(BUNDLE_DOMAIN);
        msg.extend_from_slice(xwing_pk);
        self.signing.sign(&msg).to_bytes()
    }
}

/// Identity public key + X-Wing public key, bound by an Ed25519 signature.
#[derive(Clone)]
pub struct KeyBundle {
    identity_pk: [u8; 32],
    xwing_pk: [u8; xwing::PUBLIC_KEY_SIZE],
    signature: [u8; 64],
}

impl KeyBundle {
    pub fn new(identity: &Identity, xwing_pk: &[u8; xwing::PUBLIC_KEY_SIZE]) -> Self {
        Self {
            identity_pk: identity.public_bytes(),
            xwing_pk: *xwing_pk,
            signature: identity.sign_bundle(xwing_pk),
        }
    }

    pub fn identity_pk(&self) -> &[u8; 32] {
        &self.identity_pk
    }

    pub fn xwing_pk(&self) -> &[u8; xwing::PUBLIC_KEY_SIZE] {
        &self.xwing_pk
    }

    pub fn xwing_public(&self) -> Result<XWingPublic> {
        XWingPublic::from_bytes(&self.xwing_pk)
    }

    /// `unichat-bundle-v1:<base64(identity_pk || xwing_pk || signature)>`
    pub fn encode(&self) -> String {
        let mut raw = Vec::with_capacity(32 + xwing::PUBLIC_KEY_SIZE + 64);
        raw.extend_from_slice(&self.identity_pk);
        raw.extend_from_slice(&self.xwing_pk);
        raw.extend_from_slice(&self.signature);
        format!("{}{}", BUNDLE_PREFIX, B64.encode(raw))
    }

    /// Decode AND verify. A bundle whose signature does not validate under its
    /// own claimed identity key is rejected outright.
    pub fn decode(text: &str) -> Result<Self> {
        let body = text
            .trim()
            .strip_prefix(BUNDLE_PREFIX)
            .ok_or(CryptoError::InvalidKey("missing unichat-bundle-v1 prefix"))?;
        let raw = B64
            .decode(body.trim())
            .map_err(|_| CryptoError::InvalidKey("bundle is not valid base64"))?;
        if raw.len() != 32 + xwing::PUBLIC_KEY_SIZE + 64 {
            return Err(CryptoError::InvalidKey("bundle has wrong length"));
        }
        let identity_pk: [u8; 32] = raw[..32].try_into().unwrap();
        let xwing_pk: [u8; xwing::PUBLIC_KEY_SIZE] =
            raw[32..32 + xwing::PUBLIC_KEY_SIZE].try_into().unwrap();
        let signature: [u8; 64] = raw[32 + xwing::PUBLIC_KEY_SIZE..].try_into().unwrap();

        let verifying = VerifyingKey::from_bytes(&identity_pk)
            .map_err(|_| CryptoError::InvalidKey("bundle identity key is not a valid point"))?;
        let mut msg = Vec::with_capacity(BUNDLE_DOMAIN.len() + xwing_pk.len());
        msg.extend_from_slice(BUNDLE_DOMAIN);
        msg.extend_from_slice(&xwing_pk);
        verifying
            .verify_strict(&msg, &Signature::from_bytes(&signature))
            .map_err(|_| CryptoError::InvalidKey("bundle signature verification failed"))?;

        Ok(Self {
            identity_pk,
            xwing_pk,
            signature,
        })
    }

    /// Human-comparable fingerprint of both public keys, for out-of-band
    /// verification: SHA3-256(identity_pk || xwing_pk), first 20 bytes as five
    /// hex groups.
    pub fn fingerprint(&self) -> String {
        fingerprint_of(&self.identity_pk, &self.xwing_pk)
    }
}

/// Verify a detached Ed25519 signature under a raw identity public key.
/// Returns false on any malformed input (never panics).
pub fn verify_detached(identity_pk: &[u8; 32], msg: &[u8], sig: &[u8; 64]) -> bool {
    match VerifyingKey::from_bytes(identity_pk) {
        Ok(vk) => vk.verify_strict(msg, &Signature::from_bytes(sig)).is_ok(),
        Err(_) => false,
    }
}

pub(crate) fn fingerprint_of(identity_pk: &[u8; 32], xwing_pk: &[u8]) -> String {
    let mut input = Vec::with_capacity(32 + xwing_pk.len());
    input.extend_from_slice(identity_pk);
    input.extend_from_slice(xwing_pk);
    let hash = symcrypt::hash::sha3_256(&input);
    hash[..20]
        .chunks(4)
        .map(|c| c.iter().map(|b| format!("{b:02x}")).collect::<String>())
        .collect::<Vec<_>>()
        .join("-")
}

#[derive(Serialize, Deserialize, Clone, Copy, PartialEq, Eq, Debug)]
#[serde(rename_all = "lowercase")]
pub enum ContactState {
    /// Seen (e.g. incoming knock in Phase 3) but not yet approved — no data
    /// beyond the knock is ever exchanged in this state.
    Pending,
    Approved,
    Blocked,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct Contact {
    pub alias: String,
    pub identity_pk_b64: String,
    pub xwing_pk_b64: String,
    pub state: ContactState,
    pub added_unix: u64,
    /// User confirmed the fingerprint out of band. `#[serde(default)]` keeps
    /// profiles written before this field existed loadable.
    #[serde(default)]
    pub verified: bool,
}

impl Contact {
    pub fn from_bundle(alias: &str, bundle: &KeyBundle, state: ContactState) -> Self {
        Self {
            alias: alias.to_string(),
            identity_pk_b64: B64.encode(bundle.identity_pk()),
            xwing_pk_b64: B64.encode(bundle.xwing_pk()),
            state,
            added_unix: now_unix(),
            verified: false,
        }
    }

    pub fn identity_pk(&self) -> Result<[u8; 32]> {
        B64.decode(&self.identity_pk_b64)
            .ok()
            .and_then(|v| v.try_into().ok())
            .ok_or(CryptoError::InvalidKey("stored contact identity key corrupt"))
    }

    pub fn xwing_public(&self) -> Result<XWingPublic> {
        let bytes: [u8; xwing::PUBLIC_KEY_SIZE] = B64
            .decode(&self.xwing_pk_b64)
            .ok()
            .and_then(|v| v.try_into().ok())
            .ok_or(CryptoError::InvalidKey("stored contact X-Wing key corrupt"))?;
        XWingPublic::from_bytes(&bytes)
    }

    pub fn fingerprint(&self) -> Result<String> {
        let id = self.identity_pk()?;
        let xw = B64
            .decode(&self.xwing_pk_b64)
            .map_err(|_| CryptoError::InvalidKey("stored contact X-Wing key corrupt"))?;
        Ok(fingerprint_of(&id, &xw))
    }
}

fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// A profile: display name, both long-term key seeds, and the contact list.
/// Serialized (as JSON) only inside the encrypted profile store — nothing here
/// ever touches disk in plaintext.
#[derive(Serialize, Deserialize)]
pub struct Profile {
    pub version: u32,
    pub display_name: String,
    pub created_unix: u64,
    identity_seed_b64: String,
    xwing_seed_b64: String,
    pub contacts: Vec<Contact>,
    /// Joined groups (Phase 5). `#[serde(default)]` keeps older stored profiles
    /// (written before groups existed) loadable.
    #[serde(default)]
    pub groups: Vec<StoredGroup>,
}

/// A joined group as persisted in the (encrypted) profile store. The group key
/// is secret; it lives here only because the whole profile DB is encrypted at
/// rest (same treatment as the identity/X-Wing seeds).
#[derive(Serialize, Deserialize, Clone)]
pub struct StoredGroup {
    pub name: String,
    pub group_id_b64: String,
    pub group_key_b64: String,
}

impl Drop for Profile {
    fn drop(&mut self) {
        self.identity_seed_b64.zeroize();
        self.xwing_seed_b64.zeroize();
        for g in &mut self.groups {
            g.group_key_b64.zeroize();
        }
    }
}

impl Profile {
    pub fn create(display_name: &str) -> Result<Self> {
        let mut id_seed = Zeroizing::new([0u8; 32]);
        crate::crypto::random_bytes(id_seed.as_mut());
        let mut xw_seed = Zeroizing::new([0u8; 32]);
        crate::crypto::random_bytes(xw_seed.as_mut());
        // Fail early if the seed is unusable.
        XWingPrivate::from_seed(&Zeroizing::new(*xw_seed))?;
        Ok(Self {
            version: 1,
            display_name: display_name.to_string(),
            created_unix: now_unix(),
            identity_seed_b64: B64.encode(id_seed.as_ref()),
            xwing_seed_b64: B64.encode(xw_seed.as_ref()),
            contacts: Vec::new(),
            groups: Vec::new(),
        })
    }

    /// Store a group (from `groups::Group::to_stored`). Rejects duplicate names.
    pub fn add_group(&mut self, group: StoredGroup) -> Result<()> {
        if group.name.trim().is_empty() {
            return Err(CryptoError::InvalidKey("group name must not be empty"));
        }
        if self.groups.iter().any(|g| g.name == group.name) {
            return Err(CryptoError::InvalidKey("a group with this name already exists"));
        }
        self.groups.push(group);
        Ok(())
    }

    pub fn group(&self, name: &str) -> Option<&StoredGroup> {
        self.groups.iter().find(|g| g.name == name)
    }

    pub fn remove_group(&mut self, name: &str) -> bool {
        let before = self.groups.len();
        self.groups.retain(|g| g.name != name);
        self.groups.len() != before
    }

    fn seed_from(field: &str, what: &'static str) -> Result<Zeroizing<[u8; 32]>> {
        let mut vec = B64
            .decode(field)
            .map_err(|_| CryptoError::InvalidKey(what))?;
        let arr: [u8; 32] = vec
            .as_slice()
            .try_into()
            .map_err(|_| CryptoError::InvalidKey(what))?;
        vec.zeroize();
        Ok(Zeroizing::new(arr))
    }

    pub fn identity(&self) -> Result<Identity> {
        Ok(Identity::from_seed(&Self::seed_from(
            &self.identity_seed_b64,
            "stored identity seed corrupt",
        )?))
    }

    pub fn xwing(&self) -> Result<XWingPrivate> {
        XWingPrivate::from_seed(&Self::seed_from(
            &self.xwing_seed_b64,
            "stored X-Wing seed corrupt",
        )?)
    }

    /// The shareable, signed key bundle for this profile.
    pub fn bundle(&self) -> Result<KeyBundle> {
        let identity = self.identity()?;
        let xwing = self.xwing()?;
        Ok(KeyBundle::new(&identity, xwing.public_key_bytes()))
    }

    pub fn fingerprint(&self) -> Result<String> {
        Ok(self.bundle()?.fingerprint())
    }

    /// Add a contact from a verified bundle. Rejects duplicate aliases and
    /// rejects re-adding our own identity.
    pub fn add_contact(&mut self, alias: &str, bundle: &KeyBundle) -> Result<()> {
        if alias.trim().is_empty() {
            return Err(CryptoError::InvalidKey("contact alias must not be empty"));
        }
        if self.contacts.iter().any(|c| c.alias == alias) {
            return Err(CryptoError::InvalidKey("a contact with this alias already exists"));
        }
        if bundle.identity_pk() == &self.identity()?.public_bytes() {
            return Err(CryptoError::InvalidKey("refusing to add own identity as contact"));
        }
        self.contacts
            .push(Contact::from_bundle(alias, bundle, ContactState::Approved));
        Ok(())
    }

    pub fn remove_contact(&mut self, alias: &str) -> bool {
        let before = self.contacts.len();
        self.contacts.retain(|c| c.alias != alias);
        self.contacts.len() != before
    }

    /// Mark a contact verified/unverified (after out-of-band fingerprint check).
    pub fn set_contact_verified(&mut self, alias: &str, verified: bool) -> bool {
        if let Some(c) = self.contacts.iter_mut().find(|c| c.alias == alias) {
            c.verified = verified;
            true
        } else {
            false
        }
    }

    pub fn contact(&self, alias: &str) -> Option<&Contact> {
        self.contacts.iter().find(|c| c.alias == alias)
    }
}
