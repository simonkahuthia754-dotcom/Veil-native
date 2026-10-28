//! End-to-end encryption: a hybrid classical + post-quantum key exchange,
//! feeding a single symmetric key used for authenticated encryption.
//!
//! Design, plainly stated:
//!   1. X25519 ECDH between sender and recipient's long-term identity keys
//!      (classical shared secret).
//!   2. ML-KEM-768 encapsulation to the recipient's PQ public key (post-
//!      quantum shared secret). The encapsulation ciphertext travels
//!      alongside the message — the recipient decapsulates it with their
//!      PQ secret key to recover the same PQ shared secret.
//!   3. Both secrets go through HKDF-SHA256 together to derive one 256-bit
//!      symmetric key.
//!   4. That key encrypts the message with XChaCha20-Poly1305 (AEAD).
//!
//! Why hybrid instead of PQ-only: if ML-KEM turns out to have an
//! undiscovered weakness (it's new; X25519 has 15+ years of scrutiny), the
//! classical half still protects the message, and vice versa for "a
//! quantum computer breaks X25519" — this is the same reasoning Signal and
//! major browsers use for their PQ rollouts, not a shortcut.
//!
//! This module does NOT implement forward secrecy (no ratcheting of
//! per-message keys yet) — that is a real, named gap, same as the web
//! prototype's backend. Said once here rather than buried.

use chacha20poly1305::{
    aead::{Aead, AeadCore, KeyInit, OsRng as AeadOsRng},
    XChaCha20Poly1305, XNonce,
};
use hkdf::Hkdf;
use ml_kem::{
    kem::{Decapsulate, Encapsulate, Kem},
    Ciphertext as MlKemCiphertext, KeyExport, KeyInit, MlKem768, TryKeyInit,
};
use rand_core::OsRng;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use thiserror::Error;
use x25519_dalek::{PublicKey as XPublicKey, StaticSecret as XSecretKey};
use zeroize::Zeroize;

#[derive(Debug, Error)]
pub enum E2eError {
    #[error("encryption failed")]
    Encrypt,
    #[error("decryption failed — wrong key, tampered ciphertext, or wrong recipient")]
    Decrypt,
    #[error("malformed key material")]
    BadKey,
}

/// A client's long-term identity: one classical keypair + one PQ keypair.
/// The secret halves never leave the device; only the public halves are
/// ever sent to the server or to other users.
pub struct Identity {
    x_secret: XSecretKey,
    pub x_public: XPublicKey,
    kem_dk: <MlKem768 as Kem>::DecapsulationKey,
    pub kem_ek: <MlKem768 as Kem>::EncapsulationKey,
}

impl Identity {
    pub fn generate() -> Self {
        let x_secret = XSecretKey::random_from_rng(OsRng);
        let x_public = XPublicKey::from(&x_secret);
        // Kem::generate_keypair() (not generate()) — confirmed against the
        // real trait definition in the `kem` crate's own source, which
        // this module previously wasn't checked against (see Cargo.toml's
        // note on the 0.2 -> 0.3.3 correction).
        let (kem_dk, kem_ek) = MlKem768::generate_keypair();
        Self {
            x_secret,
            x_public,
            kem_dk,
            kem_ek,
        }
    }

    /// Public bundle to publish to the server / share with contacts:
    /// (x25519 pubkey bytes, ML-KEM-768 encapsulation key bytes).
    pub fn public_bundle(&self) -> (Vec<u8>, Vec<u8>) {
        (
            self.x_public.as_bytes().to_vec(),
            // KeyExport::to_bytes() -> Array<u8, N>, which derefs to a
            // plain byte slice.
            self.kem_ek.to_bytes().to_vec(),
        )
    }

    /// Crate-internal access to the classical secret half, for
    /// `session.rs`'s X3DH-style handshake, which runs its own DH
    /// operations against this identity's long-term X25519 key alongside a
    /// medium-term/one-time prekey's. Not `pub`: nothing outside this
    /// crate should ever touch this directly.
    ///
    /// No equivalent `kem_dk()` accessor: the X3DH handshake's KEM
    /// encapsulation step is always run against the responder's
    /// medium-term prekey (so a rotated-out medium-term prekey changes the
    /// PQ contribution for new sessions too — see session.rs's module
    /// doc), never against the long-term identity's own PQ key, so nothing
    /// in this crate needs to reach `kem_dk` from outside `e2e.rs`. A
    /// first version of this accessor existed unused and was removed —
    /// caught by clippy's dead-code lint in CI, not left in as an
    /// `#[allow(dead_code)]`.
    pub(crate) fn x_secret(&self) -> &XSecretKey {
        &self.x_secret
    }

    /// Export the secret material needed to reconstruct this identity
    /// later, e.g. to persist it in a client's encrypted-at-rest vault so
    /// the same identity survives across restarts instead of being
    /// regenerated every run (which would break every contact's existing
    /// sessions with this device).
    ///
    /// Returns `(x25519 secret bytes, ML-KEM-768 seed bytes)`:
    ///   - `StaticSecret::to_bytes(&self) -> [u8; 32]` — confirmed against
    ///     the real x25519-dalek 2.x source (not assumed from the existing
    ///     `as_bytes()` usage elsewhere in this file, which returns a
    ///     reference, not an owned copy).
    ///   - `KeyExport::to_bytes(&self) -> Seed` on `DecapsulationKey` — a
    ///     64-byte seed, NOT the same byte shape as the encapsulation
    ///     key's export. Confirmed via the `ml-kem` crate's own docs: this
    ///     panics only for a key built from "expanded form", which never
    ///     applies here since every `Identity` is built by
    ///     `generate_keypair()` or by this same round-trip.
    pub fn to_secret_bytes(&self) -> (Vec<u8>, Vec<u8>) {
        (
            self.x_secret.to_bytes().to_vec(),
            self.kem_dk.to_bytes().to_vec(),
        )
    }

    /// Reconstruct an `Identity` from bytes previously produced by
    /// `to_secret_bytes()`. Both halves are re-derived deterministically
    /// from their secrets (the X25519 public key from the secret scalar,
    /// the ML-KEM encapsulation key from the decapsulation key), so the
    /// result is byte-for-byte the same identity that was exported.
    pub fn from_secret_bytes(
        x_secret_bytes: &[u8],
        kem_seed_bytes: &[u8],
    ) -> Result<Self, E2eError> {
        let x_arr: [u8; 32] = x_secret_bytes.try_into().map_err(|_| E2eError::BadKey)?;
        let x_secret = XSecretKey::from(x_arr);
        let x_public = XPublicKey::from(&x_secret);

        // KeyInit::new_from_slice(key: &[u8]) -> Result<Self, InvalidLength>
        // — a different trait and error type than EncapsulationKey's
        // TryKeyInit::new_from_slice (-> Result<Self, InvalidKey>) used
        // elsewhere in this file. Confirmed as a real asymmetry in the
        // `ml-kem` crate's own docs, not assumed to match.
        let kem_dk = <MlKem768 as Kem>::DecapsulationKey::new_from_slice(kem_seed_bytes)
            .map_err(|_| E2eError::BadKey)?;
        let kem_ek = kem_dk.encapsulation_key().clone();

        Ok(Self {
            x_secret,
            x_public,
            kem_dk,
            kem_ek,
        })
    }
}

/// A message, sealed for one specific recipient.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct SealedMessage {
    /// Sender's X25519 public key, so the recipient can redo the ECDH half.
    pub sender_x_public: Vec<u8>,
    /// ML-KEM ciphertext — the recipient decapsulates this with their own
    /// PQ secret key to recover the PQ half of the shared secret.
    pub kem_ciphertext: Vec<u8>,
    pub nonce: Vec<u8>,
    pub ciphertext: Vec<u8>,
}

/// Encrypt `plaintext` for `recipient_x_public` + `recipient_kem_ek`, signed
/// implicitly by `sender`'s identity (the recipient re-derives the same key
/// only if the sender's claimed public key really was used).
pub fn seal(
    sender: &Identity,
    recipient_x_public: &[u8],
    recipient_kem_ek: &[u8],
    plaintext: &[u8],
) -> Result<SealedMessage, E2eError> {
    let recipient_x: [u8; 32] = recipient_x_public
        .try_into()
        .map_err(|_| E2eError::BadKey)?;
    let recipient_x_public = XPublicKey::from(recipient_x);
    let classical_secret = sender.x_secret.diffie_hellman(&recipient_x_public);

    // TryKeyInit::new_from_slice — the fallible, variable-length-input
    // constructor (confirmed from the real trait: `fn new_from_slice(key:
    // &[u8]) -> Result<Self, InvalidKey>`), not an invented `from_bytes`.
    let recipient_ek = <MlKem768 as Kem>::EncapsulationKey::new_from_slice(recipient_kem_ek)
        .map_err(|_| E2eError::BadKey)?;
    // Encapsulate::encapsulate() is infallible (no Result) when the
    // "getrandom" feature is enabled — confirmed from the real trait
    // definition, not assumed.
    let (kem_ciphertext, pq_secret) = recipient_ek.encapsulate();

    let key = derive_key(classical_secret.as_bytes(), &pq_secret);
    let cipher = XChaCha20Poly1305::new((&key).into());
    let nonce = XChaCha20Poly1305::generate_nonce(&mut AeadOsRng);
    let ciphertext = cipher
        .encrypt(&nonce, plaintext)
        .map_err(|_| E2eError::Encrypt)?;

    Ok(SealedMessage {
        sender_x_public: sender.x_public.as_bytes().to_vec(),
        kem_ciphertext: kem_ciphertext.to_vec(),
        nonce: nonce.to_vec(),
        ciphertext,
    })
}

/// Decrypt a `SealedMessage` addressed to `recipient`.
pub fn open(recipient: &Identity, msg: &SealedMessage) -> Result<Vec<u8>, E2eError> {
    let sender_x: [u8; 32] = msg
        .sender_x_public
        .as_slice()
        .try_into()
        .map_err(|_| E2eError::BadKey)?;
    let sender_x_public = XPublicKey::from(sender_x);
    let classical_secret = recipient.x_secret.diffie_hellman(&sender_x_public);

    // Ciphertext<K> is a plain `Array<u8, K::CiphertextSize>` type alias
    // (confirmed from the `kem` crate's own source), which implements
    // TryFrom<&[u8]> directly — no `Kem::Ciphertext` associated type or
    // `from_bytes` constructor exists, unlike this file's first two wrong
    // guesses.
    let kem_ct: MlKemCiphertext<MlKem768> = msg
        .kem_ciphertext
        .as_slice()
        .try_into()
        .map_err(|_| E2eError::BadKey)?;
    // Decapsulate::decapsulate() is infallible by trait definition
    // (`-> SharedKey<Self::Kem>`, no Result) — confirmed, not assumed.
    let pq_secret = recipient.kem_dk.decapsulate(&kem_ct);

    let key = derive_key(classical_secret.as_bytes(), &pq_secret);
    let cipher = XChaCha20Poly1305::new((&key).into());
    let nonce = XNonce::from_slice(&msg.nonce);
    cipher
        .decrypt(nonce, msg.ciphertext.as_slice())
        .map_err(|_| E2eError::Decrypt)
}

fn derive_key(classical: &[u8], pq: &[u8]) -> [u8; 32] {
    let mut ikm = Vec::with_capacity(classical.len() + pq.len());
    ikm.extend_from_slice(classical);
    ikm.extend_from_slice(pq);
    let hk = Hkdf::<Sha256>::new(Some(b"veil-e2e-hybrid-v1"), &ikm);
    let mut okm = [0u8; 32];
    hk.expand(b"message-key", &mut okm)
        .expect("32 bytes is a valid HKDF output length");
    ikm.zeroize();
    okm
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip() {
        let alice = Identity::generate();
        let bob = Identity::generate();
        let (bob_x, bob_kem) = bob.public_bundle();

        let sealed = seal(&alice, &bob_x, &bob_kem, b"the chamber meets at dusk").unwrap();
        let opened = open(&bob, &sealed).unwrap();
        assert_eq!(opened, b"the chamber meets at dusk");
    }

    #[test]
    fn secret_bytes_round_trip_preserves_identity() {
        let original = Identity::generate();
        let (x_bytes, kem_bytes) = original.to_secret_bytes();
        let restored = Identity::from_secret_bytes(&x_bytes, &kem_bytes).unwrap();

        assert_eq!(original.x_public.as_bytes(), restored.x_public.as_bytes());
        assert_eq!(original.public_bundle(), restored.public_bundle());

        // And the restored identity must actually work for real messages,
        // not just report matching public keys.
        let other = Identity::generate();
        let (other_x, other_kem) = other.public_bundle();
        let sealed = seal(&restored, &other_x, &other_kem, b"still me").unwrap();
        assert_eq!(open(&other, &sealed).unwrap(), b"still me");

        let (restored_x, restored_kem) = restored.public_bundle();
        let sealed_to_restored = seal(&other, &restored_x, &restored_kem, b"to you").unwrap();
        assert_eq!(open(&restored, &sealed_to_restored).unwrap(), b"to you");
    }

    #[test]
    fn wrong_recipient_fails() {
        let alice = Identity::generate();
        let bob = Identity::generate();
        let eve = Identity::generate();
        let (bob_x, bob_kem) = bob.public_bundle();

        let sealed = seal(&alice, &bob_x, &bob_kem, b"secret").unwrap();
        assert!(open(&eve, &sealed).is_err());
    }
}
