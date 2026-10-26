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
    Ciphertext as MlKemCiphertext, KeyExport, MlKem768, TryKeyInit,
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
    fn wrong_recipient_fails() {
        let alice = Identity::generate();
        let bob = Identity::generate();
        let eve = Identity::generate();
        let (bob_x, bob_kem) = bob.public_bundle();

        let sealed = seal(&alice, &bob_x, &bob_kem, b"secret").unwrap();
        assert!(open(&eve, &sealed).is_err());
    }
}
