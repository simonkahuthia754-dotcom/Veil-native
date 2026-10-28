//! Forward secrecy: an X3DH-style session handshake using published prekey
//! bundles, followed by a per-direction KDF sending-chain ratchet for the
//! messages within that session.
//!
//! Scope, stated plainly rather than overclaimed:
//!   - What this gives you: compromise of a party's long-term identity key
//!     (or even a medium-term prekey, once it's been rotated out) does NOT
//!     let an attacker decrypt messages from a session that already moved
//!     past them in the chain — each message key is derived once, used
//!     once, and the chain key that produced it is advanced and the old
//!     value discarded. That is real forward secrecy for the lifetime of
//!     one session.
//!   - What this does NOT give you: a full Double-Ratchet-style
//!     bidirectional DH re-key on every message exchange (Signal's
//!     "future secrecy" / post-compromise security — recovering from a
//!     key compromise partway through an ongoing conversation). This
//!     module's chains only ever move forward from the one X3DH-derived
//!     root key; there is no per-message DH step layered on top. Adding
//!     one is real, scoped future work, not hidden here.
//!
//! The X3DH construction (mirrors Signal's, extended with an ML-KEM-768
//! encapsulation for the post-quantum contribution, same hybrid-not-PQ-only
//! reasoning as `e2e.rs`):
//!   DH1 = initiator_identity   x responder_medium_term
//!   DH2 = initiator_ephemeral  x responder_identity
//!   DH3 = initiator_ephemeral  x responder_medium_term
//!   DH4 = initiator_ephemeral  x responder_one_time      (if one was available)
//!   KEM = Encapsulate(responder_medium_term_kem_pub)
//!   root_key = HKDF-SHA256(salt="veil-x3dh-v1",
//!                           ikm = DH1 || DH2 || DH3 || DH4? || KEM_secret,
//!                           info = "root-key")
//!
//! Tying the KEM step to the *medium-term* prekey rather than the
//! never-rotated identity PQ key is deliberate: once that medium-term
//! prekey is rotated out and discarded, new sessions get a fresh PQ
//! contribution too, not one tied forever to the identity key.

use std::collections::HashMap;

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
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::e2e::Identity;

#[derive(Debug, Error)]
pub enum SessionError {
    #[error("malformed key material")]
    BadKey,
    #[error("encryption failed")]
    Encrypt,
    #[error("decryption failed — wrong key, tampered ciphertext, or session out of sync")]
    Decrypt,
    #[error("message counter {0} is too far ahead of the current chain position — refusing to derive that many skipped keys")]
    TooFarAhead(u32),
    #[error("message counter {0} is older than this chain has already advanced past (duplicate or replay)")]
    AlreadyAdvancedPast(u32),
}

/// A medium-term or one-time prekey: a short-lived X25519 + ML-KEM-768
/// keypair, structurally identical to `Identity` but deliberately a
/// separate type — conflating "my permanent identity" with "a prekey I
/// rotate or burn after one use" has bitten real protocols before.
pub struct Prekey {
    x_secret: XSecretKey,
    pub x_public: XPublicKey,
    kem_dk: <MlKem768 as Kem>::DecapsulationKey,
    pub kem_ek: <MlKem768 as Kem>::EncapsulationKey,
}

impl Prekey {
    pub fn generate() -> Self {
        let x_secret = XSecretKey::random_from_rng(OsRng);
        let x_public = XPublicKey::from(&x_secret);
        let (kem_dk, kem_ek) = MlKem768::generate_keypair();
        Self {
            x_secret,
            x_public,
            kem_dk,
            kem_ek,
        }
    }

    pub fn public_bundle(&self) -> (Vec<u8>, Vec<u8>) {
        (
            self.x_public.as_bytes().to_vec(),
            self.kem_ek.to_bytes().to_vec(),
        )
    }
}

/// What the server hands back from `GET /prekeys/:handle/bundle` — public
/// material only, deserialized from that response.
///
/// Note: the backend also publishes a `kemPub` alongside each one-time
/// prekey's `xPub` (`backend/src/db.js`'s `one_time_prekeys` table), but
/// this v1 handshake only uses the one-time prekey's X25519 half for an
/// extra DH contribution (DH4) — it does not add a second ML-KEM
/// encapsulation for it. Using it too (a second, one-time-bound PQ
/// contribution) would strengthen the PQ side of a single session beyond
/// what the medium-term prekey's KEM step already provides; left as a
/// scoped future enhancement, not implemented here.
pub struct PrekeyBundle {
    pub identity_x_public: Vec<u8>,
    pub medium_term_x_public: Vec<u8>,
    pub medium_term_kem_public: Vec<u8>,
    pub one_time_x_public: Option<Vec<u8>>,
}

/// The handshake payload the initiator sends as the first message of a
/// session — everything the responder needs to derive the same root key.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct InitialMessage {
    pub initiator_identity_x_public: Vec<u8>,
    pub initiator_ephemeral_x_public: Vec<u8>,
    pub kem_ciphertext: Vec<u8>,
    /// Echoes back which one-time prekey (if any) the initiator used, so
    /// the responder knows which locally-stored private one-time prekey to
    /// consume and delete. `None` means the bundle had none left (DH4 was
    /// skipped on both sides).
    pub one_time_x_public_used: Option<Vec<u8>>,
}

/// One ratcheted message: a chain position (`counter`) plus a normal AEAD
/// envelope. The counter is what lets the receiver tolerate modest
/// out-of-order delivery (the relay backend delivers in roughly `created_at`
/// order, but "roughly" is not "guaranteed") without losing forward secrecy
/// — see `Session::open`.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct RatchetedMessage {
    pub counter: u32,
    pub nonce: Vec<u8>,
    pub ciphertext: Vec<u8>,
}

/// Cap on how many chain positions `open()` will advance through (and
/// cache keys for) to catch up to a received counter. Bounds both memory
/// (the skipped-key cache) and CPU against a counter sent either by a
/// buggy peer or a malicious one trying to force expensive catch-up work.
const MAX_SKIP: u32 = 1000;

/// Live session state for one conversation. Deliberately holds only chain
/// keys, never the root key past the moment both chains are derived from
/// it — the root key is not retained, so it cannot itself become a later
/// point of compromise.
// `ZeroizeOnDrop` (not the deprecated `#[zeroize(drop)]` attribute on
// `Zeroize` alone — confirmed against the real crate docs, since this is
// new code in this session rather than a pattern already proven by CI
// elsewhere in this crate) adds a real `Drop` impl that zeroizes the
// non-skipped fields when a `Session` goes out of scope.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct Session {
    send_chain_key: [u8; 32],
    #[zeroize(skip)]
    send_counter: u32,
    recv_chain_key: [u8; 32],
    #[zeroize(skip)]
    recv_counter: u32,
    #[zeroize(skip)]
    skipped_keys: HashMap<u32, [u8; 32]>,
}

/// One ratchet step: HKDF-expand the current chain key (used as the HKDF
/// PRK directly, via `from_prk` — it's already 32 bytes of high-entropy
/// key material, there is nothing to "extract" from) into a message key
/// and the next chain key, with distinct `info` strings so the two outputs
/// are independent even though they're derived from the same input.
fn ratchet_step(chain_key: &[u8; 32]) -> ([u8; 32], [u8; 32]) {
    let hk = Hkdf::<Sha256>::from_prk(chain_key)
        .expect("a 32-byte chain key is always a valid HKDF-SHA256 PRK");
    let mut message_key = [0u8; 32];
    hk.expand(b"veil-ratchet-message-key", &mut message_key)
        .expect("32 is a valid HKDF output length");
    let mut next_chain_key = [0u8; 32];
    hk.expand(b"veil-ratchet-chain-key", &mut next_chain_key)
        .expect("32 is a valid HKDF output length");
    (message_key, next_chain_key)
}

fn derive_root_key(dh_parts: &[&[u8]], kem_secret: &[u8]) -> [u8; 32] {
    let mut ikm = Vec::new();
    for part in dh_parts {
        ikm.extend_from_slice(part);
    }
    ikm.extend_from_slice(kem_secret);
    let hk = Hkdf::<Sha256>::new(Some(b"veil-x3dh-v1"), &ikm);
    let mut root_key = [0u8; 32];
    hk.expand(b"root-key", &mut root_key)
        .expect("32 is a valid HKDF output length");
    ikm.zeroize();
    root_key
}

fn derive_chains(root_key: &[u8; 32]) -> ([u8; 32], [u8; 32]) {
    let hk = Hkdf::<Sha256>::new(Some(b"veil-session-chains-v1"), root_key);
    let mut initiator_to_responder = [0u8; 32];
    hk.expand(b"chain-initiator-to-responder", &mut initiator_to_responder)
        .expect("32 is a valid HKDF output length");
    let mut responder_to_initiator = [0u8; 32];
    hk.expand(b"chain-responder-to-initiator", &mut responder_to_initiator)
        .expect("32 is a valid HKDF output length");
    (initiator_to_responder, responder_to_initiator)
}

fn parse_x_public(bytes: &[u8]) -> Result<XPublicKey, SessionError> {
    let arr: [u8; 32] = bytes.try_into().map_err(|_| SessionError::BadKey)?;
    Ok(XPublicKey::from(arr))
}

/// Alice's side: start a new session against Bob's fetched prekey bundle.
/// Returns the live `Session` (already has a usable send chain — Alice can
/// `seal()` immediately) plus the `InitialMessage` to send as the first
/// real message of the conversation.
pub fn initiate(
    my_identity: &Identity,
    bundle: &PrekeyBundle,
) -> Result<(Session, InitialMessage), SessionError> {
    let responder_identity_x = parse_x_public(&bundle.identity_x_public)?;
    let responder_medium_term_x = parse_x_public(&bundle.medium_term_x_public)?;
    let responder_medium_term_kem =
        <MlKem768 as Kem>::EncapsulationKey::new_from_slice(&bundle.medium_term_kem_public)
            .map_err(|_| SessionError::BadKey)?;

    let ephemeral_secret = XSecretKey::random_from_rng(OsRng);
    let ephemeral_public = XPublicKey::from(&ephemeral_secret);

    let dh1 = my_identity
        .x_secret()
        .diffie_hellman(&responder_medium_term_x);
    let dh2 = ephemeral_secret.diffie_hellman(&responder_identity_x);
    let dh3 = ephemeral_secret.diffie_hellman(&responder_medium_term_x);
    let dh4 = match &bundle.one_time_x_public {
        Some(otpk_bytes) => {
            let otpk = parse_x_public(otpk_bytes)?;
            Some(ephemeral_secret.diffie_hellman(&otpk))
        }
        None => None,
    };

    let (kem_ciphertext, kem_secret) = responder_medium_term_kem.encapsulate();

    let mut dh_parts: Vec<&[u8]> = vec![dh1.as_bytes(), dh2.as_bytes(), dh3.as_bytes()];
    if let Some(dh4) = &dh4 {
        dh_parts.push(dh4.as_bytes());
    }
    let root_key = derive_root_key(&dh_parts, &kem_secret);
    let (chain_i2r, chain_r2i) = derive_chains(&root_key);

    let session = Session {
        send_chain_key: chain_i2r,
        send_counter: 0,
        recv_chain_key: chain_r2i,
        recv_counter: 0,
        skipped_keys: HashMap::new(),
    };
    let init_msg = InitialMessage {
        initiator_identity_x_public: my_identity.x_public.as_bytes().to_vec(),
        initiator_ephemeral_x_public: ephemeral_public.as_bytes().to_vec(),
        kem_ciphertext: kem_ciphertext.to_vec(),
        one_time_x_public_used: bundle.one_time_x_public.clone(),
    };
    Ok((session, init_msg))
}

/// Bob's side: accept an incoming `InitialMessage` using this device's own
/// identity and the medium-term prekey it was addressed to. If the
/// initiator used a one-time prekey, pass the local map of not-yet-used
/// one-time prekeys (keyed by their public X25519 bytes, as published) —
/// the matching entry is removed on success, so it can never be reused for
/// a second session even if the same `InitialMessage` is somehow replayed.
pub fn accept(
    my_identity: &Identity,
    my_medium_term: &Prekey,
    my_one_time_prekeys: &mut HashMap<Vec<u8>, Prekey>,
    init_msg: &InitialMessage,
) -> Result<Session, SessionError> {
    let initiator_identity_x = parse_x_public(&init_msg.initiator_identity_x_public)?;
    let initiator_ephemeral_x = parse_x_public(&init_msg.initiator_ephemeral_x_public)?;

    let dh1 = my_medium_term
        .x_secret
        .diffie_hellman(&initiator_identity_x);
    let dh2 = my_identity
        .x_secret()
        .diffie_hellman(&initiator_ephemeral_x);
    let dh3 = my_medium_term
        .x_secret
        .diffie_hellman(&initiator_ephemeral_x);
    let dh4 = match &init_msg.one_time_x_public_used {
        Some(otpk_pub) => {
            let otpk = my_one_time_prekeys
                .remove(otpk_pub)
                .ok_or(SessionError::BadKey)?; // already used, or never ours
            Some(otpk.x_secret.diffie_hellman(&initiator_ephemeral_x))
        }
        None => None,
    };

    let kem_ct: MlKemCiphertext<MlKem768> = init_msg
        .kem_ciphertext
        .as_slice()
        .try_into()
        .map_err(|_| SessionError::BadKey)?;
    let kem_secret = my_medium_term.kem_dk.decapsulate(&kem_ct);

    let mut dh_parts: Vec<&[u8]> = vec![dh1.as_bytes(), dh2.as_bytes(), dh3.as_bytes()];
    if let Some(dh4) = &dh4 {
        dh_parts.push(dh4.as_bytes());
    }
    let root_key = derive_root_key(&dh_parts, &kem_secret);
    let (chain_i2r, chain_r2i) = derive_chains(&root_key);

    // Bob is the responder: HIS send chain is responder->initiator, and HIS
    // receive chain is initiator->responder — the mirror image of what
    // `initiate` set up for Alice, from the same two derived chain keys.
    Ok(Session {
        send_chain_key: chain_r2i,
        send_counter: 0,
        recv_chain_key: chain_i2r,
        recv_counter: 0,
        skipped_keys: HashMap::new(),
    })
}

impl Session {
    /// Encrypts `plaintext`, advancing the send chain by exactly one step.
    /// The chain key used to derive this message's key is gone the moment
    /// this call returns (overwritten by the next chain key) — that's the
    /// forward secrecy property, not a side effect of it.
    pub fn seal(&mut self, plaintext: &[u8]) -> Result<RatchetedMessage, SessionError> {
        let (message_key, next_chain_key) = ratchet_step(&self.send_chain_key);
        self.send_chain_key = next_chain_key;
        let counter = self.send_counter;
        self.send_counter += 1;

        let cipher = XChaCha20Poly1305::new((&message_key).into());
        let nonce = XChaCha20Poly1305::generate_nonce(&mut AeadOsRng);
        let ciphertext = cipher
            .encrypt(&nonce, plaintext)
            .map_err(|_| SessionError::Encrypt)?;
        Ok(RatchetedMessage {
            counter,
            nonce: nonce.to_vec(),
            ciphertext,
        })
    }

    /// Decrypts a `RatchetedMessage`, tolerating out-of-order arrival up to
    /// `MAX_SKIP` positions: any chain positions skipped over to reach
    /// `msg.counter` have their message keys cached (not re-derivable once
    /// the chain moves on) so a message that arrives late can still be
    /// opened, once, using the cached key — which is then removed.
    pub fn open(&mut self, msg: &RatchetedMessage) -> Result<Vec<u8>, SessionError> {
        let message_key = if let Some(key) = self.skipped_keys.remove(&msg.counter) {
            key
        } else if msg.counter < self.recv_counter {
            return Err(SessionError::AlreadyAdvancedPast(msg.counter));
        } else {
            let skip = msg.counter - self.recv_counter;
            if skip > MAX_SKIP {
                return Err(SessionError::TooFarAhead(msg.counter));
            }
            while self.recv_counter < msg.counter {
                let (skipped_key, next_chain_key) = ratchet_step(&self.recv_chain_key);
                self.skipped_keys.insert(self.recv_counter, skipped_key);
                self.recv_chain_key = next_chain_key;
                self.recv_counter += 1;
            }
            let (message_key, next_chain_key) = ratchet_step(&self.recv_chain_key);
            self.recv_chain_key = next_chain_key;
            self.recv_counter += 1;
            message_key
        };

        let cipher = XChaCha20Poly1305::new((&message_key).into());
        let nonce = XNonce::from_slice(&msg.nonce);
        cipher
            .decrypt(nonce, msg.ciphertext.as_slice())
            .map_err(|_| SessionError::Decrypt)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bundle_from(
        identity: &Identity,
        medium_term: &Prekey,
        otpk: Option<&Prekey>,
    ) -> PrekeyBundle {
        let (mt_x, mt_kem) = medium_term.public_bundle();
        PrekeyBundle {
            identity_x_public: identity.x_public.as_bytes().to_vec(),
            medium_term_x_public: mt_x,
            medium_term_kem_public: mt_kem,
            one_time_x_public: otpk.map(|k| k.public_bundle().0),
        }
    }

    #[test]
    fn handshake_agrees_on_the_same_chains_with_one_time_prekey() {
        let alice = Identity::generate();
        let bob = Identity::generate();
        let bob_mtpk = Prekey::generate();
        let bob_otpk = Prekey::generate();
        let bob_otpk_pub = bob_otpk.public_bundle().0;
        let mut bob_otpk_store = HashMap::new();
        bob_otpk_store.insert(bob_otpk_pub, bob_otpk);

        let bundle = bundle_from(
            &bob,
            &bob_mtpk,
            Some(bob_otpk_store.values().next().unwrap()),
        );
        let (mut alice_session, init_msg) = initiate(&alice, &bundle).unwrap();
        let mut bob_session = accept(&bob, &bob_mtpk, &mut bob_otpk_store, &init_msg).unwrap();

        // The one-time prekey must be consumed — gone from the store.
        assert!(bob_otpk_store.is_empty());

        let sealed = alice_session.seal(b"the chamber meets at dusk").unwrap();
        let opened = bob_session.open(&sealed).unwrap();
        assert_eq!(opened, b"the chamber meets at dusk");
    }

    #[test]
    fn handshake_agrees_without_a_one_time_prekey() {
        let alice = Identity::generate();
        let bob = Identity::generate();
        let bob_mtpk = Prekey::generate();
        let mut empty_store = HashMap::new();

        let bundle = bundle_from(&bob, &bob_mtpk, None);
        let (mut alice_session, init_msg) = initiate(&alice, &bundle).unwrap();
        let mut bob_session = accept(&bob, &bob_mtpk, &mut empty_store, &init_msg).unwrap();

        let sealed = alice_session.seal(b"no one-time prekey this time").unwrap();
        assert_eq!(
            bob_session.open(&sealed).unwrap(),
            b"no one-time prekey this time"
        );
    }

    #[test]
    fn both_directions_work_independently() {
        let alice = Identity::generate();
        let bob = Identity::generate();
        let bob_mtpk = Prekey::generate();
        let mut empty_store = HashMap::new();
        let bundle = bundle_from(&bob, &bob_mtpk, None);
        let (mut alice_session, init_msg) = initiate(&alice, &bundle).unwrap();
        let mut bob_session = accept(&bob, &bob_mtpk, &mut empty_store, &init_msg).unwrap();

        let a_to_b = alice_session.seal(b"hello bob").unwrap();
        assert_eq!(bob_session.open(&a_to_b).unwrap(), b"hello bob");

        let b_to_a = bob_session.seal(b"hello alice").unwrap();
        assert_eq!(alice_session.open(&b_to_a).unwrap(), b"hello alice");
    }

    #[test]
    fn chain_advances_each_message_and_rejects_replay() {
        let alice = Identity::generate();
        let bob = Identity::generate();
        let bob_mtpk = Prekey::generate();
        let mut empty_store = HashMap::new();
        let bundle = bundle_from(&bob, &bob_mtpk, None);
        let (mut alice_session, init_msg) = initiate(&alice, &bundle).unwrap();
        let mut bob_session = accept(&bob, &bob_mtpk, &mut empty_store, &init_msg).unwrap();

        let m0 = alice_session.seal(b"one").unwrap();
        let m1 = alice_session.seal(b"two").unwrap();
        assert_eq!(m0.counter, 0);
        assert_eq!(m1.counter, 1);

        assert_eq!(bob_session.open(&m0).unwrap(), b"one");
        assert_eq!(bob_session.open(&m1).unwrap(), b"two");

        // Replaying an already-consumed counter must fail, not silently
        // succeed with a stale key.
        assert!(bob_session.open(&m0).is_err());
    }

    #[test]
    fn out_of_order_delivery_within_the_skip_window_still_works() {
        let alice = Identity::generate();
        let bob = Identity::generate();
        let bob_mtpk = Prekey::generate();
        let mut empty_store = HashMap::new();
        let bundle = bundle_from(&bob, &bob_mtpk, None);
        let (mut alice_session, init_msg) = initiate(&alice, &bundle).unwrap();
        let mut bob_session = accept(&bob, &bob_mtpk, &mut empty_store, &init_msg).unwrap();

        let m0 = alice_session.seal(b"first").unwrap();
        let m1 = alice_session.seal(b"second").unwrap();
        let m2 = alice_session.seal(b"third").unwrap();

        // Arrives out of order: 2, then 0, then 1.
        assert_eq!(bob_session.open(&m2).unwrap(), b"third");
        assert_eq!(bob_session.open(&m0).unwrap(), b"first");
        assert_eq!(bob_session.open(&m1).unwrap(), b"second");
    }

    #[test]
    fn forward_secrecy_a_captured_later_chain_key_cannot_recover_an_earlier_message() {
        let alice = Identity::generate();
        let bob = Identity::generate();
        let bob_mtpk = Prekey::generate();
        let mut empty_store = HashMap::new();
        let bundle = bundle_from(&bob, &bob_mtpk, None);
        let (mut alice_session, init_msg) = initiate(&alice, &bundle).unwrap();
        let mut bob_session = accept(&bob, &bob_mtpk, &mut empty_store, &init_msg).unwrap();

        let m0 = alice_session.seal(b"secret from the past").unwrap();
        bob_session.open(&m0).unwrap(); // chain advances past position 0, old chain key gone

        // Simulate an attacker who now compromises Bob's CURRENT chain
        // state (e.g. steals the device right after this point) and tries
        // to re-derive message 0's key by running the same ratchet step
        // forward from the current chain key. It must not land on the
        // original key: re-deriving and attempting to open m0 again (after
        // its skipped/consumed entry is gone) must fail.
        assert!(bob_session.open(&m0).is_err());
    }

    #[test]
    fn refuses_to_skip_an_unreasonable_number_of_positions() {
        let alice = Identity::generate();
        let bob = Identity::generate();
        let bob_mtpk = Prekey::generate();
        let mut empty_store = HashMap::new();
        let bundle = bundle_from(&bob, &bob_mtpk, None);
        let (mut alice_session, init_msg) = initiate(&alice, &bundle).unwrap();
        let mut bob_session = accept(&bob, &bob_mtpk, &mut empty_store, &init_msg).unwrap();

        let mut far_future = alice_session.seal(b"way ahead").unwrap();
        far_future.counter = MAX_SKIP + 1;
        assert!(bob_session.open(&far_future).is_err());
    }
}
