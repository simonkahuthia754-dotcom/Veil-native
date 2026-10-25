//! Local secure storage: one encrypted file on disk, keyed by a key derived
//! from the user's passphrase via Argon2id. Everything the client keeps
//! locally (chambers, cached messages, contacts) lives inside this single
//! encrypted blob — there is no plaintext database file sitting next to it
//! for a stolen/seized device to just read.
//!
//! This is the "SQLCipher AES-256 local DB" checklist item, implemented as
//! an encrypted single-file store rather than an encrypted SQLite file —
//! functionally the same guarantee (nothing on disk is plaintext) without
//! pulling in SQLCipher's C build toolchain, which is a real source of
//! cross-compilation breakage for Android CI. If true SQL queries over the
//! local cache are needed later, swap this file's internals for
//! `rusqlite` + a `chacha20poly1305`-wrapped VFS; nothing outside this
//! module would need to change.

use argon2::Argon2;
use chacha20poly1305::{
    aead::{Aead, AeadCore, KeyInit, OsRng},
    XChaCha20Poly1305, XNonce,
};
use serde::{de::DeserializeOwned, Serialize};
use std::{fs, path::{Path, PathBuf}};
use thiserror::Error;
use zeroize::Zeroize;

#[derive(Debug, Error)]
pub enum StorageError {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("key derivation failed")]
    Kdf,
    #[error("decryption failed — wrong passphrase or corrupted/tampered store")]
    Decrypt,
    #[error("serialization error: {0}")]
    Serde(#[from] serde_json::Error),
}

const SALT_LEN: usize = 16;

pub struct SecureStore {
    path: PathBuf,
    key: [u8; 32],
}

impl SecureStore {
    /// Open an existing store, or create a fresh empty one at `path` if it
    /// doesn't exist yet. The on-disk layout is: [16-byte salt][24-byte
    /// nonce][ciphertext]. The salt is the only unencrypted thing on disk —
    /// standard, it has to be readable to even attempt key derivation.
    pub fn open_or_create(path: impl AsRef<Path>, passphrase: &str) -> Result<Self, StorageError> {
        let path = path.as_ref().to_path_buf();
        if !path.exists() {
            let salt = random_bytes::<SALT_LEN>();
            let key = derive_key(passphrase, &salt)?;
            let store = Self { path: path.clone(), key };
            store.write_encrypted(&salt, b"{}")?;
            return Ok(store);
        }
        let bytes = fs::read(&path)?;
        if bytes.len() < SALT_LEN {
            return Err(StorageError::Decrypt);
        }
        let salt: [u8; SALT_LEN] = bytes[..SALT_LEN].try_into().expect("checked length");
        let key = derive_key(passphrase, &salt)?;
        Ok(Self { path, key })
    }

    pub fn load<T: DeserializeOwned + Default>(&self) -> Result<T, StorageError> {
        let bytes = fs::read(&self.path)?;
        let salt = &bytes[..SALT_LEN];
        let rest = &bytes[SALT_LEN..];
        let nonce = XNonce::from_slice(&rest[..24]);
        let ciphertext = &rest[24..];
        let cipher = XChaCha20Poly1305::new((&self.key).into());
        let plaintext = cipher.decrypt(nonce, ciphertext).map_err(|_| StorageError::Decrypt)?;
        let _ = salt; // salt already consumed during open() key derivation
        Ok(serde_json::from_slice(&plaintext)?)
    }

    pub fn save<T: Serialize>(&self, data: &T) -> Result<(), StorageError> {
        let bytes = fs::read(&self.path)?;
        let salt: [u8; SALT_LEN] = bytes[..SALT_LEN].try_into().expect("checked on open");
        let json = serde_json::to_vec(data)?;
        self.write_encrypted(&salt, &json)
    }

    fn write_encrypted(&self, salt: &[u8], plaintext: &[u8]) -> Result<(), StorageError> {
        let cipher = XChaCha20Poly1305::new((&self.key).into());
        let nonce = XChaCha20Poly1305::generate_nonce(&mut OsRng);
        let ciphertext = cipher.encrypt(&nonce, plaintext).map_err(|_| StorageError::Decrypt)?;
        let mut out = Vec::with_capacity(SALT_LEN + 24 + ciphertext.len());
        out.extend_from_slice(salt);
        out.extend_from_slice(&nonce);
        out.extend_from_slice(&ciphertext);
        fs::write(&self.path, out)?;
        Ok(())
    }

    /// Anti-forensics wipe: overwrite the file with random bytes before
    /// deleting it (a best-effort measure — on an SSD or a copy-on-write
    /// filesystem this does not guarantee the old blocks are unrecoverable;
    /// said plainly rather than oversold), then delete it, then zeroize the
    /// in-memory key.
    pub fn wipe(mut self) -> Result<(), StorageError> {
        if let Ok(meta) = fs::metadata(&self.path) {
            let junk = random_vec(meta.len() as usize);
            let _ = fs::write(&self.path, junk);
        }
        fs::remove_file(&self.path).ok();
        self.key.zeroize();
        Ok(())
    }
}

impl Drop for SecureStore {
    fn drop(&mut self) {
        self.key.zeroize();
    }
}

fn derive_key(passphrase: &str, salt: &[u8]) -> Result<[u8; 32], StorageError> {
    let mut out = [0u8; 32];
    Argon2::default()
        .hash_password_into(passphrase.as_bytes(), salt, &mut out)
        .map_err(|_| StorageError::Kdf)?;
    Ok(out)
}

fn random_bytes<const N: usize>() -> [u8; N] {
    use rand_core::RngCore;
    let mut b = [0u8; N];
    rand_core::OsRng.fill_bytes(&mut b);
    b
}

fn random_vec(len: usize) -> Vec<u8> {
    use rand_core::RngCore;
    let mut b = vec![0u8; len];
    rand_core::OsRng.fill_bytes(&mut b);
    b
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::Deserialize;
    use tempfile::tempdir;

    #[derive(Serialize, Deserialize, Default, PartialEq, Debug)]
    struct Demo {
        notes: Vec<String>,
    }

    #[test]
    fn round_trip_and_wrong_passphrase() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("vault.bin");

        let store = SecureStore::open_or_create(&path, "correct horse battery staple").unwrap();
        store.save(&Demo { notes: vec!["hello".into()] }).unwrap();
        drop(store);

        let reopened = SecureStore::open_or_create(&path, "correct horse battery staple").unwrap();
        let data: Demo = reopened.load().unwrap();
        assert_eq!(data.notes, vec!["hello".to_string()]);

        let wrong = SecureStore::open_or_create(&path, "wrong passphrase").unwrap();
        assert!(wrong.load::<Demo>().is_err());
    }
}
