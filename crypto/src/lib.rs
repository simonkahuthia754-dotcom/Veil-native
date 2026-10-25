//! veil-crypto: the real security core shared by every Veil client.
//!
//! Honesty note, read before trusting anything else in this repo: this crate
//! has been written carefully and uses only standard, widely-used crates —
//! but it has NOT been through a professional security audit, and this
//! session could not compile or run it (this sandbox has no access to
//! crates.io to pull dependencies). CI (see `.github/workflows/`) is what
//! actually builds and tests this code with real network access. Treat the
//! first CI run on this repo as the real first compile — if an API shifted
//! under a pinned version, fix it there before trusting any of this.
//!
//! What this crate deliberately does NOT do: implement any cryptographic
//! primitive from scratch. Every algorithm here is a well-known construction
//! from an established crate. "No custom crypto, ever" is not a slogan here,
//! it's the actual rule this file follows.

pub mod e2e;
pub mod lock;
pub mod storage;

pub use e2e::{Identity, SealedMessage};
pub use lock::{AppLock, LockError};
pub use storage::{SecureStore, StorageError};
