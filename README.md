# Veil — native clients

Two independent native clients for the Veil chambers backend (`veil-backend`,
a separate repo/folder): a Rust CLI (`cli/`, built on `veil-crypto/`) and an
Android app (`android/`). This document is written the way a real team would
hand off a security-sensitive project to the next engineer — not as a sales
pitch. It says what's solid, what's scaffolded-but-unverified, and what's
flatly not done yet. Treat the "Honest gaps" section as the actual state of
the project, not the feature list above it.

## Why two separate clients instead of one shared core

A single Rust core exposed to Android via UniFFI/JNI was considered and
rejected for this first pass: shipping an untested FFI bridge alongside
unverified crypto code (see "Can't compile here" below) would have stacked
two unverified layers instead of one. Each client talks to the same backend
REST API directly. The cost of that decision is real and is documented
below, not hidden: **the two clients do not currently share a wire-format
for end-to-end ciphertext**, so an Android user and a CLI user cannot yet
read each other's encrypted messages. Unifying onto one crypto core is the
natural fix and is the top item in "Next milestone."

## Architecture

```
veil-crypto/   Rust crate: Argon2id app-lock, encrypted single-file vault,
               hybrid X25519 + ML-KEM-768 (post-quantum) E2E encryption.
cli/           Rust binary using veil-crypto. Talks to veil-backend's REST API.
android/       Kotlin/Compose app. Argon2Kt app-lock, Tink HPKE (X25519,
               classical-only — see gaps) for E2E, AES-GCM vault file.
.github/workflows/  CI: the actual compiler/test runner, since this was
               built in a sandbox with no crates.io or Android SDK network
               access (see below).
```

## Can't compile here — why CI is load-bearing, not optional

This project was built in a sandboxed session with an allowlisted network:
`crates.io` and the Android SDK/Gradle plugin repositories were not
reachable from it. That means **no `cargo build`, `cargo test`, `cargo
clippy`, or Gradle build has actually run against this code yet.** What was
done instead, and what wasn't:

- Done: every `.rs` and `.kt` file was manually brace/paren-balance checked,
  every public API call was checked against the dependency's documented
  signature from memory, and two real bugs were caught this way during
  writing (a `reqwest::Proxy::all` type mismatch, and an `InboxRow` field
  naming mismatch against the backend's actual JSON shape — both already
  fixed, see git history).
- Not done, and not safe to assume: that the code compiles cleanly, that
  dependency versions pinned in `Cargo.toml`/`build.gradle.kts` are exactly
  correct (version numbers were written from training-data knowledge, not
  verified against the live registries), or that Argon2Kt's/Tink's exact
  API surface matches what's called here.
- **The GitHub Actions workflows in this repo are the first real
  compilation.** Until `rust.yml` and `android.yml` go green, treat every
  claim in this README about "works" as "intended to work, unverified."
  Don't deploy, don't rely on the crypto, don't call this done — that's
  what the pentester and critic roles below would say, and they'd be right.

## Honest gaps (read this before trusting anything here)

Written as a short red-team / code-review pass against this codebase, not
as marketing copy.

**Critical — blocks any real use:**
- `VeilSession.unlock()` on Android (`android/app/src/main/java/com/veil/app/state/VeilSession.kt`)
  currently **always returns `Unlocked`** — `AppLock` state (hash + salt) is
  never persisted or reloaded between app launches, so there is no real
  passphrase check yet on Android. This is a scaffold stub, clearly marked
  `TODO` in the code, and it must not be mistaken for a working lock. The
  Rust CLI has the equivalent persistence gap for identity keys (documented
  in `cli/src/main.rs`): it generates a fresh identity every run instead of
  loading a saved one.
- No forward secrecy in either client's E2E scheme (static X25519/ML-KEM
  keys, no ratchet). A compromised long-term key decrypts all past captured
  ciphertext. This is the single biggest cryptographic gap versus the
  Signal Protocol the original brief asked to match, and fixing it means
  implementing a Double-Ratchet-equivalent — real, substantial work, not a
  config flag.
- Android and CLI clients use **different E2E ciphertext formats** (Tink
  HPKE vs. a custom hybrid construction) and cannot decrypt each other's
  messages. The backend doesn't validate ciphertext shape, so this fails
  silently rather than with an error — a real interoperability landmine.

**High:**
- No certificate pinning (network_security_config.xml uses system trust
  anchors only) — explained in that file's own comments, trade-off is
  deliberate but still a gap against "zero-trust network."
- `FLAG_SECURE` (blocks screenshots/recents-tray thumbnails of message
  content) is not yet set on `MainActivity` — noted inline, must be added
  before any real install.
- Chamber fan-out isn't implemented on Android (`send()` seals to one
  recipient, not every chamber member) — same gap as the CLI's `send`
  command.
- Duress-PIN unlock on Android currently just hides the chamber list in
  memory; it does not wipe or re-key the real vault file the way the
  design (and `lock.rs`'s `should_wipe` policy) calls for.

**Medium / known and accepted trade-offs, not bugs:**
- Vault storage is a single AEAD-encrypted file, not SQLCipher, on both
  clients — a deliberate choice to avoid a C-toolchain cross-compile
  dependency in CI (documented in `crypto/src/storage.rs` and
  `SecureStore.kt`). Functionally equivalent confidentiality for a
  single-user local store; loses SQLCipher's ability to selectively query
  without decrypting everything, which this app's data volume doesn't need.
- No Tor/I2P/mixnet transport built in — both clients support routing
  through a local SOCKS5 proxy (`VEIL_SOCKS_PROXY` env var on the CLI, a
  `socksProxyHostPort` parameter on Android, meant to point at Orbot). That
  is "can use Tor if the user runs it," not "is Tor-native" — an honest
  distinction worth keeping.
- Post-quantum coverage is CLI-only (ML-KEM-768 hybrid). Android is
  classical-only (X25519) because Tink's stable Android artifact doesn't
  yet expose a post-quantum primitive, and the alternative — a DIY,
  unaudited PQ implementation — was judged worse than an honest gap.

**What the original 123-point "most secure/anonymous/fast" checklist
realistically maps to:** a meaningful subset is implemented and reviewable
here (E2E encryption with forward-secrecy explicitly absent and called out,
Argon2id locks, duress codes, auto-wipe hooks, metadata stripping on
images, anonymous-feed poisoning defenses in the backend, open-source +
CI-verified builds). Several items are architecturally impossible for any
app to honestly claim (true anonymity against a state-level network
adversary without Tor/mixnet always-on, "undetectable to all forensics",
zero-metadata at the transport layer while using a conventional HTTPS
backend). Treat any such claim elsewhere in this project's history as the
aspirational framing it was, not as this code's actual guarantee — this
README is the correction.

## Next milestone (in priority order)

1. Get CI green — first real compile/test for both clients.
2. Persist `AppLock` state on Android (close the "always unlocks" gap) and
   persist identity keys on the CLI.
3. Unify E2E wire format across both clients (likely: extract a minimal
   shared format spec, even without sharing code, so both implement the
   *same bytes*, reviewed independently).
4. Add a Double-Ratchet-equivalent for forward secrecy.
5. `FLAG_SECURE`, real duress-wipe wiring, chamber fan-out.

## Running CI yourself

Push to a GitHub repo with Actions enabled; `rust.yml` and `android.yml` run
on every push touching their respective directories and upload a debug APK
as a build artifact on success.
