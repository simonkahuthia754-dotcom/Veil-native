# Veil — chambers backend + native clients + web frontend

A full-stack implementation, not just clients: a real Express/SQLite
backend (`backend/`), two independent native clients — a Rust CLI
(`cli/`, built on `veil-crypto/`) and an Android app (`android/`) — and a
minimal web frontend (`frontend/`) for account/chamber administration.
This document is written the way a real team would hand off a
security-sensitive project to the next engineer — not as a sales pitch.
It says what's solid, what's scaffolded-but-unverified, and what's flatly
not done yet. Treat the "Honest gaps" section as the actual state of the
project, not the feature list above it.

## Why two separate native clients instead of one shared core

A single Rust core exposed to Android via UniFFI/JNI was considered and
rejected for this first pass: shipping an untested FFI bridge alongside
unverified crypto code (see "Can't compile here" below) would have stacked
two unverified layers instead of one. Each client talks to the same backend
REST API directly, and both now implement the *same* hybrid X25519 +
ML-KEM-768 wire format (unified this project phase — see "Honest gaps"
for what's still CLI-only: the forward-secret ratchet). Unifying onto one
shared crypto core remains a reasonable future simplification; it is no
longer blocking interoperability the way it originally was.

## Architecture

```
backend/       Node/Express + better-sqlite3 REST API both clients talk
               to: auth, chambers, messages, X3DH prekey bundles, and an
               intrusion-deception layer ("the Maze" — see maze.js).
veil-crypto/   Rust crate: Argon2id app-lock, encrypted single-file vault,
               hybrid X25519 + ML-KEM-768 (post-quantum) E2E encryption,
               plus an X3DH-style handshake + forward-secret ratchet
               (session.rs).
cli/           Rust binary using veil-crypto. Talks to the backend's REST
               API; uses the forward-secret ratchet when a contact has
               published prekeys, falls back to the static hybrid scheme
               (logged, not silent) otherwise.
android/       Kotlin/Compose app. Argon2Kt app-lock, a BouncyCastle
               implementation of the same hybrid X25519 + ML-KEM-768
               scheme as the CLI (not yet ratcheted — see gaps),
               AES-GCM vault file.
frontend/      Dependency-free static HTML/CSS/JS for account/chamber
               administration — deliberately does not implement E2E
               crypto; see frontend/README.md for the real scope.
.github/workflows/  CI: the actual compiler/test runner for all four
               surfaces (rust, backend, android, frontend), since this
               was built in a sandbox with no crates.io, npm registry, or
               Android SDK network access (see below).
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
as marketing copy. Last refreshed after: unifying the Android/CLI wire
format, building a real backend (`backend/`), adding a forward-secret
X3DH + ratchet crypto core (`crypto/src/session.rs`) and wiring it into
the CLI, adding an intrusion-deception layer to the backend (`maze.js`),
and adding a minimal web frontend (`frontend/`). Several items below that
used to be critical gaps are now closed — marked `[CLOSED]` rather than
deleted, so the history of what was fixed and when stays visible.

**Critical — blocks real use today:**
- **The Android client has not been ported to the forward-secret
  X3DH + ratchet scheme yet.** It still uses the older static
  X25519+ML-KEM-768 hybrid seal (`e2e.rs`'s/`E2e.kt`'s scheme) — real
  encryption, wire-format-compatible with the CLI's fallback path, but
  with no forward secrecy: a compromised long-term key decrypts all past
  captured ciphertext for Android-to-Android or Android-to-CLI traffic.
  The CLI auto-detects this per-contact and falls back to the static
  scheme with an explicit on-screen note when talking to a contact who
  hasn't published prekeys (which Android currently never does). Porting
  the ratchet to Kotlin/BouncyCastle is the next concrete milestone.
- The web frontend (`frontend/`) does not implement E2E encryption at
  all — by design, not by oversight; see `frontend/README.md`. Accounts
  created there get a placeholder identity key and can administer
  chambers but can never receive a real end-to-end-encrypted message.
  Porting ML-KEM-768 into browser JS (no native Web Crypto support for
  it) is real, unscoped future work.
- `[CLOSED]` ~~`VeilSession.unlock()` always returns `Unlocked`~~ — this
  line was stale; a repo review this session found `AppLock`
  state (Argon2id-hashed passphrase + duress code + fail-count/lockout,
  `android/app/src/main/java/com/veil/app/crypto/AppLock.kt`) is already
  persisted to `veil.meta` and actually checked on every `unlock()` call,
  with real exponential-backoff lockout and a real duress-wipe
  (`enterDuress()` deletes both the vault and meta files). What was
  genuinely missing — test coverage proving any of that actually works —
  is now partly closed: `AppLockTest.kt` is this class's first test suite,
  verifying the actual bug-prone part (lockout counting/backoff, duress
  detection not polluting the normal fail counter, JSON persistence
  round-trips) against a fake hasher. Still an honest gap, not papered
  over: `Argon2PasswordHasher`, the real production Argon2id
  implementation (Argon2Kt's native `.so` binding), is NOT exercised by
  that test or any CI job — Argon2Kt's own README only documents testing
  it via `connectedAndroidTest` on a device/emulator, and this repo's
  `android.yml` only runs host-JVM `testDebugUnitTest`, no emulator. So:
  the decision logic around the hash is now CI-verified; the hash itself
  is still "intended to work, unverified," same category as the rest of
  this project's never-compiled-locally code until CI runs it.
  `[CLI side CLOSED]`: the CLI now actually persists its
  identity (`Identity::to_secret_bytes`/`from_secret_bytes` in
  `crypto/src/e2e.rs`) and loads it back on every run instead of
  regenerating it.

**High:**
- No certificate pinning (network_security_config.xml uses system trust
  anchors only) — explained in that file's own comments, trade-off is
  deliberate but still a gap against "zero-trust network."
- `FLAG_SECURE` (blocks screenshots/recents-tray thumbnails of message
  content) is not yet set on `MainActivity` — noted inline, must be added
  before any real install.
- Chamber fan-out isn't implemented on Android or the CLI (`send()` seals
  to one recipient, not every chamber member).
- `[CLOSED]` ~~Duress-PIN unlock on Android currently just hides the
  chamber list in memory; it does not wipe or re-key the real vault
  file~~ — also stale: `VeilSession.enterDuress()` deletes the real
  vault file and the lock metadata file, reverting the app to looking
  like a fresh, never-configured install, matching `lock.rs`'s
  `should_wipe` policy on the Rust side. Now covered by
  `AppLockTest.kt`'s duress tests.
- The backend's intrusion-deception layer (`backend/src/maze.js`) is
  deception + rate-limiting, not a WAF or DDoS mitigation, and its threat
  tracker is in-memory — resets on restart, doesn't share state across
  multiple instances of the process. Same class of limitation already
  named for the existing login rate limiter, not a new one. A version
  that keeps a *banned* client inside the maze instead of showing them an
  explicit 403 (so they never learn they were caught) is named future
  work in that file, not implemented yet.
- `[CLOSED]` ~~Android and CLI clients use different E2E ciphertext
  formats and cannot decrypt each other's messages~~ — both now implement
  the same hybrid X25519 + ML-KEM-768 + HKDF-SHA256 + XChaCha20-Poly1305
  construction, verified wire-compatible in CI (`E2eTest.kt` / `e2e.rs`
  tests).
- `[CLOSED]` ~~No backend exists~~ — `backend/` is a real Express +
  better-sqlite3 + bcryptjs implementation of the contract both clients
  already assumed, CI-tested (`backend/test/`).

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
- Post-quantum coverage is CLI-only for the *ratchet* path so far
  (ML-KEM-768 hybrid). Android remains on the static hybrid scheme (still
  ML-KEM-768, just not ratcheted) until the Android port above lands.
- CodeQL's auto-added `java-kotlin` analysis job
  (`.github/workflows/codeql.yml`, added by GitHub, not authored in this
  repo) currently fails — almost certainly CodeQL's autobuild not being
  able to build the Gradle/Android project unattended, a known class of
  issue for Android projects, not yet root-caused here. The `javascript-
  typescript`, `rust`, and `actions` CodeQL analyses all pass.

**What the original 123-point "most secure/anonymous/fast" checklist
realistically maps to:** a meaningful subset is implemented and reviewable
here (E2E encryption — now with forward secrecy on the CLI path, still
absent on Android, both stated plainly above — Argon2id locks, duress
codes, auto-wipe hooks, input validation/sanitization and a verified
no-SQL-injection boundary on the backend, an intrusion-deception layer,
open-source + CI-verified builds across four workflows). Two items that
were previously (wrongly) listed here as done have been corrected: this
codebase has never actually implemented EXIF/metadata stripping on
images or any kind of "anonymous feed" at all, let alone defenses against
poisoning one — there is no image-attachment or feed/news-ingestion
feature anywhere in `cli/`, `android/`, or `backend/` to check. That line
was carried over inaccurately from an earlier description of this
project rather than verified against the actual code, which is exactly
the kind of claim this README exists to catch. If an info-feed feature
(news/weather/market data, etc.) is ever added, its own poisoning
defenses would need to be designed and verified then, not assumed from
this old line. Several items are
architecturally impossible for any app to honestly claim (true anonymity
against a state-level network adversary without Tor/mixnet always-on,
"undetectable to all forensics", zero-metadata at the transport layer
while using a conventional HTTPS backend). Treat any such claim elsewhere
in this project's history as the aspirational framing it was, not as this
code's actual guarantee — this README is the correction.

## Next milestone (in priority order)

1. Port the X3DH + ratchet handshake to Android (Kotlin/BouncyCastle),
   matching `crypto/src/session.rs`'s wire format exactly, so Android
   stops being the forward-secrecy gap. This is now the single largest
   remaining gap in the project.
2. Chamber fan-out on Android (`VeilSession.send()` seals to one
   recipient only; the backend and CLI already support per-member
   fan-out via `GET /chambers/:id/members`).
3. Root-cause the CodeQL `java-kotlin` autobuild failure.
4. Certificate pinning on Android (`network_security_config.xml`
   currently trusts the system CA store only).
5. Prekey rotation policy/automation (none exists yet on either client —
   a published one-time prekey is never replenished, so a contact who
   sends several messages before you're ever online again will exhaust
   your prekey pool and fall back to the non-ratcheted static scheme).
6. A second pass over the maze's scoring thresholds against real
   traffic, once there is any.

Deliberately **not** on this list, and why: items like a custom OS
fork, satellite transport, hardware security keys, QKD, a built-in
cryptocurrency wallet, or formal verification of the ratchet are each
independently huge (multi-month-to-multi-year) efforts, several with
real legal/regulatory exposure (a wallet moving money is a money-
transmission question, not a coding task) or questionable payoff for
this app's actual threat model (steganographic transport for a project
that already runs a conventional HTTPS backend doesn't buy much). If
any of these become real priorities, they deserve their own scoped
design doc and an explicit decision to take them on — not a silent
attempt inside a general "fix everything" pass.

## Running CI yourself

Push to a GitHub repo with Actions enabled; `rust.yml` and `android.yml` run
on every push touching their respective directories and upload a debug APK
as a build artifact on success.
