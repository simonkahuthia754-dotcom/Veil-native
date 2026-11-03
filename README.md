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
- `[CLOSED]` ~~The X3DH + ratchet crypto core is ported but not wired
  into `VeilSession.kt`~~ — now wired. `send()`/`loadInbox()` mirror the
  CLI's `seal_for_one`/`cmd_inbox` exactly: reuse a live ratchet session
  for a contact if one exists, otherwise fetch their prekey bundle
  (`GET /prekeys/:handle/bundle`) and start one via `initiateSession`,
  otherwise fall back to the static hybrid scheme with an explicit
  on-screen note — never silently. `ensurePrekeysPublished()` publishes
  this device's own medium-term + one-time prekeys (`POST /prekeys`) the
  first time it's called. The full vault envelope (identity, medium-term
  prekey, one-time prekey pool, live sessions, auth token) now persists
  through `SecureStore`, not just the identity — a restart no longer
  loses forward-secrecy state or the login session.

  Wiring this surfaced two real, previously-unexercised bugs in
  `ApiClient.kt`, found by diffing its DTOs against the actual backend
  route handlers (`backend/src/app.js`) rather than against what they
  were assumed to be: `RegisterRequest`/`LoginRequest` were missing the
  backend's required `pin` field entirely (`LoginRequest` sent a `proof`
  field the backend doesn't recognize at all), and `SendMessageRequest`
  sent a `recipientHandle` field that doesn't exist on the backend, which
  actually requires `recipientIds: string[]`. Both would have failed
  every real request with a 400 — never caught before because nothing in
  this app ever called `register()`/`login()`/`send()` far enough to
  notice (see the next gap).

- `[CLOSED]` ~~No screen in `VeilApp.kt` collects a handle or a backend
  PIN~~ — `AccountScreen` now does. It sits between `LockScreen` and
  `ChambersScreen` in the nav graph (`composable("account")`), shown only
  when `VeilSession.isLoggedIn()` is false after unlocking the local
  vault (a fresh account needs it; a returning one whose vault envelope
  already has a token skips straight to chambers). It toggles between
  register and login, validates the PIN against the same 4–8 digit shape
  the backend enforces, and calls the now-correct
  `VeilSession.register()`/`login()` — which, on success, already chains
  `ensurePrekeysPublished()` internally, so a brand-new account is
  immediately reachable for a forward-secret handshake, not just
  registered. This was the single biggest remaining Android gap: not
  "fan-out isn't wired" or "the ratchet doesn't exist," but "no Android
  install could ever create or log into an account at all." Not yet
  covered by any UI/instrumented test (this scaffold has none — see
  "Honest gaps" below); verified by `gradle lint`/`testDebugUnitTest`/
  `assembleDebug` passing in CI, which confirms it compiles and doesn't
  break anything existing, not that a human has tapped through it on a
  device.
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
- `[CLOSED]` ~~No certificate pinning (network_security_config.xml uses
  system trust anchors only)~~ — `CertPinning.kt` adds trust-on-first-use
  (TOFU) pinning, scoped per backend host and layered on top of ordinary
  system-CA validation, not instead of it. The first successful connection
  to a self-hosted backend records its certificate's SPKI SHA-256 hash
  (plaintext pin store, `veil.pins` — a public-key hash isn't a secret);
  every later connection must match it or the TLS handshake fails closed.
  Wired into `ApiClient.build()` via a new `pinStore` parameter, on by
  default from `VeilSession`. Honest, undisguised limitation (the same one
  SSH's `known_hosts` has): an attacker already positioned before the
  *first-ever* connection still gets pinned as if legitimate — this closes
  the much more common case of a MITM introduced later (a rogue CA added
  mid-lifecycle, a pentester's interception box) against which plain
  system-CA trust does nothing. `VeilSession.resetCertPin()` is the
  escape hatch for a deliberate backend cert rotation; not yet reachable
  from any settings screen (none exists). Self-signed backend certs are
  still rejected by design — supporting that is separate, unscoped work.
  Not covered by any CI-run test (this scaffold's test suite is JVM unit
  tests only, and exercising real TLS handshakes/MITM scenarios needs
  integration-level infrastructure this repo doesn't have yet) — verified
  by `gradle lint`/`testDebugUnitTest`/`assembleDebug` passing, which
  confirms it compiles cleanly, not that it's been attacked and held.
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

**Closed this pass:**
- `[CLOSED]` The backend used to see every sender's real, long-term
  identity key in plaintext on every single message (`sender_pubkey`,
  `NOT NULL`) — including for messages on an already-established
  forward-secret session, where there was never a cryptographic need for
  it. Fixed: `Session` (`crypto/src/session.rs`) now derives a second
  HKDF output alongside its two chain keys — an opaque, 256-bit
  `tag`, independently computed by both sides from the same root key,
  never transmitted during the handshake. The CLI's `seal_for_one` now
  sends `senderTag` instead of `senderPubkey` for every ratcheted
  message, including a session's first (handshake) message — the
  responder's identity needs are already met by
  `InitialMessage.initiator_identity_x_public`, which travels inside the
  encrypted envelope, not the outer plaintext row. The backend
  (`messages.sender_tag`, nullable alongside now-nullable
  `sender_pubkey`) stores and returns whichever one it was sent, and
  `POST /messages` rejects a request that sends both or neither. Only
  the static, non-forward-secret fallback scheme still needs the real
  identity key (its `open()` step requires it for the DH). Net effect:
  once two contacts have exchanged a single prekey-bundle-based message,
  the backend operator can tell "these messages belong to the same
  conversation" from the shared tag, but learns nothing about who the
  two parties actually are. Verified by new Rust tests
  (`both_sides_independently_derive_the_same_tag`,
  `two_independent_sessions_get_different_tags`,
  `tag_survives_a_serde_round_trip`) and new backend tests
  (`backend/test/api.test.js`). Ported to Android in the same pass:
  `Session.kt` now derives and carries the same `tag`/`tagB64()`
  (identical salt/info, confirmed bit-for-bit construction parity with
  `session.rs`), with 3 new mirrored tests
  (`bothSidesIndependentlyDeriveTheSameTag`,
  `twoIndependentSessionsGetDifferentTags`, `tagSurvivesAJsonRoundTrip`).
  `VeilSession.kt`'s `send()` now sends `senderTag` for both the
  existing-session and new-handshake paths (only the static fallback
  still sends `senderPubkey`), and `loadInbox()` keys sessions by the
  handshake's embedded identity key rather than `row.sender_pubkey`
  (which may now be absent), resolving a continuation message's session
  by a linear scan matching `row.sender_tag` against each live
  session's `tagB64()` — same tradeoff the CLI's `cmd_inbox` already
  documents. `ApiClient.kt`'s `SendMessageRequest`/`InboxRow` DTOs
  updated to match the backend's now-nullable, exactly-one-of shape.
  Android messages no longer leak sender identity to the backend once a
  ratchet session exists, closing the gap flagged above.
- `[CLOSED]` Three real insider-abuse gaps found by reviewing every
  `requireAuth` route against what an authenticated-but-malicious caller
  (a stolen token, or just a bad-faith registered user — not an outside
  attacker, who never gets this far) could do with it:
  - **No session revocation existed at all.** A token, once issued,
    stayed valid forever with no way to kill it from inside the app — a
    leaked or stolen token (compromised device, captured log, a
    pentester who got hold of one) was permanent. Fixed:
    `POST /auth/logout` deletes the caller's own session row (and only
    the caller's own — verified by a test asserting a second user's
    token is unaffected).
  - **Prekey-bundle fetching had no rate limit.** `GET
    /prekeys/:handle/bundle` atomically consumes one of the target's
    one-time prekeys per call — the entire point of a one-time prekey.
    Any authenticated user could silently drain a target's whole pool
    just by calling this endpoint repeatedly, no message ever sent, no
    trace the target would see except degraded forward secrecy later.
    Fixed: `makeBundleLimiter` caps requests per TARGET handle (not per
    requester — a requester-keyed limit does nothing against the same
    drain spread across several accounts, since the asset being
    protected is the target's pool). Checked *before* any prekey is
    consumed, verified by a test that confirms a blocked request
    doesn't quietly eat one anyway.
  - **`POST /messages`' `recipientIds` was unvalidated.** A made-up
    user id made `better-sqlite3` throw a raw `SQLITE_CONSTRAINT` error
    from the `messages.recipient_id` foreign key mid-transaction,
    uncaught — any authenticated caller could trigger a bare 500 at
    will, with no rate limit beyond the Maze's general scoring.
    Fixed: ids are checked against real users first, with a clean 400
    instead. Also capped `recipientIds` at 256 entries, closing a
    cheap, unbounded per-request DB-write-amplification path the
    256kb body limit alone didn't prevent (user ids are short; a lot
    of them still fit).
  All three verified by new tests in `backend/test/api.test.js`.

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

1. Chamber fan-out on Android (`VeilSession.send()` seals to one
   recipient only; the backend and CLI already support per-member
   fan-out via `GET /chambers/:id/members`).
2. Root-cause the CodeQL `java-kotlin` autobuild failure.
3. Prekey rotation policy/automation (none exists yet on either client —
   a published one-time prekey is never replenished, so a contact who
   sends several messages before you're ever online again will exhaust
   your prekey pool and fall back to the non-ratcheted static scheme).
4. A settings screen — the first real gap `CertPinning.kt`'s
   `resetCertPin()` surfaces: it exists and works, but nothing in the UI
   can call it yet, so a deliberate backend cert rotation currently has
   no in-app recovery path short of clearing app data.
5. A second pass over the maze's scoring thresholds against real
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
