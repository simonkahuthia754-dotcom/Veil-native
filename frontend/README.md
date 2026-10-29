# Veil web frontend

A small, dependency-free static page for account and chamber
administration against `veil-backend`: register, log in, create/browse
chambers, see how many messages are waiting. No build step — it's plain
HTML/CSS/JS, open `index.html` through any static file server (it makes
real `fetch()` calls, so it needs to be served over HTTP, not opened as a
`file://` URL, or the backend's CORS/browser fetch behavior gets weird).

```sh
cd frontend
python3 -m http.server 8000
# then open http://127.0.0.1:8000
```

By default it talks to `http://127.0.0.1:8787` (veil-backend's default
port). Override it either by setting `window.VEIL_BACKEND_URL` before
`app.js` loads (e.g. a small inline `<script>` in a deployed copy of
`index.html`), or by running once in the browser console:

```js
localStorage.setItem("veil-backend-url", "https://your-backend-host");
```

## What this does and does not do — read this before relying on it

This page handles accounts and chambers for real: registration creates a
genuine user row (bcrypt-hashed PIN, same as the CLI), login issues a
real bearer token, chamber creation/listing hits the real `/chambers`
routes. None of that is mocked.

What it deliberately does **not** do: the hybrid X25519 + ML-KEM-768
end-to-end encryption (and the forward-secret X3DH ratchet) that
`crypto/src/` implements for the Rust CLI. Reimplementing that safely in
browser JavaScript — particularly ML-KEM-768, which has no native Web
Crypto API support — is real, scoped future work, not something to fake
with a placeholder. So:

- An account registered **here** gets a clearly-labeled placeholder
  public key (`WEB-PLACEHOLDER-NOT-A-REAL-KEY:...`), not a real identity
  key. It can administer chambers, but it can never receive a genuine
  end-to-end-encrypted message, because it has no real key for anyone to
  encrypt to.
- The "Messages" panel only ever shows a waiting *count* — it fetches
  `GET /messages` but does not attempt to decrypt the ciphertext it gets
  back, because it has no identity key capable of doing so.
- For actual messaging, register/log in from the Rust CLI (and, once the
  ratchet is ported there, the Android app) — those have real identity
  keys and the real crypto.

If/when ML-KEM-768-in-the-browser becomes something this project wants to
take on for real, this page is the natural place to wire it in — until
then, this honest boundary is better than a UI that silently pretends to
be secure and isn't.
