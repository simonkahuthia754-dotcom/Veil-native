// SQLite schema + a thin data-access layer. better-sqlite3 is synchronous
// (no async/await ceremony for simple CRUD), which keeps route handlers
// readable — deliberately the same engine choice the Rust CLI's own
// comments already assumed ("better-sqlite3 doesn't transform [column]
// names", cli/src/main.rs), so this backend's raw row shape (snake_case)
// matches what both clients already expect from GET /messages.
"use strict";

const Database = require("better-sqlite3");
const crypto = require("crypto");

function openDb(path) {
  const db = new Database(path);
  db.pragma("journal_mode = WAL");
  db.pragma("foreign_keys = ON");

  db.exec(`
    CREATE TABLE IF NOT EXISTS users (
      id TEXT PRIMARY KEY,
      handle TEXT UNIQUE NOT NULL,
      pin_hash TEXT NOT NULL,
      pubkey TEXT NOT NULL,
      pq_pubkey TEXT,
      created_at TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS sessions (
      token TEXT PRIMARY KEY,
      user_id TEXT NOT NULL REFERENCES users(id),
      created_at TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS chambers (
      id TEXT PRIMARY KEY,
      name TEXT NOT NULL,
      owner_id TEXT NOT NULL REFERENCES users(id),
      created_at TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS chamber_members (
      chamber_id TEXT NOT NULL REFERENCES chambers(id),
      user_id TEXT NOT NULL REFERENCES users(id),
      PRIMARY KEY (chamber_id, user_id)
    );

    CREATE TABLE IF NOT EXISTS messages (
      id TEXT PRIMARY KEY,
      recipient_id TEXT NOT NULL REFERENCES users(id),
      ciphertext TEXT NOT NULL,
      nonce TEXT NOT NULL,
      sender_pubkey TEXT NOT NULL,
      created_at TEXT NOT NULL,
      acked INTEGER NOT NULL DEFAULT 0
    );

    -- One active medium-term prekey per user, rotated periodically by the
    -- client (see README "forward secrecy"). Replacing a user's row is a
    -- plain upsert: there is deliberately no history kept here, since an
    -- old prekey being retained server-side would defeat the point of
    -- rotating it.
    --
    -- Honest note, not glossed over: this is NOT cryptographically signed
    -- by the user's identity key (hence "medium_term_prekeys", not
    -- "signed_prekeys" — the field name in Signal's X3DH paper this is
    -- modeled on). The Veil identity keys are X25519 (ECDH-only) and
    -- ML-KEM (KEM-only); neither can sign. A real "signed prekey" needs a
    -- separate signing keypair (e.g. Ed25519) added to the identity, which
    -- is real future work, not done here. Until then, this endpoint trusts
    -- the server + TLS channel not to substitute a prekey undetected —
    -- the same trust boundary the existing GET /auth/users/:handle
    -- endpoint already has for the static identity key, not a new
    -- weakness introduced by this table.
    CREATE TABLE IF NOT EXISTS medium_term_prekeys (
      user_id TEXT PRIMARY KEY REFERENCES users(id),
      x_pub TEXT NOT NULL,
      kem_pub TEXT NOT NULL,
      created_at TEXT NOT NULL
    );

    -- One-time prekeys: each row is consumed (deleted) by at most one
    -- X3DH-style handshake, which is the whole point — a one-time prekey
    -- reused across sessions would let a single compromised private key
    -- retroactively break more than one conversation's forward secrecy.
    CREATE TABLE IF NOT EXISTS one_time_prekeys (
      id TEXT PRIMARY KEY,
      user_id TEXT NOT NULL REFERENCES users(id),
      x_pub TEXT NOT NULL,
      kem_pub TEXT NOT NULL,
      created_at TEXT NOT NULL
    );
    CREATE INDEX IF NOT EXISTS idx_otpk_user ON one_time_prekeys(user_id);
  `);

  return db;
}

function newId() {
  return crypto.randomUUID();
}

function newToken() {
  return crypto.randomBytes(32).toString("hex");
}

module.exports = { openDb, newId, newToken };
