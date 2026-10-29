// The Maze: an intrusion-deception layer, not an access-control one.
//
// What this actually is, stated plainly before the metaphor: a threat
// score per client (IP, or a hashed bearer-token prefix when present)
// that goes up when a request looks like reconnaissance or attack —
// hitting a path no real client would ever request (/admin, /.env,
// /wp-login.php, ...) or sending a value that looks like a SQL-injection
// or path-traversal attempt — and three real, scoped effects as that
// score rises:
//
//   1. Below the "in the maze" threshold: nothing happens except the
//      event gets logged. A single accidental hit on a weird path isn't
//      proof of anything.
//   2. Once flagged, every further request that doesn't match a real
//      route gets a plausible-looking, entirely fake JSON response
//      instead of an honest 404 — generated deterministically per
//      (client, path) so the same request always gets the same fake
//      answer, the way a real API would behave, with fake "ids" in the
//      response that themselves look like they'd lead somewhere if
//      followed. A 404 tells an attacker exactly which paths exist and
//      which don't, which is reconnaissance intel handed over for free;
//      a maze of self-consistent fake data that never dead-ends and
//      never reveals anything real denies them that for as long as they
//      keep digging. This never touches anything a legitimate client
//      calls — it only ever replaces what used to be a 404.
//   3. Past a higher threshold: responses to that client start carrying
//      an artificial, score-scaled delay (a "tarpit" — capped at 30s so
//      it can't itself become a resource-exhaustion problem for this
//      server), and past the ban threshold, EVERY request from that
//      client gets a flat 403, maze included. A version that kept a
//      banned client inside the maze instead of showing them an
//      explicit block (so they never even learn they've been caught) is
//      real, named future work — not implemented here, because doing it
//      correctly needs the ban check to run after route-matching instead
//      of before it (so a banned request to a real route can 403 while a
//      banned request to nothing in particular still gets a fake answer)
//      and this version keeps that logic simple and easy to reason about
//      instead.
//
// What this is NOT, said as directly as the rest of this codebase's
// honesty notes: it is not a replacement for TLS, for the login rate
// limiter already in app.js, for the bcrypt cost factor, or for a real
// WAF/infra-level DDoS mitigation in front of this process. The threat
// tracker is in-memory — it resets on restart and does not share state
// across multiple instances of this server, the same limitation already
// named for the login rate limiter in app.js, not a new one invented
// here. A patient, careful attacker who diffs response timing or
// response-shape consistency closely enough can in principle notice the
// maze is synthetic; this raises the cost of attacking this server and
// denies easy reconnaissance, it does not claim to make compromise
// impossible.
"use strict";

const crypto = require("crypto");

const SCORE_ENTER_MAZE = 20;
const SCORE_TARPIT = 50;
const SCORE_BAN = 100;
const SCORE_DECAY_PER_MS = 10 / (30 * 60 * 1000); // ~10 points drained per 30 quiet minutes
const BAN_DURATION_MS = 60 * 60 * 1000; // 1 hour
const MAX_TARPIT_MS = 30 * 1000;

// Paths no real Veil client (CLI or Android) ever requests — every real
// route is enumerated in app.js's own route table, which this list is
// deliberately disjoint from. A hit here is either a scanner, a stale/
// malicious crawler, or someone poking at the API by hand; never a false
// positive from normal use of this app.
const DECOY_PATH_RE =
  /^\/(admin|wp-admin|wp-login\.php|\.env|\.env\.|\.git|\.aws|phpmyadmin|pma|config(\.json|\.yml)?|backup|dump|debug|server-status|actuator|console|graphql|swagger|\.well-known\/security\.txt|api\/v1\/users\/export)(\/|$|\?)/i;

// Patterns checked against every string value in a request's query,
// params and parsed JSON body. Deliberately simple substring/regex
// checks, not a full SQL/HTML parser — the goal is "flag the obviously
// hostile shapes", not "be a WAF". False-positive risk against this
// app's own real traffic is low by construction: real request bodies
// here are handles (short identifiers), PINs (digits), and base64/opaque
// ciphertext — none of which naturally contains these shapes.
const MALICIOUS_PATTERNS = [
  /union\s+select/i,
  /('|")\s*or\s*('|")?\s*1\s*('|")?\s*=\s*('|")?\s*1/i,
  /<script[\s>]/i,
  /\.\.\//,
  /\betc\/passwd\b/i,
  /;?\s*drop\s+table/i,
  /\$\{.*\}/, // template-injection shaped
];

function looksMalicious(value) {
  if (typeof value !== "string" || value.length === 0) return false;
  return MALICIOUS_PATTERNS.some((re) => re.test(value));
}

function scanForMalice(obj, depth = 0) {
  if (obj == null || depth > 4) return false;
  if (typeof obj === "string") return looksMalicious(obj);
  if (Array.isArray(obj)) return obj.some((v) => scanForMalice(v, depth + 1));
  if (typeof obj === "object") {
    return Object.values(obj).some((v) => scanForMalice(v, depth + 1));
  }
  return false;
}

/// Identifies a client without ever storing anything a stolen token
/// would be independently usable from: a bearer token is reduced to a
/// short hash prefix, never kept or compared against in full here.
function clientKey(req) {
  const auth = req.get && req.get("authorization");
  if (auth && auth.startsWith("Bearer ")) {
    const hash = crypto.createHash("sha256").update(auth.slice(7)).digest("hex");
    return `tok:${hash.slice(0, 16)}`;
  }
  return `ip:${req.ip || "unknown"}`;
}

class ThreatTracker {
  constructor() {
    this.clients = new Map(); // key -> { score, lastSeen, bannedUntil }
  }

  _entry(key) {
    const now = Date.now();
    let entry = this.clients.get(key);
    if (!entry) {
      entry = { score: 0, lastSeen: now, bannedUntil: 0 };
      this.clients.set(key, entry);
      return entry;
    }
    const elapsed = now - entry.lastSeen;
    if (elapsed > 0 && entry.score > 0) {
      entry.score = Math.max(0, entry.score - elapsed * SCORE_DECAY_PER_MS);
    }
    entry.lastSeen = now;
    return entry;
  }

  // Records `delta` against `key` and returns the resulting state.
  score(key, delta) {
    const entry = this._entry(key);
    entry.score += delta;
    if (entry.score >= SCORE_BAN && entry.bannedUntil < Date.now()) {
      entry.bannedUntil = Date.now() + BAN_DURATION_MS;
    }
    return this.state(key);
  }

  state(key) {
    const entry = this._entry(key);
    const now = Date.now();
    const score = entry.score;
    return {
      score,
      banned: entry.bannedUntil > now,
      inMaze: score >= SCORE_ENTER_MAZE,
      tarpitMs: score >= SCORE_TARPIT ? Math.min(MAX_TARPIT_MS, (score - SCORE_TARPIT) * 300) : 0,
    };
  }

  // Test/ops hook only — not called from request handling.
  reset() {
    this.clients.clear();
  }
}

function logEvent(db, { key, path, reason, delta, total, action }) {
  db.prepare(
    `INSERT INTO security_events (id, client_key, path, reason, score_delta, score_total, action, created_at)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
  ).run(
    crypto.randomUUID(),
    key,
    path,
    reason,
    Math.round(delta),
    Math.round(total),
    action,
    new Date().toISOString(),
  );
}

// mulberry32 — small, deterministic PRNG. Used only to generate
// plausible-looking decoy content, never for anything that needs to be
// cryptographically unpredictable (the maze's job is to look consistent
// to an attacker probing it repeatedly, not to be secure itself).
function mulberry32(seed) {
  let a = seed >>> 0;
  return function () {
    a |= 0;
    a = (a + 0x6d2b79f5) | 0;
    let t = Math.imul(a ^ (a >>> 15), 1 | a);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

function hashToSeed(str) {
  return crypto.createHash("sha256").update(str).digest().readUInt32BE(0);
}

function fakeUuid(rand) {
  const bytes = Array.from({ length: 16 }, () => Math.floor(rand() * 256));
  bytes[6] = (bytes[6] & 0x0f) | 0x40;
  bytes[8] = (bytes[8] & 0x3f) | 0x80;
  const hex = bytes.map((b) => b.toString(16).padStart(2, "0"));
  return [
    hex.slice(0, 4).join(""),
    hex.slice(4, 6).join(""),
    hex.slice(6, 8).join(""),
    hex.slice(8, 10).join(""),
    hex.slice(10, 16).join(""),
  ].join("-");
}

// Fixed reference point for fake "createdAt" timestamps — see the comment
// in fakeChamber() on why this can't be Date.now().
const MAZE_TIME_ANCHOR_MS = Date.UTC(2026, 0, 1);

const FAKE_NAMES = [
  "Obsidian",
  "Marrow",
  "Veilbound",
  "Ashcroft",
  "Hollowmere",
  "Cindergate",
  "Thornwell",
  "Greywake",
  "Duskhollow",
  "Ironvale",
];
const FAKE_SUFFIX = ["Chamber", "Circle", "Order", "Assembly", "Conclave", "Society", "Cabal"];

function fakeChamber(rand) {
  const name = `${FAKE_NAMES[Math.floor(rand() * FAKE_NAMES.length)]} ${
    FAKE_SUFFIX[Math.floor(rand() * FAKE_SUFFIX.length)]
  }`;
  return {
    id: fakeUuid(rand),
    name,
    memberCount: 3 + Math.floor(rand() * 40),
    isMember: rand() > 0.5,
    // A fixed anchor, NOT Date.now() — this whole function has to be a
    // pure function of `rand` (which is itself seeded only from the
    // client key + path) for the "same request always gets the same
    // fake answer" property to actually hold. Using the real current
    // time here would make two requests milliseconds apart return
    // different createdAt values for what's supposed to be identical
    // fake data — a real bug caught by this module's own
    // determinism test, not a hypothetical one.
    createdAt: new Date(MAZE_TIME_ANCHOR_MS - Math.floor(rand() * 1e10)).toISOString(),
  };
}

// Deterministic per (client, path): the same request from the same
// flagged client always gets back the same fake answer, which is what
// makes it read as a real, stateful backend instead of random noise —
// random noise is itself a tell.
function mazeBody(key, path) {
  const rand = mulberry32(hashToSeed(`${key}:${path}`));
  const chambers = Array.from({ length: 3 + Math.floor(rand() * 5) }, () => fakeChamber(rand));
  return {
    chambers,
    nextCursor: fakeUuid(rand),
  };
}

/// Mounted once, right after body parsing and before any real route:
/// scores the request, logs anything flagged, and either tarpits,
/// blocks (if already banned), or passes through to the real routes.
function scoringMiddleware(db, tracker) {
  return function (req, res, next) {
    const key = clientKey(req);
    let state = tracker.state(key);

    if (state.banned) {
      logEvent(db, {
        key,
        path: req.path,
        reason: "banned client",
        delta: 0,
        total: state.score,
        action: "block",
      });
      return res.status(403).json({ error: "forbidden" });
    }

    let delta = 0;
    const reasons = [];
    if (DECOY_PATH_RE.test(req.path)) {
      delta += 15;
      reasons.push("decoy path");
    }
    if (scanForMalice(req.query) || scanForMalice(req.body) || scanForMalice(req.params)) {
      delta += 20;
      reasons.push("malicious-looking payload");
    }

    if (delta > 0) {
      state = tracker.score(key, delta);
      logEvent(db, {
        key,
        path: req.path,
        reason: reasons.join("+"),
        delta,
        total: state.score,
        action: state.banned ? "ban" : state.inMaze ? "maze" : "flag",
      });
      if (state.banned) {
        return res.status(403).json({ error: "forbidden" });
      }
    }

    req.veilThreat = state;
    if (state.tarpitMs > 0) {
      setTimeout(next, state.tarpitMs);
      return;
    }
    next();
  };
}

/// Mounted last, after every real route: anything that reaches this
/// point didn't match a real endpoint. A flagged client (or anyone
/// landing on an explicit decoy path, flagged or not — the very first
/// hit IS the detection, there's nothing to wait for) gets fake data
/// instead of a 404; everyone else gets an honest 404, same as before
/// this module existed.
function catchAllMiddleware(tracker) {
  return function (req, res) {
    const key = clientKey(req);
    const state = tracker.state(key);
    if (state.inMaze || DECOY_PATH_RE.test(req.path)) {
      return res.status(200).json(mazeBody(key, req.path));
    }
    return res.status(404).json({ error: "not found" });
  };
}

/// Operator-only: read the audit trail. Gated on VEIL_ADMIN_TOKEN (set
/// as an env var by whoever deploys this) rather than a normal user
/// session, and deliberately NOT mounted at a path matching
/// DECOY_PATH_RE — "/admin" itself is bait, never the real thing.
function securityEventsRoute(db) {
  return function (req, res) {
    const adminToken = process.env.VEIL_ADMIN_TOKEN;
    const provided = req.get("x-admin-token");
    if (!adminToken || !provided || provided !== adminToken) {
      return res.status(404).json({ error: "not found" });
    }
    const limit = Math.min(500, Math.max(1, parseInt(req.query.limit, 10) || 100));
    const rows = db
      .prepare(`SELECT * FROM security_events ORDER BY created_at DESC LIMIT ?`)
      .all(limit);
    return res.json(rows);
  };
}

module.exports = {
  ThreatTracker,
  scoringMiddleware,
  catchAllMiddleware,
  securityEventsRoute,
  clientKey,
  scanForMalice,
  DECOY_PATH_RE,
  SCORE_ENTER_MAZE,
  SCORE_TARPIT,
  SCORE_BAN,
};
