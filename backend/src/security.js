// Web-facing hardening for a JSON API that may be reached directly from
// a browser (the frontend/ page, or any future one) rather than only
// from the native clients. No new dependencies pulled in (this sandbox
// has no npm registry access to add/verify one, same constraint as
// everything else this session) — these are plain, well-understood HTTP
// response headers and a hand-rolled origin allowlist, not a reimplementation
// of something like `helmet` from scratch for its own sake.
"use strict";

// Every response from this API is JSON, never rendered as a web page, so
// the CSP can be maximally restrictive: nothing is ever allowed to load
// or execute as a result of a response from THIS process. If a future
// change ever serves the frontend's HTML from this same Express app
// (currently it's served separately — see frontend/README.md), that
// route needs its own, less restrictive CSP; this default must not be
// loosened globally to accommodate that.
const API_CSP = "default-src 'none'; frame-ancestors 'none'";

function securityHeaders(req, res, next) {
  res.removeHeader("X-Powered-By");
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("X-Frame-Options", "DENY");
  res.setHeader("Referrer-Policy", "no-referrer");
  res.setHeader("Content-Security-Policy", API_CSP);
  res.setHeader("Cross-Origin-Resource-Policy", "same-site");
  res.setHeader("Cross-Origin-Opener-Policy", "same-origin");
  // This API has no business touching any of these browser features;
  // say so explicitly rather than leaving it to a browser's defaults.
  res.setHeader(
    "Permissions-Policy",
    "camera=(), microphone=(), geolocation=(), usb=(), payment=(), interest-cohort=()",
  );
  // Only meaningful once this is actually served over HTTPS (directly or
  // via a TLS-terminating reverse proxy) -- harmless to send over plain
  // HTTP in local development, where no browser acts on it.
  res.setHeader("Strict-Transport-Security", "max-age=63072000; includeSubDomains");
  next();
}

// A minimal, explicit-allowlist CORS implementation: default-DENY for
// cross-origin browser requests, not default-ALLOW. A messaging app's
// API is exactly the kind of thing that should never be reachable from
// an arbitrary third-party page the user happens to have open — the
// native clients (CLI, Android) aren't browsers and aren't subject to
// CORS at all, so this only ever restricts browser-based access, which
// is the frontend/ page (or any future one) and nothing else.
//
// Configure via VEIL_ALLOWED_ORIGINS, a comma-separated list of exact
// origins (scheme + host + port), e.g.
//   VEIL_ALLOWED_ORIGINS=https://veil.example,http://127.0.0.1:8000
// Unset/empty means "no cross-origin browser access at all" -- the
// honest default for something this sensitive, not a silent allow-all.
function corsAllowlist({ allowedOrigins = parseAllowedOrigins() } = {}) {
  return function (req, res, next) {
    const origin = req.get("origin");
    if (origin && allowedOrigins.has(origin)) {
      res.setHeader("Access-Control-Allow-Origin", origin);
      res.setHeader("Vary", "Origin");
      res.setHeader("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
      res.setHeader("Access-Control-Allow-Headers", "content-type, authorization, x-admin-token");
      res.setHeader("Access-Control-Max-Age", "600");
    }
    if (req.method === "OPTIONS") {
      return res.sendStatus(204);
    }
    next();
  };
}

function parseAllowedOrigins() {
  const raw = process.env.VEIL_ALLOWED_ORIGINS || "";
  return new Set(
    raw
      .split(",")
      .map((s) => s.trim())
      .filter(Boolean),
  );
}

module.exports = { securityHeaders, corsAllowlist, parseAllowedOrigins };
