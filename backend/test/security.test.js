"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const { openDb } = require("../src/db");
const { createApp } = require("../src/app");

async function withServer(t) {
  const db = openDb(":memory:");
  const app = createApp(db);
  const server = app.listen(0);
  t.after(() => server.close());
  await new Promise((resolve) => server.once("listening", resolve));
  return `http://127.0.0.1:${server.address().port}`;
}

test("responses carry the expected hardening headers and never X-Powered-By", async (t) => {
  const base = await withServer(t);
  const res = await fetch(`${base}/chambers`); // 401, but headers apply to every response
  assert.equal(res.headers.get("x-content-type-options"), "nosniff");
  assert.equal(res.headers.get("x-frame-options"), "DENY");
  assert.equal(res.headers.get("referrer-policy"), "no-referrer");
  assert.match(res.headers.get("content-security-policy") || "", /default-src 'none'/);
  assert.ok(res.headers.get("strict-transport-security"));
  assert.equal(res.headers.get("x-powered-by"), null);
});

test("CORS: an unlisted origin gets no Access-Control-Allow-Origin", async (t) => {
  const base = await withServer(t);
  const res = await fetch(`${base}/chambers`, { headers: { origin: "https://evil.example" } });
  assert.equal(res.headers.get("access-control-allow-origin"), null);
});

test("CORS: an allowlisted origin is reflected back", async (t) => {
  // The allowlist is read once, at app-creation time (createApp ->
  // corsAllowlist()), not per-request -- so the env var has to be set
  // BEFORE createApp runs, not just before the request.
  process.env.VEIL_ALLOWED_ORIGINS = "https://good.example";
  let base;
  try {
    const db = openDb(":memory:");
    const app = require("../src/app").createApp(db);
    const server = app.listen(0);
    t.after(() => server.close());
    await new Promise((resolve) => server.once("listening", resolve));
    base = `http://127.0.0.1:${server.address().port}`;

    const res = await fetch(`${base}/chambers`, { headers: { origin: "https://good.example" } });
    assert.equal(res.headers.get("access-control-allow-origin"), "https://good.example");
  } finally {
    delete process.env.VEIL_ALLOWED_ORIGINS;
  }
});

test("an oversized request body is rejected, not silently parsed", async (t) => {
  const base = await withServer(t);
  const huge = "x".repeat(300 * 1024); // over the 256kb limit
  const res = await fetch(`${base}/auth/register`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ handle: "a", pin: "1234", pubkey: huge }),
  });
  assert.equal(res.status, 413);
});
