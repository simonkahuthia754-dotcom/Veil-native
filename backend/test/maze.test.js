"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const { openDb } = require("../src/db");
const { createApp } = require("../src/app");
const maze = require("../src/maze");

async function withServer(t) {
  const db = openDb(":memory:");
  const threatTracker = new maze.ThreatTracker();
  const app = createApp(db, { threatTracker });
  const server = app.listen(0);
  t.after(() => server.close());
  await new Promise((resolve) => server.once("listening", resolve));
  const base = `http://127.0.0.1:${server.address().port}`;
  return { base, db, threatTracker };
}

test("an ordinary unknown path still gets a plain 404, not the maze", async (t) => {
  const { base, db } = await withServer(t);
  const res = await fetch(`${base}/this-route-does-not-exist`);
  assert.equal(res.status, 404);
  const body = await res.json();
  assert.equal(body.error, "not found");

  const events = db.prepare("SELECT * FROM security_events").all();
  assert.equal(events.length, 0, "an ordinary unmatched path shouldn't be logged as a threat");
});

test("a decoy path is flagged, logged, and answered with fake data instead of a 404", async (t) => {
  const { base, db } = await withServer(t);
  const res = await fetch(`${base}/admin`);
  assert.equal(res.status, 200, "a decoy hit should never see a plain 404");
  const body = await res.json();
  assert.ok(Array.isArray(body.chambers), "maze response should look like a real chambers listing");
  assert.ok(body.chambers.length > 0);

  const events = db.prepare("SELECT * FROM security_events").all();
  assert.equal(events.length, 1);
  assert.match(events[0].reason, /decoy path/);
  assert.equal(events[0].action, "flag");
});

test("the same client always gets the same fake data back for the same path", async (t) => {
  const { base } = await withServer(t);
  const first = await (await fetch(`${base}/admin`)).json();
  const second = await (await fetch(`${base}/admin`)).json();
  assert.deepEqual(first, second, "deterministic maze content is what makes it look like a real stateful backend");
});

test("a malicious-looking payload is scored even on a non-decoy path", async (t) => {
  const { base, db } = await withServer(t);
  const res = await fetch(`${base}/auth/login`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ handle: "x' OR '1'='1", pin: "1234" }),
  });
  // The login route itself still runs (and correctly fails, since no such
  // user exists) — the maze scores and logs the attempt without
  // interfering with a route it doesn't own.
  assert.equal(res.status, 401);

  const events = db.prepare("SELECT * FROM security_events").all();
  assert.equal(events.length, 1);
  assert.match(events[0].reason, /malicious-looking payload/);
});

test("repeated flagged requests escalate to a hard ban", async (t) => {
  const { base, db } = await withServer(t);
  // Each malicious POST to a non-decoy, non-real path scores 20
  // ("malicious-looking payload" only). Comfortably more than the 5
  // needed to cross the ban threshold (100) — extra headroom so the
  // tracker's small time-based score decay between requests can't make
  // this test flaky.
  let last;
  for (let i = 0; i < 8; i++) {
    last = await fetch(`${base}/some/unknown/path`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ q: "'; DROP TABLE users; --" }),
    });
  }
  assert.equal(last.status, 403, "crossing the ban threshold should block immediately");

  const banned = await fetch(`${base}/chambers`);
  assert.equal(banned.status, 403, "a banned client is blocked from real routes too");

  const events = db.prepare("SELECT * FROM security_events ORDER BY created_at ASC").all();
  assert.ok(events.some((e) => e.action === "ban"));
});

test("the ops security-events endpoint requires the admin token", async (t) => {
  const { base } = await withServer(t);
  await fetch(`${base}/admin`); // generate one event to read back

  const noAuth = await fetch(`${base}/ops/security-events`);
  assert.equal(noAuth.status, 404, "without a valid admin token this should look like nothing is there");

  process.env.VEIL_ADMIN_TOKEN = "test-admin-token";
  try {
    const authed = await fetch(`${base}/ops/security-events`, {
      headers: { "x-admin-token": "test-admin-token" },
    });
    assert.equal(authed.status, 200);
    const rows = await authed.json();
    assert.ok(Array.isArray(rows));
    assert.ok(rows.length >= 1);
  } finally {
    delete process.env.VEIL_ADMIN_TOKEN;
  }
});
