"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const { openDb } = require("../src/db");
const { createApp } = require("../src/app");
const { isValidHandle, isSafeChamberName } = require("../src/sanitize");

async function withServer(t) {
  const db = openDb(":memory:");
  const app = createApp(db);
  const server = app.listen(0);
  t.after(() => server.close());
  await new Promise((resolve) => server.once("listening", resolve));
  return { base: `http://127.0.0.1:${server.address().port}`, db };
}

test("isValidHandle rejects control/spoofing characters and oversized input", () => {
  assert.equal(isValidHandle("alice_99"), true);
  assert.equal(isValidHandle("a-b-c"), true);
  assert.equal(isValidHandle(""), false);
  assert.equal(isValidHandle("a".repeat(65)), false);
  assert.equal(isValidHandle("alice bob"), false); // no spaces
  assert.equal(isValidHandle("alice\u0000"), false); // NUL byte
  assert.equal(isValidHandle("alice‮bob"), false); // bidi-override (spoofing)
  assert.equal(isValidHandle("alice'; DROP TABLE users; --"), false);
  assert.equal(isValidHandle(42), false); // wrong type entirely
});

test("isSafeChamberName rejects control characters and oversized input, allows normal text", () => {
  assert.equal(isSafeChamberName("Inner Circle"), true);
  assert.equal(isSafeChamberName(""), false);
  assert.equal(isSafeChamberName("x".repeat(81)), false);
  assert.equal(isSafeChamberName("<script>alert(1)</script>"), false);
  assert.equal(isSafeChamberName("name\u0000with\u0000nulls"), false);
});

test("registration rejects a SQL-injection-shaped handle at the boundary", async (t) => {
  const { base } = await withServer(t);
  const res = await fetch(`${base}/auth/register`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ handle: "x' OR '1'='1", pin: "1234", pubkey: "pk" }),
  });
  assert.equal(res.status, 400);
});

test("chamber creation rejects an XSS-shaped name at the boundary", async (t) => {
  const { base } = await withServer(t);
  const owner = await (
    await fetch(`${base}/auth/register`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ handle: "chamowner", pin: "1234", pubkey: "pk" }),
    })
  ).json();
  const res = await fetch(`${base}/chambers`, {
    method: "POST",
    headers: { authorization: `Bearer ${owner.token}`, "content-type": "application/json" },
    body: JSON.stringify({ name: "<img src=x onerror=alert(1)>" }),
  });
  assert.equal(res.status, 400);
});

// This is the actual proof that SQL injection is structurally
// impossible here, independent of the charset validation above: it
// goes straight at the database layer the way app.js does (a
// parameterized db.prepare(...).run(...) call), bypassing the HTTP
// route's own input validation entirely, to show that even a value an
// attacker fully controls is only ever treated as inert data by
// better-sqlite3's bound parameters -- never as SQL to execute.
test("parameterized queries treat a malicious value as inert data, not SQL", () => {
  const db = openDb(":memory:");
  const malicious = "x'; DROP TABLE users; --";
  db.prepare(
    `INSERT INTO users (id, handle, pin_hash, pubkey, pq_pubkey, created_at)
     VALUES (?, ?, ?, ?, ?, ?)`,
  ).run("test-id", malicious, "hash", "pk", null, new Date().toISOString());

  // If the payload had executed as SQL, this table wouldn't exist anymore.
  const row = db.prepare("SELECT * FROM users WHERE id = ?").get("test-id");
  assert.equal(row.handle, malicious); // stored byte-for-byte, not interpreted
  const stillThere = db.prepare("SELECT COUNT(*) as n FROM users").get();
  assert.equal(stillThere.n, 1);
});
