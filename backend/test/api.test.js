"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const { openDb } = require("../src/db");
const { createApp, makeLoginLimiter } = require("../src/app");

// Real HTTP calls against a real in-memory SQLite DB, not a mocked
// handler — this is the same "actually run it" discipline as the Rust and
// Kotlin tests elsewhere in this repo. Each test gets a fresh app + an
// ephemeral port so tests can't see each other's state.
async function withServer(t, fn) {
  const db = openDb(":memory:");
  const app = createApp(db, { loginLimiter: makeLoginLimiter({ maxAttempts: 3, windowMs: 60_000 }) });
  const server = app.listen(0);
  t.after(() => server.close());
  await new Promise((resolve) => server.once("listening", resolve));
  const base = `http://127.0.0.1:${server.address().port}`;
  return fn(base);
}

async function register(base, handle, pin, pubkey = "x-" + handle, pqPubkey = "pq-" + handle) {
  const res = await fetch(`${base}/auth/register`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ handle, pin, pubkey, pqPubkey }),
  });
  assert.equal(res.status, 201, await res.text());
  return res.json();
}

test("register then fetch own public keys via another user's session", async (t) => {
  await withServer(t, async (base) => {
    const alice = await register(base, "alice", "1234");
    const bob = await register(base, "bob", "5678");

    const res = await fetch(`${base}/auth/users/alice`, {
      headers: { authorization: `Bearer ${bob.token}` },
    });
    assert.equal(res.status, 200);
    const body = await res.json();
    assert.equal(body.pubkey, alice.pubkey);
    assert.equal(body.pqPubkey, alice.pqPubkey);
  });
});

test("login succeeds with the right PIN, fails with the wrong one", async (t) => {
  await withServer(t, async (base) => {
    await register(base, "carol", "9999");

    const bad = await fetch(`${base}/auth/login`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ handle: "carol", pin: "0000" }),
    });
    assert.equal(bad.status, 401);

    const good = await fetch(`${base}/auth/login`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ handle: "carol", pin: "9999" }),
    });
    assert.equal(good.status, 200);
    const body = await good.json();
    assert.equal(body.handle, "carol");
    assert.ok(body.token);
  });
});

test("login is rate-limited after repeated failures", async (t) => {
  await withServer(t, async (base) => {
    await register(base, "dave", "1111");
    for (let i = 0; i < 3; i++) {
      const res = await fetch(`${base}/auth/login`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ handle: "dave", pin: "0000" }),
      });
      assert.equal(res.status, 401);
    }
    const locked = await fetch(`${base}/auth/login`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ handle: "dave", pin: "1111" }), // even the RIGHT pin, now locked out
    });
    assert.equal(locked.status, 429);
  });
});

test("registering a duplicate handle is rejected", async (t) => {
  await withServer(t, async (base) => {
    await register(base, "erin", "1234");
    const res = await fetch(`${base}/auth/register`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ handle: "erin", pin: "4321", pubkey: "whatever" }),
    });
    assert.equal(res.status, 409);
  });
});

test("send a message, recipient receives and acks it, then it's gone", async (t) => {
  await withServer(t, async (base) => {
    const alice = await register(base, "alice2", "1234");
    const bob = await register(base, "bob2", "5678");

    const send = await fetch(`${base}/messages`, {
      method: "POST",
      headers: { authorization: `Bearer ${alice.token}`, "content-type": "application/json" },
      body: JSON.stringify({
        scope: "dm",
        scopeId: "bob2",
        recipientIds: [bob.id],
        ciphertext: "cipher-blob",
        nonce: "nonce-blob",
        senderPubkey: alice.pubkey,
      }),
    });
    assert.equal(send.status, 201);

    const inboxRes = await fetch(`${base}/messages`, {
      headers: { authorization: `Bearer ${bob.token}` },
    });
    const inbox = await inboxRes.json();
    assert.equal(inbox.length, 1);
    assert.equal(inbox[0].ciphertext, "cipher-blob");
    assert.equal(inbox[0].sender_pubkey, alice.pubkey);

    const ackRes = await fetch(`${base}/messages/ack`, {
      method: "POST",
      headers: { authorization: `Bearer ${bob.token}`, "content-type": "application/json" },
      body: JSON.stringify({ ids: [inbox[0].id] }),
    });
    assert.equal(ackRes.status, 200);

    const afterAck = await (
      await fetch(`${base}/messages`, { headers: { authorization: `Bearer ${bob.token}` } })
    ).json();
    assert.equal(afterAck.length, 0);
  });
});

test("prekey bundle: medium-term prekey is reusable, one-time prekeys are consumed exactly once", async (t) => {
  await withServer(t, async (base) => {
    const bob = await register(base, "bob3", "5678");
    const alice = await register(base, "alice3", "1234");

    const publish = await fetch(`${base}/prekeys`, {
      method: "POST",
      headers: { authorization: `Bearer ${bob.token}`, "content-type": "application/json" },
      body: JSON.stringify({
        mediumTermPrekey: { xPub: "mtpk-x", kemPub: "mtpk-kem" },
        oneTimePrekeys: [
          { xPub: "otpk-x-1", kemPub: "otpk-kem-1" },
          { xPub: "otpk-x-2", kemPub: "otpk-kem-2" },
        ],
      }),
    });
    assert.equal(publish.status, 201);

    const countBefore = await (
      await fetch(`${base}/prekeys/mine/count`, { headers: { authorization: `Bearer ${bob.token}` } })
    ).json();
    assert.equal(countBefore.count, 2);

    const bundle1 = await (
      await fetch(`${base}/prekeys/bob3/bundle`, { headers: { authorization: `Bearer ${alice.token}` } })
    ).json();
    assert.equal(bundle1.identityPubkey, bob.pubkey);
    assert.equal(bundle1.mediumTermPrekey.xPub, "mtpk-x");
    assert.ok(bundle1.oneTimePrekey); // one of the two, order not asserted

    const bundle2 = await (
      await fetch(`${base}/prekeys/bob3/bundle`, { headers: { authorization: `Bearer ${alice.token}` } })
    ).json();
    assert.notEqual(bundle2.oneTimePrekey.xPub, bundle1.oneTimePrekey.xPub); // different one-time key, not reused

    const bundle3 = await (
      await fetch(`${base}/prekeys/bob3/bundle`, { headers: { authorization: `Bearer ${alice.token}` } })
    ).json();
    assert.equal(bundle3.oneTimePrekey, null); // pool exhausted — still get identity + medium-term key
    assert.equal(bundle3.mediumTermPrekey.xPub, "mtpk-x");

    const countAfter = await (
      await fetch(`${base}/prekeys/mine/count`, { headers: { authorization: `Bearer ${bob.token}` } })
    ).json();
    assert.equal(countAfter.count, 0);
  });
});

test("requests without a bearer token are rejected", async (t) => {
  await withServer(t, async (base) => {
    const res = await fetch(`${base}/chambers`);
    assert.equal(res.status, 401);
  });
});
