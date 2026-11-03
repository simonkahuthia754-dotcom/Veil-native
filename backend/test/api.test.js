"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const { openDb } = require("../src/db");
const { createApp, makeLoginLimiter, makeBundleLimiter } = require("../src/app");

// Real HTTP calls against a real in-memory SQLite DB, not a mocked
// handler — this is the same "actually run it" discipline as the Rust and
// Kotlin tests elsewhere in this repo. Each test gets a fresh app + an
// ephemeral port so tests can't see each other's state. `appOptions` lets
// an individual test override createApp's defaults (e.g. a tight
// bundleLimiter to actually exercise the 429 path without 20 real calls).
async function withServer(t, fn, appOptions = {}) {
  const db = openDb(":memory:");
  const app = createApp(db, {
    loginLimiter: makeLoginLimiter({ maxAttempts: 3, windowMs: 60_000 }),
    ...appOptions,
  });
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
  // Read the body exactly once — a fetch Response body stream can only be
  // consumed once; calling res.text() for a failure message and then
  // res.json() to return the parsed body (the original, broken version of
  // this helper) throws "Body is unusable: Body has already been read" on
  // EVERY call, success or not, since both branches of `assert.equal`'s
  // arguments are evaluated regardless of whether the assertion passes.
  const body = await res.json();
  assert.equal(res.status, 201, JSON.stringify(body));
  return body;
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

test("a ratcheted message can use senderTag instead of senderPubkey, and the backend never sees sender_pubkey for it", async (t) => {
  await withServer(t, async (base) => {
    const alice = await register(base, "alice3", "1234");
    const bob = await register(base, "bob3", "5678");

    const send = await fetch(`${base}/messages`, {
      method: "POST",
      headers: { authorization: `Bearer ${alice.token}`, "content-type": "application/json" },
      body: JSON.stringify({
        scope: "dm",
        scopeId: "bob3",
        recipientIds: [bob.id],
        ciphertext: "cipher-blob",
        nonce: "nonce-blob",
        senderTag: "opaque-session-tag",
      }),
    });
    assert.equal(send.status, 201);

    const inbox = await (
      await fetch(`${base}/messages`, { headers: { authorization: `Bearer ${bob.token}` } })
    ).json();
    assert.equal(inbox.length, 1);
    assert.equal(inbox[0].sender_tag, "opaque-session-tag");
    assert.equal(inbox[0].sender_pubkey, null); // never populated for a tagged send
  });
});

test("sending a message with both senderPubkey and senderTag, or neither, is rejected", async (t) => {
  await withServer(t, async (base) => {
    const alice = await register(base, "alice4", "1234");
    const bob = await register(base, "bob4", "5678");
    const baseBody = {
      scope: "dm",
      scopeId: "bob4",
      recipientIds: [bob.id],
      ciphertext: "cipher-blob",
      nonce: "nonce-blob",
    };

    const neither = await fetch(`${base}/messages`, {
      method: "POST",
      headers: { authorization: `Bearer ${alice.token}`, "content-type": "application/json" },
      body: JSON.stringify(baseBody),
    });
    assert.equal(neither.status, 400);

    const both = await fetch(`${base}/messages`, {
      method: "POST",
      headers: { authorization: `Bearer ${alice.token}`, "content-type": "application/json" },
      body: JSON.stringify({ ...baseBody, senderPubkey: alice.pubkey, senderTag: "tag" }),
    });
    assert.equal(both.status, 400);
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

test("chamber fan-out: invite, member list, and non-members can't see either", async (t) => {
  await withServer(t, async (base) => {
    const owner = await register(base, "owner1", "1234");
    const invitee = await register(base, "invitee1", "1234");
    const outsider = await register(base, "outsider1", "1234");

    const created = await (
      await fetch(`${base}/chambers`, {
        method: "POST",
        headers: { authorization: `Bearer ${owner.token}`, "content-type": "application/json" },
        body: JSON.stringify({ name: "Inner Circle" }),
      })
    ).json();

    // The owner is already a member (chamber creation auto-joins them) —
    // isMember/memberCount should reflect that from the first listing.
    const ownerChambers = await (
      await fetch(`${base}/chambers`, { headers: { authorization: `Bearer ${owner.token}` } })
    ).json();
    assert.equal(ownerChambers.length, 1);
    assert.equal(ownerChambers[0].memberCount, 1);
    assert.equal(ownerChambers[0].isMember, true);

    // An outsider can't even confirm the chamber exists.
    const outsiderSeesMembers = await fetch(`${base}/chambers/${created.id}/members`, {
      headers: { authorization: `Bearer ${outsider.token}` },
    });
    assert.equal(outsiderSeesMembers.status, 404);

    const invite = await fetch(`${base}/chambers/${created.id}/members`, {
      method: "POST",
      headers: { authorization: `Bearer ${owner.token}`, "content-type": "application/json" },
      body: JSON.stringify({ handle: "invitee1" }),
    });
    assert.equal(invite.status, 201);

    // Re-inviting the same person is rejected, not silently duplicated.
    const reinvite = await fetch(`${base}/chambers/${created.id}/members`, {
      method: "POST",
      headers: { authorization: `Bearer ${owner.token}`, "content-type": "application/json" },
      body: JSON.stringify({ handle: "invitee1" }),
    });
    assert.equal(reinvite.status, 409);

    // An outsider still can't invite themselves in.
    const selfInvite = await fetch(`${base}/chambers/${created.id}/members`, {
      method: "POST",
      headers: { authorization: `Bearer ${outsider.token}`, "content-type": "application/json" },
      body: JSON.stringify({ handle: "outsider1" }),
    });
    assert.equal(selfInvite.status, 404);

    // Now that invitee1 is a member, they can see the member list too --
    // this is what lets a client fan a message out to everyone's keys.
    const members = await (
      await fetch(`${base}/chambers/${created.id}/members`, {
        headers: { authorization: `Bearer ${invitee.token}` },
      })
    ).json();
    const handles = members.map((m) => m.handle).sort();
    assert.deepEqual(handles, ["invitee1", "owner1"]);
    assert.ok(members.every((m) => typeof m.pubkey === "string" && m.pubkey.length > 0));
  });
});

test("the careers list is static reference data, no auth required", async (t) => {
  await withServer(t, async (base) => {
    const res = await fetch(`${base}/chambers/careers`);
    assert.equal(res.status, 200);
    const careers = await res.json();
    assert.ok(Array.isArray(careers));
    assert.ok(careers.includes("Technology"));
  });
});

test("logout revokes the caller's own token, and nobody else's", async (t) => {
  await withServer(t, async (base) => {
    const alice = await register(base, "alicelogout", "1234");
    const bob = await register(base, "boblogout", "5678");

    const logout = await fetch(`${base}/auth/logout`, {
      method: "POST",
      headers: { authorization: `Bearer ${alice.token}` },
    });
    assert.equal(logout.status, 200);

    // Alice's own token is now dead.
    const afterLogout = await fetch(`${base}/chambers`, {
      headers: { authorization: `Bearer ${alice.token}` },
    });
    assert.equal(afterLogout.status, 401);

    // Bob's token is unaffected — logout only revokes the caller's own.
    const bobStillWorks = await fetch(`${base}/chambers`, {
      headers: { authorization: `Bearer ${bob.token}` },
    });
    assert.equal(bobStillWorks.status, 200);
  });
});

test("sending to a nonexistent recipient id fails cleanly with 400, not a raw 500 from the FK constraint", async (t) => {
  await withServer(t, async (base) => {
    const alice = await register(base, "alicefk", "1234");

    const res = await fetch(`${base}/messages`, {
      method: "POST",
      headers: { authorization: `Bearer ${alice.token}`, "content-type": "application/json" },
      body: JSON.stringify({
        recipientIds: ["not-a-real-user-id"],
        ciphertext: "cipher-blob",
        nonce: "nonce-blob",
        senderPubkey: alice.pubkey,
      }),
    });
    assert.equal(res.status, 400);
    const body = await res.json();
    assert.match(body.error, /unknown user id/);
  });
});

test("recipientIds over the cap is rejected", async (t) => {
  await withServer(t, async (base) => {
    const alice = await register(base, "alicecap", "1234");
    const tooMany = Array.from({ length: 257 }, (_, i) => `id-${i}`);

    const res = await fetch(`${base}/messages`, {
      method: "POST",
      headers: { authorization: `Bearer ${alice.token}`, "content-type": "application/json" },
      body: JSON.stringify({
        recipientIds: tooMany,
        ciphertext: "cipher-blob",
        nonce: "nonce-blob",
        senderPubkey: alice.pubkey,
      }),
    });
    assert.equal(res.status, 400);
  });
});

test("repeatedly fetching a victim's prekey bundle to drain their one-time prekeys is rate-limited", async (t) => {
  await withServer(
    t,
    async (base) => {
      const victim = await register(base, "victim1", "1234");
      const attacker = await register(base, "attacker1", "5678");

      await fetch(`${base}/prekeys`, {
        method: "POST",
        headers: { authorization: `Bearer ${victim.token}`, "content-type": "application/json" },
        body: JSON.stringify({
          mediumTermPrekey: { xPub: "mtpk-x", kemPub: "mtpk-kem" },
          oneTimePrekeys: Array.from({ length: 10 }, (_, i) => ({ xPub: `otpk-x-${i}`, kemPub: `otpk-kem-${i}` })),
        }),
      });

      // The test's bundleLimiter below caps this at 2 — the third call
      // from the SAME or, just as importantly, a DIFFERENT authenticated
      // requester must still be blocked, since the limiter is keyed by
      // the victim's handle, not the caller's identity (see
      // makeBundleLimiter's doc comment on why).
      const first = await fetch(`${base}/prekeys/victim1/bundle`, {
        headers: { authorization: `Bearer ${attacker.token}` },
      });
      assert.equal(first.status, 200);

      const secondAttacker = await register(base, "attacker2", "9012");
      const second = await fetch(`${base}/prekeys/victim1/bundle`, {
        headers: { authorization: `Bearer ${secondAttacker.token}` },
      });
      assert.equal(second.status, 200);

      const third = await fetch(`${base}/prekeys/victim1/bundle`, {
        headers: { authorization: `Bearer ${attacker.token}` },
      });
      assert.equal(third.status, 429);

      // Crucially: the blocked request must NOT have consumed a one-time
      // prekey — the whole point is that the rate limit protects the
      // pool, not just the HTTP response.
      const countAfter = await (
        await fetch(`${base}/prekeys/mine/count`, { headers: { authorization: `Bearer ${victim.token}` } })
      ).json();
      assert.equal(countAfter.count, 8); // 10 published - 2 actually consumed
    },
    { bundleLimiter: makeBundleLimiter({ maxAttempts: 2, windowMs: 60_000 }) },
  );
});
