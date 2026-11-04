# Security Policy

Veil is an early-stage, actively-developed prototype — not yet audited,
not yet run by real users outside development, and honest about both of
those facts throughout its own [README](README.md) ("Honest gaps"
section). That makes a clear disclosure path more important, not less:
this is exactly the stage where a real report is most valuable and least
likely to be ignored.

## Reporting a vulnerability

**Please do not open a public GitHub issue for a security
vulnerability.** A public issue discloses the problem to everyone,
including anyone who'd misuse it, before a fix exists.

Instead, report it privately:

- **Preferred:** use GitHub's private vulnerability reporting for this
  repository (Security tab → "Report a vulnerability"), if enabled here.
- **Email:** `<maintainer-security-contact-TODO>` — *(a real contact
  address goes here before this file is relied on; left as a visible
  placeholder rather than silently populated, since publishing a
  personal address to a public repository is the maintainer's call to
  make, not something to fill in on their behalf.)*

When reporting, please include:

- What component is affected (`crypto/`, `cli/`, `backend/`, `android/`,
  `frontend/`) and, if you have it, the exact file/function.
- Steps to reproduce, or a proof-of-concept if you have one.
- What you think the actual impact is (what an attacker gains, not just
  "this looks wrong").
- Whether you want public credit once it's fixed, and how to name you.

## What's in scope

Everything in this repository: the hybrid X25519 + ML-KEM-768 crypto
core (`crypto/`), the X3DH-style handshake + ratchet (`session.rs`/
`Session.kt`), the CLI (`cli/`), the backend (`backend/`, including the
Maze intrusion-deception layer and the rate limiters), the Android app
(`android/`), and the web frontend (`frontend/`).

Particularly welcome: anything that breaks the forward-secrecy or
sender-anonymity properties described in the README, any way to bypass
`requireAuth`, `requireChamberMember`, or the per-target/per-device rate
limits, any way to make the backend leak a real identity key for a
ratcheted message, or any gap between what the README claims and what
the code actually does — a documentation/reality mismatch is a real
finding here, not a nitpick, given how much of this project's trust
model rests on the README being accurate.

## What's already known (check here before reporting)

This project keeps its own gap list current and public, deliberately,
in [README.md's "Honest gaps" section](README.md#honest-gaps-read-this-before-trusting-anything-here).
Known limitations like "no formal third-party audit yet," "prekey
rotation isn't automated," or "the CodeQL Android autobuild fails" are
already tracked there — still worth a report if you find a *concrete,
exploitable consequence* of one of them that isn't already spelled out,
but the general gap itself doesn't need re-reporting.

## What to expect

This is presently maintained by one person in their own time, not a
funded security team — response times will be best-effort, not SLA'd.
A genuine, reproducible report into the crypto core, the auth/session
logic, or the backend's trust boundaries will be treated as the highest
priority thing in the project at the time it arrives.

## No bug bounty

There is currently no paid bug bounty program. Credit in the README's
changelog/commit history (if wanted) is what's on offer right now, not
payment.
