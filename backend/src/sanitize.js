// Defense-in-depth input validation.
//
// SQL injection: this backend already uses parameterized queries
// everywhere (every db.prepare(...).run/get/all(...) call in app.js and
// db.js passes user-controlled values as bound `?` parameters, never
// string-concatenated into SQL text -- the one template-literal SQL
// string in this codebase, db.js's schema DDL, contains no interpolated
// values at all). That makes SQL injection structurally impossible here
// regardless of what a handle or chamber name contains, independent of
// this module -- locked in by a regression test
// (test/sanitize.test.js) that proves a classic SQLi-shaped handle is
// stored and compared literally, not executed.
//
// What THIS module is actually for: the risks "parameterized queries"
// doesn't cover. A handle with control characters, bidi-override
// characters, or zero-width characters can make one identity LOOK like a
// different one at a glance -- a real social-engineering risk in an
// invite-only-society app where people trust a handle on sight. And
// bounding every user-supplied string's size and character set at the
// boundary means a future change to the frontend (or a new client) can't
// silently reopen an XSS vector just because this backend happened to
// allow arbitrary bytes through. (The current frontend only ever writes
// user-supplied strings via `textContent`, never `innerHTML`, so there is
// no live XSS vector in it today -- this is about not depending on that
// staying true everywhere forever.)
"use strict";

const HANDLE_PATTERN = /^[A-Za-z0-9_-]{1,64}$/;
const MAX_CHAMBER_NAME_LEN = 80;

// Printable ASCII plus common punctuation/space only. Rejects control
// characters (including bidi-override and zero-width spoofing
// characters) and anything outside the Basic Latin block. Deliberately
// conservative: a chamber name is short-lived display text, not a place
// that needs full Unicode expressiveness, and "reject anything unusual"
// is a safer default than trying to enumerate every spoofing trick one
// at a time.
const SAFE_TEXT_PATTERN = /^[\x20-\x7E]+$/;

function isValidHandle(value) {
  return typeof value === "string" && HANDLE_PATTERN.test(value);
}

function isSafeChamberName(value) {
  return (
    typeof value === "string" &&
    value.length >= 1 &&
    value.length <= MAX_CHAMBER_NAME_LEN &&
    SAFE_TEXT_PATTERN.test(value)
  );
}

module.exports = { isValidHandle, isSafeChamberName, HANDLE_PATTERN, MAX_CHAMBER_NAME_LEN };
