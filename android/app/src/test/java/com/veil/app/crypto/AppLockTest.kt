package com.veil.app.crypto

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * First real tests for `AppLock` — the Argon2id passphrase/duress logic that
 * `VeilSession.createLock()`/`unlock()`/`enterDuress()` depend on. This class
 * previously had zero test coverage despite being the thing standing between
 * "the app is locked" and "the app isn't locked", which is exactly the kind
 * of gap this project's own standard (CI-verified, not just written) exists
 * to catch. Pure-JVM, no Android framework needed — same reasoning as
 * E2eTest.
 */
class AppLockTest {
    @Test
    fun correctPassphraseUnlocks() {
        val lock = AppLock.create("correct horse battery staple")
        val verdict = lock.attempt("correct horse battery staple", nowMs = 0L)
        assertTrue(verdict is AppLock.Verdict.Unlocked)
    }

    @Test
    fun wrongPassphraseIsRejectedAndCountsDown() {
        val lock = AppLock.create("correct horse battery staple", maxFails = 3)
        val v1 = lock.attempt("wrong", nowMs = 0L)
        assertTrue(v1 is AppLock.Verdict.WrongPassphrase)
        assertEquals(2, (v1 as AppLock.Verdict.WrongPassphrase).attemptsLeft)
    }

    @Test
    fun exceedingMaxFailsLocksOutWithBackoff() {
        val lock = AppLock.create("correct horse battery staple", maxFails = 2)
        lock.attempt("wrong", nowMs = 0L)
        val tripped = lock.attempt("wrong", nowMs = 1L)
        assertTrue(tripped is AppLock.Verdict.Locked)

        // Still within the backoff window: locked out even with the right passphrase.
        val duringLockout = lock.attempt("correct horse battery staple", nowMs = 2L)
        assertTrue(duringLockout is AppLock.Verdict.Locked)
    }

    @Test
    fun lockoutExpiresAndCorrectPassphraseThenWorks() {
        val lock = AppLock.create("correct horse battery staple", maxFails = 1)
        val tripped = lock.attempt("wrong", nowMs = 0L)
        val retryAfter = (tripped as AppLock.Verdict.Locked).retryAfterMs

        val afterExpiry = lock.attempt("correct horse battery staple", nowMs = retryAfter + 1)
        assertTrue(afterExpiry is AppLock.Verdict.Unlocked)
    }

    @Test
    fun duressPassphraseReturnsDuressNotUnlocked() {
        val lock = AppLock.create("correct horse battery staple", duressPassphrase = "fire drill")
        val verdict = lock.attempt("fire drill", nowMs = 0L)
        assertTrue(verdict is AppLock.Verdict.Duress)
    }

    @Test
    fun duressCheckDoesNotLeakIntoNormalFailCount() {
        // A duress match must not be treated as a wrong-passphrase attempt
        // (that would make duress entries count toward a forced wipe via
        // shouldWipe(), which should only ever be driven by genuinely wrong
        // guesses).
        val lock = AppLock.create("correct horse battery staple", duressPassphrase = "fire drill", maxFails = 5)
        lock.attempt("fire drill", nowMs = 0L)
        assertTrue(!lock.shouldWipe(wipeAfterFails = 1))
    }

    @Test
    fun shouldWipeTripsAfterConfiguredFailCount() {
        val lock = AppLock.create("correct horse battery staple", maxFails = 100)
        lock.attempt("wrong", nowMs = 0L)
        lock.attempt("wrong", nowMs = 1L)
        assertTrue(lock.shouldWipe(wipeAfterFails = 2))
        assertTrue(!lock.shouldWipe(wipeAfterFails = 3))
    }

    @Test
    fun jsonRoundTripPreservesVerdictBehavior() {
        val original = AppLock.create("correct horse battery staple", duressPassphrase = "fire drill", maxFails = 4)
        original.attempt("wrong", nowMs = 0L) // bump fail count before serializing

        val restored = AppLock.fromJson(original.toJson())

        assertTrue(restored.attempt("correct horse battery staple", nowMs = 100L) is AppLock.Verdict.Unlocked)
    }

    @Test
    fun jsonRoundTripWithNoDuressCodeOmitsIt() {
        val original = AppLock.create("correct horse battery staple")
        val restored = AppLock.fromJson(original.toJson())

        // No duress code was set, so a distinct guess must fall through to
        // an ordinary wrong-passphrase result, never Duress.
        val verdict = restored.attempt("fire drill", nowMs = 0L)
        assertTrue(verdict is AppLock.Verdict.WrongPassphrase)
    }
}
