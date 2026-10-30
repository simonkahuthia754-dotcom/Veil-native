package com.veil.app.crypto

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * First real tests for `AppLock` — the passphrase/duress lockout state
 * machine that `VeilSession.createLock()`/`unlock()`/`enterDuress()` depend
 * on. This class previously had zero test coverage despite being the thing
 * standing between "the app is locked" and "the app isn't locked".
 *
 * Deliberately does NOT exercise `Argon2PasswordHasher` (the real
 * production hasher): that class wraps Argon2Kt's native `.so` binding,
 * which per Argon2Kt's own README is only documented as testable via
 * `connectedAndroidTest` on a device/emulator — this repo's CI runs
 * `gradle testDebugUnitTest` on the host JVM with no emulator, where a
 * native-library call throws `UnsatisfiedLinkError` regardless of whether
 * AppLock's own logic is correct. `FakeHasher` below is a trivial,
 * deliberately-NOT-constant-time, deliberately-not-salted stand-in used
 * only to drive `AppLock`'s state machine in tests; it proves nothing about
 * Argon2Kt's native integration, which remains unverified by CI (named in
 * the README's "Honest gaps" — the same honest limitation `E2eTest.kt`
 * already carries for the BouncyCastle crypto path, just for a different
 * reason: that one runs for real because BouncyCastle is pure JVM).
 */
private class FakeHasher : PasswordHasher {
    override fun hash(secret: String): String = "fake:$secret"
    override fun verify(encoded: String, secret: String): Boolean = encoded == "fake:$secret"
}

class AppLockTest {
    @Test
    fun correctPassphraseUnlocks() {
        val lock = AppLock.create("correct horse battery staple", hasher = FakeHasher())
        val verdict = lock.attempt("correct horse battery staple", nowMs = 0L)
        assertTrue(verdict is AppLock.Verdict.Unlocked)
    }

    @Test
    fun wrongPassphraseIsRejectedAndCountsDown() {
        val lock = AppLock.create("correct horse battery staple", maxFails = 3, hasher = FakeHasher())
        val v1 = lock.attempt("wrong", nowMs = 0L)
        assertTrue(v1 is AppLock.Verdict.WrongPassphrase)
        assertEquals(2, (v1 as AppLock.Verdict.WrongPassphrase).attemptsLeft)
    }

    @Test
    fun exceedingMaxFailsLocksOutWithBackoff() {
        val lock = AppLock.create("correct horse battery staple", maxFails = 2, hasher = FakeHasher())
        lock.attempt("wrong", nowMs = 0L)
        val tripped = lock.attempt("wrong", nowMs = 1L)
        assertTrue(tripped is AppLock.Verdict.Locked)

        // Still within the backoff window: locked out even with the right passphrase.
        val duringLockout = lock.attempt("correct horse battery staple", nowMs = 2L)
        assertTrue(duringLockout is AppLock.Verdict.Locked)
    }

    @Test
    fun lockoutExpiresAndCorrectPassphraseThenWorks() {
        val lock = AppLock.create("correct horse battery staple", maxFails = 1, hasher = FakeHasher())
        val tripped = lock.attempt("wrong", nowMs = 0L)
        val retryAfter = (tripped as AppLock.Verdict.Locked).retryAfterMs

        val afterExpiry = lock.attempt("correct horse battery staple", nowMs = retryAfter + 1)
        assertTrue(afterExpiry is AppLock.Verdict.Unlocked)
    }

    @Test
    fun duressPassphraseReturnsDuressNotUnlocked() {
        val lock = AppLock.create(
            "correct horse battery staple",
            duressPassphrase = "fire drill",
            hasher = FakeHasher(),
        )
        val verdict = lock.attempt("fire drill", nowMs = 0L)
        assertTrue(verdict is AppLock.Verdict.Duress)
    }

    @Test
    fun duressCheckDoesNotLeakIntoNormalFailCount() {
        // A duress match must not be treated as a wrong-passphrase attempt
        // (that would make duress entries count toward a forced wipe via
        // shouldWipe(), which should only ever be driven by genuinely wrong
        // guesses).
        val lock = AppLock.create(
            "correct horse battery staple",
            duressPassphrase = "fire drill",
            maxFails = 5,
            hasher = FakeHasher(),
        )
        lock.attempt("fire drill", nowMs = 0L)
        assertTrue(!lock.shouldWipe(wipeAfterFails = 1))
    }

    @Test
    fun shouldWipeTripsAfterConfiguredFailCount() {
        val lock = AppLock.create("correct horse battery staple", maxFails = 100, hasher = FakeHasher())
        lock.attempt("wrong", nowMs = 0L)
        lock.attempt("wrong", nowMs = 1L)
        assertTrue(lock.shouldWipe(wipeAfterFails = 2))
        assertTrue(!lock.shouldWipe(wipeAfterFails = 3))
    }

    @Test
    fun jsonRoundTripPreservesVerdictBehavior() {
        val original = AppLock.create(
            "correct horse battery staple",
            duressPassphrase = "fire drill",
            maxFails = 4,
            hasher = FakeHasher(),
        )
        original.attempt("wrong", nowMs = 0L) // bump fail count before serializing

        val restored = AppLock.fromJson(original.toJson(), hasher = FakeHasher())

        assertTrue(restored.attempt("correct horse battery staple", nowMs = 100L) is AppLock.Verdict.Unlocked)
    }

    @Test
    fun jsonRoundTripWithNoDuressCodeOmitsIt() {
        val original = AppLock.create("correct horse battery staple", hasher = FakeHasher())
        val restored = AppLock.fromJson(original.toJson(), hasher = FakeHasher())

        // No duress code was set, so a distinct guess must fall through to
        // an ordinary wrong-passphrase result, never Duress.
        val verdict = restored.attempt("fire drill", nowMs = 0L)
        assertTrue(verdict is AppLock.Verdict.WrongPassphrase)
    }
}
