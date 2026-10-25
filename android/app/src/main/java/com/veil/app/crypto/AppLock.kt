package com.veil.app.crypto

import com.lambdapioneer.argon2kt.Argon2Kt
import com.lambdapioneer.argon2kt.Argon2Mode
import java.security.SecureRandom
import kotlin.math.min

/**
 * App-lock logic — the Kotlin sibling of veil-crypto's `lock.rs` in the CLI.
 * Kept deliberately parallel so a security reviewer can diff the two and
 * confirm they actually implement the same policy, not two different ones
 * that happen to share a name.
 *
 * Pentester note: this class holds derived hashes, not the passphrase
 * itself, once `unlock()` returns. The raw passphrase lives only as long as
 * the caller's own CharArray/String does — Kotlin Strings are immutable and
 * can't be zeroized, which is a real, known gap (see README "Honest gaps").
 * A production-grade version would take the passphrase as a CharArray and
 * wipe it after hashing.
 */
class AppLock(
    private val passphraseHash: ByteArray,
    private val passphraseSalt: ByteArray,
    private val duressHash: ByteArray?,
    private val duressSalt: ByteArray?,
    private var failCount: Int = 0,
    private var lockedUntilMs: Long = 0L,
    private val maxFails: Int = 10,
) {
    sealed class Verdict {
        object Unlocked : Verdict()
        object Duress : Verdict()
        data class WrongPassphrase(val attemptsLeft: Int) : Verdict()
        data class Locked(val retryAfterMs: Long) : Verdict()
    }

    private val argon2 = Argon2Kt()

    fun attempt(passphrase: String, nowMs: Long): Verdict {
        if (nowMs < lockedUntilMs) {
            return Verdict.Locked(lockedUntilMs - nowMs)
        }
        if (duressHash != null && duressSalt != null && verify(passphrase, duressSalt, duressHash)) {
            // Correct, but matches the duress code: caller must trigger the
            // wipe-and-decoy-open flow, never a normal unlock.
            return Verdict.Duress
        }
        if (verify(passphrase, passphraseSalt, passphraseHash)) {
            failCount = 0
            return Verdict.Unlocked
        }
        failCount += 1
        if (failCount >= maxFails) {
            // Exponential backoff, capped at ~1 hour — mirrors lock.rs so a
            // brute-force script gains nothing by targeting whichever
            // client looks weaker.
            val backoffSecs = min(1L shl min(failCount - maxFails, 12), 3600L)
            lockedUntilMs = nowMs + backoffSecs * 1000
            return Verdict.Locked(backoffSecs * 1000)
        }
        return Verdict.WrongPassphrase(maxFails - failCount)
    }

    /** Caller-visible policy switch: does this fail count warrant a wipe? */
    fun shouldWipe(wipeAfterFails: Int): Boolean = failCount >= wipeAfterFails

    private fun verify(passphrase: String, salt: ByteArray, expected: ByteArray): Boolean {
        val hash = hashRaw(passphrase, salt)
        return constantTimeEquals(hash, expected)
    }

    private fun hashRaw(passphrase: String, salt: ByteArray): ByteArray {
        val result = argon2.hash(
            mode = Argon2Mode.ARGON2_ID,
            password = passphrase.toByteArray(Charsets.UTF_8),
            salt = salt,
            tCostInIterations = 3,
            mCostInKibibyte = 65536, // 64 MiB — matches lock.rs's OWASP-recommended profile
            parallelism = 4,
        )
        return result.rawHashAsByteArray()
    }

    private fun constantTimeEquals(a: ByteArray, b: ByteArray): Boolean {
        if (a.size != b.size) return false
        var diff = 0
        for (i in a.indices) diff = diff or (a[i].toInt() xor b[i].toInt())
        return diff == 0
    }

    companion object {
        fun newSalt(): ByteArray = ByteArray(16).also { SecureRandom().nextBytes(it) }

        /** Creates a fresh lock, hashing the given passphrase (and optional duress code) now. */
        fun create(passphrase: String, duressPassphrase: String? = null): AppLock {
            val pSalt = newSalt()
            val argon2 = Argon2Kt()
            val pHash = argon2.hash(
                Argon2Mode.ARGON2_ID,
                passphrase.toByteArray(Charsets.UTF_8),
                pSalt,
                3, 65536, 4,
            ).rawHashAsByteArray()

            var dSalt: ByteArray? = null
            var dHash: ByteArray? = null
            if (duressPassphrase != null) {
                dSalt = newSalt()
                dHash = argon2.hash(
                    Argon2Mode.ARGON2_ID,
                    duressPassphrase.toByteArray(Charsets.UTF_8),
                    dSalt,
                    3, 65536, 4,
                ).rawHashAsByteArray()
            }
            return AppLock(pHash, pSalt, dHash, dSalt)
        }
    }
}
