package com.veil.app.crypto

import com.lambdapioneer.argon2kt.Argon2Kt
import com.lambdapioneer.argon2kt.Argon2Mode
import java.security.SecureRandom
import kotlin.math.min
import org.json.JSONObject

/**
 * App-lock logic — the Kotlin sibling of veil-crypto's `lock.rs` in the CLI.
 * Kept deliberately parallel so a security reviewer can diff the two and
 * confirm they actually implement the same policy, not two different ones
 * that happen to share a name.
 *
 * Corrected against Argon2Kt's real, confirmed API (looked up the same way
 * as the Rust ml-kem and Android Tink fixes — this file's first version
 * called `rawHashAsByteArray()` and a `parallelism` parameter that were
 * never confirmed to exist, and used a hand-rolled constant-time compare
 * against raw hash bytes). The confirmed API instead returns a
 * self-contained, PHC-style encoded string (`encodedOutputAsString()`,
 * salt included) and provides its own `verify()` — the same shape as the
 * Rust side's `argon2::password_hash` usage in lock.rs, and it means this
 * class never has to roll its own comparison.
 *
 * Pentester note: this class holds derived hashes, not the passphrase
 * itself, once `attempt()` returns. The raw passphrase lives only as long
 * as the caller's own String does — Kotlin Strings are immutable and can't
 * be zeroized, which is a real, known gap (see README "Honest gaps"). A
 * production-grade version would take the passphrase as a CharArray and
 * wipe it after hashing.
 */
class AppLock private constructor(
    private var passphraseEncoded: String,
    private var duressEncoded: String?,
    private var failCount: Int,
    private var lockedUntilMs: Long,
    private val maxFails: Int,
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
        val passBytes = passphrase.toByteArray(Charsets.UTF_8)
        duressEncoded?.let { encoded ->
            if (argon2.verify(Argon2Mode.ARGON2_ID, encoded, passBytes)) {
                // Correct, but matches the duress code: caller must trigger
                // the wipe-and-decoy-open flow, never a normal unlock.
                return Verdict.Duress
            }
        }
        if (argon2.verify(Argon2Mode.ARGON2_ID, passphraseEncoded, passBytes)) {
            failCount = 0
            lockedUntilMs = 0L
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

    /**
     * Serializes the lock's state (encoded hashes + fail/lockout counters)
     * as JSON, for SecureStore-independent persistence: this file is NOT
     * secret (the Argon2 hashes are the whole point of being safe to store
     * — the same reasoning the Rust CLI's `AppLock` relies on), so it can
     * sit next to, not inside, the encrypted vault, avoiding a chicken-
     * and-egg problem where you'd need the vault unlocked to check whether
     * it should unlock.
     */
    fun toJson(): String {
        val obj = JSONObject()
        obj.put("passphraseEncoded", passphraseEncoded)
        obj.put("duressEncoded", duressEncoded)
        obj.put("failCount", failCount)
        obj.put("lockedUntilMs", lockedUntilMs)
        obj.put("maxFails", maxFails)
        return obj.toString()
    }

    companion object {
        /** Creates a fresh lock, hashing the given passphrase (and optional duress code) now. */
        fun create(passphrase: String, duressPassphrase: String? = null, maxFails: Int = 10): AppLock {
            val argon2 = Argon2Kt()
            val passEncoded = hashEncoded(argon2, passphrase)
            val duressEncodedStr = duressPassphrase?.let { hashEncoded(argon2, it) }
            return AppLock(passEncoded, duressEncodedStr, failCount = 0, lockedUntilMs = 0L, maxFails = maxFails)
        }

        fun fromJson(json: String): AppLock {
            val obj = JSONObject(json)
            return AppLock(
                passphraseEncoded = obj.getString("passphraseEncoded"),
                duressEncoded = if (obj.isNull("duressEncoded")) null else obj.getString("duressEncoded"),
                failCount = obj.optInt("failCount", 0),
                lockedUntilMs = obj.optLong("lockedUntilMs", 0L),
                maxFails = obj.optInt("maxFails", 10),
            )
        }

        private fun hashEncoded(argon2: Argon2Kt, secret: String): String {
            val salt = ByteArray(16).also { SecureRandom().nextBytes(it) }
            return argon2.hash(
                mode = Argon2Mode.ARGON2_ID,
                password = secret.toByteArray(Charsets.UTF_8),
                salt = salt,
                tCostInIterations = 3,
                mCostInKibibyte = 65536, // 64 MiB — matches lock.rs's OWASP-recommended profile
            ).encodedOutputAsString()
        }
    }
}
