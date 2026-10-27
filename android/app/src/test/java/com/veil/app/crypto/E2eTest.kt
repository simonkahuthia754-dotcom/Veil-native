package com.veil.app.crypto

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertThrows
import org.junit.Test

/**
 * Real round-trip tests for the hybrid X25519 + ML-KEM-768 scheme, mirroring
 * the Rust CLI's own `crypto::e2e::tests` (crypto/src/e2e.rs) — a pure-JVM
 * test, no Android framework or device needed, since BouncyCastle's
 * lightweight API has no Android dependency. This is the first real test
 * this module has had; previously `testDebugUnitTest` in CI ran against an
 * empty test source set, which is not the same thing as "tested."
 */
class E2eTest {
    @Test
    fun roundTrip() {
        val alice = VeilIdentity.generate()
        val bob = VeilIdentity.generate()

        val plaintext = "the chamber meets at dusk".toByteArray(Charsets.UTF_8)
        val sealed = alice.seal(plaintext, bob.publicKeyBase64(), bob.pqPublicKeyBase64())
        val opened = bob.open(sealed)

        assertArrayEquals(plaintext, opened)
    }

    @Test
    fun wrongRecipientFails() {
        val alice = VeilIdentity.generate()
        val bob = VeilIdentity.generate()
        val eve = VeilIdentity.generate()

        val sealed = alice.seal("secret".toByteArray(Charsets.UTF_8), bob.publicKeyBase64(), bob.pqPublicKeyBase64())

        assertThrows(Exception::class.java) { eve.open(sealed) }
    }

    @Test
    fun tamperedCiphertextFailsAuth() {
        val alice = VeilIdentity.generate()
        val bob = VeilIdentity.generate()

        val sealed = alice.seal("secret".toByteArray(Charsets.UTF_8), bob.publicKeyBase64(), bob.pqPublicKeyBase64())
        val tampered = sealed.copy(ciphertext = sealed.ciphertext.also { it[0] = (it[0].toInt() xor 1).toByte() })

        assertThrows(Exception::class.java) { bob.open(tampered) }
    }

    @Test
    fun serializeRoundTripPreservesIdentity() {
        val original = VeilIdentity.generate()
        val restored = VeilIdentity.fromSerialized(VeilIdentity.serializePrivate(original))

        // Public keys must match exactly after a private-key serialize/
        // deserialize cycle — this is what SecureStore round-trips through
        // the encrypted vault on every unlock.
        assert(original.publicKeyBase64() == restored.publicKeyBase64())
        assert(original.pqPublicKeyBase64() == restored.pqPublicKeyBase64())

        // And the restored identity must actually decrypt messages sealed
        // against the original's published public keys.
        val sender = VeilIdentity.generate()
        val sealed = sender.seal(
            "after restart".toByteArray(Charsets.UTF_8),
            original.publicKeyBase64(),
            original.pqPublicKeyBase64(),
        )
        assertArrayEquals("after restart".toByteArray(Charsets.UTF_8), restored.open(sealed))
    }
}
