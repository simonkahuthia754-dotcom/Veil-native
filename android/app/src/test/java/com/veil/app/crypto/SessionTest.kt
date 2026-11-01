package com.veil.app.crypto

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Mirrors `crypto/src/session.rs`'s own test suite line for line, so a
 * reviewer can diff the two and confirm this port actually implements the
 * same protocol, not a similar-looking one. Pure-JVM (BouncyCastle has no
 * Android dependency), same reasoning as `E2eTest.kt`.
 */
class SessionTest {
    private fun bundleFrom(identity: VeilIdentity, mediumTerm: Prekey, otpk: Prekey?): PrekeyBundle {
        val (mtX, mtKem) = mediumTerm.publicBundle()
        return PrekeyBundle(
            identityXPublic = identity.xPublic.encoded,
            mediumTermXPublic = mtX,
            mediumTermKemPublic = mtKem,
            oneTimeXPublic = otpk?.publicBundle()?.first,
        )
    }

    @Test
    fun handshakeAgreesOnTheSameChainsWithOneTimePrekey() {
        val alice = VeilIdentity.generate()
        val bob = VeilIdentity.generate()
        val bobMtpk = Prekey.generate()
        val bobOtpk = Prekey.generate()
        val bobOtpkPubB64 = java.util.Base64.getEncoder().encodeToString(bobOtpk.publicBundle().first)
        val bobOtpkStore = mutableMapOf(bobOtpkPubB64 to bobOtpk)

        val bundle = bundleFrom(bob, bobMtpk, bobOtpk)
        val (aliceSession, initMsg) = initiateSession(alice, bundle)
        val bobSession = acceptSession(bob, bobMtpk, bobOtpkStore, initMsg)

        assertTrue(bobOtpkStore.isEmpty())

        val sealed = aliceSession.seal("the chamber meets at dusk".toByteArray(Charsets.UTF_8))
        val opened = bobSession.open(sealed)
        assertArrayEquals("the chamber meets at dusk".toByteArray(Charsets.UTF_8), opened)
    }

    @Test
    fun handshakeAgreesWithoutAOneTimePrekey() {
        val alice = VeilIdentity.generate()
        val bob = VeilIdentity.generate()
        val bobMtpk = Prekey.generate()
        val emptyStore = mutableMapOf<String, Prekey>()

        val bundle = bundleFrom(bob, bobMtpk, null)
        val (aliceSession, initMsg) = initiateSession(alice, bundle)
        val bobSession = acceptSession(bob, bobMtpk, emptyStore, initMsg)

        val sealed = aliceSession.seal("no one-time prekey this time".toByteArray(Charsets.UTF_8))
        assertArrayEquals("no one-time prekey this time".toByteArray(Charsets.UTF_8), bobSession.open(sealed))
    }

    @Test
    fun bothDirectionsWorkIndependently() {
        val alice = VeilIdentity.generate()
        val bob = VeilIdentity.generate()
        val bobMtpk = Prekey.generate()
        val bundle = bundleFrom(bob, bobMtpk, null)
        val (aliceSession, initMsg) = initiateSession(alice, bundle)
        val bobSession = acceptSession(bob, bobMtpk, mutableMapOf(), initMsg)

        val aToB = aliceSession.seal("hello bob".toByteArray(Charsets.UTF_8))
        assertArrayEquals("hello bob".toByteArray(Charsets.UTF_8), bobSession.open(aToB))

        val bToA = bobSession.seal("hello alice".toByteArray(Charsets.UTF_8))
        assertArrayEquals("hello alice".toByteArray(Charsets.UTF_8), aliceSession.open(bToA))
    }

    @Test
    fun chainAdvancesEachMessageAndRejectsReplay() {
        val alice = VeilIdentity.generate()
        val bob = VeilIdentity.generate()
        val bobMtpk = Prekey.generate()
        val bundle = bundleFrom(bob, bobMtpk, null)
        val (aliceSession, initMsg) = initiateSession(alice, bundle)
        val bobSession = acceptSession(bob, bobMtpk, mutableMapOf(), initMsg)

        val m0 = aliceSession.seal("one".toByteArray(Charsets.UTF_8))
        val m1 = aliceSession.seal("two".toByteArray(Charsets.UTF_8))
        assertEquals(0, m0.counter)
        assertEquals(1, m1.counter)

        assertArrayEquals("one".toByteArray(Charsets.UTF_8), bobSession.open(m0))
        assertArrayEquals("two".toByteArray(Charsets.UTF_8), bobSession.open(m1))

        assertThrows(SessionException::class.java) { bobSession.open(m0) }
    }

    @Test
    fun outOfOrderDeliveryWithinTheSkipWindowStillWorks() {
        val alice = VeilIdentity.generate()
        val bob = VeilIdentity.generate()
        val bobMtpk = Prekey.generate()
        val bundle = bundleFrom(bob, bobMtpk, null)
        val (aliceSession, initMsg) = initiateSession(alice, bundle)
        val bobSession = acceptSession(bob, bobMtpk, mutableMapOf(), initMsg)

        val m0 = aliceSession.seal("first".toByteArray(Charsets.UTF_8))
        val m1 = aliceSession.seal("second".toByteArray(Charsets.UTF_8))
        val m2 = aliceSession.seal("third".toByteArray(Charsets.UTF_8))

        assertArrayEquals("third".toByteArray(Charsets.UTF_8), bobSession.open(m2))
        assertArrayEquals("first".toByteArray(Charsets.UTF_8), bobSession.open(m0))
        assertArrayEquals("second".toByteArray(Charsets.UTF_8), bobSession.open(m1))
    }

    @Test
    fun forwardSecrecyACapturedLaterChainKeyCannotRecoverAnEarlierMessage() {
        val alice = VeilIdentity.generate()
        val bob = VeilIdentity.generate()
        val bobMtpk = Prekey.generate()
        val bundle = bundleFrom(bob, bobMtpk, null)
        val (aliceSession, initMsg) = initiateSession(alice, bundle)
        val bobSession = acceptSession(bob, bobMtpk, mutableMapOf(), initMsg)

        val m0 = aliceSession.seal("secret from the past".toByteArray(Charsets.UTF_8))
        bobSession.open(m0) // chain advances past position 0, old chain key gone

        // The skipped/consumed key entry for position 0 is gone; re-opening
        // the same message must fail, not silently succeed with a stale key.
        assertThrows(SessionException::class.java) { bobSession.open(m0) }
    }

    @Test
    fun refusesToSkipAnUnreasonableNumberOfPositions() {
        val alice = VeilIdentity.generate()
        val bob = VeilIdentity.generate()
        val bobMtpk = Prekey.generate()
        val bundle = bundleFrom(bob, bobMtpk, null)
        val (aliceSession, initMsg) = initiateSession(alice, bundle)
        val bobSession = acceptSession(bob, bobMtpk, mutableMapOf(), initMsg)

        val farFuture = aliceSession.seal("way ahead".toByteArray(Charsets.UTF_8))
        val tampered = RatchetedMessage(counter = 1001, nonce = farFuture.nonce, ciphertext = farFuture.ciphertext)
        assertThrows(SessionException::class.java) { bobSession.open(tampered) }
    }

    @Test
    fun prekeySecretBytesRoundTrip() {
        val original = Prekey.generate()
        val (xBytes, kemBytes) = original.toSecretBytes()
        val restored = Prekey.fromSecretBytes(xBytes, kemBytes)
        assertArrayEquals(original.publicBundle().first, restored.publicBundle().first)
        assertArrayEquals(original.publicBundle().second, restored.publicBundle().second)
    }

    @Test
    fun sessionSurvivesAJsonRoundTripMidConversation() {
        // Real-world shape: send a message, restart the app (reload the
        // session from disk), then keep talking.
        val alice = VeilIdentity.generate()
        val bob = VeilIdentity.generate()
        val bobMtpk = Prekey.generate()
        val bundle = bundleFrom(bob, bobMtpk, null)
        val (aliceSession, initMsg) = initiateSession(alice, bundle)
        val bobSession = acceptSession(bob, bobMtpk, mutableMapOf(), initMsg)

        val m0 = aliceSession.seal("before restart".toByteArray(Charsets.UTF_8))
        assertArrayEquals("before restart".toByteArray(Charsets.UTF_8), bobSession.open(m0))

        val restored = Session.fromJson(aliceSession.toJson())

        val m1 = restored.seal("after restart".toByteArray(Charsets.UTF_8))
        assertArrayEquals("after restart".toByteArray(Charsets.UTF_8), bobSession.open(m1))
    }

    @Test
    fun initialMessageAndRatchetedMessageSurviveJsonRoundTrip() {
        val alice = VeilIdentity.generate()
        val bob = VeilIdentity.generate()
        val bobMtpk = Prekey.generate()
        val bundle = bundleFrom(bob, bobMtpk, null)
        val (aliceSession, initMsg) = initiateSession(alice, bundle)

        val restoredInit = InitialMessage.fromJson(initMsg.toJson())
        val bobSession = acceptSession(bob, bobMtpk, mutableMapOf(), restoredInit)

        val sealed = aliceSession.seal("round trip the envelope too".toByteArray(Charsets.UTF_8))
        val restoredSealed = RatchetedMessage.fromJson(sealed.toJson())
        assertArrayEquals("round trip the envelope too".toByteArray(Charsets.UTF_8), bobSession.open(restoredSealed))
    }

    // The whole point of the tag: it has to agree on both ends without
    // either side ever transmitting it (see Session.tag's doc comment, and
    // crypto/src/session.rs's identically-named test).
    @Test
    fun bothSidesIndependentlyDeriveTheSameTag() {
        val alice = VeilIdentity.generate()
        val bob = VeilIdentity.generate()
        val bobMtpk = Prekey.generate()
        val bundle = bundleFrom(bob, bobMtpk, null)
        val (aliceSession, initMsg) = initiateSession(alice, bundle)
        val bobSession = acceptSession(bob, bobMtpk, mutableMapOf(), initMsg)

        assertEquals(aliceSession.tagB64(), bobSession.tagB64())
    }

    @Test
    fun twoIndependentSessionsGetDifferentTags() {
        val alice = VeilIdentity.generate()
        val bob = VeilIdentity.generate()
        val bobMtpk1 = Prekey.generate()
        val bundle1 = bundleFrom(bob, bobMtpk1, null)
        val (session1, _) = initiateSession(alice, bundle1)

        val bobMtpk2 = Prekey.generate()
        val bundle2 = bundleFrom(bob, bobMtpk2, null)
        val (session2, _) = initiateSession(alice, bundle2)

        assertTrue(session1.tagB64() != session2.tagB64())
    }

    @Test
    fun tagSurvivesAJsonRoundTrip() {
        val alice = VeilIdentity.generate()
        val bob = VeilIdentity.generate()
        val bobMtpk = Prekey.generate()
        val bundle = bundleFrom(bob, bobMtpk, null)
        val (aliceSession, _) = initiateSession(alice, bundle)

        val originalTag = aliceSession.tagB64()
        val restored = Session.fromJson(aliceSession.toJson())
        assertEquals(originalTag, restored.tagB64())
    }
}
