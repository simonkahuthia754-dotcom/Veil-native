package com.veil.app.crypto

import org.bouncycastle.crypto.digests.SHA256Digest
import org.bouncycastle.crypto.generators.HKDFBytesGenerator
import org.bouncycastle.crypto.generators.MLKEMKeyPairGenerator
import org.bouncycastle.crypto.kems.MLKEMExtractor
import org.bouncycastle.crypto.kems.MLKEMGenerator
import org.bouncycastle.crypto.params.MLKEMKeyGenerationParameters
import org.bouncycastle.crypto.modes.XChaCha20Poly1305
import org.bouncycastle.crypto.params.AEADParameters
import org.bouncycastle.crypto.params.HKDFParameters
import org.bouncycastle.crypto.params.KeyParameter
import org.bouncycastle.crypto.params.MLKEMParameters
import org.bouncycastle.crypto.params.MLKEMPrivateKeyParameters
import org.bouncycastle.crypto.params.MLKEMPublicKeyParameters
import org.bouncycastle.crypto.params.X25519PrivateKeyParameters
import org.bouncycastle.crypto.params.X25519PublicKeyParameters
import org.json.JSONObject
import java.security.SecureRandom
import java.util.Base64

/**
 * Forward secrecy for Android — the Kotlin twin of the Rust CLI's
 * `crypto/src/session.rs`: an X3DH-style handshake using published prekey
 * bundles, followed by a per-direction KDF sending-chain ratchet. Read
 * `session.rs`'s own module doc first; the scope statement there (real
 * forward secrecy within a session, NOT Signal's full bidirectional
 * Double Ratchet / post-compromise security) applies here unchanged, not
 * re-litigated per file.
 *
 * This is a same-construction, same-wire-format port, not a reinterpretation:
 *   DH1 = initiator_identity   x responder_medium_term
 *   DH2 = initiator_ephemeral  x responder_identity
 *   DH3 = initiator_ephemeral  x responder_medium_term
 *   DH4 = initiator_ephemeral  x responder_one_time      (if one was available)
 *   KEM = Encapsulate(responder_medium_term_kem_pub)
 *   root_key = HKDF-SHA256(salt="veil-x3dh-v1", ikm = DH1||DH2||DH3||DH4?||KEM_secret, info="root-key")
 *   (chain_i2r, chain_r2i) = HKDF-SHA256(salt="veil-session-chains-v1", ikm=root_key,
 *                                         info="chain-initiator-to-responder" / "chain-responder-to-initiator")
 * Per-message ratchet step: HKDF-SHA256 using the current chain key AS THE
 * PRK directly (`HKDFParameters.skipExtractParameters`, the BouncyCastle
 * equivalent of the Rust side's `Hkdf::from_prk` — confirmed against the
 * real javadoc: a plain `HKDFParameters(ikm, salt, info)` would re-extract
 * from the chain key as if it were raw entropy, which is a DIFFERENT and
 * wrong derivation; expand-only is what `session.rs` actually does and what
 * must be matched here), with distinct `info` strings for the message key
 * and the next chain key.
 *
 * Honest scope note on cross-client interop: the HANDSHAKE and WIRE
 * TYPES here (`PrekeyBundle`, `InitialMessage`, `RatchetedMessage`) use the
 * same byte encodings as `session.rs` and are designed to interoperate with
 * it (X25519/ML-KEM-768 public-key encodings already proven wire-compatible
 * by `E2eTest.kt`/`e2e.rs`'s own tests for the static scheme). What is NOT
 * yet true, and is a separate, still-open task: nothing in `VeilSession.kt`
 * calls this module yet. Publishing this device's own prekey bundle,
 * fetching a contact's bundle from `GET /prekeys/:handle/bundle`, and
 * choosing this ratchet path over the static `VeilIdentity.seal()`/`open()`
 * fallback (the way the CLI's `seal_for_one` already does) is unwired —
 * tracked in the README, not hidden.
 */
class SessionException(message: String) : Exception(message)

/** Cap on how many chain positions [Session.open] will advance through to catch up to a received counter. */
private const val MAX_SKIP = 1000

/**
 * A medium-term or one-time prekey: a short-lived X25519 + ML-KEM-768
 * keypair. Deliberately a separate type from [VeilIdentity] — conflating
 * "my permanent identity" with "a prekey I rotate or burn after one use"
 * is a real protocol-design mistake this keeps structurally impossible.
 */
class Prekey private constructor(
    private val xSecret: X25519PrivateKeyParameters,
    val xPublic: X25519PublicKeyParameters,
    internal val kemPrivate: MLKEMPrivateKeyParameters,
    val kemPublic: MLKEMPublicKeyParameters,
) {
    internal fun diffieHellman(peer: X25519PublicKeyParameters): ByteArray {
        val out = ByteArray(X25519PrivateKeyParameters.SECRET_SIZE)
        xSecret.generateSecret(peer, out, 0)
        return out
    }

    /** (x_public, kem_public) — publish this pair as one prekey entry. */
    fun publicBundle(): Pair<ByteArray, ByteArray> = Pair(xPublic.encoded, kemPublic.encoded)

    /** Secret material for vault persistence — same reasoning as [VeilIdentity.serializePrivate]. */
    fun toSecretBytes(): Pair<ByteArray, ByteArray> = Pair(xSecret.encoded, kemPrivate.encoded)

    companion object {
        fun generate(): Prekey {
            val xSecret = X25519PrivateKeyParameters(SecureRandom())
            val xPublic = xSecret.generatePublicKey()
            val kemGen = MLKEMKeyPairGenerator()
            kemGen.init(MLKEMKeyGenerationParameters(SecureRandom(), MLKEMParameters.ml_kem_768))
            val kemPair = kemGen.generateKeyPair()
            val kemPrivate = kemPair.getPrivate() as MLKEMPrivateKeyParameters
            val kemPublic = kemPair.getPublic() as MLKEMPublicKeyParameters
            return Prekey(xSecret, xPublic, kemPrivate, kemPublic)
        }

        fun fromSecretBytes(xSecretBytes: ByteArray, kemSecretBytes: ByteArray): Prekey {
            val xSecret = X25519PrivateKeyParameters(xSecretBytes)
            val xPublic = xSecret.generatePublicKey()
            val kemPrivate = MLKEMPrivateKeyParameters(MLKEMParameters.ml_kem_768, kemSecretBytes)
            val kemPublic = kemPrivate.publicKeyParameters
            return Prekey(xSecret, xPublic, kemPrivate, kemPublic)
        }
    }
}

/** What `GET /prekeys/:handle/bundle` hands back — public material only. */
data class PrekeyBundle(
    val identityXPublic: ByteArray,
    val mediumTermXPublic: ByteArray,
    val mediumTermKemPublic: ByteArray,
    val oneTimeXPublic: ByteArray?,
)

/** The handshake payload the initiator sends as the first message of a session. */
data class InitialMessage(
    val initiatorIdentityXPublic: ByteArray,
    val initiatorEphemeralXPublic: ByteArray,
    val kemCiphertext: ByteArray,
    val oneTimeXPublicUsed: ByteArray?,
) {
    fun toJson(): String {
        val obj = JSONObject()
        obj.put("initiatorIdentityXPublic", b64(initiatorIdentityXPublic))
        obj.put("initiatorEphemeralXPublic", b64(initiatorEphemeralXPublic))
        obj.put("kemCiphertext", b64(kemCiphertext))
        obj.put("oneTimeXPublicUsed", oneTimeXPublicUsed?.let { b64(it) })
        return obj.toString()
    }

    companion object {
        fun fromJson(json: String): InitialMessage {
            val obj = JSONObject(json)
            return InitialMessage(
                initiatorIdentityXPublic = unb64(obj.getString("initiatorIdentityXPublic")),
                initiatorEphemeralXPublic = unb64(obj.getString("initiatorEphemeralXPublic")),
                kemCiphertext = unb64(obj.getString("kemCiphertext")),
                oneTimeXPublicUsed = if (obj.isNull("oneTimeXPublicUsed")) null else unb64(obj.getString("oneTimeXPublicUsed")),
            )
        }
    }
}

/** One ratcheted message: a chain position plus a normal AEAD envelope. */
data class RatchetedMessage(val counter: Int, val nonce: ByteArray, val ciphertext: ByteArray) {
    fun toJson(): String {
        val obj = JSONObject()
        obj.put("counter", counter)
        obj.put("nonce", b64(nonce))
        obj.put("ciphertext", b64(ciphertext))
        return obj.toString()
    }

    companion object {
        fun fromJson(json: String): RatchetedMessage {
            val obj = JSONObject(json)
            return RatchetedMessage(
                counter = obj.getInt("counter"),
                nonce = unb64(obj.getString("nonce")),
                ciphertext = unb64(obj.getString("ciphertext")),
            )
        }
    }
}

/**
 * Live session state for one conversation. Holds only chain keys, never
 * the root key past the moment both chains are derived from it.
 *
 * Mutable (`var` chain keys/counters) by design — advancing the ratchet
 * destroys the previous chain key, which is the forward-secrecy property,
 * not a side effect of it. Persistable via [toJson]/[fromJson] so a
 * restart doesn't force a brand-new handshake per contact — same vault
 * trust model as everything else this class's secrets sit alongside.
 */
class Session internal constructor(
    private var sendChainKey: ByteArray,
    private var sendCounter: Int,
    private var recvChainKey: ByteArray,
    private var recvCounter: Int,
    private val skippedKeys: MutableMap<Int, ByteArray> = mutableMapOf(),
) {
    /** Encrypts [plaintext], advancing the send chain by exactly one step. */
    fun seal(plaintext: ByteArray): RatchetedMessage {
        val (messageKey, nextChainKey) = ratchetStep(sendChainKey)
        sendChainKey = nextChainKey
        val counter = sendCounter
        sendCounter += 1

        val nonce = ByteArray(NONCE_SIZE).also { SecureRandom().nextBytes(it) }
        val cipher = XChaCha20Poly1305()
        cipher.init(true, AEADParameters(KeyParameter(messageKey), MAC_SIZE_BITS, nonce))
        val out = ByteArray(cipher.getOutputSize(plaintext.size))
        var len = cipher.processBytes(plaintext, 0, plaintext.size, out, 0)
        len += cipher.doFinal(out, len)

        return RatchetedMessage(counter, nonce, out.copyOf(len))
    }

    /**
     * Decrypts [msg], tolerating out-of-order arrival up to [MAX_SKIP]
     * positions by caching skipped-over message keys (removed once used, so
     * a replay of an already-opened counter fails rather than reusing a key).
     */
    fun open(msg: RatchetedMessage): ByteArray {
        val messageKey: ByteArray = skippedKeys.remove(msg.counter)
            ?: run {
                if (msg.counter < recvCounter) {
                    throw SessionException("counter ${msg.counter} already advanced past (duplicate or replay)")
                }
                val skip = msg.counter - recvCounter
                if (skip > MAX_SKIP) {
                    throw SessionException("counter ${msg.counter} is too far ahead to catch up to")
                }
                while (recvCounter < msg.counter) {
                    val (skippedKey, nextChainKey) = ratchetStep(recvChainKey)
                    skippedKeys[recvCounter] = skippedKey
                    recvChainKey = nextChainKey
                    recvCounter += 1
                }
                val (key, nextChainKey) = ratchetStep(recvChainKey)
                recvChainKey = nextChainKey
                recvCounter += 1
                key
            }

        val cipher = XChaCha20Poly1305()
        cipher.init(false, AEADParameters(KeyParameter(messageKey), MAC_SIZE_BITS, msg.nonce))
        val out = ByteArray(cipher.getOutputSize(msg.ciphertext.size))
        var len = cipher.processBytes(msg.ciphertext, 0, msg.ciphertext.size, out, 0)
        len += cipher.doFinal(out, len) // throws InvalidCipherTextException on tamper — same as e2e.rs's seal/open
        return out.copyOf(len)
    }

    fun toJson(): String {
        val obj = JSONObject()
        obj.put("sendChainKey", b64(sendChainKey))
        obj.put("sendCounter", sendCounter)
        obj.put("recvChainKey", b64(recvChainKey))
        obj.put("recvCounter", recvCounter)
        val skipped = JSONObject()
        skippedKeys.forEach { (counter, key) -> skipped.put(counter.toString(), b64(key)) }
        obj.put("skippedKeys", skipped)
        return obj.toString()
    }

    companion object {
        fun fromJson(json: String): Session {
            val obj = JSONObject(json)
            val skippedObj = obj.getJSONObject("skippedKeys")
            val skipped = mutableMapOf<Int, ByteArray>()
            skippedObj.keys().forEach { k -> skipped[k.toInt()] = unb64(skippedObj.getString(k)) }
            return Session(
                sendChainKey = unb64(obj.getString("sendChainKey")),
                sendCounter = obj.getInt("sendCounter"),
                recvChainKey = unb64(obj.getString("recvChainKey")),
                recvCounter = obj.getInt("recvCounter"),
                skippedKeys = skipped,
            )
        }
    }
}

private const val NONCE_SIZE = 24
private const val MAC_SIZE_BITS = 128

private fun b64(bytes: ByteArray): String = Base64.getEncoder().encodeToString(bytes)
private fun unb64(s: String): ByteArray = Base64.getDecoder().decode(s)

/**
 * One ratchet step: HKDF-expand the current chain key — used directly as
 * the HKDF PRK (already 32 bytes of high-entropy key material, nothing to
 * extract from) — into a message key and the next chain key, via distinct
 * `info` strings. `HKDFParameters.skipExtractParameters(ikm, info)`
 * constructs exactly this "PRK supplied directly" mode (confirmed against
 * the real javadoc) — the Kotlin equivalent of `Hkdf::from_prk` on the
 * Rust side; an ordinary `HKDFParameters(ikm, salt, info)` would wrongly
 * re-extract and silently diverge from `session.rs`.
 */
private fun ratchetStep(chainKey: ByteArray): Pair<ByteArray, ByteArray> {
    val messageKey = ByteArray(32)
    val hkdfMsg = HKDFBytesGenerator(SHA256Digest())
    hkdfMsg.init(HKDFParameters.skipExtractParameters(chainKey, "veil-ratchet-message-key".toByteArray(Charsets.UTF_8)))
    hkdfMsg.generateBytes(messageKey, 0, 32)

    val nextChainKey = ByteArray(32)
    val hkdfChain = HKDFBytesGenerator(SHA256Digest())
    hkdfChain.init(HKDFParameters.skipExtractParameters(chainKey, "veil-ratchet-chain-key".toByteArray(Charsets.UTF_8)))
    hkdfChain.generateBytes(nextChainKey, 0, 32)

    return Pair(messageKey, nextChainKey)
}

private fun deriveRootKey(dhParts: List<ByteArray>, kemSecret: ByteArray): ByteArray {
    val ikm = ByteArray(dhParts.sumOf { it.size } + kemSecret.size)
    var offset = 0
    for (part in dhParts) {
        part.copyInto(ikm, offset)
        offset += part.size
    }
    kemSecret.copyInto(ikm, offset)

    val rootKey = ByteArray(32)
    val hkdf = HKDFBytesGenerator(SHA256Digest())
    hkdf.init(HKDFParameters(ikm, "veil-x3dh-v1".toByteArray(Charsets.UTF_8), "root-key".toByteArray(Charsets.UTF_8)))
    hkdf.generateBytes(rootKey, 0, 32)
    return rootKey
}

private fun deriveChains(rootKey: ByteArray): Pair<ByteArray, ByteArray> {
    val initiatorToResponder = ByteArray(32)
    val hkdf1 = HKDFBytesGenerator(SHA256Digest())
    hkdf1.init(HKDFParameters(rootKey, "veil-session-chains-v1".toByteArray(Charsets.UTF_8), "chain-initiator-to-responder".toByteArray(Charsets.UTF_8)))
    hkdf1.generateBytes(initiatorToResponder, 0, 32)

    val responderToInitiator = ByteArray(32)
    val hkdf2 = HKDFBytesGenerator(SHA256Digest())
    hkdf2.init(HKDFParameters(rootKey, "veil-session-chains-v1".toByteArray(Charsets.UTF_8), "chain-responder-to-initiator".toByteArray(Charsets.UTF_8)))
    hkdf2.generateBytes(responderToInitiator, 0, 32)

    return Pair(initiatorToResponder, responderToInitiator)
}

/**
 * Alice's side: start a new session against Bob's fetched prekey bundle.
 * Returns the live [Session] (already has a usable send chain) plus the
 * [InitialMessage] to send as the first real message of the conversation.
 */
fun initiateSession(myIdentity: VeilIdentity, bundle: PrekeyBundle): Pair<Session, InitialMessage> {
    val responderIdentityX = X25519PublicKeyParameters(bundle.identityXPublic)
    val responderMediumTermX = X25519PublicKeyParameters(bundle.mediumTermXPublic)
    val responderMediumTermKem = MLKEMPublicKeyParameters(MLKEMParameters.ml_kem_768, bundle.mediumTermKemPublic)

    val ephemeralSecret = X25519PrivateKeyParameters(SecureRandom())
    val ephemeralPublic = ephemeralSecret.generatePublicKey()
    fun ephemeralDh(peer: X25519PublicKeyParameters): ByteArray {
        val out = ByteArray(X25519PrivateKeyParameters.SECRET_SIZE)
        ephemeralSecret.generateSecret(peer, out, 0)
        return out
    }

    val dh1 = myIdentity.diffieHellman(responderMediumTermX)
    val dh2 = ephemeralDh(responderIdentityX)
    val dh3 = ephemeralDh(responderMediumTermX)
    val dh4 = bundle.oneTimeXPublic?.let { ephemeralDh(X25519PublicKeyParameters(it)) }

    val encapsulated = MLKEMGenerator(SecureRandom()).generateEncapsulated(responderMediumTermKem)
    val kemSecret = encapsulated.secret
    val kemCiphertext = encapsulated.encapsulation

    val dhParts = mutableListOf(dh1, dh2, dh3)
    dh4?.let { dhParts.add(it) }
    val rootKey = deriveRootKey(dhParts, kemSecret)
    val (chainI2r, chainR2i) = deriveChains(rootKey)

    val session = Session(sendChainKey = chainI2r, sendCounter = 0, recvChainKey = chainR2i, recvCounter = 0)
    val initMsg = InitialMessage(
        initiatorIdentityXPublic = myIdentity.xPublic.encoded,
        initiatorEphemeralXPublic = ephemeralPublic.encoded,
        kemCiphertext = kemCiphertext,
        oneTimeXPublicUsed = bundle.oneTimeXPublic,
    )
    return Pair(session, initMsg)
}

/**
 * Bob's side: accept an incoming [InitialMessage]. If the initiator used a
 * one-time prekey, [myOneTimePrekeys] (keyed by its base64-encoded X25519
 * public bytes, as published) has the matching entry removed on success, so
 * it can never be reused even if the same [InitialMessage] is replayed.
 */
fun acceptSession(
    myIdentity: VeilIdentity,
    myMediumTerm: Prekey,
    myOneTimePrekeys: MutableMap<String, Prekey>,
    initMsg: InitialMessage,
): Session {
    val initiatorIdentityX = X25519PublicKeyParameters(initMsg.initiatorIdentityXPublic)
    val initiatorEphemeralX = X25519PublicKeyParameters(initMsg.initiatorEphemeralXPublic)

    val dh1 = myMediumTerm.diffieHellman(initiatorIdentityX)
    val dh2 = myIdentity.diffieHellman(initiatorEphemeralX)
    val dh3 = myMediumTerm.diffieHellman(initiatorEphemeralX)
    val dh4 = initMsg.oneTimeXPublicUsed?.let { otpkPub ->
        val otpk = myOneTimePrekeys.remove(b64(otpkPub)) ?: throw SessionException("one-time prekey already used, or never ours")
        otpk.diffieHellman(initiatorEphemeralX)
    }

    val kemSecret = MLKEMExtractor(myMediumTerm.kemPrivate).extractSecret(initMsg.kemCiphertext)

    val dhParts = mutableListOf(dh1, dh2, dh3)
    dh4?.let { dhParts.add(it) }
    val rootKey = deriveRootKey(dhParts, kemSecret)
    val (chainI2r, chainR2i) = deriveChains(rootKey)

    // Bob is the responder: HIS send chain is responder->initiator, and HIS
    // receive chain is initiator->responder — the mirror image of what
    // `initiateSession` set up for Alice, from the same two derived chains.
    return Session(sendChainKey = chainR2i, sendCounter = 0, recvChainKey = chainI2r, recvCounter = 0)
}
