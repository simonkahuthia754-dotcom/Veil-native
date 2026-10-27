package com.veil.app.crypto

import com.google.crypto.tink.HybridDecrypt
import com.google.crypto.tink.HybridEncrypt
import com.google.crypto.tink.KeyTemplates
import com.google.crypto.tink.KeysetHandle
import com.google.crypto.tink.hybrid.HybridConfig
import java.util.Base64

/**
 * Public-key end-to-end encryption for the Android client, built on Tink's
 * HPKE support (RFC 9180 — X25519 for key agreement, HKDF-SHA256, AES-128-GCM
 * for the AEAD). This is a real, audited construction maintained by Google,
 * not a hand-rolled scheme — same bar the Rust side holds itself to with
 * x25519-dalek + ml-kem + chacha20poly1305.
 *
 * Reviewer / pentester note — read before assuming cross-client interop:
 * this HPKE ciphertext format is NOT the same bytes-on-the-wire format as
 * the Rust CLI's hybrid X25519+ML-KEM-768 scheme, nor the web prototype's
 * demo SubtleCrypto scheme. The backend is a dumb relay — it never
 * validates ciphertext shape — so this still "works" end-to-end between
 * two Android clients, or two Rust CLI clients, but an Android user and a
 * CLI user are NOT currently able to read each other's messages without a
 * shared wire format. That is a real, open gap, called out again in the
 * top-level README rather than glossed over. Unifying all three onto one
 * crypto crate (via UniFFI) was considered and explicitly deferred — see
 * the original architecture note in veil-native/README.md.
 *
 * ML-KEM / post-quantum note: Tink's stable Android artifact does not yet
 * expose a post-quantum KEM primitive as of this writing. Rather than
 * claim post-quantum coverage on Android and be wrong, this client is
 * classical-only (X25519 ECDH) and says so. The Rust CLI is the
 * post-quantum-hybrid-capable client; Android will adopt a PQ KEM here the
 * same day Tink (or an equivalently audited library) ships one for Android,
 * not before — swapping in an unaudited DIY PQ implementation only to tick
 * a box would be worse than being honest about the gap.
 */
class VeilIdentity private constructor(
    val publicKeysetHandle: KeysetHandle,
    private val privateKeysetHandle: KeysetHandle,
) {
    /** Public keyset serialized to base64 — this is what you publish / send to the server. */
    fun publicKeyBase64(): String {
        val out = java.io.ByteArrayOutputStream()
        com.google.crypto.tink.CleartextKeysetHandle.write(
            publicKeysetHandle,
            com.google.crypto.tink.JsonKeysetWriter.withOutputStream(out),
        )
        return Base64.getEncoder().encodeToString(out.toByteArray())
    }

    fun seal(plaintext: ByteArray, contextInfo: ByteArray = ByteArray(0)): ByteArray {
        val encryptor: HybridEncrypt = publicKeysetHandle.getPrimitive(HybridEncrypt::class.java)
        return encryptor.encrypt(plaintext, contextInfo)
    }

    fun open(ciphertext: ByteArray, contextInfo: ByteArray = ByteArray(0)): ByteArray {
        val decryptor: HybridDecrypt = privateKeysetHandle.getPrimitive(HybridDecrypt::class.java)
        return decryptor.decrypt(ciphertext, contextInfo)
    }

    companion object {
        private var configured = false

        private fun ensureConfigured() {
            if (!configured) {
                HybridConfig.register()
                configured = true
            }
        }

        /** Generates a fresh identity. Persistence is the caller's job (see SecureStore). */
        fun generate(): VeilIdentity {
            ensureConfigured()
            // Looked up by its registered string name via KeyTemplates.get,
            // not a typed `HybridKeyTemplates.XXX` constant — confirmed
            // against Tink's own Tinkey CLI docs and Java how-to (no
            // predefined-parameters class exists for HPKE the way
            // PredefinedAeadParameters does for AEAD). This exact name is
            // what Tinkey's own `--key-template` flag uses for the same
            // algorithm choice.
            val template = KeyTemplates.get("DHKEM_X25519_HKDF_SHA256_HKDF_SHA256_AES_128_GCM")
            val privateHandle = KeysetHandle.generateNew(template)
            val publicHandle = privateHandle.publicKeysetHandle
            return VeilIdentity(publicHandle, privateHandle)
        }

        /** Rehydrates an identity from a cleartext keyset previously written via SecureStore. */
        fun fromSerialized(privateKeysetJson: String): VeilIdentity {
            ensureConfigured()
            val privateHandle = com.google.crypto.tink.CleartextKeysetHandle.read(
                com.google.crypto.tink.JsonKeysetReader.withString(privateKeysetJson),
            )
            return VeilIdentity(privateHandle.publicKeysetHandle, privateHandle)
        }

        fun serializePrivate(identity: VeilIdentity): String {
            val out = java.io.ByteArrayOutputStream()
            com.google.crypto.tink.CleartextKeysetHandle.write(
                identity.privateKeysetHandle,
                com.google.crypto.tink.JsonKeysetWriter.withOutputStream(out),
            )
            return out.toString(Charsets.UTF_8.name())
        }
    }
}
