package com.veil.app.crypto

import com.lambdapioneer.argon2kt.Argon2Kt
import com.lambdapioneer.argon2kt.Argon2Mode
import java.io.File
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

/**
 * Single encrypted-file-at-rest store, deliberately parallel to the Rust
 * CLI's `storage.rs`: same file layout (`[16-byte salt][12-byte
 * nonce][ciphertext]`, AES-256-GCM here vs XChaCha20-Poly1305 there — both
 * are AEADs with no known practical breaks; the difference is Android's
 * platform JCE vs a pure-Rust crate, not a security downgrade), same
 * Argon2id key derivation, same caveat: this encrypts Veil's own vault
 * file (identity keys, cached chamber state). It is NOT SQLCipher, for the
 * same reason stated in storage.rs — avoiding a native-toolchain
 * dependency that complicates CI across Rust and Android in the same repo.
 *
 * `wipe()` overwrites then deletes; on flash storage with wear-leveling
 * this is best-effort, not a forensic guarantee — the same honest caveat
 * storage.rs carries, not a weaker one.
 */
class SecureStore private constructor(
    private val file: File,
    private val key: ByteArray,
) {
    fun save(plaintext: ByteArray) {
        val salt = ByteArray(16).also { SecureRandom().nextBytes(it) }
        val nonce = ByteArray(12).also { SecureRandom().nextBytes(it) }
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(key, "AES"), GCMParameterSpec(128, nonce))
        val ct = cipher.doFinal(plaintext)
        file.writeBytes(salt + nonce + ct)
    }

    fun load(): ByteArray? {
        if (!file.exists()) return null
        val bytes = file.readBytes()
        if (bytes.size < 28) return null
        val nonce = bytes.copyOfRange(16, 28)
        val ct = bytes.copyOfRange(28, bytes.size)
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.DECRYPT_MODE, SecretKeySpec(key, "AES"), GCMParameterSpec(128, nonce))
        return cipher.doFinal(ct)
    }

    /** Best-effort overwrite-then-delete. See class doc for the forensic caveat. */
    fun wipe() {
        if (file.exists()) {
            val len = file.length()
            file.writeBytes(ByteArray(len.toInt()) { 0 })
            file.delete()
        }
    }

    companion object {
        private val argon2 = Argon2Kt()

        /** Derives the file key from the already-unlocked passphrase. Call only after AppLock.attempt() == Unlocked. */
        fun open(vaultFile: File, passphrase: String, keySalt: ByteArray): SecureStore {
            val key = argon2.hash(
                Argon2Mode.ARGON2_ID,
                passphrase.toByteArray(Charsets.UTF_8),
                keySalt,
                3, 65536, 4,
            ).rawHashAsByteArray().copyOf(32) // AES-256 key
            return SecureStore(vaultFile, key)
        }
    }
}
