package com.veil.app.state

import android.content.Context
import com.veil.app.crypto.AppLock
import com.veil.app.crypto.SealedMessage
import com.veil.app.crypto.SecureStore
import com.veil.app.crypto.VeilIdentity
import com.veil.app.net.ApiClient
import com.veil.app.net.Chamber
import com.veil.app.net.CreateChamberRequest
import com.veil.app.net.SendMessageRequest
import com.veil.app.net.UserPublicKeys
import com.veil.app.net.VeilApi
import org.json.JSONObject
import retrofit2.Call
import retrofit2.Callback
import retrofit2.Response
import java.io.File
import java.util.Base64

/**
 * Thin, explicit session/state holder — deliberately NOT a ViewModel
 * framework-heavy abstraction for this scaffold, so a reviewer can read the
 * whole lifecycle (lock → identity → network) in one file without chasing
 * DI wiring. A production hardening pass would move this behind
 * `ViewModel` + `SavedStateHandle` and inject `backendUrl`/`socksProxy`
 * from a settings screen instead of the hardcoded defaults below.
 *
 * Lock + identity persistence (the README's top "Next milestone" item) is
 * now real: `veil.meta` holds the Argon2-hashed passphrase/duress state
 * plus the vault's key-derivation salt (none of that is secret — the
 * Argon2 PHC strings are safe to store, same reasoning as lock.rs on the
 * Rust side), and `veil.vault` holds the AES-GCM-encrypted serialized
 * identity keyset. `unlock()` now actually checks the passphrase against
 * what was persisted at `createLock()` time, instead of always succeeding.
 */
class VeilSession(private val context: Context) {
    private var lock: AppLock? = null
    private var identity: VeilIdentity? = null
    private var store: SecureStore? = null
    private var api: VeilApi? = null
    private var token: String? = null
    private var duress = false

    private val vaultFile: File get() = File(context.filesDir, "veil.vault")
    private val metaFile: File get() = File(context.filesDir, "veil.meta")

    fun isLockSet(): Boolean = metaFile.exists()

    fun createLock(passphrase: String) {
        val newLock = AppLock.create(passphrase)
        val keySalt = SecureStore.newSalt()
        writeMeta(newLock, keySalt)
        lock = newLock

        val newStore = SecureStore.open(vaultFile, passphrase, keySalt)
        store = newStore
        val newIdentity = VeilIdentity.generate()
        identity = newIdentity
        newStore.save(VeilIdentity.serializePrivate(newIdentity).toByteArray(Charsets.UTF_8))

        api = ApiClient.build(backendUrl())
    }

    fun unlock(passphrase: String): AppLock.Verdict {
        if (!metaFile.exists()) {
            // Shouldn't happen if the UI gates on isLockSet() first, but
            // fail closed rather than silently unlocking.
            return AppLock.Verdict.WrongPassphrase(0)
        }
        val metaJson = metaFile.readText()
        val metaObj = JSONObject(metaJson)
        val keySaltB64 = metaObj.getString("keySalt")
        val keySalt = Base64.getDecoder().decode(keySaltB64)
        val loadedLock = AppLock.fromJson(metaJson)

        val verdict = loadedLock.attempt(passphrase, System.currentTimeMillis())
        // Persist updated fail-count/lockout state on every attempt —
        // right or wrong — so a lockout survives the app being killed and
        // restarted between guesses, closing the gap a purely in-memory
        // fail counter would leave open.
        writeMeta(loadedLock, keySalt)

        when (verdict) {
            is AppLock.Verdict.Unlocked -> {
                lock = loadedLock
                val newStore = SecureStore.open(vaultFile, passphrase, keySalt)
                store = newStore
                val serialized = newStore.load()
                identity = if (serialized != null) {
                    VeilIdentity.fromSerialized(String(serialized, Charsets.UTF_8))
                } else {
                    // Vault file missing or undecryptable even though the
                    // passphrase checked out — regenerate rather than
                    // crash. A real client would treat this as data loss
                    // worth surfacing to the user, not silently paper over;
                    // flagged here rather than pretending it can't happen.
                    VeilIdentity.generate()
                }
                api = ApiClient.build(backendUrl())
                duress = false
            }
            is AppLock.Verdict.Duress -> {
                // Caller is expected to call enterDuress() next, which does
                // the actual wipe — this class never wipes on its own
                // initiative from inside attempt()'s result handling, same
                // separation-of-concerns lock.rs documents on the Rust side.
            }
            else -> {}
        }
        return verdict
    }

    /**
     * Real duress handling: wipes both the encrypted vault and the lock
     * metadata itself, so the app reverts to looking like a fresh,
     * never-configured install — not just an in-memory flag that still
     * left the real encrypted data sitting on disk, which is what this
     * method used to do.
     */
    fun enterDuress() {
        duress = true
        store?.wipe()
        if (vaultFile.exists()) vaultFile.delete()
        if (metaFile.exists()) metaFile.delete()
        identity = null
        store = null
        lock = null
    }

    private fun writeMeta(appLock: AppLock, keySalt: ByteArray) {
        val obj = JSONObject(appLock.toJson())
        obj.put("keySalt", Base64.getEncoder().encodeToString(keySalt))
        metaFile.writeText(obj.toString())
    }

    fun backendUrl(): String =
        System.getenv("VEIL_BACKEND_URL") ?: "https://your-veil-backend.example/api"

    fun listChambers(onSuccess: (List<Chamber>) -> Unit, onError: (String) -> Unit) {
        if (duress) { onSuccess(emptyList()); return }
        val t = token
        val a = api
        if (a == null) { onError("Not connected."); return }
        if (t == null) { onSuccess(emptyList()); return }
        a.chambers("Bearer $t").enqueue(object : Callback<List<Chamber>> {
            override fun onResponse(call: Call<List<Chamber>>, response: Response<List<Chamber>>) {
                if (response.isSuccessful) onSuccess(response.body() ?: emptyList())
                else onError("Server error: ${response.code()}")
            }
            override fun onFailure(call: Call<List<Chamber>>, t: Throwable) {
                onError(t.message ?: "Network error")
            }
        })
    }

    /**
     * Inbox rows carry `ciphertext` as a JSON string of `{"kemCt":...,
     * "ct":...}` (base64 each) — NOT a bare ciphertext blob. This matches
     * the CLI's own packing in `cmd_send`/`cmd_inbox` (cli/src/main.rs):
     * the backend's `/messages` route was built against the web
     * prototype's simpler crypto_box-only scheme (one ciphertext field,
     * one nonce field), so a hybrid-aware client packs its extra KEM
     * ciphertext into the same string field, delimited, rather than
     * waiting on a backend schema change. A row whose `ciphertext` isn't
     * valid JSON in that shape is a message from a non-hybrid sender (the
     * web prototype) and is skipped — same as the CLI does, not an error.
     */
    fun loadInbox(onSuccess: (List<String>) -> Unit, onError: (String) -> Unit) {
        if (duress) { onSuccess(emptyList()); return }
        val t = token
        val a = api
        if (a == null || t == null) { onSuccess(emptyList()); return }
        a.inbox("Bearer $t").enqueue(object : Callback<List<com.veil.app.net.InboxRow>> {
            override fun onResponse(
                call: Call<List<com.veil.app.net.InboxRow>>,
                response: Response<List<com.veil.app.net.InboxRow>>,
            ) {
                val rows = response.body() ?: emptyList()
                val id = identity ?: return
                val decoded = rows.mapNotNull { row ->
                    try {
                        val packed = JSONObject(row.ciphertext)
                        val kemCt = Base64.getDecoder().decode(packed.getString("kemCt"))
                        val ct = Base64.getDecoder().decode(packed.getString("ct"))
                        val sealed = SealedMessage(
                            senderXPublic = Base64.getDecoder().decode(row.sender_pubkey),
                            kemCiphertext = kemCt,
                            nonce = Base64.getDecoder().decode(row.nonce),
                            ciphertext = ct,
                        )
                        String(id.open(sealed), Charsets.UTF_8)
                    } catch (e: Exception) {
                        // Not a hybrid-packed message (likely the web
                        // prototype's simpler scheme), not addressed to us,
                        // or corrupt — silently skip, never crash the inbox
                        // render on one bad row.
                        null
                    }
                }
                onSuccess(decoded)
            }
            override fun onFailure(call: Call<List<com.veil.app.net.InboxRow>>, t: Throwable) {
                onError(t.message ?: "Network error")
            }
        })
    }

    /**
     * Resolves `recipientHandle`'s public bundle, then seals and sends.
     * Chamber fan-out (resolving every member's pubkey and sealing once
     * per recipient) isn't implemented yet — single-recipient only, same
     * documented gap as the CLI's `send` command — so `recipientHandle`
     * must be a user handle, not yet a real chamber ID with multiple
     * members.
     *
     * Known gap this surfaces rather than hides: nothing in this client
     * currently calls `VeilApi.register()`, so a fresh identity's
     * X25519/ML-KEM-768 public keys are never actually published to the
     * backend — `getUserKeys()` below will 404/come back without a
     * `pqPubkey` for any user who hasn't registered through some other
     * path (e.g. the CLI). Wiring registration into the lock-creation flow
     * is a separate, still-open task, not silently assumed done here.
     */
    fun send(recipientHandle: String, plaintext: String, onError: (String) -> Unit = {}) {
        val id = identity ?: return onError("Not unlocked.")
        val a = api ?: return onError("Not connected.")
        val t = token ?: return onError("Not authenticated.")

        a.getUserKeys("Bearer $t", recipientHandle).enqueue(object : Callback<UserPublicKeys> {
            override fun onResponse(call: Call<UserPublicKeys>, response: Response<UserPublicKeys>) {
                val contact = response.body()
                val xPub = contact?.pubkey
                val pqPub = contact?.pqPubkey
                if (!response.isSuccessful || contact == null || xPub == null) {
                    onError("No such user: $recipientHandle")
                    return
                }
                if (pqPub == null) {
                    onError(
                        "$recipientHandle has no ML-KEM public key on file (registered from " +
                            "a non-hybrid client) — can't do a hybrid seal to them.",
                    )
                    return
                }

                val sealed = id.seal(plaintext.toByteArray(Charsets.UTF_8), xPub, pqPub)
                val packed = JSONObject().apply {
                    put("kemCt", Base64.getEncoder().encodeToString(sealed.kemCiphertext))
                    put("ct", Base64.getEncoder().encodeToString(sealed.ciphertext))
                }.toString()

                a.sendMessage(
                    "Bearer $t",
                    SendMessageRequest(
                        recipientHandle = recipientHandle,
                        ciphertext = packed,
                        nonce = Base64.getEncoder().encodeToString(sealed.nonce),
                        senderPubkey = Base64.getEncoder().encodeToString(sealed.senderXPublic),
                    ),
                ).enqueue(object : Callback<Unit> {
                    override fun onResponse(call: Call<Unit>, response: Response<Unit>) {
                        if (!response.isSuccessful) onError("Send failed: ${response.code()}")
                    }
                    override fun onFailure(call: Call<Unit>, t: Throwable) {
                        onError(t.message ?: "Network error")
                    }
                })
            }
            override fun onFailure(call: Call<UserPublicKeys>, t: Throwable) {
                onError(t.message ?: "Network error")
            }
        })
    }
}
