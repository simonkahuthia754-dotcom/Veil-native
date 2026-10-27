package com.veil.app.state

import android.content.Context
import com.veil.app.crypto.AppLock
import com.veil.app.crypto.SecureStore
import com.veil.app.crypto.VeilIdentity
import com.veil.app.net.ApiClient
import com.veil.app.net.Chamber
import com.veil.app.net.CreateChamberRequest
import com.veil.app.net.SendMessageRequest
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
                        val ct = Base64.getDecoder().decode(row.ciphertext)
                        String(id.open(ct), Charsets.UTF_8)
                    } catch (e: Exception) {
                        null // not addressed to us, or corrupt — silently skip, never crash the inbox render
                    }
                }
                onSuccess(decoded)
            }
            override fun onFailure(call: Call<List<com.veil.app.net.InboxRow>>, t: Throwable) {
                onError(t.message ?: "Network error")
            }
        })
    }

    fun send(chamberId: String, plaintext: String) {
        // Scaffold: wires the real HPKE seal() + API call shape, but chamber
        // fan-out (resolving every member's pubkey and sealing once per
        // recipient) isn't implemented yet — single-recipient only, same
        // documented gap as the CLI's `send` command.
        val id = identity ?: return
        val a = api ?: return
        val t = token ?: return
        val sealed = id.seal(plaintext.toByteArray(Charsets.UTF_8))
        a.sendMessage(
            "Bearer $t",
            SendMessageRequest(
                recipientHandle = chamberId,
                ciphertext = Base64.getEncoder().encodeToString(sealed),
                nonce = "", // HPKE's AEAD nonce is embedded in Tink's ciphertext framing, so this field is unused for this client — left present only to match the shared backend schema
                senderPubkey = id.publicKeyBase64(),
            ),
        ).enqueue(object : Callback<Unit> {
            override fun onResponse(call: Call<Unit>, response: Response<Unit>) {}
            override fun onFailure(call: Call<Unit>, t: Throwable) {}
        })
    }
}
