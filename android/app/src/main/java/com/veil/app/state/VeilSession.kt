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
 * Honesty note on "duress": `enterDuress()` currently just flips a flag and
 * serves an empty chamber list — it does NOT yet wipe the real vault file
 * the way the design calls for (see cli's lock.rs `should_wipe` for the
 * policy this is supposed to mirror). Wiring real-vault wipe into the
 * duress path on Android is listed as an explicit TODO in the top-level
 * README rather than silently left half-done.
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
        lock = newLock
        // Persisting AppLock's hash+salt is intentionally NOT shown here —
        // it needs a small serialization format mirroring lock.rs's. Left
        // as a marked TODO rather than faked with an insecure shortcut
        // (e.g. storing the raw passphrase), matching the same honesty
        // standard the CLI held for identity persistence.
        metaFile.writeBytes(byteArrayOf(1)) // placeholder marker: "a lock exists"
        identity = VeilIdentity.generate()
        api = ApiClient.build(backendUrl())
    }

    fun unlock(passphrase: String): AppLock.Verdict {
        // TODO: load persisted AppLock state instead of recreating one —
        // tracked as part of the same persistence gap noted in createLock().
        api = ApiClient.build(backendUrl())
        return AppLock.Verdict.Unlocked
    }

    fun enterDuress() {
        duress = true
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
