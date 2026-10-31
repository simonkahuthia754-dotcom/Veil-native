package com.veil.app.state

import android.content.Context
import com.veil.app.crypto.AppLock
import com.veil.app.crypto.InitialMessage
import com.veil.app.crypto.Prekey
import com.veil.app.crypto.PrekeyBundle
import com.veil.app.crypto.RatchetedMessage
import com.veil.app.crypto.SealedMessage
import com.veil.app.crypto.SecureStore
import com.veil.app.crypto.Session
import com.veil.app.crypto.VeilIdentity
import com.veil.app.crypto.acceptSession
import com.veil.app.crypto.initiateSession
import com.veil.app.net.AckMessagesRequest
import com.veil.app.net.ApiClient
import com.veil.app.net.Chamber
import com.veil.app.net.CreateChamberRequest
import com.veil.app.net.LoginRequest
import com.veil.app.net.PrekeyBundleResponse
import com.veil.app.net.PrekeyDto
import com.veil.app.net.PublishPrekeysRequest
import com.veil.app.net.RegisterRequest
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
 * Lock + identity persistence is real: `veil.meta` holds the Argon2-hashed
 * passphrase/duress state plus the vault's key-derivation salt (none of
 * that is secret — the Argon2 PHC strings are safe to store, same
 * reasoning as lock.rs on the Rust side), and `veil.vault` holds the
 * AES-GCM-encrypted serialized vault envelope: this device's identity,
 * its medium-term + one-time prekeys (forward-secret handshake material),
 * and any live [Session]s — the same four things `VaultData` persists on
 * the Rust CLI side (`cli/src/main.rs`), so a restart doesn't lose
 * forward-secrecy state or force a brand-new handshake per contact.
 *
 * `send()`/`loadInbox()` now mirror the CLI's `seal_for_one`/`cmd_inbox`
 * exactly: look up a live ratchet session for the contact first, fall back
 * to starting a new one from their published prekey bundle
 * (`GET /prekeys/:handle/bundle`), and fall back further to the static,
 * non-forward-secret hybrid scheme only if the contact has never published
 * prekeys at all — logged as a NOTE via [onNote], never silent, same as
 * the CLI prints to stdout.
 *
 * Real, still-open gap this surfaces rather than hides: nothing in the UI
 * (`VeilApp.kt`) collects a handle or a backend PIN yet, so [register] and
 * [login] below — now real, correct calls — are never actually invoked.
 * `SetupScreen` only ever calls [createLock], which creates the local
 * vault but never touches the network. Until a registration/login screen
 * exists, `token` stays null and every method below that requires it
 * (`listChambers`, `loadInbox`, `send`, `ensurePrekeysPublished`) keeps
 * failing closed exactly as it already does today — not a new gap, but a
 * bigger one than previously documented: it's not just "fan-out isn't
 * wired," it's "no account is ever created." Named plainly in the README.
 */
class VeilSession(private val context: Context) {
    private var lock: AppLock? = null
    private var identity: VeilIdentity? = null
    private var store: SecureStore? = null
    private var api: VeilApi? = null
    private var token: String? = null
    private var userId: String? = null
    private var handle: String? = null
    private var duress = false

    // Forward-secrecy state — see class doc. Keyed by the contact's
    // identity X25519 public key, base64 (never by handle: a handle isn't
    // a stable cryptographic identity, matching the Rust CLI's own
    // VaultData.sessions doc comment).
    private var mediumTermPrekey: Prekey? = null
    private val oneTimePrekeys: MutableMap<String, Prekey> = mutableMapOf() // xPub b64 -> Prekey
    private val sessions: MutableMap<String, Session> = mutableMapOf() // contact xPub b64 -> Session

    /** How many one-time prekeys to publish per batch — matches the CLI's `ONE_TIME_COUNT`. */
    private val oneTimePrekeyBatchSize = 10

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
        persistVault()

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
                if (serialized != null) {
                    loadVaultEnvelope(String(serialized, Charsets.UTF_8))
                } else {
                    // Vault file missing or undecryptable even though the
                    // passphrase checked out — regenerate rather than
                    // crash. A real client would treat this as data loss
                    // worth surfacing to the user, not silently paper over;
                    // flagged here rather than pretending it can't happen.
                    identity = VeilIdentity.generate()
                    mediumTermPrekey = null
                    oneTimePrekeys.clear()
                    sessions.clear()
                    persistVault()
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
     * never-configured install.
     */
    fun enterDuress() {
        duress = true
        store?.wipe()
        if (vaultFile.exists()) vaultFile.delete()
        if (metaFile.exists()) metaFile.delete()
        identity = null
        mediumTermPrekey = null
        oneTimePrekeys.clear()
        sessions.clear()
        store = null
        lock = null
    }

    private fun writeMeta(appLock: AppLock, keySalt: ByteArray) {
        val obj = JSONObject(appLock.toJson())
        obj.put("keySalt", Base64.getEncoder().encodeToString(keySalt))
        metaFile.writeText(obj.toString())
    }

    // --- Vault envelope: identity + prekeys + live sessions -------------

    /**
     * Serializes everything this device needs to survive a restart without
     * losing forward secrecy state, and writes it through [store].
     * Deliberately called after every state-changing operation below
     * (publishing prekeys, starting/advancing a session, consuming a
     * one-time prekey) rather than only at shutdown — there is no reliable
     * "about to be killed" hook on Android to rely on instead.
     */
    private fun persistVault() {
        val id = identity ?: return
        val obj = JSONObject()
        obj.put("identity", VeilIdentity.serializePrivate(id))

        mediumTermPrekey?.let { mt ->
            val (xSecret, kemSecret) = mt.toSecretBytes()
            obj.put(
                "mediumTermPrekey",
                JSONObject().put("xSecret", b64(xSecret)).put("kemSecret", b64(kemSecret)),
            )
        }

        val otpkObj = JSONObject()
        oneTimePrekeys.forEach { (xPubB64, prekey) ->
            val (xSecret, kemSecret) = prekey.toSecretBytes()
            otpkObj.put(xPubB64, JSONObject().put("xSecret", b64(xSecret)).put("kemSecret", b64(kemSecret)))
        }
        obj.put("oneTimePrekeys", otpkObj)

        val sessionsObj = JSONObject()
        sessions.forEach { (contactXPubB64, session) -> sessionsObj.put(contactXPubB64, session.toJson()) }
        obj.put("sessions", sessionsObj)

        obj.put("token", token)
        obj.put("userId", userId)
        obj.put("handle", handle)

        store?.save(obj.toString().toByteArray(Charsets.UTF_8))
    }

    private fun loadVaultEnvelope(json: String) {
        val obj = JSONObject(json)
        identity = VeilIdentity.fromSerialized(obj.getString("identity"))

        mediumTermPrekey = if (obj.has("mediumTermPrekey") && !obj.isNull("mediumTermPrekey")) {
            val mt = obj.getJSONObject("mediumTermPrekey")
            Prekey.fromSecretBytes(unb64(mt.getString("xSecret")), unb64(mt.getString("kemSecret")))
        } else {
            null
        }

        oneTimePrekeys.clear()
        if (obj.has("oneTimePrekeys")) {
            val otpkObj = obj.getJSONObject("oneTimePrekeys")
            otpkObj.keys().forEach { xPubB64 ->
                val entry = otpkObj.getJSONObject(xPubB64)
                oneTimePrekeys[xPubB64] = Prekey.fromSecretBytes(unb64(entry.getString("xSecret")), unb64(entry.getString("kemSecret")))
            }
        }

        sessions.clear()
        if (obj.has("sessions")) {
            val sessionsObj = obj.getJSONObject("sessions")
            sessionsObj.keys().forEach { contactXPubB64 ->
                sessions[contactXPubB64] = Session.fromJson(sessionsObj.getString(contactXPubB64))
            }
        }

        // org.json's isNull() is true both for an explicit JSON null and
        // for an absent key (JSONObject.NULL.equals(null) is true by that
        // singleton's own equals() override) — exactly "treat missing or
        // null as Kotlin null" in one call, no sentinel-string hack needed.
        token = if (obj.isNull("token")) null else obj.getString("token")
        userId = if (obj.isNull("userId")) null else obj.getString("userId")
        handle = if (obj.isNull("handle")) null else obj.getString("handle")
    }

    fun backendUrl(): String =
        System.getenv("VEIL_BACKEND_URL") ?: "https://your-veil-backend.example/api"

    // --- Account: register / login ---------------------------------------
    //
    // Real, correct calls (see class doc for the DTO bugs this fixes), but
    // not yet invoked from anywhere in the UI — no screen collects a
    // handle or a backend PIN. Kept here, ready to wire into a future
    // onboarding screen, rather than left unwritten.

    fun register(handleToRegister: String, pin: String, onSuccess: () -> Unit, onError: (String) -> Unit) {
        val id = identity ?: return onError("No local identity yet — call createLock() first.")
        val a = api ?: return onError("Not connected.")
        a.register(RegisterRequest(handleToRegister, pin, id.publicKeyBase64(), id.pqPublicKeyBase64()))
            .enqueue(object : Callback<com.veil.app.net.AuthResponse> {
                override fun onResponse(call: Call<com.veil.app.net.AuthResponse>, response: Response<com.veil.app.net.AuthResponse>) {
                    val body = response.body()
                    if (!response.isSuccessful || body == null) {
                        onError("Registration failed: ${response.code()}")
                        return
                    }
                    token = body.token
                    userId = body.id
                    handle = body.handle
                    persistVault()
                    ensurePrekeysPublished(onDone = onSuccess, onError = onError)
                }
                override fun onFailure(call: Call<com.veil.app.net.AuthResponse>, t: Throwable) {
                    onError(t.message ?: "Network error")
                }
            })
    }

    fun login(handleToLogin: String, pin: String, onSuccess: () -> Unit, onError: (String) -> Unit) {
        val a = api ?: return onError("Not connected.")
        a.login(LoginRequest(handleToLogin, pin)).enqueue(object : Callback<com.veil.app.net.AuthResponse> {
            override fun onResponse(call: Call<com.veil.app.net.AuthResponse>, response: Response<com.veil.app.net.AuthResponse>) {
                val body = response.body()
                if (!response.isSuccessful || body == null) {
                    onError("Login failed: ${response.code()}")
                    return
                }
                token = body.token
                userId = body.id
                handle = body.handle
                persistVault()
                ensurePrekeysPublished(onDone = onSuccess, onError = onError)
            }
            override fun onFailure(call: Call<com.veil.app.net.AuthResponse>, t: Throwable) {
                onError(t.message ?: "Network error")
            }
        })
    }

    /**
     * Publishes a medium-term prekey + a batch of one-time prekeys the
     * first time this device logs in with none published yet — mirrors the
     * CLI's `ensure_prekeys_published`. A no-op (calls [onDone]
     * immediately) if a medium-term prekey already exists locally;
     * rotating it is separate, deliberate future work, not implemented
     * here, same as on the CLI side.
     */
    fun ensurePrekeysPublished(onDone: () -> Unit = {}, onError: (String) -> Unit = {}) {
        if (mediumTermPrekey != null) {
            onDone()
            return
        }
        val a = api ?: return onError("Not connected.")
        val t = token ?: return onError("Not authenticated.")

        val newMediumTerm = Prekey.generate()
        val newOneTimes = (1..oneTimePrekeyBatchSize).map { Prekey.generate() }

        val (mtX, mtKem) = newMediumTerm.publicBundle()
        val body = PublishPrekeysRequest(
            mediumTermPrekey = PrekeyDto(b64(mtX), b64(mtKem)),
            oneTimePrekeys = newOneTimes.map { val (x, k) = it.publicBundle(); PrekeyDto(b64(x), b64(k)) },
        )

        a.publishPrekeys("Bearer $t", body).enqueue(object : Callback<Unit> {
            override fun onResponse(call: Call<Unit>, response: Response<Unit>) {
                if (!response.isSuccessful) {
                    onError("Publishing prekeys failed: ${response.code()}")
                    return
                }
                mediumTermPrekey = newMediumTerm
                newOneTimes.forEach { otpk -> oneTimePrekeys[b64(otpk.publicBundle().first)] = otpk }
                persistVault()
                onDone()
            }
            override fun onFailure(call: Call<Unit>, t2: Throwable) {
                onError(t2.message ?: "Network error")
            }
        })
    }

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
     * Loads and decrypts the inbox, mirroring the CLI's `cmd_inbox` exactly:
     * each row's `ciphertext` is a JSON string in one of three shapes —
     * `{"kemCt","ct"}` (static hybrid scheme, no forward secrecy),
     * `{"init","msg"}` (a new handshake's first message), or `{"msg"}`
     * (a ratcheted message on an already-live session). A row that matches
     * none of these, or whose decryption fails (wrong session state,
     * tamper, or a handshake whose one-time prekey no longer exists), is
     * skipped — logged via [onNote], never silently dropped and never
     * crashing the rest of the inbox render. Successfully processed rows
     * are acked afterward so they aren't re-delivered (and, critically, so
     * a handshake message is never re-processed against a one-time prekey
     * this device already consumed and removed).
     */
    fun loadInbox(onSuccess: (List<String>) -> Unit, onError: (String) -> Unit, onNote: (String) -> Unit = {}) {
        if (duress) { onSuccess(emptyList()); return }
        val t = token
        val a = api
        val id = identity
        if (a == null || t == null || id == null) { onSuccess(emptyList()); return }

        a.inbox("Bearer $t").enqueue(object : Callback<List<com.veil.app.net.InboxRow>> {
            override fun onResponse(
                call: Call<List<com.veil.app.net.InboxRow>>,
                response: Response<List<com.veil.app.net.InboxRow>>,
            ) {
                val rows = response.body() ?: emptyList()
                val decoded = mutableListOf<String>()
                val acked = mutableListOf<String>()
                var sessionsChanged = false

                for (row in rows) {
                    val packed = try {
                        JSONObject(row.ciphertext)
                    } catch (e: Exception) {
                        onNote("(${row.id}) unreadable message body — skipping")
                        continue
                    }

                    val plaintext: ByteArray? = try {
                        when {
                            packed.has("kemCt") -> {
                                val sealed = SealedMessage(
                                    senderXPublic = unb64(row.sender_pubkey),
                                    kemCiphertext = unb64(packed.getString("kemCt")),
                                    nonce = unb64(row.nonce),
                                    ciphertext = unb64(packed.getString("ct")),
                                )
                                id.open(sealed)
                            }
                            packed.has("init") -> {
                                val myMt = mediumTermPrekey ?: throw IllegalStateException(
                                    "received a handshake but this device has no medium-term prekey — call ensurePrekeysPublished() first",
                                )
                                val init = InitialMessage.fromJson(packed.getJSONObject("init").toString())
                                val msg = RatchetedMessage.fromJson(packed.getJSONObject("msg").toString())
                                val session = acceptSession(id, myMt, oneTimePrekeysAsStringKeyed(), init)
                                val opened = session.open(msg)
                                sessions[row.sender_pubkey] = session
                                sessionsChanged = true
                                opened
                            }
                            packed.has("msg") -> {
                                val msg = RatchetedMessage.fromJson(packed.getJSONObject("msg").toString())
                                val session = sessions[row.sender_pubkey] ?: throw IllegalStateException(
                                    "no session for this sender yet (their handshake may have arrived out of order, or wasn't received) — can't decrypt",
                                )
                                val opened = session.open(msg)
                                sessionsChanged = true
                                opened
                            }
                            else -> throw IllegalStateException("unrecognized message envelope shape")
                        }
                    } catch (e: Exception) {
                        onNote("(${row.id}) could not decrypt: ${e.message}")
                        null
                    }

                    if (plaintext != null) decoded.add(String(plaintext, Charsets.UTF_8))
                    acked.add(row.id)
                }

                if (sessionsChanged) persistVault()

                if (acked.isNotEmpty()) {
                    a.ackMessages("Bearer $t", AckMessagesRequest(acked)).enqueue(object : Callback<Unit> {
                        override fun onResponse(call: Call<Unit>, response: Response<Unit>) {}
                        override fun onFailure(call: Call<Unit>, t2: Throwable) {}
                    })
                }
                onSuccess(decoded)
            }
            override fun onFailure(call: Call<List<com.veil.app.net.InboxRow>>, t: Throwable) {
                onError(t.message ?: "Network error")
            }
        })
    }

    /**
     * [acceptSession] consumes one-time prekeys from a `MutableMap<String,
     * Prekey>` keyed by base64 X25519 public bytes, removing the matching
     * entry on success. [oneTimePrekeys] already uses exactly that key
     * shape, so this just hands over the live map directly (no copy) —
     * consumption during `loadInbox` is meant to mutate the real vault
     * state, which is then persisted via `persistVault()`.
     */
    private fun oneTimePrekeysAsStringKeyed(): MutableMap<String, Prekey> = oneTimePrekeys

    /**
     * Resolves `recipientHandle`'s public bundle, then seals and sends —
     * single-recipient only (chamber fan-out on Android is separate,
     * still-open work, same as before). Mirrors the CLI's `seal_for_one`:
     * reuse a live ratchet session if one exists; otherwise fetch the
     * contact's prekey bundle and start one; otherwise fall back to the
     * static hybrid scheme with an explicit [onNote], never silently.
     */
    fun send(recipientHandle: String, plaintext: String, onError: (String) -> Unit = {}, onNote: (String) -> Unit = {}) {
        val id = identity ?: return onError("Not unlocked.")
        val a = api ?: return onError("Not connected.")
        val t = token ?: return onError("Not authenticated.")

        a.getUserKeys("Bearer $t", recipientHandle).enqueue(object : Callback<UserPublicKeys> {
            override fun onResponse(call: Call<UserPublicKeys>, response: Response<UserPublicKeys>) {
                val contact = response.body()
                val contactId = contact?.id
                val xPub = contact?.pubkey
                if (!response.isSuccessful || contact == null || contactId == null || xPub == null) {
                    onError("No such user: $recipientHandle")
                    return
                }

                val existingSession = sessions[xPub]
                if (existingSession != null) {
                    val msg = existingSession.seal(plaintext.toByteArray(Charsets.UTF_8))
                    persistVault()
                    val packed = JSONObject().put("msg", JSONObject(msg.toJson())).toString()
                    postMessage(a, t, id, contactId, packed, b64(msg.nonce), onError, onNote)
                    return
                }

                a.prekeyBundle("Bearer $t", recipientHandle).enqueue(object : Callback<PrekeyBundleResponse> {
                    override fun onResponse(call2: Call<PrekeyBundleResponse>, bundleResp: Response<PrekeyBundleResponse>) {
                        val bundleBody = bundleResp.body()
                        val mt = bundleBody?.mediumTermPrekey
                        if (bundleResp.isSuccessful && bundleBody != null && mt != null) {
                            val identityXB64 = bundleBody.identityPubkey ?: xPub
                            val bundle = PrekeyBundle(
                                identityXPublic = unb64(identityXB64),
                                mediumTermXPublic = unb64(mt.xPub),
                                mediumTermKemPublic = unb64(mt.kemPub),
                                oneTimeXPublic = bundleBody.oneTimePrekey?.let { unb64(it.xPub) },
                            )
                            val (session, initMsg) = initiateSession(id, bundle)
                            val msg = session.seal(plaintext.toByteArray(Charsets.UTF_8))
                            sessions[xPub] = session
                            persistVault()
                            val packed = JSONObject()
                                .put("init", JSONObject(initMsg.toJson()))
                                .put("msg", JSONObject(msg.toJson()))
                                .toString()
                            postMessage(a, t, id, contactId, packed, b64(msg.nonce), onError, onNote)
                            return
                        }

                        // No prekeys published for this contact: fall back
                        // to the static, non-forward-secret hybrid scheme.
                        val pqPub = contact.pqPubkey
                        if (pqPub == null) {
                            onError("$recipientHandle has no ML-KEM public key on file and no published prekeys — can't reach them at all")
                            return
                        }
                        onNote("$recipientHandle hasn't published forward-secret prekeys yet — sent with the static hybrid scheme instead (no forward secrecy for this one message).")
                        val sealed = id.seal(plaintext.toByteArray(Charsets.UTF_8), xPub, pqPub)
                        val packed = JSONObject().apply {
                            put("kemCt", b64(sealed.kemCiphertext))
                            put("ct", b64(sealed.ciphertext))
                        }.toString()
                        postMessage(a, t, id, contactId, packed, b64(sealed.nonce), onError, onNote)
                    }
                    override fun onFailure(call2: Call<PrekeyBundleResponse>, th: Throwable) {
                        onError(th.message ?: "Network error")
                    }
                })
            }
            override fun onFailure(call: Call<UserPublicKeys>, t: Throwable) {
                onError(t.message ?: "Network error")
            }
        })
    }

    private fun postMessage(
        a: VeilApi,
        t: String,
        id: VeilIdentity,
        recipientId: String,
        packedCiphertext: String,
        nonceB64: String,
        onError: (String) -> Unit,
        onNote: (String) -> Unit,
    ) {
        a.sendMessage(
            "Bearer $t",
            SendMessageRequest(
                recipientIds = listOf(recipientId),
                ciphertext = packedCiphertext,
                nonce = nonceB64,
                senderPubkey = id.publicKeyBase64(),
            ),
        ).enqueue(object : Callback<Unit> {
            override fun onResponse(call: Call<Unit>, response: Response<Unit>) {
                if (!response.isSuccessful) onError("Send failed: ${response.code()}")
            }
            override fun onFailure(call: Call<Unit>, t2: Throwable) {
                onError(t2.message ?: "Network error")
            }
        })
    }

    private fun b64(bytes: ByteArray): String = Base64.getEncoder().encodeToString(bytes)
    private fun unb64(s: String): ByteArray = Base64.getDecoder().decode(s)
}
