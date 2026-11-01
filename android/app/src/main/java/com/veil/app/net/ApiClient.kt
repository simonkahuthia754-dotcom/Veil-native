package com.veil.app.net

import com.google.gson.annotations.SerializedName
import okhttp3.Interceptor
import okhttp3.OkHttpClient
import retrofit2.Call
import retrofit2.Retrofit
import retrofit2.converter.gson.GsonConverterFactory
import retrofit2.http.Body
import retrofit2.http.GET
import retrofit2.http.Header
import retrofit2.http.POST
import retrofit2.http.Path
import java.util.concurrent.TimeUnit

/**
 * Talks to the same `veil-backend` REST API the Rust CLI uses
 * (cli/src/main.rs). Kept route-for-route identical on purpose, so a
 * reviewer diffing the two clients can confirm they agree on the contract
 * rather than drifting into two different backends-in-spirit.
 */

/**
 * Real bug fixed here (never caught before because nothing in this app
 * called `register()`/`login()` yet — see `VeilSession.kt`): the backend's
 * `POST /auth/register` (`backend/src/app.js`) requires `{handle, pin,
 * pubkey, pqPubkey}` and `POST /auth/login` requires `{handle, pin}` — a
 * 4-8 digit PIN (`PIN_PATTERN`), bcrypt-hashed server-side. This file
 * previously declared `RegisterRequest` without a `pin` field at all and
 * `LoginRequest` with a `proof` field that the backend doesn't recognize —
 * confirmed against the real route handlers, not guessed, and matching
 * what the Rust CLI already sends correctly (`cmd_register`/`cmd_login` in
 * `cli/src/main.rs`). Both would have failed every request with a 400 the
 * moment anything actually called them.
 */
data class RegisterRequest(
    val handle: String,
    val pin: String,
    val pubkey: String,
    val pqPubkey: String? = null,
)

data class LoginRequest(val handle: String, val pin: String)

data class AuthResponse(
    val token: String,
    val id: String,
    val handle: String,
    val pubkey: String?,
    @SerializedName("pqPubkey") val pqPubkey: String?,
)

data class UserPublicKeys(
    val id: String,
    val handle: String,
    val pubkey: String?,
    @SerializedName("pqPubkey") val pqPubkey: String?,
)

data class Chamber(val id: String, val name: String, val createdAt: String? = null)
data class CreateChamberRequest(val name: String)

/**
 * Another real, previously-unexercised bug fixed here: `POST /messages`
 * (`backend/src/app.js`) requires `recipientIds: string[]` (a user-id
 * fan-out list — one row inserted per id) plus `ciphertext`/`nonce`/
 * exactly one of `senderPubkey`/`senderTag`. There is no `recipientHandle`
 * field on the backend at all; this struct's old shape would have failed
 * every send with a 400, same root cause as the auth-DTO bug above
 * (nothing ever called `send()` far enough to notice, since `token` was
 * always null with no register()/login() call anywhere in this app — see
 * `VeilSession.kt`). `scope`/`scopeId` are accepted but not required
 * server-side (the CLI sends them; the backend ignores them today) —
 * included for parity, harmless either way.
 *
 * `senderPubkey`/`senderTag` are both nullable and exactly one must be set
 * per send — mirrors the CLI's `SenderId::{Pubkey,Tag}` (see
 * `cli/src/main.rs`'s `seal_for_one`/`cmd_send`) and `VeilSession.kt`'s own
 * `SenderId` sealed class: a ratcheted message (continuing session OR its
 * handshake) sends `senderTag`, so the backend never learns the real
 * identity key for any message past the point a session exists; only the
 * static, non-forward-secret fallback still needs the real `senderPubkey`.
 * Gson's default converter (configured below, no `serializeNulls()`) omits
 * a null field from the request body entirely, which is exactly what the
 * backend's `typeof senderPubkey === "string"` check wants — not just "the
 * field happens to be null" but genuinely absent.
 */
data class SendMessageRequest(
    val recipientIds: List<String>,
    val ciphertext: String,
    val nonce: String,
    val senderPubkey: String? = null,
    val senderTag: String? = null,
    val scope: String = "dm",
    val scopeId: String? = null,
)

data class AckMessagesRequest(val ids: List<String>)

/**
 * Prekey wire types — field-for-field match to `backend/src/app.js`'s
 * `/prekeys` routes (`xPub`/`kemPub`, not snake_case; confirmed against
 * the route handlers, same discipline as the auth-DTO fix above) and to
 * what the CLI already sends/receives for the same endpoints.
 */
data class PrekeyDto(val xPub: String, val kemPub: String)

data class PublishPrekeysRequest(
    val mediumTermPrekey: PrekeyDto,
    val oneTimePrekeys: List<PrekeyDto>,
)

data class PrekeyBundleResponse(
    val identityPubkey: String?,
    val identityPqPubkey: String?,
    val mediumTermPrekey: PrekeyDto?,
    val oneTimePrekey: PrekeyDto?,
)

data class InboxRow(
    val id: String,
    // Deliberately snake_case, not @SerializedName-renamed to camelCase —
    // the backend returns raw SQLite column names here (see the same fix
    // already made once in the Rust CLI's InboxRow, documented there).
    // Keeping both clients honest about the same real backend shape beats
    // guessing a nicer one and finding out only at runtime.
    val ciphertext: String,
    val nonce: String,
    // Both nullable, and exactly one populated per row, mirroring the
    // backend's `messages` table (see `backend/src/db.js`): a ratcheted
    // message now carries sender_tag instead of the real sender_pubkey.
    // Only the static, non-forward-secret fallback scheme still has a
    // sender_pubkey.
    val sender_pubkey: String?,
    val sender_tag: String?,
    val created_at: String,
)

interface VeilApi {
    @POST("auth/register")
    fun register(@Body body: RegisterRequest): Call<AuthResponse>

    @POST("auth/login")
    fun login(@Body body: LoginRequest): Call<AuthResponse>

    @GET("auth/users/{handle}")
    fun getUserKeys(@Header("Authorization") bearer: String, @Path("handle") handle: String): Call<UserPublicKeys>

    @GET("chambers")
    fun chambers(@Header("Authorization") bearer: String): Call<List<Chamber>>

    @POST("chambers")
    fun createChamber(@Header("Authorization") bearer: String, @Body body: CreateChamberRequest): Call<Chamber>

    @POST("messages")
    fun sendMessage(@Header("Authorization") bearer: String, @Body body: SendMessageRequest): Call<Unit>

    @GET("messages")
    fun inbox(@Header("Authorization") bearer: String): Call<List<InboxRow>>

    @POST("prekeys")
    fun publishPrekeys(@Header("Authorization") bearer: String, @Body body: PublishPrekeysRequest): Call<Unit>

    @GET("prekeys/{handle}/bundle")
    fun prekeyBundle(@Header("Authorization") bearer: String, @Path("handle") handle: String): Call<PrekeyBundleResponse>

    @POST("messages/ack")
    fun ackMessages(@Header("Authorization") bearer: String, @Body body: AckMessagesRequest): Call<Unit>
}

object ApiClient {
    /**
     * `baseUrl` is caller-supplied, not hardcoded, same reasoning as the
     * CLI's `VEIL_BACKEND_URL` env var: there is no single "the Veil
     * server" — self-hosting the backend is the whole point of the
     * zero-trust design (see backend README), so the app must ask, not
     * assume.
     *
     * `socksProxy` (host:port, e.g. "127.0.0.1:9050" for Orbot/Tor) is
     * optional, matching the CLI's `VEIL_SOCKS_PROXY`. Routing through Tor
     * is the Android equivalent of the CLI's SOCKS support — Orbot exposes
     * a local SOCKS5 port exactly like the desktop `tor` daemon does, so
     * this needs no Android-specific protocol work, just pointing OkHttp
     * at it.
     */
    fun build(baseUrl: String, socksProxyHostPort: String? = null): VeilApi {
        val builder = OkHttpClient.Builder()
            .connectTimeout(20, TimeUnit.SECONDS)
            .readTimeout(30, TimeUnit.SECONDS)

        if (socksProxyHostPort != null) {
            val (host, portStr) = socksProxyHostPort.split(":", limit = 2)
            val proxy = java.net.Proxy(
                java.net.Proxy.Type.SOCKS,
                java.net.InetSocketAddress(host, portStr.toInt()),
            )
            builder.proxy(proxy)
        }

        // Minimal request-shape sanity log would belong here in debug
        // builds only — deliberately NOT adding an HttpLoggingInterceptor
        // at BODY level, since that would log plaintext request/response
        // bodies (which, for /messages, are already ciphertext — but
        // /auth/register's pubkey and handle are not secrets worth logging
        // either, on a "don't log more than you need" principle).
        val noop = Interceptor { chain -> chain.proceed(chain.request()) }
        builder.addInterceptor(noop)

        val retrofit = Retrofit.Builder()
            .baseUrl(if (baseUrl.endsWith("/")) baseUrl else "$baseUrl/")
            .client(builder.build())
            .addConverterFactory(GsonConverterFactory.create())
            .build()
        return retrofit.create(VeilApi::class.java)
    }
}
