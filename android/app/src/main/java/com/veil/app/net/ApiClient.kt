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

data class RegisterRequest(
    val handle: String,
    val pubkey: String,
    val pqPubkey: String? = null,
)

data class LoginRequest(val handle: String, val proof: String)

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

data class SendMessageRequest(
    val recipientHandle: String,
    val ciphertext: String,
    val nonce: String,
    val senderPubkey: String,
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
    val sender_pubkey: String,
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
