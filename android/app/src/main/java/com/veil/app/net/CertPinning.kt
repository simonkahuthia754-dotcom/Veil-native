package com.veil.app.net

import java.io.File
import java.security.MessageDigest
import java.security.cert.X509Certificate
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLSocketFactory
import javax.net.ssl.TrustManagerFactory
import javax.net.ssl.X509TrustManager
import org.json.JSONObject

/**
 * Trust-on-first-use (TOFU) certificate pinning for a self-hosted Veil
 * backend — the real fix for the gap `network_security_config.xml` used to
 * leave open ("trusts the system CA store only"). Addressed honestly, not
 * glossed over: a static, build-time pin (via OkHttp's `CertificatePinner`
 * or a `<pin-set>` in the network security config) doesn't fit Veil's
 * actual deployment model. There is no single "the Veil server" — anyone
 * can self-host `backend/` at any URL (`ApiClient.build`'s own doc
 * comment), so there is no one cert to bake into the APK at build time.
 * Baking in a pin for *a* backend would make the app unusable against
 * everyone else's.
 *
 * So Veil pins per-install, per-host, the same trust model SSH's
 * known_hosts uses: the first successful connection to a given host
 * records that leaf certificate's SPKI SHA-256 hash; every later
 * connection to the same host must present a certificate hashing to the
 * same pin, or the TLS handshake fails closed (surfaced to the UI as an
 * ordinary network error via the existing `onError` callbacks — nothing
 * swallows it silently). An operator who rotates their backend's cert
 * doesn't get bricked forever: `PinStore.resetPin`/`VeilSession.resetCertPin`
 * clear the stored pin so the next connection re-pins, same as deleting a
 * stale `known_hosts` line.
 *
 * Honest limitation, same one TOFU always has: if an attacker is already
 * positioned between this device and the backend *before* the very first
 * connection ever made (e.g. a MITM proxy whose root CA was installed on
 * this device ahead of first launch), that first, pin-establishing
 * connection is exactly where TOFU can't help — the attacker's certificate
 * gets pinned as if it were legitimate. What this still defends against,
 * and the backbone of why it's worth building: every connection *after*
 * that first one, including a MITM introduced later (a rogue CA added to
 * the device, a captive-portal proxy, a pentester's interception box
 * dropped onto the network mid-session) — exactly the attack a system-CA-
 * only trust model (the previous state) does nothing to catch, since a
 * device-trusted MITM root sails straight through ordinary TLS validation.
 *
 * This sits ON TOP of ordinary system-CA validation, not instead of it —
 * `TofuTrustManager` delegates to the platform's default trust manager
 * first and only pins afterward, so a certificate that isn't even
 * chain-valid is still rejected outright, same as before this existed.
 * Self-signed backend certs (common for a home-server self-host) are
 * therefore still rejected by design; supporting that is real, separate,
 * unscoped future work, not silently enabled here.
 */
object CertPinning {
    /** SPKI SHA-256 of an X509Certificate's public key, base64 — the same quantity HPKP/`CertificatePinner` pin to. */
    fun spkiSha256B64(cert: X509Certificate): String {
        val spki = cert.publicKey.encoded
        val digest = MessageDigest.getInstance("SHA-256").digest(spki)
        return java.util.Base64.getEncoder().encodeToString(digest)
    }

    /**
     * Plaintext, non-secret pin storage — a public key hash is not
     * sensitive data (same reasoning `VeilSession`'s `veil.meta` already
     * applies to its Argon2 PHC string and key-derivation salt), so this
     * deliberately lives outside the encrypted vault: it has to be
     * readable before the vault is ever unlocked, since pinning happens at
     * the TLS layer underneath every request, including the very first
     * `register()`/`login()` call.
     */
    class PinStore(private val file: File) {
        @Synchronized
        fun getPin(host: String): String? {
            if (!file.exists()) return null
            return try {
                val obj = JSONObject(file.readText())
                if (obj.has(host)) obj.getString(host) else null
            } catch (e: Exception) {
                null // Corrupt pin file fails open to re-pinning, not closed to a permanent lockout.
            }
        }

        @Synchronized
        fun setPin(host: String, spkiSha256B64: String) {
            val obj = if (file.exists()) {
                try { JSONObject(file.readText()) } catch (e: Exception) { JSONObject() }
            } else {
                JSONObject()
            }
            obj.put(host, spkiSha256B64)
            file.writeText(obj.toString())
        }

        @Synchronized
        fun resetPin(host: String) {
            if (!file.exists()) return
            val obj = try { JSONObject(file.readText()) } catch (e: Exception) { return }
            obj.remove(host)
            file.writeText(obj.toString())
        }
    }

    /**
     * Wraps the platform's default [X509TrustManager] with TOFU pinning
     * for exactly one [host]. One instance is scoped to one host because
     * one [okhttp3.OkHttpClient] built by `ApiClient.build(baseUrl, ...)`
     * only ever talks to that one backend (Retrofit's `baseUrl`) — no need
     * for a general multi-host trust manager.
     */
    private class TofuTrustManager(
        private val host: String,
        private val delegate: X509TrustManager,
        private val pinStore: PinStore,
    ) : X509TrustManager {
        override fun checkClientTrusted(chain: Array<out X509Certificate>?, authType: String?) {
            delegate.checkClientTrusted(chain, authType)
        }

        override fun checkServerTrusted(chain: Array<out X509Certificate>?, authType: String?) {
            // Baseline: still a chain-valid, system-CA-trusted certificate.
            // TOFU pinning narrows trust further; it never widens it.
            delegate.checkServerTrusted(chain, authType)

            val leaf = chain?.firstOrNull()
                ?: throw java.security.cert.CertificateException("empty certificate chain")
            val presentedPin = spkiSha256B64(leaf)
            val storedPin = pinStore.getPin(host)
            if (storedPin == null) {
                pinStore.setPin(host, presentedPin)
                return
            }
            if (storedPin != presentedPin) {
                throw java.security.cert.CertificateException(
                    "Certificate for $host changed since it was first pinned. " +
                        "If you rotated this backend's certificate on purpose, reset the pin " +
                        "in Veil's settings; otherwise this may be an interception attempt.",
                )
            }
        }

        // Android's TLS stack (Conscrypt) looks up this exact signature by
        // reflection on trust managers passed to SSLContext.init — not part
        // of the javax.net.ssl.X509TrustManager interface itself, but
        // required for Android to use the chain this trust manager
        // actually validated (rather than silently falling back to a
        // different internal path). Confirmed against OkHttp's own HTTPS
        // guide, which calls this out explicitly for custom trust managers
        // used with `OkHttpClient.Builder.sslSocketFactory`.
        @Suppress("unused")
        fun checkServerTrusted(chain: Array<X509Certificate>, authType: String, host: String): List<X509Certificate> {
            checkServerTrusted(chain, authType)
            return chain.toList()
        }

        override fun getAcceptedIssuers(): Array<X509Certificate> = delegate.acceptedIssuers
    }

    /** Extracts just the host (no scheme, no port, no path) from a backend base URL, for keying the pin store. */
    fun hostOf(baseUrl: String): String = java.net.URI(baseUrl).host ?: baseUrl

    /**
     * Builds an [SSLSocketFactory] + [X509TrustManager] pair pinned (TOFU)
     * to [host], ready to pass to `OkHttpClient.Builder.sslSocketFactory`.
     */
    fun buildPinnedSslFactory(host: String, pinStore: PinStore): Pair<SSLSocketFactory, X509TrustManager> {
        val tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm())
        tmf.init(null as java.security.KeyStore?)
        val defaultTrustManager = tmf.trustManagers.filterIsInstance<X509TrustManager>().firstOrNull()
            ?: throw IllegalStateException("no default X509TrustManager available on this platform")

        val pinned = TofuTrustManager(host, defaultTrustManager, pinStore)
        val sslContext = SSLContext.getInstance("TLS")
        sslContext.init(null, arrayOf(pinned), null)
        return Pair(sslContext.socketFactory, pinned)
    }
}
