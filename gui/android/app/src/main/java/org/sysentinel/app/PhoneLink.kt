// SPDX-License-Identifier: Apache-2.0
package org.sysentinel.app

import android.util.Log
import org.json.JSONArray
import org.json.JSONObject
import java.io.DataInputStream
import java.io.DataOutputStream
import java.net.InetSocketAddress
import java.net.Socket
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec

/**
 * The client half of the daemon's phone channel — the thing that replaces
 * Telegram.
 *
 * Wire format, matching `daemon/src/phone.rs`:
 *
 *  - a 4-byte big-endian length, then that many bytes;
 *  - each frame is `nonce(12) || ciphertext || tag(16)`, AEAD-sealed under the
 *    32-byte pairing key with no associated data;
 *  - the plaintext is one JSON object.
 *
 * Sealing the first frame correctly **is** the authentication. There is no
 * separate login, no token to steal, and a peer that cannot produce a valid
 * frame gets no reply at all — so a port scan learns nothing, not even that it
 * found the right protocol.
 *
 * # Which cipher
 *
 * The daemon picks from its own CPU: AES-256-GCM where it has hardware AES,
 * ChaCha20-Poly1305 where it does not. The phone cannot know which, so it tries
 * both and keeps whichever authenticates. That is safe precisely because AEAD
 * fails closed — a wrong cipher fails the tag exactly as a wrong key does, so
 * guessing costs a round trip and reveals nothing.
 *
 * ChaCha20-Poly1305 only exists in the platform from API 28. On an older
 * handset paired to a daemon whose CPU lacks AES, [connect] reports that
 * plainly rather than failing with something unreadable.
 *
 * # Threading
 *
 * Every call here blocks on a socket. None of them may run on the main thread —
 * Android will throw `NetworkOnMainThreadException`, and rightly.
 */
class PhoneLink(
    private val host: String,
    private val port: Int,
    private val key: ByteArray,
) {
    companion object {
        private const val TAG = "sysentinel"
        private const val NONCE_LEN = 12
        private const val TAG_BITS = 128
        private const val MAX_FRAME = 1 shl 20
        private const val CONNECT_TIMEOUT_MS = 8_000
        private const val IO_TIMEOUT_MS = 30_000

        /** Parse the 64-hex-character pairing key the daemon printed. */
        fun parseKey(hex: String): ByteArray? {
            val clean = hex.trim().replace(" ", "")
            if (clean.length != 64) return null
            return try {
                ByteArray(32) { i ->
                    clean.substring(i * 2, i * 2 + 2).toInt(16).toByte()
                }
            } catch (e: NumberFormatException) {
                null
            }
        }
    }

    /** Ciphers to try, best-supported first. */
    private enum class Suite(val transform: String) {
        AES_GCM("AES/GCM/NoPadding"),
        CHACHA("ChaCha20-Poly1305"),
    }

    /** Settled after the first successful frame, so later ones cost one try. */
    private var agreed: Suite? = null

    private var socket: Socket? = null
    private var input: DataInputStream? = null
    private var output: DataOutputStream? = null

    /** What the daemon said when it accepted us. */
    data class Welcome(val host: String, val queued: Int)

    /**
     * Connect and authenticate.
     *
     * @throws PhoneLinkException with something a person can act on.
     */
    fun connect(appVersion: String): Welcome {
        val s = Socket()
        try {
            s.connect(InetSocketAddress(host, port), CONNECT_TIMEOUT_MS)
        } catch (e: Exception) {
            throw PhoneLinkException(
                "No pude conectar con $host:$port.\n\n" +
                    "Esta es una conexión directa: no hay relay. Comprueba que estás " +
                    "en la misma red que el equipo, o que la VPN está levantada.",
                e,
            )
        }
        s.soTimeout = IO_TIMEOUT_MS
        socket = s
        input = DataInputStream(s.getInputStream())
        output = DataOutputStream(s.getOutputStream())

        val hello = JSONObject()
            .put("op", "hello")
            .put("app_version", appVersion)
        val reply = try {
            exchange(hello)
        } catch (e: PhoneLinkException) {
            close()
            throw e
        }

        if (reply.optString("op") == "error") {
            close()
            throw PhoneLinkException(reply.optString("message", "el daemon rechazó el saludo"))
        }
        return Welcome(
            host = reply.optString("host", host),
            queued = reply.optInt("queued", 0),
        )
    }

    /** Everything the daemon has been holding for us. */
    fun fetch(): List<Message> {
        val reply = exchange(JSONObject().put("op", "fetch"))
        return parseAlerts(reply)
    }

    /**
     * Confirm receipt up to `id`. Until this happens the daemon keeps them, so
     * an app that crashes mid-read loses nothing.
     */
    fun acknowledge(id: Long) {
        exchange(JSONObject().put("op", "ack").put("id", id))
    }

    /** Say something to the machine and get its reply. */
    fun say(text: String): List<Message> {
        val reply = exchange(JSONObject().put("op", "say").put("text", text))
        return parseAlerts(reply)
    }

    fun close() {
        try { socket?.close() } catch (_: Exception) {}
        socket = null; input = null; output = null
    }

    /** Highest alert id in a batch, for acknowledging. */
    fun highestId(alerts: List<Message>): Long = alerts.maxOfOrNull { it.serverId } ?: 0L

    // ── Framing ──────────────────────────────────────────────────────────────

    private fun exchange(request: JSONObject): JSONObject {
        val out = output ?: throw PhoneLinkException("no hay conexión abierta")
        val inp = input ?: throw PhoneLinkException("no hay conexión abierta")

        val sealed = seal(request.toString().toByteArray(Charsets.UTF_8))
        out.writeInt(sealed.size)
        out.write(sealed)
        out.flush()

        val len = inp.readInt()
        if (len <= 0 || len > MAX_FRAME) {
            throw PhoneLinkException("el daemon anunció un frame de $len bytes")
        }
        val frame = ByteArray(len)
        inp.readFully(frame)
        val plain = open(frame)
        return JSONObject(String(plain, Charsets.UTF_8))
    }

    private fun seal(plaintext: ByteArray): ByteArray {
        val nonce = ByteArray(NONCE_LEN).also { SecureRandom().nextBytes(it) }
        val suite = agreed ?: Suite.AES_GCM
        val body = cipher(suite, Cipher.ENCRYPT_MODE, nonce).doFinal(plaintext)
        return nonce + body
    }

    /**
     * Open a frame, settling on whichever suite authenticates.
     *
     * Trying the other one on failure is safe: AEAD fails closed, so a wrong
     * suite is indistinguishable from a wrong key and neither reveals anything.
     */
    private fun open(frame: ByteArray): ByteArray {
        if (frame.size <= NONCE_LEN) throw PhoneLinkException("frame demasiado corto")
        val nonce = frame.copyOfRange(0, NONCE_LEN)
        val body = frame.copyOfRange(NONCE_LEN, frame.size)

        val order = agreed?.let { listOf(it) } ?: listOf(Suite.AES_GCM, Suite.CHACHA)
        var lastFailure: Exception? = null
        for (suite in order) {
            try {
                val plain = cipher(suite, Cipher.DECRYPT_MODE, nonce).doFinal(body)
                if (agreed != suite) {
                    Log.i(TAG, "frame suite settled on ${suite.name}")
                    agreed = suite
                }
                return plain
            } catch (e: Exception) {
                lastFailure = e
            }
        }
        throw PhoneLinkException(
            "El frame no autenticó.\n\n" +
                "Casi siempre significa que la clave de emparejamiento no coincide " +
                "con la del equipo. Si el equipo usa ChaCha20-Poly1305 (CPU sin AES " +
                "por hardware), este teléfono necesita Android 9 o superior.",
            lastFailure,
        )
    }

    private fun cipher(suite: Suite, mode: Int, nonce: ByteArray): Cipher {
        val algorithm = if (suite == Suite.AES_GCM) "AES" else "ChaCha20"
        val c = Cipher.getInstance(suite.transform)
        val spec = SecretKeySpec(key, algorithm)
        if (suite == Suite.AES_GCM) {
            c.init(mode, spec, GCMParameterSpec(TAG_BITS, nonce))
        } else {
            c.init(mode, spec, IvParameterSpec(nonce))
        }
        return c
    }

    private fun parseAlerts(reply: JSONObject): List<Message> {
        if (reply.optString("op") == "error") {
            throw PhoneLinkException(reply.optString("message", "error del daemon"))
        }
        val arr: JSONArray = reply.optJSONArray("alerts") ?: return emptyList()
        return (0 until arr.length()).map { i ->
            val o = arr.getJSONObject(i)
            Message(
                text = o.optString("text"),
                fromMe = false,
                timestamp = o.optLong("unix_time") * 1000L,
                serverId = o.optLong("id"),
                photoPath = o.optString("photo").takeIf { it.isNotEmpty() && it != "null" },
            )
        }
    }
}

/** Anything that went wrong, phrased for the person holding the phone. */
class PhoneLinkException(message: String, cause: Throwable? = null) :
    Exception(message, cause)
