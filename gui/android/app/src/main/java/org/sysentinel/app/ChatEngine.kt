// SPDX-License-Identifier: Apache-2.0
package org.sysentinel.app

import android.os.Handler
import android.os.Looper
import java.util.concurrent.Executors

/**
 * Everything both faces of the app need, so the modern and legacy UIs share one
 * implementation and cannot drift apart in behaviour.
 *
 * All network work happens on a single background thread and results are handed
 * back on the main one. Android forbids sockets on the main thread, and a chat
 * window that freezes while a laptop is probed would be worse than no window
 * anyway.
 *
 * # It polls, it is never pushed to
 *
 * There is no push, no notification channel, no service waking this up. The app
 * fetches when it is open, on a slow timer. That is the same promise the
 * desktop GUI makes and for the same reason: a phone that lights up with
 * "ROSTRO NO REGISTRADO" while somebody is standing over its owner has just
 * announced that the machine informed on them.
 */
class ChatEngine(private val pairing: Pairing, private val appVersion: String) {

    private val io = Executors.newSingleThreadExecutor()
    private val main = Handler(Looper.getMainLooper())
    private var link: PhoneLink? = null

    interface Listener {
        fun onMessages(messages: List<Message>)
        fun onStatus(text: String, ok: Boolean)
    }

    /** Connect and drain whatever the daemon has been holding. */
    fun start(listener: Listener) {
        if (!pairing.isPaired) {
            listener.onStatus("Sin emparejar — falta el equipo y la clave", false)
            return
        }
        io.execute {
            try {
                val l = pairing.link() ?: throw PhoneLinkException("emparejamiento incompleto")
                val welcome = l.connect(appVersion)
                link = l

                // Prove which handset this is before anything else. The pairing
                // key got us onto the channel; this answers the question it
                // cannot — whether the phone at this end is the one the owner
                // paired, or a different one holding a copy of the secret.
                val identity = proveIdentity(l, welcome.challenge)
                post(listener) { it.onStatus(statusLine(welcome, identity), identity == null || identity.verdict != "different_device") }
                if (identity?.verdict == "different_device") {
                    // Do not go quiet about it: this is the case the device key
                    // exists to catch.
                    post(listener) {
                        it.onMessages(listOf(Message(
                            "⚠️ El equipo dice que este NO es el teléfono con el que " +
                                "emparejaste.\n\n${identity.detail}",
                            fromMe = false,
                        )))
                    }
                }
                drain(listener, l)
            } catch (e: Exception) {
                post(listener) { it.onStatus(e.message ?: "no pude conectar", false) }
            }
        }
    }

    /** Fetch and acknowledge in one pass. */
    fun refresh(listener: Listener) {
        val l = link ?: return start(listener)
        io.execute {
            try {
                drain(listener, l)
            } catch (e: Exception) {
                link = null
                post(listener) { it.onStatus(e.message ?: "conexión perdida", false) }
            }
        }
    }

    fun send(text: String, listener: Listener) {
        val l = link ?: run {
            listener.onStatus("sin conexión — no puedo enviarlo todavía", false)
            return
        }
        io.execute {
            try {
                val replies = l.say(text)
                post(listener) { it.onMessages(replies) }
            } catch (e: Exception) {
                link = null
                post(listener) { it.onStatus(e.message ?: "no se pudo enviar", false) }
            }
        }
    }

    /** Send a photo for `/face register`. */
    fun sendPhoto(jpeg: ByteArray, listener: Listener) {
        val l = link ?: run {
            listener.onStatus("sin conexión — la foto no salió", false)
            return
        }
        io.execute {
            try {
                l.sendPhoto(jpeg)
                post(listener) { it.onStatus("foto enviada", true) }
                drain(listener, l)
            } catch (e: Exception) {
                post(listener) { it.onStatus(e.message ?: "no se pudo enviar la foto", false) }
            }
        }
    }

    fun stop() {
        io.execute { link?.close(); link = null }
    }

    /**
     * Sign the daemon's challenge with the device key.
     *
     * Returns `null` on a handset with no hardware-backed key at all, which is
     * not fatal — the channel still works, it simply proves less, and the
     * daemon's ladder grades it for what it is.
     */
    private fun proveIdentity(l: PhoneLink, challenge: ByteArray): PhoneLink.Identity? {
        if (challenge.isEmpty()) return null
        val pub = DeviceIdentity.devicePublicKey() ?: return null
        val sig = DeviceIdentity.signChallenge(challenge) ?: return null
        return try {
            l.identify(
                publicKey = pub,
                signature = sig,
                backing = DeviceIdentity.deviceKeyBacking(),
                model = android.os.Build.MODEL,
                manufacturer = android.os.Build.MANUFACTURER,
            )
        } catch (e: Exception) {
            null
        }
    }

    private fun statusLine(w: PhoneLink.Welcome, id: PhoneLink.Identity?): String {
        val base = "Conectado a ${w.host}" +
            if (w.queued > 0) " · ${w.queued} esperando" else ""
        return when (id?.verdict) {
            "same_device" -> "$base · teléfono reconocido"
            "paired" -> "$base · teléfono registrado como tuyo"
            "different_device" -> "$base · ⚠️ TELÉFONO DISTINTO"
            "rejected" -> "$base · la firma no verificó"
            else -> "$base · sin clave de dispositivo"
        }
    }

    /**
     * Pull pending alerts and confirm them.
     *
     * Acknowledging only after the UI has them is deliberate: the daemon keeps
     * everything until told otherwise, so an app that dies mid-read gets the
     * same alerts again rather than losing them.
     */
    private fun drain(listener: Listener, l: PhoneLink) {
        val alerts = l.fetch()
        if (alerts.isEmpty()) return
        post(listener) { it.onMessages(alerts) }
        val highest = l.highestId(alerts)
        if (highest > 0) {
            l.acknowledge(highest)
            pairing.lastAckedId = highest
        }
    }

    private fun post(listener: Listener, block: (Listener) -> Unit) {
        main.post { block(listener) }
    }
}
