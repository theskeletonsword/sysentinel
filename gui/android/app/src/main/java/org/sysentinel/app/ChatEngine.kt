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
class ChatEngine(
    /** For string resources: everything here ends up in front of a person. */
    private val ctx: android.content.Context,
    private val pairing: Pairing,
    private val appVersion: String,
) {

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
            listener.onStatus(ctx.getString(R.string.state_unpaired), false)
            return
        }
        io.execute {
            try {
                val l = pairing.link() ?: throw PhoneLinkException(ctx.getString(R.string.pairing_incomplete))
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
                            ctx.getString(R.string.state_wrong_phone) +
                                "\n\n${identity.detail}",
                            fromMe = false,
                        )))
                    }
                }
                drain(listener, l)
            } catch (e: Exception) {
                post(listener) { it.onStatus(e.message ?: ctx.getString(R.string.state_could_not_connect), false) }
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
                post(listener) { it.onStatus(e.message ?: ctx.getString(R.string.state_lost), false) }
            }
        }
    }

    /**
     * Send a command and capture its response WITHOUT showing it in the chat.
     *
     * The daemon's command handlers run synchronously before returning Ok, so
     * calling fetch() right after say() is guaranteed to pick up the response.
     * The caller gets the raw reply text; the main chat stream never sees it.
     */
    fun sendSilent(text: String, onReply: (String) -> Unit) {
        val l = link ?: return
        io.execute {
            try {
                l.say(text)
                val replies = l.fetch()
                val replyText = replies.lastOrNull()?.text.orEmpty()
                if (replies.isNotEmpty()) {
                    val highest = l.highestId(replies)
                    if (highest > 0) { l.acknowledge(highest); pairing.lastAckedId = highest }
                }
                main.post { onReply(replyText) }
            } catch (_: Exception) {
                main.post { onReply("") }
            }
        }
    }

    fun send(text: String, listener: Listener) {
        val l = link ?: run {
            listener.onStatus(ctx.getString(R.string.state_offline_send), false)
            return
        }
        io.execute {
            try {
                val replies = l.say(text)
                post(listener) { it.onMessages(replies) }
            } catch (e: Exception) {
                link = null
                post(listener) { it.onStatus(e.message ?: ctx.getString(R.string.state_send_failed), false) }
            }
        }
    }

    /** Send a photo for `/face register`. */
    fun sendPhoto(jpeg: ByteArray, listener: Listener) {
        val l = link ?: run {
            listener.onStatus(ctx.getString(R.string.state_offline_photo), false)
            return
        }
        io.execute {
            try {
                l.sendPhoto(jpeg)
                post(listener) { it.onStatus(ctx.getString(R.string.state_photo_sent), true) }
                drain(listener, l)
            } catch (e: Exception) {
                post(listener) { it.onStatus(e.message ?: ctx.getString(R.string.state_photo_failed), false) }
            }
        }
    }

    /** Send an attachment (image/PDF/doc), optionally converted with MarkItDown. */
    fun sendDocument(filename: String, bytes: ByteArray, markitdown: Boolean, listener: Listener) {
        val l = link ?: run {
            listener.onStatus(ctx.getString(R.string.state_offline_send), false)
            return
        }
        io.execute {
            try {
                l.sendDocument(filename, bytes, markitdown)
                post(listener) { it.onStatus(ctx.getString(R.string.attach_sent), true) }
                drain(listener, l)
            } catch (e: Exception) {
                post(listener) { it.onStatus(e.message ?: ctx.getString(R.string.state_send_failed), false) }
            }
        }
    }

    /** Send a photo for face enrolment, signed with the biometric confirm key. */
    fun enrollFace(jpeg: ByteArray, confirmSig: ByteArray?, listener: Listener) {
        val l = link ?: run {
            listener.onStatus(ctx.getString(R.string.state_offline_photo), false)
            return
        }
        io.execute {
            try {
                l.sendPhoto(jpeg, confirmSig)
                post(listener) { it.onStatus(ctx.getString(R.string.state_photo_sent), true) }
                drain(listener, l)
            } catch (e: Exception) {
                post(listener) { it.onStatus(e.message ?: ctx.getString(R.string.state_photo_failed), false) }
            }
        }
    }

    /** Send a signed confirmation for an armed order. */
    fun confirm(nonce: String, signature: ByteArray, onResult: (String) -> Unit) {
        val l = link ?: run { onResult(ctx.getString(R.string.state_offline_confirm)); return }
        io.execute {
            val msg = try {
                l.confirm(nonce, signature)
            } catch (e: Exception) {
                e.message ?: ctx.getString(R.string.state_confirm_failed)
            }
            main.post { onResult(msg) }
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
                attestationChain = DeviceIdentity.deviceAttestationChain(),
                confirmPublicKey = DeviceIdentity.confirmPublicKey(),
            )
        } catch (e: Exception) {
            null
        }
    }

    /**
     * "Define this as my phone" — say it to the daemon now, from the
     * finger-side, and get the daemon's honest verdict back.
     *
     * On first pairing this *is* the registration: the daemon saves the device
     * key (recorded with its verified attestation) and from then on treats this
     * exact handset as home. On a later run the daemon confirms the same handset
     * — or reports that a *different* phone answered, which means the pairing
     * secret has been copied. The verdict text is displayed verbatim, so what
     * the daemon decided is exactly what the owner reads.
     */
    fun definePhone(listener: Listener, onResult: (String) -> Unit) {
        io.execute {
            // Enrollment: delete any stale device key and generate a fresh one
            // before opening the connection. The daemon receives the key that
            // actually lives in the Keystore right now, never a leftover from a
            // previous install or a failed enrollment.
            DeviceIdentity.generateFreshDeviceKey()

            val verdict = try {
                if (!pairing.isPaired) {
                    ctx.getString(R.string.state_unpaired)
                } else {
                    val l = pairing.link()
                        ?: throw PhoneLinkException(ctx.getString(R.string.pairing_incomplete))
                    val welcome = l.connect(appVersion)
                    val id = proveIdentity(l, welcome.challenge)
                    l.close()
                    id?.verdict?.let { v ->
                        when (v) {
                            "paired" -> ctx.getString(R.string.own_definephone_paired, v)
                            "same_device" -> ctx.getString(R.string.own_definephone_same, v)
                            "different_device" -> ctx.getString(R.string.own_definephone_different, v)
                            "rejected" -> ctx.getString(R.string.own_definephone_rejected, v)
                            else -> ctx.getString(R.string.own_definephone_unknown, v)
                        }
                    } ?: ctx.getString(R.string.own_definephone_no_key)
                }
            } catch (e: Exception) {
                e.message ?: ctx.getString(R.string.state_offline_confirm)
            }
            main.post { onResult(verdict) }
        }
    }

    private fun statusLine(w: PhoneLink.Welcome, id: PhoneLink.Identity?): String {
        val base = ctx.getString(R.string.state_connected, w.host) +
            if (w.queued > 0) " · " + ctx.getString(R.string.state_waiting, w.queued) else ""
        val tail = when (id?.verdict) {
            "same_device" -> ctx.getString(R.string.state_recognised)
            "paired" -> ctx.getString(R.string.state_registered)
            "different_device" -> ctx.getString(R.string.state_different)
            "rejected" -> ctx.getString(R.string.state_signature_failed)
            else -> ctx.getString(R.string.state_no_device_key)
        }
        return "$base · $tail"
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
