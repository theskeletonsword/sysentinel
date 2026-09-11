// SPDX-License-Identifier: Apache-2.0
package org.sysentinel.app

import android.content.Context
import android.content.SharedPreferences

/**
 * Where the phone remembers which machine it is paired to.
 *
 * The pairing key is the whole secret: sealing a frame with it is the
 * authentication, so anything that can read it can speak as the owner.
 *
 * It is therefore **encrypted under a key held in the TEE or the secure
 * element** and never written in the clear. Private storage is not the same as
 * hardware-backed storage — on a rooted handset the difference is the whole
 * question — so an attacker who copies the app's data directory now gets
 * ciphertext and a key handle that is useless anywhere else.
 *
 * On a handset with no usable Keystore the key is stored in the clear and
 * [wrappedInHardware] says so, rather than the app refusing to work. The owner
 * can then decide; silently pretending would be worse than either.
 *
 * A factory reset or a reinstall destroys the Keystore key and makes the stored
 * blob unreadable. That is a re-pair, not a bug — and it is exactly the
 * property that makes wrapping worth having.
 */
class Pairing(context: Context) {

    private val prefs: SharedPreferences =
        context.getSharedPreferences("sysentinel-pairing", Context.MODE_PRIVATE)

    var host: String
        get() = prefs.getString(KEY_HOST, "") ?: ""
        set(v) = prefs.edit().putString(KEY_HOST, v.trim()).apply()

    var port: Int
        get() = prefs.getInt(KEY_PORT, 8443)
        set(v) = prefs.edit().putInt(KEY_PORT, v).apply()

    /**
     * The 64-hex pairing key; empty when not paired or when the wrapping key is
     * gone (a reset or reinstall), which reads the same and means re-pair.
     */
    var keyHex: String
        get() {
            prefs.getString(KEY_WRAPPED, null)?.let { wrapped ->
                return DeviceIdentity.unwrapSecret(wrapped) ?: ""
            }
            // Written before wrapping existed, or by a handset with no usable
            // Keystore. Upgrade it in place the first time it is read.
            val plain = prefs.getString(KEY_HEX, "") ?: ""
            if (plain.isNotEmpty()) {
                DeviceIdentity.wrapSecret(plain)?.let { wrapped ->
                    prefs.edit().putString(KEY_WRAPPED, wrapped).remove(KEY_HEX).apply()
                }
            }
            return plain
        }
        set(v) {
            val clean = v.trim()
            val wrapped = DeviceIdentity.wrapSecret(clean)
            if (wrapped != null) {
                prefs.edit().putString(KEY_WRAPPED, wrapped).remove(KEY_HEX).apply()
            } else {
                // No Keystore to lean on. Store it, and let the UI say so.
                prefs.edit().putString(KEY_HEX, clean).remove(KEY_WRAPPED).apply()
            }
        }

    /** True when the pairing key is protected by hardware rather than by file
     *  permissions alone. Surfaced in the UI: it changes what a stolen phone
     *  costs. */
    val wrappedInHardware: Boolean
        get() = prefs.contains(KEY_WRAPPED)

    /**
     * The machine's TLS certificate pin, `sha256/…`, from the pairing QR.
     *
     * Not a secret — it is a public key's fingerprint — so it is stored in the
     * clear beside the host. Losing it is not dangerous; having the wrong one
     * simply means refusing to connect, which is the correct direction to fail
     * in.
     */
    var certPin: String
        get() = prefs.getString(KEY_CERT, "") ?: ""
        set(v) = prefs.edit().putString(KEY_CERT, v.trim()).apply()

    /** Highest alert id already acknowledged, so a reinstall does not re-ask. */
    var lastAckedId: Long
        get() = prefs.getLong(KEY_ACK, 0L)
        set(v) = prefs.edit().putLong(KEY_ACK, v).apply()

    val isPaired: Boolean
        get() = host.isNotEmpty() &&
            PhoneLink.parseKey(keyHex) != null &&
            certPin.isNotEmpty()

    /** A link to the paired machine, or `null` when pairing is incomplete. */
    fun link(): PhoneLink? {
        val key = PhoneLink.parseKey(keyHex) ?: return null
        if (host.isEmpty()) return null
        return PhoneLink(host, port, key, certPin)
    }

    private companion object {
        const val KEY_HOST = "host"
        const val KEY_PORT = "port"
        const val KEY_HEX = "key"
        const val KEY_WRAPPED = "key_wrapped"
        const val KEY_ACK = "acked"
        const val KEY_CERT = "cert_pin"
    }
}
