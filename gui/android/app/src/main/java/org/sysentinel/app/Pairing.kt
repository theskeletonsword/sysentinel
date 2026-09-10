// SPDX-License-Identifier: Apache-2.0
package org.sysentinel.app

import android.content.Context
import android.content.SharedPreferences

/**
 * Where the phone remembers which machine it is paired to.
 *
 * The pairing key is the whole secret: sealing a frame with it is the
 * authentication, so anything that can read it can speak as the owner. It lives
 * in the app's private preferences, which on a non-rooted device other apps
 * cannot read.
 *
 * That is *private storage*, not *hardware-backed storage*, and the difference
 * is worth stating plainly: on a rooted handset, or one whose backups are not
 * encrypted, private is not the same as safe. Wrapping this with the Keystore
 * key from [DeviceIdentity] — so reading it needs the fingerprint too — is the
 * obvious next step and is not done yet. `android:allowBackup="false"` in the
 * manifest at least keeps it out of cloud backups.
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

    /** The 64-hex pairing key as typed; empty when not paired. */
    var keyHex: String
        get() = prefs.getString(KEY_HEX, "") ?: ""
        set(v) = prefs.edit().putString(KEY_HEX, v.trim()).apply()

    /** Highest alert id already acknowledged, so a reinstall does not re-ask. */
    var lastAckedId: Long
        get() = prefs.getLong(KEY_ACK, 0L)
        set(v) = prefs.edit().putLong(KEY_ACK, v).apply()

    val isPaired: Boolean
        get() = host.isNotEmpty() && PhoneLink.parseKey(keyHex) != null

    /** A link to the paired machine, or `null` when pairing is incomplete. */
    fun link(): PhoneLink? {
        val key = PhoneLink.parseKey(keyHex) ?: return null
        if (host.isEmpty()) return null
        return PhoneLink(host, port, key)
    }

    private companion object {
        const val KEY_HOST = "host"
        const val KEY_PORT = "port"
        const val KEY_HEX = "key"
        const val KEY_ACK = "acked"
    }
}
