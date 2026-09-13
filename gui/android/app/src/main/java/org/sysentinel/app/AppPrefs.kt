// SPDX-License-Identifier: Apache-2.0
package org.sysentinel.app

import android.content.Context

/**
 * App-wide preferences that are NOT the pairing secret: the interface language
 * and whether background alert notifications are allowed.
 *
 * Kept in their own SharedPreferences file, apart from [Pairing]: these are
 * plain settings, not the key, and there is no reason to route them through the
 * Keystore wrapping that the pairing secret needs.
 */
class AppPrefs(context: Context) {

    private val prefs = context.getSharedPreferences("sysentinel-app", Context.MODE_PRIVATE)

    /**
     * BCP-47 language tag for the UI. English is the default and the source
     * language; Spanish is the one optional translation. The phone's own locale
     * is deliberately NOT followed — the machine speaks English by default and
     * the owner opts into Spanish, rather than the handset deciding.
     */
    var language: String
        get() = prefs.getString(KEY_LANG, DEFAULT_LANG) ?: DEFAULT_LANG
        set(v) = prefs.edit().putString(KEY_LANG, v).apply()

    /** Whether the app may run its background poller and post alert
     *  notifications. Off by default: the app's original promise was that it
     *  never lights up on its own (see AlertService), so turning this on is a
     *  deliberate choice the owner makes. */
    var notificationsEnabled: Boolean
        get() = prefs.getBoolean(KEY_NOTIF, false)
        set(v) = prefs.edit().putBoolean(KEY_NOTIF, v).apply()

    /**
     * Date format for evidence timestamps in the Multimedia screen.
     *   "dmy" (default)  ->  dd/mm/yyyy
     *   "ymd"            ->  yyyy/mm/dd
     *   "mdy"            ->  mm/dd/yyyy
     */
    var dateFormat: String
        get() = prefs.getString(KEY_DATE_FMT, "dmy") ?: "dmy"
        set(v) = prefs.edit().putString(KEY_DATE_FMT, v).apply()

    /**
     * Highest alert id the background service has already raised a notification
     * for. Separate from [Pairing.lastAckedId]: the service notifies but never
     * acknowledges, leaving the queue for the app to drain and display when
     * opened — so this is only about not buzzing twice for the same alert.
     */
    var lastNotifiedId: Long
        get() = prefs.getLong(KEY_NOTIFIED, 0L)
        set(v) = prefs.edit().putLong(KEY_NOTIFIED, v).apply()

    companion object {
        const val DEFAULT_LANG = "en"
        /** The languages offered in the picker: English (source) + Spanish. */
        val SUPPORTED = listOf("en" to "English", "es" to "Español")
        private const val KEY_LANG = "language"
        private const val KEY_NOTIF = "notifications"
        private const val KEY_NOTIFIED = "last_notified_id"
        private const val KEY_DATE_FMT = "date_format"
    }
}
