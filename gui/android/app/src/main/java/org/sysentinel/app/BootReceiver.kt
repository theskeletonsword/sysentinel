// SPDX-License-Identifier: Apache-2.0
package org.sysentinel.app

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent

/**
 * Restarts the alert poller after a reboot, but only if the owner turned
 * notifications on and the phone is paired. Without this, "push" would silently
 * stop working the first time the phone restarts, which is exactly when someone
 * would assume it was still watching.
 */
class BootReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        if (intent.action != Intent.ACTION_BOOT_COMPLETED) return
        val prefs = AppPrefs(context)
        if (prefs.notificationsEnabled && Pairing(context).isPaired) {
            AlertService.start(context)
        }
    }
}
