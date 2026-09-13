// SPDX-License-Identifier: Apache-2.0
package org.sysentinel.app

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent

/**
 * Starts the background service after a reboot.
 *
 * [AlertService] runs whenever the phone is paired, so messages arrive even
 * when the app is closed. Without this receiver, the service would silently
 * stop surviving a reboot — exactly when the owner would assume it was still
 * watching.
 */
class BootReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        if (intent.action != Intent.ACTION_BOOT_COMPLETED) return
        if (Pairing(context).isPaired) {
            AlertService.start(context)
        }
    }
}
