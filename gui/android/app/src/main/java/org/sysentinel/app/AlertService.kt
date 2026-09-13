// SPDX-License-Identifier: Apache-2.0
package org.sysentinel.app

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Service
import android.content.Context
import android.content.Intent
import android.os.Build
import android.os.IBinder
import androidx.core.app.NotificationCompat
import androidx.core.app.NotificationManagerCompat

/**
 * Background poller that turns the machine's alerts into phone notifications.
 *
 * # This reverses a deliberate default
 *
 * The rest of this app was built to NEVER notify — see the class docs in
 * [ChatEngine] and `daemon/src/facenn.rs`. The reasoning stands: a phone that
 * lights up with "unknown face at the keyboard" while somebody is standing over
 * its owner has announced that the machine informed on them, and the owner is
 * the one who pays for that. So this service exists but is OFF by default; the
 * owner turns it on knowing the trade, and can turn it back off.
 *
 * # Why a foreground service and not push
 *
 * There is no third party in this design — no FCM, no relay — so there is
 * nowhere for a push to originate. The only way the phone learns of an alert is
 * to ask, so this holds a foreground service and polls [PhoneLink.fetch] on a
 * timer. The persistent notification a foreground service requires is honest:
 * it means "monitoring is on".
 *
 * # It notifies, it does not acknowledge
 *
 * The service raises a notification for any alert newer than
 * [AppPrefs.lastNotifiedId] and advances that marker, but it never calls `ack`.
 * Draining and acknowledging stay with the foreground app, so opening it still
 * shows every alert in the conversation. The daemon's queue simply holds them
 * until then (bounded by its own queue_capacity).
 */
class AlertService : Service() {

    @Volatile private var running = false
    private var worker: Thread? = null

    override fun onBind(intent: Intent?): IBinder? = null

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        startInForeground()
        if (!running) {
            running = true
            worker = Thread { pollLoop() }.also { it.start() }
        }
        return START_STICKY
    }

    override fun onDestroy() {
        running = false
        worker?.interrupt()
        super.onDestroy()
    }

    private fun startInForeground() {
        val open = PendingIntent.getActivity(
            this, 0, Intent(this, ChatActivity::class.java),
            PendingIntent.FLAG_IMMUTABLE,
        )
        val ongoing = NotificationCompat.Builder(this, CHANNEL_ONGOING)
            .setSmallIcon(R.mipmap.ic_launcher)
            .setContentTitle(getString(R.string.notif_monitoring_title))
            .setContentText(getString(R.string.notif_monitoring_text))
            .setContentIntent(open)
            .setOngoing(true)
            .setSilent(true)
            .setPriority(NotificationCompat.PRIORITY_LOW)
            .build()
        startForeground(ID_ONGOING, ongoing)
    }

    private fun pollLoop() {
        val prefs = AppPrefs(this)
        val pairing = Pairing(this)
        var link: PhoneLink? = null
        while (running) {
            try {
                if (!prefs.notificationsEnabled || !pairing.isPaired) {
                    stopSelf(); break
                }
                val l = link ?: pairing.link()?.also { it.connect(BuildConfig.VERSION_NAME); link = it }
                if (l == null) { sleep(POLL_MS); continue }
                val alerts = l.fetch()
                val fresh = alerts.filter { it.serverId > prefs.lastNotifiedId }
                if (fresh.isNotEmpty()) {
                    fresh.forEach { notifyAlert(it) }
                    prefs.lastNotifiedId = fresh.maxOf { it.serverId }
                }
            } catch (e: Exception) {
                // A dropped connection is normal off Wi-Fi / VPN flaps; drop the
                // link and let the next tick reconnect rather than dying.
                try { link?.close() } catch (_: Exception) {}
                link = null
            }
            sleep(POLL_MS)
        }
        try { link?.close() } catch (_: Exception) {}
    }

    private fun sleep(ms: Long) {
        try { Thread.sleep(ms) } catch (e: InterruptedException) { running = false }
    }

    private fun notifyAlert(m: Message) {
        if (!NotificationManagerCompat.from(this).areNotificationsEnabled()) return
        val open = PendingIntent.getActivity(
            this, m.serverId.toInt(), Intent(this, ChatActivity::class.java),
            PendingIntent.FLAG_IMMUTABLE,
        )
        val n = NotificationCompat.Builder(this, CHANNEL_ALERTS)
            .setSmallIcon(R.mipmap.ic_launcher)
            .setContentTitle(getString(R.string.notif_alert_title))
            .setContentText(m.text.lineSequence().firstOrNull()?.take(120) ?: m.text.take(120))
            .setStyle(NotificationCompat.BigTextStyle().bigText(m.text.take(1000)))
            .setContentIntent(open)
            .setAutoCancel(true)
            .setPriority(NotificationCompat.PRIORITY_HIGH)
            .build()
        try {
            NotificationManagerCompat.from(this).notify(m.serverId.toInt(), n)
        } catch (_: SecurityException) {
            // POST_NOTIFICATIONS not granted; nothing to do but skip.
        }
    }

    companion object {
        private const val CHANNEL_ONGOING = "sysentinel-monitoring"
        private const val CHANNEL_ALERTS = "sysentinel-alerts"
        private const val ID_ONGOING = 1
        private const val POLL_MS = 30_000L

        /** Create the two channels once; safe to call repeatedly. */
        fun ensureChannels(ctx: Context) {
            if (Build.VERSION.SDK_INT < Build.VERSION_CODES.O) return
            val mgr = ctx.getSystemService(NotificationManager::class.java)
            mgr.createNotificationChannel(
                NotificationChannel(
                    CHANNEL_ONGOING, ctx.getString(R.string.notif_channel_monitoring),
                    NotificationManager.IMPORTANCE_LOW,
                )
            )
            mgr.createNotificationChannel(
                NotificationChannel(
                    CHANNEL_ALERTS, ctx.getString(R.string.notif_channel_alerts),
                    NotificationManager.IMPORTANCE_HIGH,
                ).apply { description = ctx.getString(R.string.notif_channel_alerts_desc) }
            )
        }

        fun start(ctx: Context) {
            ensureChannels(ctx)
            val i = Intent(ctx, AlertService::class.java)
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) ctx.startForegroundService(i)
            else ctx.startService(i)
        }

        fun stop(ctx: Context) {
            ctx.stopService(Intent(ctx, AlertService::class.java))
        }
    }
}
