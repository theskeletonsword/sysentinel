// SPDX-License-Identifier: Apache-2.0
package org.sysentinel.app

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
 * Always-on background service that keeps a connection to the daemon alive
 * and delivers messages when the app is not in the foreground.
 *
 * # Why it runs unconditionally
 *
 * The foreground indicator ("Monitoring active") is honest: as long as this
 * phone is paired with a machine, the machine can reach it. Turning off the
 * [AppPrefs.notificationsEnabled] flag only suppresses the heads-up
 * notifications — it does not stop the service or the incoming messages.
 * Messages received while the app is closed are saved to [MessageHistory] so
 * the user sees them the next time they open the app.
 *
 * # Identity proof
 *
 * The daemon now requires every connection to prove it is the paired handset
 * before any other operation. This service calls [PhoneLink.identify] right
 * after [PhoneLink.connect], exactly as [ChatEngine] does.
 *
 * # No acknowledgement
 *
 * The service fetches but never acknowledges. Messages stay in the daemon's
 * queue until [ChatEngine] drains and acks them in the foreground session.
 * This means the activity always gets a clean drain on open, and the service
 * only has to keep up with what is new.
 */
class AlertService : Service() {

    @Volatile private var running = false
    private var worker: Thread? = null

    override fun onBind(intent: Intent?): IBinder? = null

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        startInForeground()
        if (!running) {
            running = true
            worker = Thread { pollLoop() }.also { it.isDaemon = true; it.start() }
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
        val n = NotificationCompat.Builder(this, CHANNEL_ONGOING)
            .setSmallIcon(R.mipmap.ic_launcher)
            .setContentTitle(getString(R.string.notif_monitoring_title))
            .setContentText(getString(R.string.notif_monitoring_text))
            .setContentIntent(open)
            .setOngoing(true)
            .setSilent(true)
            .setPriority(NotificationCompat.PRIORITY_LOW)
            .build()
        startForeground(ID_ONGOING, n)
    }

    private fun pollLoop() {
        val pairing   = Pairing(this)
        val history   = MessageHistory(this)
        var link: PhoneLink? = null

        while (running) {
            try {
                if (!pairing.isPaired) { sleep(POLL_MS); continue }

                // Establish / reuse connection.
                val l = link ?: run {
                    val nl = pairing.link()
                    if (nl == null) { sleep(POLL_MS); return@run null }
                    val welcome = nl.connect(BuildConfig.VERSION_NAME)
                    // The daemon refuses every op until identify is sent.
                    val pub = DeviceIdentity.devicePublicKey()
                    val sig = if (pub != null && welcome.challenge.isNotEmpty())
                        DeviceIdentity.signChallenge(welcome.challenge) else null
                    if (pub != null && sig != null) {
                        try {
                            nl.identify(
                                publicKey    = pub,
                                signature    = sig,
                                backing      = DeviceIdentity.deviceKeyBacking(),
                                model        = android.os.Build.MODEL,
                                manufacturer = android.os.Build.MANUFACTURER,
                                attestationChain = DeviceIdentity.deviceAttestationChain(),
                                confirmPublicKey = DeviceIdentity.confirmPublicKey(),
                            )
                        } catch (_: Exception) { /* daemon logged it */ }
                    }
                    link = nl
                    nl
                } ?: continue

                // When the app is in the foreground ChatEngine is live and draining
                // the queue itself — skip our fetch to avoid racing with it.
                if (appInForeground) { sleep(POLL_MS); continue }

                val incoming = l.fetch()
                if (incoming.isEmpty()) { sleep(POLL_MS); continue }

                // Merge into history, deduplicating by serverId.
                val existing  = history.load()
                val knownIds  = existing.mapNotNullTo(HashSet()) { m -> m.serverId.takeIf { it > 0L } }
                val fresh     = incoming.filter { m -> m.serverId == 0L || m.serverId !in knownIds }
                if (fresh.isNotEmpty()) {
                    history.save(existing + fresh)
                    if (AppPrefs(this).notificationsEnabled) {
                        fresh.forEach { notifyMessage(it) }
                    }
                }
            } catch (_: Exception) {
                try { link?.close() } catch (_: Exception) {}
                link = null
            }
            sleep(POLL_MS)
        }
        try { link?.close() } catch (_: Exception) {}
    }

    private fun sleep(ms: Long) {
        try { Thread.sleep(ms) } catch (_: InterruptedException) { running = false }
    }

    private fun notifyMessage(m: Message) {
        if (!NotificationManagerCompat.from(this).areNotificationsEnabled()) return
        val open = PendingIntent.getActivity(
            this, m.serverId.toInt(), Intent(this, ChatActivity::class.java),
            PendingIntent.FLAG_IMMUTABLE,
        )
        val preview = m.text.lineSequence().firstOrNull()?.take(120) ?: m.text.take(120)
        val n = NotificationCompat.Builder(this, CHANNEL_ALERTS)
            .setSmallIcon(R.mipmap.ic_launcher)
            .setContentTitle(getString(R.string.notif_alert_title))
            .setContentText(preview)
            .setStyle(NotificationCompat.BigTextStyle().bigText(m.text.take(1000)))
            .setContentIntent(open)
            .setAutoCancel(true)
            .setPriority(NotificationCompat.PRIORITY_HIGH)
            .build()
        try {
            NotificationManagerCompat.from(this).notify(
                if (m.serverId > 0L) m.serverId.toInt() else System.currentTimeMillis().toInt(),
                n,
            )
        } catch (_: SecurityException) {}
    }

    companion object {
        private const val CHANNEL_ONGOING = "sysentinel-monitoring"
        private const val CHANNEL_ALERTS  = "sysentinel-alerts"
        private const val ID_ONGOING      = 1
        private const val POLL_MS         = 15_000L

        fun ensureChannels(ctx: Context) {
            if (Build.VERSION.SDK_INT < Build.VERSION_CODES.O) return
            val mgr = ctx.getSystemService(NotificationManager::class.java)
            mgr.createNotificationChannel(
                NotificationChannel(
                    CHANNEL_ONGOING,
                    ctx.getString(R.string.notif_channel_monitoring),
                    NotificationManager.IMPORTANCE_LOW,
                )
            )
            mgr.createNotificationChannel(
                NotificationChannel(
                    CHANNEL_ALERTS,
                    ctx.getString(R.string.notif_channel_alerts),
                    NotificationManager.IMPORTANCE_HIGH,
                ).apply { description = ctx.getString(R.string.notif_channel_alerts_desc) }
            )
        }

        /**
         * Set to true by [ChatActivity.onStart] and false by [ChatActivity.onStop].
         * When true, [ChatEngine] is live and draining the daemon queue, so this
         * service skips its own fetch to avoid racing.
         */
        @Volatile var appInForeground = false

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
