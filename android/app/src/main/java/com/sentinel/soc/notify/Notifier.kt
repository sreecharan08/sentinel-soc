package com.sentinel.soc.notify

import android.Manifest
import android.app.Notification
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import androidx.core.app.ActivityCompat
import androidx.core.app.NotificationCompat
import androidx.core.app.NotificationManagerCompat
import com.sentinel.soc.R
import com.sentinel.soc.SentinelApp
import com.sentinel.soc.ui.InboxActivity
import com.sentinel.soc.ui.VerdictActivity

object NotificationIds {
    const val SERVICE = 1
    fun verdict(scanId: Long): Int = 2000 + scanId.toInt()
}

/** Builds and posts notifications (Stage 1 section 9). Tapping opens VerdictActivity with the scan id. */
object Notifier {

    fun serviceNotification(context: Context, protectionOn: Boolean): Notification {
        val open = PendingIntent.getActivity(context, 0,
            Intent(context, com.sentinel.soc.ui.MainActivity::class.java),
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT)
        return NotificationCompat.Builder(context, SentinelApp.CHANNEL_STATUS)
            .setSmallIcon(R.drawable.ic_stat_shield)
            .setContentTitle(context.getString(R.string.notif_service_title))
            .setContentText(context.getString(
                if (protectionOn) R.string.notif_service_text else R.string.notif_service_text_off))
            .setOngoing(true)
            .setContentIntent(open)
            .setPriority(NotificationCompat.PRIORITY_LOW)
            .build()
    }

    fun verdict(app: SentinelApp, scanId: Long, appLabel: String, label: String, confidence: Double, summary: String) {
        val title = when (label) {
            "malicious" -> app.getString(R.string.notif_malicious_title)
            "suspicious" -> app.getString(R.string.notif_suspicious_title)
            else -> app.getString(R.string.notif_benign_title)
        }
        val text = app.getString(R.string.notif_verdict_text, appLabel, (confidence * 100).toInt())
        post(app, scanId, title, if (summary.isNotBlank()) summary else text, label)
    }

    fun uninstallProposed(app: SentinelApp, scanId: Long, appLabel: String) {
        post(app, scanId, app.getString(R.string.notif_proposed_title, appLabel),
            app.getString(R.string.notif_proposed_text), "suspicious")
    }

    fun cancelUninstall(app: SentinelApp, scanId: Long) {
        NotificationManagerCompat.from(app).cancel(NotificationIds.verdict(scanId))
    }

    /** Immediate heads-up when a monitored app appears; the verdict notification later replaces it (same id). */
    fun detected(app: SentinelApp, scanId: Long, appLabel: String) {
        post(app, scanId, app.getString(R.string.notif_detected_title),
            app.getString(R.string.notif_detected_text, appLabel), "unknown")
    }

    private fun post(app: SentinelApp, scanId: Long, title: String, text: String, label: String) {
        if (ActivityCompat.checkSelfPermission(app, Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED
            && android.os.Build.VERSION.SDK_INT >= 33) return
        val intent = Intent(app, VerdictActivity::class.java).apply {
            putExtra(VerdictActivity.EXTRA_SCAN_ID, scanId)
            flags = Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TOP
        }
        val pi = PendingIntent.getActivity(app, scanId.toInt(), intent,
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT)
        val inbox = PendingIntent.getActivity(app, -scanId.toInt() - 1,
            Intent(app, InboxActivity::class.java).apply { flags = Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TOP },
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT)
        val colour = when (label) {
            "malicious" -> 0xFFF0524F.toInt()
            "suspicious" -> 0xFFF5A524.toInt()
            "benign" -> 0xFF2FBF71.toInt()
            else -> 0xFF8B98A8.toInt()
        }
        val builder = NotificationCompat.Builder(app, SentinelApp.CHANNEL_ALERTS)
            .setSmallIcon(R.drawable.ic_stat_shield)
            .setContentTitle(title)
            .setContentText(text)
            .setStyle(NotificationCompat.BigTextStyle().bigText(text))
            .setColor(colour)
            .setPublicVersion(NotificationCompat.Builder(app, SentinelApp.CHANNEL_ALERTS)
                .setSmallIcon(R.drawable.ic_stat_shield)
                .setContentTitle(app.getString(R.string.notif_public_title))
                .build())
            .setContentIntent(pi)
            .setAutoCancel(true)
            .setPriority(NotificationCompat.PRIORITY_HIGH)
        if (label == "malicious" || label == "suspicious") {
            builder.addAction(0, app.getString(R.string.notif_action_details), inbox)
        }
        app.getSystemService(NotificationManager::class.java).notify(NotificationIds.verdict(scanId), builder.build())
    }
}
