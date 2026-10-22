package com.sentinel.soc.watch

import android.app.Service
import android.content.Intent
import android.content.IntentFilter
import android.os.Handler
import android.os.IBinder
import android.os.Looper
import androidx.core.content.ContextCompat
import com.sentinel.soc.BuildConfig
import com.sentinel.soc.SentinelApp
import com.sentinel.soc.inspect.PackageInspector
import com.sentinel.soc.notify.Notifier
import com.sentinel.soc.notify.NotificationIds
import com.sentinel.soc.sync.DeviceScan
import com.sentinel.soc.sync.Outbox
import android.util.Log
import java.util.concurrent.Executors

/**
 * Foreground service: owns the runtime InstallReceiver and the poll loop (Stage 1 section 3).
 * Protected by a persistent low-priority notification, as Android requires for long-running background work.
 */
class WatchService : Service() {

    private lateinit var app: SentinelApp
    private val handler = Handler(Looper.getMainLooper())
    private val executor = Executors.newSingleThreadExecutor()
    private var receiver: InstallReceiver? = null
    private var lastHeartbeatMs = 0L
    private var live: com.sentinel.soc.sync.LiveLink? = null

    private val tick = object : Runnable {
        override fun run() {
            executor.execute { pollTick() }
            handler.postDelayed(this, app.prefs.pollSeconds * 1000L)
        }
    }

    override fun onCreate() {
        super.onCreate()
        app = application as SentinelApp
        startForeground(NotificationIds.SERVICE, Notifier.serviceNotification(this, app.prefs.protectionOn))
        val rx = InstallReceiver(::onInstall)
        val filter = IntentFilter().apply {
            addAction(Intent.ACTION_PACKAGE_ADDED)
            addAction(Intent.ACTION_PACKAGE_REPLACED)
            addAction(Intent.ACTION_PACKAGE_REMOVED)
            addDataScheme("package")
        }
        ContextCompat.registerReceiver(this, rx, filter, ContextCompat.RECEIVER_NOT_EXPORTED)
        receiver = rx
        if (app.prefs.knownPackages == null) {
            // Record the apps installed right now as the baseline; only apps that appear later count as new.
            app.prefs.knownPackages = packageManager.getInstalledPackages(0)
                .filter { (it.applicationInfo?.flags?.and(android.content.pm.ApplicationInfo.FLAG_SYSTEM) ?: 1) == 0 }
                .map { it.packageName }.toSet()
        }
        handler.post(tick)
        live = com.sentinel.soc.sync.LiveLink(app, ::onLiveEvent).also { it.start() }
    }

    /** A pushed pipeline event: apply it now instead of waiting for the next poll, then tell the open screen. */
    private fun onLiveEvent(e: com.sentinel.soc.sync.LiveEvent) {
        executor.execute {
            if (app.prefs.protectionOn) CommandPoller(app).pollOnce()
            if (e.stage == "verdict" || e.stage == "remediation") {
                e.submissionId?.let(app.db::scanBySubmission)?.let { com.sentinel.soc.sync.VerdictDetail.refresh(app, it) }
            }
            app.prefs.lastSyncMs = System.currentTimeMillis()
            app.live.publish(e)
        }
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int = START_STICKY

    override fun onBind(intent: Intent?): IBinder? = null

    override fun onDestroy() {
        live?.stop()
        handler.removeCallbacksAndMessages(null)
        receiver?.let { runCatching { unregisterReceiver(it) } }
        executor.shutdownNow()
        super.onDestroy()
    }

    /** Runs on the executor, never inside onReceive (Stage 1 rule 4). */
    fun onInstall(event: InstallEvent) {
        executor.execute {
            // Only the monitored apps are watched; installs and removals of anything else are ignored.
            if (!com.sentinel.soc.data.MonitoredApps.isMonitored(event.packageName)) return@execute
            val prefs = app.prefs
            if (event.kind == InstallEvent.Kind.REMOVED) {
                // Mark the app as removed, forget it in the baseline, then re-check the tracked apps.
                app.db.latestScanFor(event.packageName)?.let { app.db.updateScan(it.id, mapOf("status" to "skipped_removed")) }
                prefs.knownPackages?.let { prefs.knownPackages = it - event.packageName }
                if (prefs.isPaired) {
                    val progress = DeviceScan.run(this, app)
                    Log.i(TAG, "rescan after removal: ${progress.newApps} new, ${progress.rechecked} re-checked")
                }
                return@execute
            }
            // A newly installed app becomes part of the baseline, so a later manual scan does not repeat it.
            prefs.knownPackages?.let { prefs.knownPackages = it + event.packageName }
            if (!prefs.protectionOn || !prefs.isPaired) return@execute
            val meta = PackageInspector.inspect(this, event.packageName) ?: return@execute
            if (meta.isSystem) return@execute
            val scanId = app.db.insertScan(meta.packageName, meta.appLabel, meta.versionName, null, "detected")
            app.db.trim()
            Notifier.detected(app, scanId, meta.appLabel)
            Outbox.enqueue(this, app, scanId)
        }
    }

    private fun pollTick() {
        val prefs = app.prefs
        if (!prefs.isPaired) return
        val now = System.currentTimeMillis()
        if (now - lastHeartbeatMs >= HEARTBEAT_MS) {
            lastHeartbeatMs = now
            try {
                app.api.heartbeat(BuildConfig.VERSION_NAME, prefs.protectionOn)
            } catch (_: Exception) {
                // Heartbeats are best-effort; the status card shows "Offline" from lastSyncMs.
            }
        }
        if (prefs.protectionOn) CommandPoller(app).pollOnce()
    }

    companion object {
        private const val TAG = "SentinelWatch"
        private const val HEARTBEAT_MS = 30_000L
    }
}
