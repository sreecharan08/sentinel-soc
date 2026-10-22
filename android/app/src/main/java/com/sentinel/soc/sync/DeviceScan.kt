package com.sentinel.soc.sync

import android.content.Context
import com.sentinel.soc.SentinelApp
import com.sentinel.soc.data.MonitoredApps
import com.sentinel.soc.inspect.ApkHasher
import java.io.File

/**
 * "Scan device": checks the monitored apps that are installed on this phone (see [MonitoredApps]). Nothing else on
 * the phone is looked at. Each installed monitored app gets a fresh scan; apps that are not installed are skipped.
 */
object DeviceScan {

    data class Progress(val newApps: Int, val rechecked: Int, val baselined: Boolean)

    @Suppress("DEPRECATION")
    fun run(context: Context, app: SentinelApp): Progress {
        val pm = context.packageManager
        var newApps = 0
        var rechecked = 0
        for (pkg in MonitoredApps.packages) {
            val info = try {
                pm.getPackageInfo(pkg, 0)
            } catch (_: android.content.pm.PackageManager.NameNotFoundException) {
                continue   // not installed: nothing to scan
            }
            val ai = info.applicationInfo ?: continue
            val sha = try {
                ApkHasher.sha256(File(ai.sourceDir))
            } catch (_: Exception) {
                continue
            }
            val previous = app.db.latestScanFor(pkg)
            val label = pm.getApplicationLabel(ai).toString()
            val scanId = app.db.insertScan(pkg, label, info.versionName, sha, "detected")
            Outbox.enqueue(context, app, scanId)
            if (previous == null || previous.status == "skipped_removed") newApps++ else rechecked++
        }
        app.prefs.knownPackages = MonitoredApps.packages.filter {
            try { pm.getPackageInfo(it, 0); true } catch (_: Exception) { false }
        }.toSet()
        return Progress(newApps = newApps, rechecked = rechecked, baselined = false)
    }
}
