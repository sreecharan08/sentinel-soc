package com.sentinel.soc.remediate

import com.sentinel.soc.SentinelApp
import com.sentinel.soc.data.ScanRecord

object Remediation {

    val OPEN_STATES = setOf("pending", "delivered")

    /** A request still needs the user only while its state is open AND the app is still on the phone. */
    fun isOpen(context: android.content.Context, scan: ScanRecord): Boolean =
        scan.remediationState in OPEN_STATES &&
            com.sentinel.soc.inspect.PackageInspector.isInstalled(context, scan.packageName)

    fun openRequests(app: SentinelApp): List<ScanRecord> = app.db.remediations().filter { isOpen(app, it) }

    /** Tells the SOC the user keeps the app. Network call: run off the main thread. False = try again later. */
    fun decline(app: SentinelApp, scan: ScanRecord): Boolean {
        val remId = scan.remediationId ?: return false
        return try {
            app.api.reportRemediation(remId, "declined", "")
            app.db.updateScan(scan.id, mapOf("remediation_state" to "declined"))
            true
        } catch (_: Exception) {
            false
        }
    }
}
