package com.sentinel.soc.watch

import android.util.Log
import com.sentinel.soc.SentinelApp
import com.sentinel.soc.net.ApiException
import com.sentinel.soc.notify.Notifier

/**
 * Polls /devices/me/commands with a numeric cursor, applies each command, then acks it (Stage 1 section 3).
 * Idempotent: applying the same command id twice is harmless.
 */
class CommandPoller(private val app: SentinelApp) {

    fun pollOnce() {
        val prefs = app.prefs
        if (!prefs.isPaired) return
        val resp = try {
            app.api.pollCommands(prefs.commandCursor)
        } catch (e: ApiException) {
            if (e.code == "invalid_token") app.prefs.unpair()
            Log.w(TAG, "poll failed: ${e.code}")
            return
        } catch (e: java.io.IOException) {
            // Offline or server down: keep the cursor and try again on the next tick. Never crash the service.
            Log.w(TAG, "poll unreachable: ${e.message}")
            return
        }
        val commands = resp.getJSONArray("commands")
        for (i in 0 until commands.length()) {
            val cmd = commands.getJSONObject(i)
            val id = cmd.getLong("id")
            val payload = cmd.getJSONObject("payload")
            when (cmd.getString("type")) {
                "verdict_notify" -> applyVerdict(payload)
                "uninstall_proposed" -> applyProposal(payload)
                "uninstall_cancelled" -> applyCancel(payload)
            }
            try {
                app.api.ackCommand(id)
            } catch (e: ApiException) {
                Log.w(TAG, "ack failed for $id: ${e.code}")
                return
            } catch (e: java.io.IOException) {
                Log.w(TAG, "ack unreachable for $id")
                return
            }
            prefs.commandCursor = id
        }
        prefs.lastSyncMs = System.currentTimeMillis()
    }

    private fun applyVerdict(p: org.json.JSONObject) {
        val sid = p.getString("submission_id")
        val label = p.getString("label")
        val confidence = p.optDouble("confidence", 0.0)
        val summary = p.optString("summary", "")
        val scan = app.db.scanBySubmission(sid)
        val pkg = p.optString("package_name", "")
        if (scan != null) {
            app.db.updateScan(scan.id, mapOf("status" to "verdict_ready", "label" to label,
                "confidence" to confidence, "summary" to summary))
        }
        if (label == "malicious" || label == "suspicious" || app.prefs.notifySafe) {
            Notifier.verdict(app, scan?.id ?: 0L, p.optString("app_label", pkg), label, confidence, summary)
        }
    }

    private fun applyProposal(p: org.json.JSONObject) {
        val remId = p.getString("remediation_id")
        val sid = p.optString("submission_id", "")
        val scan = app.db.scanBySubmission(sid) ?: return
        app.db.updateScan(scan.id, mapOf("remediation_id" to remId, "remediation_state" to "delivered"))
        Notifier.uninstallProposed(app, scan.id, p.optString("app_label", scan.packageName))
    }

    private fun applyCancel(p: org.json.JSONObject) {
        val scan = app.db.scanByRemediation(p.getString("remediation_id")) ?: return
        app.db.updateScan(scan.id, mapOf("remediation_state" to "cancelled"))
        Notifier.cancelUninstall(app, scan.id)
    }

    companion object {
        private const val TAG = "SentinelPoller"
    }
}
