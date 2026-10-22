package com.sentinel.soc.sync

import com.sentinel.soc.SentinelApp
import com.sentinel.soc.data.ScanRecord
import org.json.JSONObject

/** Fetches a submission and caches it on the local scan row: verdict (signals, IOCs, techniques) and timeline. */
object VerdictDetail {

    /** Network call: run off the main thread. Returns true when the row changed. */
    fun refresh(app: SentinelApp, scan: ScanRecord): Boolean {
        val sid = scan.submissionId ?: return false
        val body = try {
            app.api.getSubmission(sid)
        } catch (_: Exception) {
            return false  // offline: keep the cached detail
        }
        // "skipped_removed" is phone-side knowledge (the app is gone); the server's status must not undo it.
        val fields = mutableMapOf<String, Any?>("detail_json" to body.toString())
        if (scan.status != "skipped_removed") fields["status"] = body.getString("status")
        if (!body.isNull("verdict")) {
            val v = body.getJSONObject("verdict")
            fields += mapOf("label" to v.getString("label"), "confidence" to v.optDouble("confidence", 0.0),
                "summary" to v.optString("summary", ""))
        }
        if (!body.isNull("remediation")) {
            val r = body.getJSONObject("remediation")
            fields += mapOf("remediation_id" to r.getString("id"), "remediation_state" to r.getString("state"))
        }
        app.db.updateScan(scan.id, fields)
        return true
    }

    private fun body(scan: ScanRecord): JSONObject? = scan.detailJson?.let { runCatching { JSONObject(it) }.getOrNull() }

    /** The verdict object. Rows cached by the previous app version hold the verdict itself, not the whole body. */
    fun parse(scan: ScanRecord): JSONObject? {
        val b = body(scan) ?: return null
        return if (b.has("submission_id")) b.optJSONObject("verdict") else b
    }

    fun timeline(scan: ScanRecord): List<LiveEvent> {
        val a = body(scan)?.optJSONArray("timeline") ?: return emptyList()
        return List(a.length()) { i ->
            val e = a.getJSONObject(i)
            LiveEvent(scan.submissionId, e.optString("stage"), e.optString("step"), e.optString("level", "info"),
                e.optString("message"), e.optString("ts"))
        }
    }
}
