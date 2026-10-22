package com.sentinel.soc.ui

import android.app.Activity
import android.content.Intent
import android.content.res.ColorStateList
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.view.View
import androidx.activity.result.contract.ActivityResultContracts
import androidx.appcompat.app.AppCompatActivity
import androidx.core.app.NotificationManagerCompat
import androidx.core.content.ContextCompat
import com.sentinel.soc.R
import com.sentinel.soc.SentinelApp
import com.sentinel.soc.data.ScanRecord
import com.sentinel.soc.databinding.ActivityVerdictBinding
import com.sentinel.soc.inspect.PackageInspector
import com.sentinel.soc.net.ApiException
import com.sentinel.soc.notify.NotificationIds
import com.sentinel.soc.remediate.UninstallLauncher
import java.io.IOException
import java.util.concurrent.Executors

/**
 * Verdict detail and the uninstall flow (Stage 1 frontend section 5). The uninstall dialog is Android's own;
 * the outcome is verified on the device before it is reported to the server.
 */
class VerdictActivity : AppCompatActivity() {

    private lateinit var binding: ActivityVerdictBinding
    private lateinit var app: SentinelApp
    private val worker = Executors.newSingleThreadExecutor()
    private val main = Handler(Looper.getMainLooper())
    private var scanId = -1L
    private var autoUninstall = false
    private var polling = false
    private val poll = object : Runnable {
        override fun run() {
            refreshFromServer()
            if (polling) main.postDelayed(this, 3000)
        }
    }

    private val uninstallLauncher = registerForActivityResult(ActivityResultContracts.StartActivityForResult()) { result ->
        val scan = app.db.scan(scanId) ?: return@registerForActivityResult
        val outcome = UninstallLauncher.outcome(this, scan.packageName, result.resultCode)
        if (outcome == "uninstalled") {
            app.db.updateScan(scan.id, mapOf("status" to "verdict_ready"))
        }
        val remId = scan.remediationId
        if (remId != null) {
            worker.execute {
                try {
                    app.api.reportRemediation(remId, outcome, "")
                    app.db.updateScan(scan.id, mapOf("remediation_state" to when (outcome) {
                        "uninstalled" -> "completed"
                        "declined" -> "declined"
                        else -> "failed"
                    }))
                } catch (e: IOException) {
                    // Keep the local state; the screen says the result is still being sent.
                } catch (e: ApiException) {
                    // 409: the server already has a different outcome; show what the server says on next refresh.
                }
                main.post { render() }
            }
        } else {
            main.post { render() }
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        app = application as SentinelApp
        binding = ActivityVerdictBinding.inflate(layoutInflater)
        setContentView(binding.root)
        scanId = intent.getLongExtra(EXTRA_SCAN_ID, -1L)
        autoUninstall = intent.getBooleanExtra(EXTRA_AUTO_UNINSTALL, false)
        binding.uninstallButton.setOnClickListener { startUninstall() }
        binding.keepButton.setOnClickListener { keepForNow() }
        binding.backButton.setOnClickListener { finish() }
        binding.graphButton.setOnClickListener { startActivity(ThreatGraphActivity.intent(this, scanId)) }
        binding.sheetRoot.scrollTarget = binding.sheetScroll
        binding.sheetRoot.onDismissed = { dismissed = true; finish() }
        NotificationManagerCompat.from(this).cancel(NotificationIds.verdict(scanId))
    }

    // ---- live scan timeline -----------------------------------------------------------------------------------

    /** Steps pushed while this sheet is open, on top of the timeline cached from the server. */
    private val liveEvents = mutableListOf<com.sentinel.soc.sync.LiveEvent>()
    private var loggedCount = -1

    private val liveListener: (com.sentinel.soc.sync.LiveEvent?) -> Unit = { e ->
        runOnUiThread {
            val sid = app.db.scan(scanId)?.submissionId
            if (e != null && sid != null && e.submissionId == sid) liveEvents += e
            render()
        }
    }

    private fun renderTimeline(scan: ScanRecord) {
        val cached = com.sentinel.soc.sync.VerdictDetail.timeline(scan)
        val seen = cached.map { Triple(it.stage, it.step, it.message) }.toSet()
        val events = cached + liveEvents.filter { Triple(it.stage, it.step, it.message) !in seen }
        binding.timeline.setStates(ScanTimeline.states(scan.status, scan.label, events.map { it.stage to it.step }))
        binding.timelineLive.visibility = if (app.live.connected && scan.label == null) View.VISIBLE else View.GONE

        if (events.size == loggedCount) return
        val firstRender = loggedCount < 0
        loggedCount = events.size
        val shown = events.takeLast(6)
        binding.timelineLog.removeAllViews()
        if (shown.isEmpty()) {
            binding.timelineLog.addView(logLine(getString(R.string.timeline_empty), R.color.text_3))
            return
        }
        shown.forEachIndexed { i, e ->
            val color = when {
                e.level == "error" -> R.color.v_malicious
                e.level == "warn" -> R.color.v_suspicious
                e.stage == "verdict" -> R.color.v_benign
                else -> R.color.text_2
            }
            val line = logLine("${clock(e.ts)}  ${e.stage.replace('_', ' ').padEnd(15).take(15)} ${e.message}", color)
            binding.timelineLog.addView(line)
            if (!firstRender && i == shown.lastIndex) {
                line.alpha = 0f; line.translationY = 16f
                line.animate().alpha(1f).translationY(0f).setDuration(260).start()
            }
        }
    }

    private fun logLine(text: String, color: Int) = android.widget.TextView(this).apply {
        this.text = text
        textSize = 10.5f
        typeface = android.graphics.Typeface.MONOSPACE
        maxLines = 1
        ellipsize = android.text.TextUtils.TruncateAt.END
        setTextColor(ContextCompat.getColor(this@VerdictActivity, color))
        setPadding(0, 3, 0, 3)
    }

    /** "2026-10-21T16:45:03Z" -> local "22:15:03". */
    private fun clock(ts: String): String = try {
        val utc = java.text.SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss'Z'", java.util.Locale.US)
            .apply { timeZone = java.util.TimeZone.getTimeZone("UTC") }.parse(ts)
        java.text.SimpleDateFormat("HH:mm:ss", java.util.Locale.getDefault()).format(utc!!)
    } catch (_: Exception) {
        "--:--:--"
    }

    override fun onResume() {
        super.onResume()
        app.live.listen(liveListener)
        render()
        if (!polling) {
            polling = true
            main.post(poll)
        }
        if (autoUninstall) {
            autoUninstall = false
            startUninstall()
        }
    }

    override fun onPause() {
        super.onPause()
        app.live.unlisten(liveListener)
        polling = false
        main.removeCallbacks(poll)
    }

    override fun onDestroy() {
        worker.shutdownNow()
        super.onDestroy()
    }

    private var dismissed = false

    /** Every exit (back, the chevron, a vanished scan) slides the sheet down first; the window has no animation. */
    @Suppress("DEPRECATION")
    override fun finish() {
        if (!dismissed && ::binding.isInitialized) {
            binding.sheetRoot.dismiss()
            return
        }
        super.finish()
        overridePendingTransition(0, 0)
    }

    private fun refreshFromServer() {
        val scan = app.db.scan(scanId) ?: return
        val sid = scan.submissionId ?: return
        if (sid.isEmpty()) return
        // Done and cached in the current format (with the timeline): nothing left to fetch.
        if (scan.status == "verdict_ready" && scan.remediationState == null &&
            scan.detailJson?.contains("\"timeline\"") == true) return
        worker.execute {
            // Offline: keep showing the last known result (Stage 1 frontend section 5).
            com.sentinel.soc.sync.VerdictDetail.refresh(app, scan)
            main.post { render() }
        }
    }

    /** Signals, techniques and indicators. Rebuilt only when the cached detail changes, so the 3 s poll doesn't
     *  replay the entry animation. */
    private var renderedDetail: String? = null

    private fun renderEvidence(scan: ScanRecord) {
        if (scan.detailJson == renderedDetail) return
        renderedDetail = scan.detailJson
        val d = com.sentinel.soc.sync.VerdictDetail.parse(scan) ?: return
        binding.riskScore.text = getString(R.string.risk_score, d.optDouble("score", 0.0))
        binding.provider.text = getString(R.string.verdict_provider, d.optString("provider", "rule_engine"))

        val techniques = d.optJSONArray("techniques")
        binding.techniqueRow.removeAllViews()
        for (i in 0 until (techniques?.length() ?: 0)) {
            val t = techniques!!.getJSONObject(i)
            binding.techniqueRow.addView(pill("${t.optString("id")} · ${t.optString("name")}", R.color.accent))
        }
        binding.techniqueScroll.visibility = if (binding.techniqueRow.childCount > 0) View.VISIBLE else View.GONE

        val signals = d.optJSONArray("signals")
        val n = signals?.length() ?: 0
        binding.signalList.removeAllViews()
        binding.signalsTitle.visibility = if (n > 0) View.VISIBLE else View.GONE
        binding.signalsTitle.text = getString(R.string.signals_title, n)
        for (i in 0 until n) {
            val s = signals!!.getJSONObject(i)
            val color = when (s.optString("severity")) {
                "high" -> R.color.v_malicious
                "medium" -> R.color.v_suspicious
                else -> R.color.v_unknown
            }
            addRow(binding.signalList, s.optString("severity").uppercase(), color, s.optString("name"), s.optString("detail"), i)
        }

        val iocs = d.optJSONObject("iocs")
        binding.iocList.removeAllViews()
        if (iocs != null) {
            val flagged = iocs.optJSONObject("flagged_hosts")
            val telegram = iocs.optBoolean("telegram_bot")
            val hosts = (jsonStrings(iocs, "domains") + jsonStrings(iocs, "ips")).distinct()
            hosts.forEachIndexed { i, host ->
                val reason = flagged?.optString(host)?.takeIf { it.isNotEmpty() }
                val (tag, color) = when {
                    reason != null -> getString(R.string.ioc_flagged) to R.color.v_malicious
                    telegram && host.contains("telegram") -> getString(R.string.ioc_c2) to R.color.v_malicious
                    host.firstOrNull()?.isDigit() == true -> getString(R.string.ioc_c2) to R.color.v_suspicious
                    else -> getString(R.string.ioc_host) to R.color.accent
                }
                addRow(binding.iocList, tag, color, host, reason ?: "", n + i)
            }
            jsonStrings(iocs, "urls").forEachIndexed { i, url ->
                addRow(binding.iocList, getString(R.string.ioc_url), R.color.info, url, "", n + hosts.size + i)
            }
        }
        binding.iocsTitle.visibility = if (binding.iocList.childCount > 0) View.VISIBLE else View.GONE
        binding.graphButton.visibility = if (n > 0 || binding.iocList.childCount > 0) View.VISIBLE else View.GONE
    }

    private fun jsonStrings(o: org.json.JSONObject, key: String): List<String> {
        val a = o.optJSONArray(key) ?: return emptyList()
        return List(a.length()) { a.getString(it) }
    }

    private fun pill(text: String, color: Int) = android.widget.TextView(this).apply {
        this.text = text
        textSize = 11f
        setTypeface(typeface, android.graphics.Typeface.BOLD)
        setTextColor(ContextCompat.getColor(this@VerdictActivity, color))
        setBackgroundResource(R.drawable.bg_chip_pill)
        backgroundTintList = ColorStateList.valueOf(ContextCompat.getColor(this@VerdictActivity, ScanAdapter.softFor(color)))
        val px = (resources.displayMetrics.density * 10).toInt()
        setPadding(px, px / 3, px, px / 3)
        layoutParams = android.widget.LinearLayout.LayoutParams(-2, -2).apply { marginEnd = px / 2 }
    }

    private fun addRow(parent: android.widget.LinearLayout, tag: String, color: Int, title: String, detail: String, index: Int) {
        val row = com.sentinel.soc.databinding.ItemSignalBinding.inflate(layoutInflater, parent, false)
        row.sigLevel.text = tag
        row.sigLevel.setTextColor(ContextCompat.getColor(this, color))
        row.sigLevel.backgroundTintList = ColorStateList.valueOf(ContextCompat.getColor(this, ScanAdapter.softFor(color)))
        row.sigName.text = title
        row.sigDetail.text = detail
        row.sigDetail.visibility = if (detail.isEmpty()) View.GONE else View.VISIBLE
        parent.addView(row.root)
        row.root.alpha = 0f
        row.root.translationX = 40f
        row.root.animate().alpha(1f).translationX(0f).setStartDelay(120L + index.coerceAtMost(14) * 45L)
            .setDuration(280).setInterpolator(android.view.animation.DecelerateInterpolator()).start()
    }

    private fun render() {
        val scan = app.db.scan(scanId)
        if (scan == null) {
            finish()
            return
        }
        val label = scan.label
        binding.appName.text = scan.appLabel ?: scan.packageName
        binding.packageName.text = scan.packageName + (scan.versionName?.let { "  v$it" } ?: "")
        binding.verdictChip.text = verdictText(scan)
        binding.verdictChip.setTextColor(ContextCompat.getColor(this, verdictColor(label)))
        binding.verdictChip.backgroundTintList =
            ColorStateList.valueOf(ContextCompat.getColor(this, ScanAdapter.softFor(verdictColor(label))))
        binding.verdictChip.contentDescription = getString(R.string.verdict_description, verdictText(scan))
        val pct = ((scan.confidence ?: 0.0) * 100).toInt()
        val ringText = if (label == null) "--" else "$pct%"
        if (binding.confidenceRing.centerText != ringText) {
            binding.confidenceRing.sweepDegrees = 360f
            binding.confidenceRing.centerText = ringText
            binding.confidenceRing.subText = getString(R.string.confidence)
            binding.confidenceRing.color = ContextCompat.getColor(this, verdictColor(label))
            binding.confidenceRing.setValue(pct / 100f)
        }
        binding.summary.text = scan.summary?.takeIf { it.isNotBlank() } ?: getString(R.string.verdict_no_summary)
        if (binding.provider.text.isNullOrEmpty()) binding.provider.text = getString(R.string.verdict_provider, "rule_engine")
        renderEvidence(scan)
        renderTimeline(scan)
        // Evidence is on its way: placeholder rows instead of an empty gap.
        binding.evidenceSkeleton.visibility = if (com.sentinel.soc.sync.VerdictDetail.parse(scan) == null &&
            scan.submissionId != null && scan.status !in setOf("upload_failed", "error", "skipped_too_large"))
            View.VISIBLE else View.GONE

        val installed = PackageInspector.isInstalled(this, scan.packageName)
        val remState = scan.remediationState
        val banner: Pair<String, Int>? = when {
            scan.status == "skipped_removed" -> getString(R.string.banner_removed_earlier) to R.color.v_benign
            scan.status == "skipped_too_large" -> getString(R.string.banner_too_large) to R.color.info
            !installed && remState == "completed" -> getString(R.string.banner_uninstalled, scan.appLabel ?: scan.packageName) to R.color.v_benign
            !installed -> getString(R.string.banner_removed_earlier) to R.color.v_benign
            remState == "declined" -> getString(R.string.banner_declined) to R.color.info
            remState == "cancelled" -> getString(R.string.banner_cancelled) to R.color.info
            remState == "failed" -> getString(R.string.banner_failed) to R.color.v_malicious
            scan.status == "upload_failed" || scan.status == "error" -> getString(R.string.banner_upload_failed) to R.color.v_malicious
            scan.label == null && scan.status != "skipped_removed" -> getString(R.string.banner_analysing) to R.color.info
            else -> null
        }
        if (banner != null) {
            binding.banner.visibility = View.VISIBLE
            binding.banner.text = banner.first
            binding.banner.setBackgroundResource(R.drawable.bg_banner)
            binding.banner.backgroundTintList = android.content.res.ColorStateList.valueOf(
                ContextCompat.getColor(this, banner.second))
        } else {
            binding.banner.visibility = View.GONE
        }

        val actionable = installed && (label == "malicious" || label == "suspicious") &&
            remState != "completed" && remState != "declined" && remState != "cancelled"
        val offerAnyway = installed && label == "suspicious" && remState == null
        val canUninstall = installed && (actionable || scan.remediationId != null && remState == "delivered")
        binding.uninstallButton.visibility = if (canUninstall) View.VISIBLE else View.GONE
        binding.uninstallButton.text = getString(R.string.btn_uninstall, scan.appLabel ?: scan.packageName)
        binding.uninstallButton.isEnabled = true
        binding.keepButton.visibility = if (actionable || offerAnyway) View.VISIBLE else View.GONE
        binding.hintSystem.visibility = binding.uninstallButton.visibility
        val inProgress = scan.label == null && scan.status !in setOf("upload_failed", "error", "skipped_removed")
        binding.progress.visibility = if (inProgress) View.VISIBLE else View.GONE
    }

    private fun startUninstall() {
        val scan = app.db.scan(scanId) ?: return
        if (!PackageInspector.isInstalled(this, scan.packageName)) {
            render()
            return
        }
        uninstallLauncher.launch(UninstallLauncher.intent(scan.packageName))
    }

    private fun keepForNow() {
        val scan = app.db.scan(scanId) ?: return
        if (scan.remediationId == null) {
            render()
            return
        }
        worker.execute {
            // On failure: report again on the next visit; the banner will say what the server knows.
            com.sentinel.soc.remediate.Remediation.decline(app, scan)
            main.post { render() }
        }
    }

    private fun verdictText(scan: ScanRecord): String = when (scan.label) {
        "malicious" -> getString(R.string.verdict_malicious)
        "suspicious" -> getString(R.string.verdict_suspicious)
        "benign" -> getString(R.string.verdict_benign)
        "unknown" -> getString(R.string.verdict_unknown)
        else -> getString(statusLabel(scan.status))
    }

    private fun statusLabel(status: String): Int = when (status) {
        "submitted", "analyzing" -> R.string.status_label_static_analysis
        "uploading" -> R.string.status_label_awaiting_upload
        "skipped_removed" -> R.string.status_label_removed
        "upload_failed", "error" -> R.string.status_label_error
        else -> R.string.status_label_queued
    }

    private fun verdictColor(label: String?): Int = when (label) {
        "malicious" -> R.color.v_malicious
        "suspicious" -> R.color.v_suspicious
        "benign" -> R.color.v_benign
        else -> R.color.v_unknown
    }

    companion object {
        const val EXTRA_SCAN_ID = "scan_id"
        const val EXTRA_AUTO_UNINSTALL = "auto_start_uninstall"

        fun intent(activity: Activity, scanId: Long): Intent =
            Intent(activity, VerdictActivity::class.java).putExtra(EXTRA_SCAN_ID, scanId)
    }
}
