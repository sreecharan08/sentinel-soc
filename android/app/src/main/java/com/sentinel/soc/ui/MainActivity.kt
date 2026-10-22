package com.sentinel.soc.ui

import android.Manifest
import android.content.Intent
import android.content.pm.PackageManager
import android.os.Build
import android.os.Bundle
import android.provider.Settings
import android.view.View
import androidx.appcompat.app.AppCompatActivity
import androidx.core.app.ActivityCompat
import androidx.core.app.NotificationManagerCompat
import androidx.core.content.ContextCompat
import androidx.core.splashscreen.SplashScreen.Companion.installSplashScreen
import androidx.recyclerview.widget.LinearLayoutManager
import com.sentinel.soc.R
import com.sentinel.soc.SentinelApp
import com.sentinel.soc.databinding.ActivityMainBinding
import com.sentinel.soc.watch.WatchService

/** Status, protection toggle, recent scans. Screen states follow Stage 1 frontend section 4. */
class MainActivity : AppCompatActivity() {

    private lateinit var binding: ActivityMainBinding
    private lateinit var app: SentinelApp
    // id <= 0 is a placeholder row for a monitored app that has no scan yet; there is no result screen for it.
    private val adapter = ScanAdapter(
        onClick = { scan -> if (scan.id > 0) openVerdict(scan.id) },
        onLongClick = { scan, row -> quickActions(scan, row) })
    private val installedAdapter = InstalledAdapter(
        onClick = { item -> onInstalledTapped(item) },
        onLongClick = { item, row -> item.scan?.let { quickActions(it, row) } })

    /** User apps installed right now (package, label, version). Refreshed off the UI thread, then joined with scans. */
    @Volatile private var installedCache: List<Triple<String, String, String?>> = emptyList()
    private var tick = 0

    private val notifPermission = registerForActivityResult(
        androidx.activity.result.contract.ActivityResultContracts.RequestPermission()) { refresh() }

    override fun onCreate(savedInstanceState: Bundle?) {
        val splash = installSplashScreen()
        val launchedAt = android.os.SystemClock.uptimeMillis()
        // Let the shield finish drawing before Home appears, then zoom the icon out.
        splash.setKeepOnScreenCondition { android.os.SystemClock.uptimeMillis() - launchedAt < 850 }
        splash.setOnExitAnimationListener { provider ->
            // Splashes shown on in-app relaunch have no icon view; the getter throws instead of returning null.
            runCatching { provider.iconView }.getOrNull()
                ?.animate()?.scaleX(1.8f)?.scaleY(1.8f)?.alpha(0f)?.setDuration(320)?.start()
            provider.view.animate().alpha(0f).setStartDelay(120).setDuration(300)
                .withEndAction { provider.remove() }.start()
        }
        super.onCreate(savedInstanceState)
        app = application as SentinelApp
        binding = ActivityMainBinding.inflate(layoutInflater)
        setContentView(binding.root)
        binding.scanList.layoutManager = LinearLayoutManager(this)
        binding.scanList.adapter = adapter
        binding.installedList.layoutManager = LinearLayoutManager(this)
        binding.installedList.adapter = installedAdapter
        binding.protectionSwitch.setOnCheckedChangeListener { _, checked ->
            if (checked == app.prefs.protectionOn) return@setOnCheckedChangeListener
            app.prefs.protectionOn = checked
            if (checked) startWatch() else refresh()
            refresh()
        }
        binding.statusCard.setOnClickListener { onStatusTapped() }
        binding.fixNotifications.setOnClickListener { askNotifications() }
        binding.scanDeviceButton.setOnClickListener { scanDevice() }
        BottomNav.wire(this, binding.bottomNav, BottomNav.Tab.HOME,
            onHomeTap = { binding.scrollHome.smoothScrollTo(0, 0) },
            onActivityTap = { binding.scrollHome.smoothScrollTo(0, binding.recentScansTitle.top) })
        binding.statusOrb.onDragging = { dragging -> binding.refreshHome.isEnabled = !dragging }
        binding.refreshHome.setColorSchemeResources(R.color.accent)
        binding.refreshHome.setProgressBackgroundColorSchemeResource(R.color.bg_2)
        binding.refreshHome.setOnRefreshListener {
            loadInstalled()
            refresh()
            handler.postDelayed({
                binding.refreshHome.isRefreshing = false
                android.widget.Toast.makeText(this, R.string.refreshed, android.widget.Toast.LENGTH_SHORT).show()
            }, 700)
        }
        binding.scoreGauge.sweepDegrees = 270f
        binding.historyLegend.text = legend()
    }

    // ---- live push (WebSocket via the watch service) -------------------------------------------------------------

    private val liveListener: (com.sentinel.soc.sync.LiveEvent?) -> Unit = { e ->
        runOnUiThread {
            renderLive()
            if (e != null) {
                refresh()
                headsUpFor(e)
            }
        }
    }

    private fun renderLive() {
        val on = app.live.connected
        val color = ContextCompat.getColor(this, if (on) R.color.v_benign else R.color.v_unknown)
        binding.liveText.setText(if (on) R.string.live_on else R.string.live_off)
        binding.liveText.setTextColor(color)
        binding.liveDot.backgroundTintList = android.content.res.ColorStateList.valueOf(color)
        binding.livePill.backgroundTintList = android.content.res.ColorStateList.valueOf(
            ContextCompat.getColor(this, if (on) R.color.v_benign_soft else R.color.v_unknown_soft))
        if (on) {
            binding.liveDot.animate().alpha(0.25f).setDuration(700).withEndAction {
                binding.liveDot.animate().alpha(1f).setDuration(700).start()
            }.start()
        }
        val last = app.live.last
        binding.liveTicker.visibility = if (last != null) View.VISIBLE else View.GONE
        if (last != null) binding.liveTicker.text = "› ${last.stage.replace('_', ' ')} · ${last.message}"
    }

    /** A verdict or an analyst request that arrives while the app is open drops a banner from the top. */
    private fun headsUpFor(e: com.sentinel.soc.sync.LiveEvent) {
        val scan = e.submissionId?.let(app.db::scanBySubmission) ?: return
        val name = scan.appLabel ?: scan.packageName
        val (text, color) = when {
            e.stage == "verdict" && e.step == "stored" && scan.label != null ->
                getString(R.string.headsup_verdict, name, scan.label.uppercase()) to ScanAdapter.colorFor(scan.label)
            e.stage == "remediation" && e.step == "proposed" ->
                getString(R.string.headsup_request, name) to R.color.v_malicious
            else -> return
        }
        val c = ContextCompat.getColor(this, color)
        binding.headsUpText.text = text
        AppIcons.bind(binding.headsUpAppIcon, binding.headsUpIcon, scan.packageName)
        binding.headsUpIcon.setTextColor(c)
        binding.headsUpIcon.backgroundTintList =
            android.content.res.ColorStateList.valueOf(ContextCompat.getColor(this, ScanAdapter.softFor(color)))
        binding.headsUp.setOnClickListener { hideHeadsUp(); openVerdict(scan.id) }
        binding.headsUp.performHapticFeedback(if (Build.VERSION.SDK_INT >= 30) android.view.HapticFeedbackConstants.CONFIRM
            else android.view.HapticFeedbackConstants.VIRTUAL_KEY)
        binding.headsUp.translationY = -binding.headsUp.height.toFloat() - 200f
        binding.headsUp.visibility = View.VISIBLE
        binding.headsUp.animate().translationY(0f).setDuration(340)
            .setInterpolator(android.view.animation.OvershootInterpolator(0.9f)).start()
        handler.removeCallbacks(hideHeadsUpRunnable)
        handler.postDelayed(hideHeadsUpRunnable, 5000)
        if (scan.label == "malicious" && e.stage == "verdict") threatMoment()
    }

    private val hideHeadsUpRunnable = Runnable { hideHeadsUp() }

    // ---- threat moment ---------------------------------------------------------------------------------------

    /** Malicious apps on the phone at the last refresh; -1 until the first one, so opening the app isn't a "new" threat. */
    private var lastThreats = -1
    private var lastMomentMs = 0L

    /** A new threat: red edge pulse + vibration, the orb bursts, the status card shakes. */
    private fun threatMoment() {
        val now = System.currentTimeMillis()
        if (now - lastMomentMs < 4000) return
        lastMomentMs = now
        binding.vignette.flash()
        binding.statusOrb.setThreat(false)  // re-arm so the burst fires even if the orb already knew
        binding.statusOrb.setThreat(true)
        binding.scrollHome.smoothScrollTo(0, 0)
        val card = binding.statusCard
        android.animation.ObjectAnimator.ofFloat(card, View.TRANSLATION_X, 0f, -18f, 16f, -12f, 9f, -5f, 0f)
            .setDuration(520).start()
    }

    private fun hideHeadsUp() {
        binding.headsUp.animate().translationY(-binding.headsUp.height.toFloat() - 200f).setDuration(260)
            .withEndAction { binding.headsUp.visibility = View.INVISIBLE }.start()
    }

    // ---- security score + history --------------------------------------------------------------------------------

    private fun renderScore(installedFlagged: List<com.sentinel.soc.data.ScanRecord>, online: Boolean) {
        val malicious = installedFlagged.count { it.label == "malicious" }
        val suspicious = installedFlagged.count { it.label == "suspicious" }
        val requests = com.sentinel.soc.remediate.Remediation.openRequests(app).size
        val inputs = SecurityScore.Inputs(malicious, suspicious, app.prefs.protectionOn, notificationsAllowed(), online, requests)
        val score = SecurityScore.of(inputs)
        val (gradeRes, colorRes) = SecurityScore.grade(score)
        val color = ContextCompat.getColor(this, colorRes)
        if (binding.scoreGauge.centerText != score.toString()) {
            binding.scoreGauge.centerText = score.toString()
            binding.scoreGauge.subText = "/ 100"
            binding.scoreGauge.color = color
            binding.scoreGauge.setValue(score / 100f)
        }
        binding.scoreGrade.setText(gradeRes)
        binding.scoreGrade.setTextColor(color)
        val reasons = buildList {
            if (malicious > 0) add(getString(R.string.reason_malicious, malicious))
            if (suspicious > 0) add(getString(R.string.reason_suspicious, suspicious))
            if (!inputs.protectionOn) add(getString(R.string.reason_protection_off))
            if (!inputs.alertsOn) add(getString(R.string.reason_alerts_off))
            if (!online) add(getString(R.string.reason_offline))
            if (requests > 0) add(getString(R.string.reason_requests, requests))
        }
        binding.scoreReasons.text = if (reasons.isEmpty()) getString(R.string.reason_all_clear)
            else reasons.joinToString("\n") { "• $it" }
        binding.historyChart.setData(app.db.historyByDay(14))
    }

    private fun legend(): CharSequence {
        val text = getString(R.string.history_legend)
        val span = android.text.SpannableString(text)
        val colors = listOf(R.color.v_malicious, R.color.v_suspicious, R.color.v_benign, R.color.info)
        var from = 0
        for (c in colors) {
            val i = text.indexOf('●', from)
            if (i < 0) break
            span.setSpan(android.text.style.ForegroundColorSpan(ContextCompat.getColor(this, c)), i, i + 1, 0)
            from = i + 1
        }
        return span
    }

    private val swipe by lazy { BottomNav.Swipe(this, BottomNav.Tab.HOME) { listOf(binding.statusOrb) } }

    override fun dispatchTouchEvent(ev: android.view.MotionEvent): Boolean {
        swipe.onTouch(ev)
        return super.dispatchTouchEvent(ev)
    }

    @Suppress("DEPRECATION")
    private fun openVerdict(scanId: Long, autoUninstall: Boolean = false) {
        startActivity(VerdictActivity.intent(this, scanId).putExtra(VerdictActivity.EXTRA_AUTO_UNINSTALL, autoUninstall))
        overridePendingTransition(0, 0)  // the sheet animates itself
    }

    /** Long-press on a row: details, plus "Uninstall now" for a flagged app that is still on the phone. */
    private fun quickActions(scan: com.sentinel.soc.data.ScanRecord, row: View) {
        if (scan.id <= 0) return
        row.performHapticFeedback(android.view.HapticFeedbackConstants.LONG_PRESS)
        val flagged = (scan.label == "malicious" || scan.label == "suspicious") && scan.status != "skipped_removed"
        android.widget.PopupMenu(this, row).apply {
            menuInflater.inflate(R.menu.scan_quick_actions, menu)
            menu.findItem(R.id.actionUninstallNow).isVisible = flagged
            setOnMenuItemClickListener {
                openVerdict(scan.id, autoUninstall = it.itemId == R.id.actionUninstallNow)
                true
            }
            show()
        }
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        setIntent(intent)
        maybeScrollToActivity()
    }

    private fun maybeScrollToActivity() {
        if (intent.getBooleanExtra(EXTRA_SCROLL_TO_ACTIVITY, false)) {
            intent.removeExtra(EXTRA_SCROLL_TO_ACTIVITY)
            binding.scrollHome.post { binding.scrollHome.smoothScrollTo(0, binding.recentScansTitle.top) }
        }
    }

    private val handler = android.os.Handler(android.os.Looper.getMainLooper())
    private val ticker = object : Runnable {
        override fun run() {
            refresh()
            if (++tick % 5 == 0) loadInstalled()   // every ~10 s: picks up installs/removals made while this screen is open
            handler.postDelayed(this, 2000)
        }
    }

    override fun onResume() {
        super.onResume()
        if (!app.prefs.isPaired) {
            startActivity(Intent(this, PairingActivity::class.java))
            finish()
            return
        }
        binding.statusOrb.onResume()
        app.live.listen(liveListener)
        renderLive()
        app.db.keepOnly(com.sentinel.soc.data.MonitoredApps.packages)
        if (app.prefs.protectionOn) startWatch()
        askNotificationsOnce()
        refresh()
        loadInstalled()
        maybeScrollToActivity()
        handler.removeCallbacks(ticker)
        handler.postDelayed(ticker, 2000)  // keep the status card and feed live while visible
    }

    override fun onPause() {
        super.onPause()
        binding.statusOrb.onPause()
        app.live.unlisten(liveListener)
        handler.removeCallbacks(ticker)
    }

    /** Checks every user app on the phone. Results appear in the list as each one comes back from the server. */
    private fun scanDevice() {
        binding.scanDeviceButton.isEnabled = false
        Thread {
            com.sentinel.soc.sync.DeviceScan.run(this, app)
            runOnUiThread {
                binding.scanDeviceButton.isEnabled = true
                loadInstalled()
                refresh()
            }
        }.start()
    }

    /**
     * Reads the installed user apps on a worker thread and, in the same pass, marks any tracked app that is gone as
     * removed (it keeps its verdict and stays in Recent scans). Apps that are not installed never reach the
     * "Apps on this phone" list.
     */
    @Suppress("DEPRECATION")
    private fun loadInstalled() {
        Thread {
            val pm = packageManager
            // Only the monitored apps are ever looked up; the rest of the phone is not listed or scanned.
            val rows = com.sentinel.soc.data.MonitoredApps.labels.keys.mapNotNull { pkg ->
                try {
                    val info = pm.getPackageInfo(pkg, 0)
                    val ai = info.applicationInfo ?: return@mapNotNull null
                    Triple(pkg, pm.getApplicationLabel(ai).toString(), info.versionName)
                } catch (_: android.content.pm.PackageManager.NameNotFoundException) {
                    null
                }
            }
            val installed = rows.map { it.first }.toSet()
            com.sentinel.soc.data.MonitoredApps.labels.keys.forEach(AppIcons::evict)  // installs/removals since
            val changed = app.db.markGoneAsRemoved { it in installed || com.sentinel.soc.inspect.PackageInspector.isInstalled(this, it) }
            installedCache = rows
            runOnUiThread {
                if (binding.installedSkeleton.visibility == View.VISIBLE) {
                    binding.installedSkeleton.animate().alpha(0f).setDuration(200)
                        .withEndAction { binding.installedSkeleton.visibility = View.GONE }.start()
                }
                if (changed > 0 || !isFinishing) refresh()
            }
        }.start()
    }

    /** Scanned apps open their result; an app that has not been checked yet is queued for a scan. */
    private fun onInstalledTapped(item: InstalledApp) {
        val scan = item.scan
        if (scan != null && scan.status != "skipped_removed") {
            openVerdict(scan.id)
            return
        }
        if (!app.prefs.isPaired) return
        val scanId = app.db.insertScan(item.packageName, item.label, item.versionName, null, "detected")
        app.prefs.knownPackages = (app.prefs.knownPackages ?: emptySet()) + item.packageName
        com.sentinel.soc.sync.Outbox.enqueue(this, app, scanId)
        refresh()
    }

    /**
     * The report under the scan button: "scanning" while any tracked app has no verdict yet,
     * then either the malicious apps found or "No malicious apps found".
     */
    private fun showReport(tracked: List<com.sentinel.soc.data.ScanRecord>) {
        val pending = tracked.filter { it.label == null && it.status !in setOf("verdict_ready", "upload_failed",
            "error", "skipped_too_large", "skipped_removed") }
        val malicious = tracked.filter { it.label == "malicious" }
        val suspicious = tracked.count { it.label == "suspicious" }
        val safe = tracked.count { it.label == "benign" }
        binding.scanSummary.text = when {
            tracked.isEmpty() -> getString(R.string.scan_none)
            pending.isNotEmpty() -> getString(R.string.report_scanning, pending.size)
            malicious.isEmpty() -> getString(R.string.report_clean, tracked.size, suspicious, safe)
            else -> getString(R.string.report_malicious, malicious.size, malicious.joinToString { it.appLabel ?: it.packageName })
        }
    }

    private fun startWatch() {
        ContextCompat.startForegroundService(this, Intent(this, WatchService::class.java))
    }

    private fun askNotificationsOnce() {
        if (Build.VERSION.SDK_INT >= 33 && !notificationsAllowed() && !app.prefs.notifAskedOnce) {
            app.prefs.notifAskedOnce = true
            notifPermission.launch(Manifest.permission.POST_NOTIFICATIONS)
        }
    }

    /** First ask the system dialog; if it cannot be shown any more, open this app's notification settings. */
    private fun askNotifications() {
        val permissionGranted = Build.VERSION.SDK_INT < 33 ||
            ContextCompat.checkSelfPermission(this, Manifest.permission.POST_NOTIFICATIONS) == PackageManager.PERMISSION_GRANTED
        if (!permissionGranted && !ActivityCompat.shouldShowRequestPermissionRationale(this, Manifest.permission.POST_NOTIFICATIONS)
            && app.prefs.notifAskedOnce) {
            startActivity(Intent(Settings.ACTION_APP_NOTIFICATION_SETTINGS).putExtra(Settings.EXTRA_APP_PACKAGE, packageName))
        } else if (!permissionGranted) {
            notifPermission.launch(Manifest.permission.POST_NOTIFICATIONS)
        } else {
            startActivity(Intent(Settings.ACTION_APP_NOTIFICATION_SETTINGS).putExtra(Settings.EXTRA_APP_PACKAGE, packageName))
        }
    }

    private fun onStatusTapped() {
        if (!notificationsAllowed()) askNotifications() else startWatch()
    }

    private fun notificationsAllowed(): Boolean = NotificationManagerCompat.from(this).areNotificationsEnabled() &&
        (Build.VERSION.SDK_INT < 33 || ContextCompat.checkSelfPermission(this, Manifest.permission.POST_NOTIFICATIONS)
            == PackageManager.PERMISSION_GRANTED)

    fun refresh() {
        val prefs = app.prefs
        val now = System.currentTimeMillis()
        val syncedAgo = if (prefs.lastSyncMs == 0L) null else (now - prefs.lastSyncMs) / 1000
        val host = prefs.serverUrl.removePrefix("http://").removePrefix("https://")

        binding.protectionSwitch.isChecked = prefs.protectionOn
        binding.protectionState.text = getString(if (prefs.protectionOn) R.string.toggle_on else R.string.toggle_off)

        // One status at a time, in priority order (Stage 1 frontend section 4). Colour/speed on the orb IS the
        // state; it carries no separate icon.
        val threatsOnPhone = app.db.recent().count {
            com.sentinel.soc.data.MonitoredApps.isMonitored(it.packageName) &&
                it.status != "skipped_removed" && it.label == "malicious"
        }
        val (title, subtitle, tint) = when {
            !notificationsAllowed() -> Triple(getString(R.string.status_alerts_off),
                getString(R.string.status_alerts_off_sub), R.color.v_malicious)
            !prefs.protectionOn -> Triple(getString(R.string.status_paused),
                getString(R.string.status_paused_sub), R.color.v_unknown)
            threatsOnPhone > 0 -> Triple(getString(R.string.status_threat),
                getString(R.string.status_threat_sub, threatsOnPhone), R.color.v_malicious)
            syncedAgo == null || syncedAgo > 60 -> Triple(getString(R.string.status_offline),
                getString(R.string.status_offline_sub), R.color.v_suspicious)
            else -> Triple(getString(R.string.status_protected),
                getString(R.string.status_protected_sub, host, syncedAgo), R.color.v_benign)
        }
        binding.statusOrb.setColor(ContextCompat.getColor(this, tint))
        binding.statusOrb.setPulsing(!binding.scanDeviceButton.isEnabled)
        binding.statusOrb.setThreat(threatsOnPhone > 0)
        if (lastThreats >= 0 && threatsOnPhone > lastThreats) threatMoment()
        lastThreats = threatsOnPhone
        binding.statusTitle.text = title
        binding.statusTitle.setTextColor(ContextCompat.getColor(this, tint))
        binding.statusSubtitle.text = subtitle
        binding.fixNotifications.visibility = if (notificationsAllowed()) View.GONE else View.VISIBLE

        // Recent scans: all monitored apps, newest activity first, removed ones included. A monitored app with no
        // scan yet gets a placeholder row so the list always shows the full set.
        val monitored = com.sentinel.soc.data.MonitoredApps
        val real = app.db.recent().filter { monitored.isMonitored(it.packageName) }
        val seen = real.map { it.packageName }.toSet()
        val placeholders = monitored.labels.filterKeys { it !in seen }.map { (pkg, label) ->
            com.sentinel.soc.data.ScanRecord(-1, pkg, label, null, null, null, "never_scanned", null, null, null, null, null, 0L, 0L)
        }
        val scans = real + placeholders
        showReport(real.filter { it.status != "skipped_removed" })
        binding.statToday.statValue.text = real.count { it.createdAt >= startOfToday() }.toString()
        binding.statToday.statLabel.text = getString(R.string.stat_today)
        // Threats still on the phone: a removed app keeps its row in Recent scans but is no longer a threat.
        binding.statThreats.statValue.text = scans.count {
            it.status != "skipped_removed" && (it.label == "malicious" || it.label == "suspicious")
        }.toString()
        binding.statThreats.statLabel.text = getString(R.string.stat_threats)
        val openRequests = com.sentinel.soc.remediate.Remediation.openRequests(app).size
        binding.statPending.statValue.text = openRequests.toString()
        binding.statPending.statLabel.text = getString(R.string.stat_pending)
        renderScore(real.filter { it.status != "skipped_removed" && (it.label == "malicious" || it.label == "suspicious") },
            online = syncedAgo != null && syncedAgo <= 60)
        BottomNav.setInboxBadge(binding.bottomNav, openRequests)
        adapter.submit(scans)
        binding.emptyState.visibility = if (scans.isEmpty()) View.VISIBLE else View.GONE
        binding.scanList.visibility = if (scans.isEmpty()) View.GONE else View.VISIBLE

        // "Apps on this phone": installed now, joined with each app's newest scan (if any).
        val byPackage = scans.associateBy { it.packageName }
        val installed = installedCache.map { (pkg, label, version) -> InstalledApp(pkg, label, version, byPackage[pkg]) }
        installedAdapter.submit(installed)
        binding.installedTitle.text = getString(R.string.installed_count, installed.size)
        binding.installedHint.text = if (installed.isEmpty()) getString(R.string.installed_empty) else getString(R.string.installed_hint)
    }

    private fun startOfToday(): Long {
        val cal = java.util.Calendar.getInstance()
        cal.set(java.util.Calendar.HOUR_OF_DAY, 0)
        cal.set(java.util.Calendar.MINUTE, 0)
        cal.set(java.util.Calendar.SECOND, 0)
        cal.set(java.util.Calendar.MILLISECOND, 0)
        return cal.timeInMillis
    }

    companion object {
        const val EXTRA_SCROLL_TO_ACTIVITY = "scroll_to_activity"
    }
}
