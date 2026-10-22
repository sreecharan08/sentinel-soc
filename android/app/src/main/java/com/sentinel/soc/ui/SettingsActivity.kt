package com.sentinel.soc.ui

import android.app.AlertDialog
import android.content.Intent
import android.os.Bundle
import androidx.appcompat.app.AppCompatActivity
import com.sentinel.soc.BuildConfig
import com.sentinel.soc.R
import com.sentinel.soc.SentinelApp
import com.sentinel.soc.databinding.ActivitySettingsBinding
import com.sentinel.soc.watch.WatchService

/** Poll interval, notification choice, re-pair and unpair (Stage 1 frontend section 6). */
class SettingsActivity : AppCompatActivity() {

    private lateinit var binding: ActivitySettingsBinding
    private lateinit var app: SentinelApp

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        app = application as SentinelApp
        binding = ActivitySettingsBinding.inflate(layoutInflater)
        setContentView(binding.root)
        binding.backButton.setOnClickListener { finish() }
        binding.rowServer.rowLabel.text = getString(R.string.settings_server)
        binding.rowServer.root.setOnClickListener { startActivity(Intent(this, PairingActivity::class.java)) }
        binding.rowPoll.rowLabel.text = getString(R.string.settings_poll_row)
        binding.rowPoll.root.setOnClickListener { pickPollInterval() }
        binding.notifySafe.isChecked = app.prefs.notifySafe
        binding.notifySafe.setOnCheckedChangeListener { _, checked -> app.prefs.notifySafe = checked }
        binding.rowRepair.rowLabel.text = getString(R.string.settings_repair)
        binding.rowRepair.root.setOnClickListener { startActivity(Intent(this, PairingActivity::class.java)) }
        binding.rowUnpair.rowLabel.text = getString(R.string.settings_unpair)
        binding.rowUnpair.rowLabel.setTextColor(androidx.core.content.ContextCompat.getColor(this, R.color.v_malicious))
        binding.rowUnpair.root.setOnClickListener { confirmUnpair() }
        binding.about.text = getString(R.string.about_text, BuildConfig.VERSION_NAME, BuildConfig.CONTRACT_VERSION,
            app.prefs.deviceId.take(8).ifEmpty { "-" })
        BottomNav.wire(this, binding.bottomNav, BottomNav.Tab.SETTINGS)
    }

    private val swipe by lazy { BottomNav.Swipe(this, BottomNav.Tab.SETTINGS) }

    override fun dispatchTouchEvent(ev: android.view.MotionEvent): Boolean {
        swipe.onTouch(ev)
        return super.dispatchTouchEvent(ev)
    }

    override fun onResume() {
        super.onResume()
        BottomNav.setInboxBadge(binding.bottomNav, com.sentinel.soc.remediate.Remediation.openRequests(app).size)
        binding.rowServer.rowValue.text = app.prefs.serverUrl.removePrefix("http://").removePrefix("https://")
        binding.rowPoll.rowValue.text = getString(R.string.poll_seconds_value, app.prefs.pollSeconds)
    }

    private fun pickPollInterval() {
        val options = arrayOf(5, 10, 30)
        val labels = options.map { getString(R.string.poll_seconds_value, it) }.toTypedArray()
        val current = options.indexOf(app.prefs.pollSeconds).coerceAtLeast(0)
        AlertDialog.Builder(this)
            .setTitle(R.string.settings_poll_title)
            .setSingleChoiceItems(labels, current) { dialog, which ->
                app.prefs.pollSeconds = options[which]
                dialog.dismiss()
                onResume()
            }
            .setNegativeButton(R.string.btn_cancel, null)
            .show()
    }

    private fun confirmUnpair() {
        AlertDialog.Builder(this)
            .setTitle(R.string.unpair_title)
            .setMessage(R.string.unpair_message)
            .setNegativeButton(R.string.btn_cancel, null)
            .setPositiveButton(R.string.btn_unpair) { _, _ ->
                stopService(Intent(this, WatchService::class.java))
                app.db.writableDatabase.delete("scans", null, null)
                app.db.writableDatabase.delete("outbox", null, null)
                app.prefs.unpair()
                startActivity(Intent(this, PairingActivity::class.java))
                finishAffinity()
            }
            .show()
    }
}
