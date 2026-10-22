package com.sentinel.soc.ui

import android.content.Intent
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import androidx.appcompat.app.AppCompatActivity
import androidx.core.content.ContextCompat
import com.sentinel.soc.BuildConfig
import com.sentinel.soc.R
import com.sentinel.soc.SentinelApp
import com.sentinel.soc.databinding.ActivityPairingBinding
import com.sentinel.soc.net.ApiException
import com.sentinel.soc.watch.WatchService
import java.io.IOException
import java.util.concurrent.Executors

/** One-time pairing: server address + 6-digit code from the dashboard (Stage 1 frontend section 3). */
class PairingActivity : AppCompatActivity() {

    private lateinit var binding: ActivityPairingBinding
    private lateinit var app: SentinelApp
    private val worker = Executors.newSingleThreadExecutor()
    private val main = Handler(Looper.getMainLooper())

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        app = application as SentinelApp
        binding = ActivityPairingBinding.inflate(layoutInflater)
        setContentView(binding.root)
        binding.serverInput.setText(app.prefs.serverUrl)
        binding.hint.text = getString(R.string.pair_hint_emulator, BuildConfig.DEFAULT_SERVER_URL)
        binding.codeInput.addTextChangedListener(SimpleWatcher { updateButton() })
        binding.serverInput.addTextChangedListener(SimpleWatcher { updateButton() })
        binding.pairButton.setOnClickListener { pair() }
        updateButton()
    }

    override fun onDestroy() {
        worker.shutdownNow()
        super.onDestroy()
    }

    private fun updateButton() {
        val url = binding.serverInput.text.toString().trim()
        val code = binding.codeInput.text.toString().trim()
        val looksValid = url.matches(Regex("^https?://[^\\s]+$")) && code.matches(Regex("^\\d{6}$"))
        binding.pairButton.isEnabled = looksValid
    }

    private fun pair() {
        val url = binding.serverInput.text.toString().trim()
        val code = binding.codeInput.text.toString().trim()
        setBusy(true)
        binding.error.text = ""
        app.prefs.serverUrl = url
        worker.execute {
            val message: String? = try {
                val reg = app.api.register(code, android.os.Build.MODEL, android.os.Build.VERSION.RELEASE,
                    BuildConfig.VERSION_NAME)
                app.prefs.deviceId = reg.getString("device_id")
                app.prefs.deviceToken = reg.getString("device_token")
                app.prefs.commandCursor = 0L
                null
            } catch (e: ApiException) {
                when (e.code) {
                    "pairing_failed" -> getString(R.string.pair_error_code)
                    else -> getString(R.string.pair_error_server)
                }
            } catch (e: IOException) {
                getString(R.string.pair_error_unreachable)
            }
            main.post {
                setBusy(false)
                if (message != null) {
                    binding.error.text = message
                } else {
                    ContextCompat.startForegroundService(this, Intent(this, WatchService::class.java))
                    startActivity(Intent(this, MainActivity::class.java))
                    finish()
                }
            }
        }
    }

    private fun setBusy(busy: Boolean) {
        binding.pairButton.isEnabled = !busy
        binding.serverInput.isEnabled = !busy
        binding.codeInput.isEnabled = !busy
        binding.pairButton.text = getString(if (busy) R.string.pair_busy else R.string.pair_button)
        binding.progress.visibility = if (busy) android.view.View.VISIBLE else android.view.View.GONE
    }
}
