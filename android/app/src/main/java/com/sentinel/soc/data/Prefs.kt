package com.sentinel.soc.data

import android.content.Context
import com.sentinel.soc.BuildConfig

/** App-private settings (MODE_PRIVATE). The device token lives here; see Stage 1 section 9. */
class Prefs(context: Context) {
    private val sp = context.getSharedPreferences("sentinel", Context.MODE_PRIVATE)

    var serverUrl: String
        get() {
            val saved = sp.getString("server_url", null) ?: return BuildConfig.DEFAULT_SERVER_URL
            // Builds up to 0.1.5 defaulted to port 8000 and saved it at pairing time. Move those phones to the
            // current default (the pairing token is untouched, so no re-pair is needed).
            if (saved == LEGACY_DEFAULT_SERVER_URL) {
                sp.edit().putString("server_url", BuildConfig.DEFAULT_SERVER_URL).apply()
                return BuildConfig.DEFAULT_SERVER_URL
            }
            return saved
        }
        set(value) = sp.edit().putString("server_url", value.trim().trimEnd('/')).apply()

    var deviceId: String
        get() = sp.getString("device_id", "") ?: ""
        set(value) = sp.edit().putString("device_id", value).apply()

    var deviceToken: String
        get() = sp.getString("device_token", "") ?: ""
        set(value) = sp.edit().putString("device_token", value).apply()

    var pollSeconds: Int
        get() = sp.getInt("poll_seconds", 5)
        set(value) = sp.edit().putInt("poll_seconds", value).apply()

    var commandCursor: Long
        get() = sp.getLong("command_cursor", 0L)
        set(value) = sp.edit().putLong("command_cursor", value).apply()

    var protectionOn: Boolean
        get() = sp.getBoolean("protection_on", true)
        set(value) = sp.edit().putBoolean("protection_on", value).apply()

    var notifySafe: Boolean
        get() = sp.getBoolean("notify_safe", false)
        set(value) = sp.edit().putBoolean("notify_safe", value).apply()

    var lastSyncMs: Long
        get() = sp.getLong("last_sync_ms", 0L)
        set(value) = sp.edit().putLong("last_sync_ms", value).apply()

    /**
     * Packages this phone already knows about (the baseline for "new app" detection). Null until the first scan
     * records the apps that were installed at that moment, so the first scan does not flood the list.
     */
    var knownPackages: Set<String>?
        get() = sp.getStringSet("known_packages", null)
        set(value) = sp.edit().putStringSet("known_packages", value).apply()

    /** The system notification prompt is shown once automatically; after that the status card offers it again. */
    var notifAskedOnce: Boolean
        get() = sp.getBoolean("notif_asked_once", false)
        set(value) = sp.edit().putBoolean("notif_asked_once", value).apply()

    val isPaired: Boolean get() = deviceToken.isNotEmpty()

    private companion object {
        const val LEGACY_DEFAULT_SERVER_URL = "http://127.0.0.1:8000"
    }

    /** Clears pairing and history on this phone. Used by "Unpair" and by `invalid_token` from the server. */
    fun unpair() {
        sp.edit().remove("device_id").remove("device_token").remove("command_cursor").apply()
    }
}
