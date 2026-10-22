package com.sentinel.soc

import android.app.Application
import android.app.NotificationChannel
import android.app.NotificationManager
import com.sentinel.soc.data.LocalDb
import com.sentinel.soc.data.Prefs
import com.sentinel.soc.net.ApiClient

/** Creates notification channels and the small service locator the rest of the app uses. */
class SentinelApp : Application() {

    lateinit var prefs: Prefs
        private set
    lateinit var db: LocalDb
        private set
    lateinit var api: ApiClient
        private set
    val live = com.sentinel.soc.sync.LiveBus()

    override fun onCreate() {
        super.onCreate()
        prefs = Prefs(this)
        db = LocalDb(this)
        api = ApiClient(prefs)
        createChannels()
    }

    private fun createChannels() {
        val nm = getSystemService(NotificationManager::class.java)
        nm.createNotificationChannel(
            NotificationChannel(CHANNEL_ALERTS, getString(R.string.channel_alerts), android.app.NotificationManager.IMPORTANCE_HIGH)
        )
        nm.createNotificationChannel(
            NotificationChannel(CHANNEL_STATUS, getString(R.string.channel_status), android.app.NotificationManager.IMPORTANCE_LOW)
        )
    }

    companion object {
        const val CHANNEL_ALERTS = "verdict_alerts"
        const val CHANNEL_STATUS = "service_status"
    }
}
