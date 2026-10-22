package com.sentinel.soc.sync

import android.os.Handler
import android.os.Looper
import android.util.Log
import com.sentinel.soc.SentinelApp
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.Response
import okhttp3.WebSocket
import okhttp3.WebSocketListener
import org.json.JSONObject
import java.util.concurrent.CopyOnWriteArraySet
import java.util.concurrent.TimeUnit

/** One pipeline event pushed by the server for this phone's submissions. */
data class LiveEvent(val submissionId: String?, val stage: String, val step: String, val level: String,
                     val message: String, val ts: String = "")

/** In-process fan-out of live events and the connection state, for whichever screen is open. */
class LiveBus {
    @Volatile var connected = false
        internal set
    @Volatile var last: LiveEvent? = null
        private set
    private val listeners = CopyOnWriteArraySet<(LiveEvent?) -> Unit>()

    fun listen(l: (LiveEvent?) -> Unit) { listeners += l }
    fun unlisten(l: (LiveEvent?) -> Unit) { listeners -= l }

    /** null = only the connection state changed. */
    fun publish(e: LiveEvent?) {
        if (e != null) last = e
        listeners.forEach { it(e) }
    }
}

/**
 * Holds the phone's WebSocket to `/ws/device/` while the watch service runs. Each event triggers [onEvent]
 * (the service then polls commands / refreshes the verdict right away); polling stays as the fallback when offline.
 */
class LiveLink(private val app: SentinelApp, private val onEvent: (LiveEvent) -> Unit) {

    private val http = OkHttpClient.Builder().pingInterval(20, TimeUnit.SECONDS).build()
    private val main = Handler(Looper.getMainLooper())
    private var socket: WebSocket? = null
    private var stopped = false
    private var backoffMs = RETRY_MIN_MS

    fun start() {
        stopped = false
        connect()
    }

    fun stop() {
        stopped = true
        main.removeCallbacksAndMessages(null)
        socket?.close(1000, null)
        socket = null
        setConnected(false)
    }

    private fun connect() {
        if (stopped || !app.prefs.isPaired) return
        val wsUrl = app.prefs.serverUrl.replaceFirst("http", "ws").trimEnd('/') + "/ws/device/"
        val req = Request.Builder().url(wsUrl)
            .header("Authorization", "Device ${app.prefs.deviceToken}")
            .header("Origin", app.prefs.serverUrl)
            .build()
        socket = http.newWebSocket(req, object : WebSocketListener() {
            override fun onOpen(webSocket: WebSocket, response: Response) {
                backoffMs = RETRY_MIN_MS
                setConnected(true)
            }

            override fun onMessage(webSocket: WebSocket, text: String) {
                val e = try {
                    val j = JSONObject(text)
                    LiveEvent(j.optString("submission_id").ifEmpty { null }, j.optString("stage"), j.optString("step"),
                        j.optString("level", "info"), j.optString("message"), j.optString("ts"))
                } catch (_: Exception) {
                    return
                }
                onEvent(e)  // the service applies it, then publishes to the screens
            }

            override fun onClosed(webSocket: WebSocket, code: Int, reason: String) = retry()
            override fun onFailure(webSocket: WebSocket, t: Throwable, response: Response?) {
                Log.w(TAG, "live link down: ${t.message}")
                retry()
            }
        })
    }

    private fun retry() {
        setConnected(false)
        if (stopped) return
        main.postDelayed(::connect, backoffMs)
        backoffMs = (backoffMs * 2).coerceAtMost(RETRY_MAX_MS)
    }

    private fun setConnected(value: Boolean) {
        if (app.live.connected == value) return
        app.live.connected = value
        app.live.publish(null)
    }

    companion object {
        private const val TAG = "SentinelLive"
        private const val RETRY_MIN_MS = 2_000L
        private const val RETRY_MAX_MS = 30_000L
    }
}
