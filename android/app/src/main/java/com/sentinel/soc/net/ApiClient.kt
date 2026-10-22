package com.sentinel.soc.net

import com.sentinel.soc.data.Prefs
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody
import okhttp3.RequestBody.Companion.asRequestBody
import okhttp3.RequestBody.Companion.toRequestBody
import org.json.JSONObject
import java.io.File
import java.io.IOException
import java.util.concurrent.TimeUnit

/** A contract error (CONTRACTS section 2). `code` is the machine code, e.g. `invalid_token`. */
class ApiException(val status: Int, val code: String, message: String) : IOException(message)

/** Every HTTP call the phone makes (Stage 1 section 3, ApiClient). Bodies follow CONTRACTS section 5. */
class ApiClient(private val prefs: Prefs) {

    private val http = OkHttpClient.Builder()
        .connectTimeout(5, TimeUnit.SECONDS)
        .readTimeout(20, TimeUnit.SECONDS)
        .writeTimeout(120, TimeUnit.SECONDS)
        .build()

    private val json = "application/json".toMediaType()

    /** POST /api/v1/devices/register. Returns (device_id, device_token). */
    fun register(pairingCode: String, deviceName: String, androidVersion: String, appVersion: String): JSONObject {
        val body = JSONObject()
            .put("pairing_code", pairingCode)
            .put("device_name", deviceName)
            .put("android_version", androidVersion)
            .put("app_version", appVersion)
        val req = Request.Builder().url(url("/api/v1/devices/register"))
            .post(body.toString().toRequestBody(json)).build()
        return JSONObject(execute(req, auth = false))
    }

    fun heartbeat(appVersion: String, protectionOn: Boolean) {
        val body = JSONObject().put("app_version", appVersion).put("protection_on", protectionOn)
        execute(authed("/api/v1/devices/me/heartbeat").post(body.toString().toRequestBody(json)).build())
    }

    /** POST /api/v1/submissions. Returns submission_id, status, need_upload and cached_verdict. */
    fun createSubmission(meta: JSONObject): JSONObject {
        val req = authed("/api/v1/submissions").post(meta.toString().toRequestBody(json)).build()
        return JSONObject(execute(req))
    }

    /** PUT /api/v1/submissions/{id}/apk, streamed from disk with the expected hash. */
    fun uploadApk(submissionId: String, file: File, sha256: String) {
        val body: RequestBody = file.asRequestBody("application/octet-stream".toMediaType())
        val req = authed("/api/v1/submissions/$submissionId/apk")
            .put(body)
            .header("X-Content-SHA256", sha256)
            .build()
        execute(req)
    }

    fun getSubmission(submissionId: String): JSONObject =
        JSONObject(execute(authed("/api/v1/submissions/$submissionId").get().build()))

    fun pollCommands(cursor: Long): JSONObject =
        JSONObject(execute(authed("/api/v1/devices/me/commands?cursor=$cursor").get().build()))

    fun ackCommand(commandId: Long) {
        execute(authed("/api/v1/devices/me/commands/$commandId/ack").post("".toRequestBody(null)).build())
    }

    fun reportRemediation(remediationId: String, outcome: String, detail: String) {
        val body = JSONObject().put("outcome", outcome).put("detail", detail.take(500))
        execute(authed("/api/v1/remediations/$remediationId/result").post(body.toString().toRequestBody(json)).build())
    }

    private fun url(path: String) = prefs.serverUrl + path

    private fun authed(path: String): Request.Builder =
        Request.Builder().url(url(path)).header("Authorization", "Device ${prefs.deviceToken}")

    private fun execute(req: Request, auth: Boolean = true): String {
        if (auth && !prefs.isPaired) throw ApiException(401, "invalid_token", "Not paired")
        http.newCall(req).execute().use { resp ->
            val text = resp.body?.string().orEmpty()
            if (resp.isSuccessful) return text
            val err = try {
                JSONObject(text).getJSONObject("error")
            } catch (_: Exception) {
                null
            }
            throw ApiException(
                resp.code,
                err?.optString("code", "internal_error") ?: "internal_error",
                err?.optString("message", "The server had a problem. Try again.") ?: "The server had a problem. Try again.",
            )
        }
    }
}
