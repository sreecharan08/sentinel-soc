package com.sentinel.soc.sync

import android.content.Context
import androidx.work.CoroutineWorker
import androidx.work.WorkerParameters
import androidx.work.Data
import com.sentinel.soc.BuildConfig
import com.sentinel.soc.SentinelApp
import com.sentinel.soc.inspect.ApkHasher
import com.sentinel.soc.inspect.PackageInspector
import com.sentinel.soc.net.ApiException
import com.sentinel.soc.notify.Notifier
import java.io.File
import java.io.IOException

/**
 * Submits metadata, uploads the base APK when the server asks, and records the cached verdict if there is one.
 * Retries on network failures and 5xx; gives up on 4xx except 408 and 429 (Stage 1 section 3, SubmitWorker).
 */
class SubmitWorker(context: Context, params: WorkerParameters) : CoroutineWorker(context, params) {

    override suspend fun doWork(): Result {
        val app = applicationContext as SentinelApp
        val scanId = inputData.getLong(KEY_SCAN_ID, -1L)
        if (scanId < 0) return Result.failure(Data.EMPTY)
        val scan = app.db.scan(scanId) ?: return Result.failure()
        if (!app.prefs.isPaired) return Result.failure()

        // 1. Re-inspect: the package may have disappeared since the install event.
        val meta = PackageInspector.inspect(applicationContext, scan.packageName)
        if (meta == null) {
            app.db.updateScan(scanId, mapOf("status" to "skipped_removed"))
            return Result.success()
        }
        if (meta.isSystem) {
            app.db.updateScan(scanId, mapOf("status" to "skipped_removed"))
            return Result.success()
        }
        val apk = File(meta.apkPath)
        val sha = try {
            ApkHasher.sha256(apk)
        } catch (e: IOException) {
            app.db.updateScan(scanId, mapOf("status" to "upload_failed"))
            return Result.retry()
        }
        app.db.updateScan(scanId, mapOf("apk_sha256" to sha, "app_label" to meta.appLabel))

        // Over the server's size cap: nothing is sent and this is not a failure (Stage 1 section 7).
        if (meta.apkSizeBytes > BuildConfig.MAX_APK_MB * 1024L * 1024L) {
            app.db.updateScan(scanId, mapOf("status" to "skipped_too_large"))
            return Result.success()
        }

        return try {
            // 2. Create the submission.
            val created = app.api.createSubmission(meta.toSubmissionJson(sha))
            val submissionId = created.getString("submission_id")
            app.db.updateScan(scanId, mapOf("submission_id" to submissionId, "status" to "submitted"))

            // 3. A cached verdict is available for files the server has analysed before.
            if (!created.isNull("cached_verdict")) {
                val cached = created.getJSONObject("cached_verdict")
                val label = cached.getString("label")
                val confidence = cached.optDouble("confidence", 0.0)
                val summary = cached.optString("summary", "")
                app.db.updateScan(scanId, mapOf("status" to "verdict_ready", "label" to label,
                    "confidence" to confidence, "summary" to summary))
                if (label == "malicious" || label == "suspicious" || app.prefs.notifySafe) {
                    Notifier.verdict(app, scanId, meta.appLabel, label, confidence, summary)
                }
                return Result.success()
            }

            // 4. Upload the bytes when asked, streamed from the installed APK.
            if (created.getBoolean("need_upload")) {
                if (meta.apkSizeBytes > BuildConfig.MAX_APK_MB * 1024L * 1024L) {
                    app.db.updateScan(scanId, mapOf("status" to "skipped_too_large"))
                    return Result.success()
                }
                app.db.updateScan(scanId, mapOf("status" to "uploading"))
                app.api.uploadApk(submissionId, apk, sha)
            }
            app.db.updateScan(scanId, mapOf("status" to "analyzing"))
            Result.success()
        } catch (e: ApiException) {
            when {
                e.code == "invalid_token" -> {
                    app.prefs.unpair()
                    Result.failure()
                }
                e.status == 408 || e.status == 429 || e.status >= 500 -> retryOrFail(app, scanId)
                e.code == "hash_mismatch" -> retryOrFail(app, scanId)
                else -> {
                    app.db.updateScan(scanId, mapOf("status" to "upload_failed"))
                    Result.failure()
                }
            }
        } catch (e: IOException) {
            retryOrFail(app, scanId)
        }
    }

    private fun retryOrFail(app: SentinelApp, scanId: Long): Result {
        return if (runAttemptCount + 1 >= MAX_ATTEMPTS) {
            app.db.updateScan(scanId, mapOf("status" to "upload_failed"))
            Result.failure()
        } else {
            app.db.updateScan(scanId, mapOf("status" to "queued"))
            Result.retry()
        }
    }

    companion object {
        const val KEY_SCAN_ID = "scan_id"
        private const val MAX_ATTEMPTS = 5
    }
}
