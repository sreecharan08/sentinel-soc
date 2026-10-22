package com.sentinel.soc.sync

import android.content.Context
import androidx.work.BackoffPolicy
import androidx.work.Constraints
import androidx.work.ExistingWorkPolicy
import androidx.work.NetworkType
import androidx.work.OneTimeWorkRequestBuilder
import androidx.work.WorkManager
import androidx.work.workDataOf
import com.sentinel.soc.SentinelApp
import java.util.concurrent.TimeUnit

/**
 * Queues one submit job per scan. WorkManager survives process death and network drops (Stage 1 section 5).
 * No network constraint: the server is usually reached over the USB tunnel (127.0.0.1), which works with no
 * internet and where Android reports "not connected". A failed attempt is retried with backoff instead.
 */
object Outbox {

    fun enqueue(context: Context, app: SentinelApp, scanId: Long) {
        val request = OneTimeWorkRequestBuilder<SubmitWorker>()
            .setInputData(workDataOf(SubmitWorker.KEY_SCAN_ID to scanId))
            .setConstraints(Constraints.Builder().setRequiredNetworkType(NetworkType.NOT_REQUIRED).build())
            .setBackoffCriteria(BackoffPolicy.EXPONENTIAL, 30, TimeUnit.SECONDS)
            .build()
        app.db.outboxEnqueue(scanId, System.currentTimeMillis())
        WorkManager.getInstance(context).enqueueUniqueWork("scan-$scanId", ExistingWorkPolicy.KEEP, request)
    }
}
