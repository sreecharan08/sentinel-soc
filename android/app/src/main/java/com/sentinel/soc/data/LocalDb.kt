package com.sentinel.soc.data

import android.content.ContentValues
import android.content.Context
import android.database.Cursor
import android.database.sqlite.SQLiteDatabase
import android.database.sqlite.SQLiteOpenHelper

/** One row per install event the phone has seen. Status values follow Stage 1 section 3 (LocalDb). */
data class ScanRecord(
    val id: Long,
    val packageName: String,
    val appLabel: String?,
    val versionName: String?,
    val apkSha256: String?,
    val submissionId: String?,
    val status: String,
    val label: String?,
    val confidence: Double?,
    val summary: String?,
    val remediationId: String?,
    val remediationState: String?,
    val createdAt: Long,
    val updatedAt: Long,
    /** The server's verdict object (signals, IOCs, techniques) as JSON, cached for the "why" screen and graph. */
    val detailJson: String? = null,
)

class LocalDb(context: Context) : SQLiteOpenHelper(context, "sentinel.db", null, 2) {

    override fun onCreate(db: SQLiteDatabase) {
        db.execSQL(
            """CREATE TABLE scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                package_name TEXT NOT NULL, app_label TEXT, version_name TEXT,
                apk_sha256 TEXT, submission_id TEXT,
                status TEXT NOT NULL,
                label TEXT, confidence REAL, summary TEXT,
                remediation_id TEXT, remediation_state TEXT,
                created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL, detail_json TEXT)"""
        )
        db.execSQL("CREATE INDEX idx_scans_created ON scans(created_at DESC)")
        db.execSQL(
            """CREATE TABLE outbox (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id INTEGER NOT NULL, attempts INTEGER NOT NULL DEFAULT 0, next_try_at INTEGER NOT NULL)"""
        )
    }

    override fun onUpgrade(db: SQLiteDatabase, oldVersion: Int, newVersion: Int) {
        // v1 -> v2 keeps the scan history; only the cached verdict detail column is new.
        if (oldVersion < 2) db.execSQL("ALTER TABLE scans ADD COLUMN detail_json TEXT")
    }

    fun insertScan(packageName: String, label: String?, version: String?, sha: String?, status: String): Long {
        val now = System.currentTimeMillis()
        val values = ContentValues().apply {
            put("package_name", packageName)
            put("app_label", label)
            put("version_name", version)
            put("apk_sha256", sha)
            put("status", status)
            put("created_at", now)
            put("updated_at", now)
        }
        return writableDatabase.insert("scans", null, values)
    }

    fun updateScan(id: Long, fields: Map<String, Any?>) {
        val values = ContentValues()
        for ((k, v) in fields) {
            when (v) {
                null -> values.putNull(k)
                is String -> values.put(k, v)
                is Long -> values.put(k, v)
                is Int -> values.put(k, v)
                is Double -> values.put(k, v)
                else -> values.put(k, v.toString())
            }
        }
        values.put("updated_at", System.currentTimeMillis())
        writableDatabase.update("scans", values, "id = ?", arrayOf(id.toString()))
    }

    fun scan(id: Long): ScanRecord? = query("SELECT * FROM scans WHERE id = ?", arrayOf(id.toString())).firstOrNull()

    fun scanBySubmission(submissionId: String): ScanRecord? =
        query("SELECT * FROM scans WHERE submission_id = ?", arrayOf(submissionId)).firstOrNull()

    fun scanByRemediation(remediationId: String): ScanRecord? =
        query("SELECT * FROM scans WHERE remediation_id = ?", arrayOf(remediationId)).firstOrNull()

    /** One row per app: the newest scan of each package, so a rescan updates the list instead of growing it. */
    fun recent(limit: Int = 200): List<ScanRecord> =
        query(
            "SELECT * FROM scans WHERE id IN (SELECT MAX(id) FROM scans GROUP BY package_name) " +
                "ORDER BY updated_at DESC LIMIT ?",
            arrayOf(limit.toString())
        )

    /** Packages the phone is tracking: every app with a scan that was not removed since. */
    fun trackedPackages(): Set<String> =
        recent(Int.MAX_VALUE).filter { it.status != "skipped_removed" }.map { it.packageName }.toSet()

    fun latestScanFor(packageName: String): ScanRecord? =
        query("SELECT * FROM scans WHERE package_name = ? ORDER BY id DESC LIMIT 1", arrayOf(packageName)).firstOrNull()

    /**
     * Marks the newest scan of each tracked package as removed when the app is no longer installed (it may have been
     * uninstalled while the watch service was not running). The verdict stays on the row, so a removed malware app
     * remains in Recent scans as "REMOVED". Returns how many rows changed.
     */
    fun markGoneAsRemoved(isInstalled: (String) -> Boolean): Int {
        var changed = 0
        for (scan in recent(Int.MAX_VALUE)) {
            if (scan.status == "skipped_removed" || isInstalled(scan.packageName)) continue
            updateScan(scan.id, mapOf("status" to "skipped_removed"))
            changed++
        }
        return changed
    }

    /** Drops local rows (and their queued uploads) for apps outside [packages]. Server-side history is untouched. */
    fun keepOnly(packages: Set<String>) {
        if (packages.isEmpty()) return
        val marks = packages.joinToString(",") { "?" }
        writableDatabase.execSQL("DELETE FROM scans WHERE package_name NOT IN ($marks)", packages.toTypedArray())
        writableDatabase.execSQL("DELETE FROM outbox WHERE scan_id NOT IN (SELECT id FROM scans)")
    }

    fun countSince(sinceMs: Long, where: String = ""): Int {
        val sql = "SELECT COUNT(*) FROM scans WHERE created_at >= ?" + (if (where.isNotEmpty()) " AND $where" else "")
        writableDatabase.rawQuery(sql, arrayOf(sinceMs.toString())).use { c ->
            return if (c.moveToFirst()) c.getInt(0) else 0
        }
    }

    /** Every app the SOC asked to remove (newest scan per app only), most recent first. */
    fun remediations(): List<ScanRecord> =
        query("SELECT * FROM scans WHERE remediation_id IS NOT NULL AND id IN " +
            "(SELECT MAX(id) FROM scans WHERE remediation_id IS NOT NULL GROUP BY package_name) " +
            "ORDER BY created_at DESC", emptyArray())

    /** Scans created per day for the last [days] days (oldest first), each as label -> count. */
    fun historyByDay(days: Int): List<Map<String, Int>> {
        val cal = java.util.Calendar.getInstance().apply {
            set(java.util.Calendar.HOUR_OF_DAY, 0); set(java.util.Calendar.MINUTE, 0)
            set(java.util.Calendar.SECOND, 0); set(java.util.Calendar.MILLISECOND, 0)
            add(java.util.Calendar.DAY_OF_YEAR, -(days - 1))
        }
        val start = cal.timeInMillis
        val buckets = List(days) { mutableMapOf<String, Int>() }
        readableDatabase.rawQuery("SELECT created_at, label FROM scans WHERE created_at >= ?", arrayOf(start.toString()))
            .use { c ->
                while (c.moveToNext()) {
                    val day = ((c.getLong(0) - start) / 86_400_000L).toInt()
                    if (day !in 0 until days) continue
                    val label = if (c.isNull(1)) "pending" else c.getString(1)
                    buckets[day][label] = (buckets[day][label] ?: 0) + 1
                }
            }
        return buckets
    }

    fun outboxEnqueue(scanId: Long, nextTryAt: Long) {
        writableDatabase.insert("outbox", null, ContentValues().apply {
            put("scan_id", scanId)
            put("next_try_at", nextTryAt)
        })
    }

    /** Keeps the last 200 scans; older rows are removed on app start (Stage 1 section 3). */
    fun trim(keep: Int = 200) {
        writableDatabase.execSQL(
            "DELETE FROM scans WHERE id NOT IN (SELECT id FROM scans ORDER BY created_at DESC LIMIT ?)",
            arrayOf(keep)
        )
    }

    private fun query(sql: String, args: Array<String>): List<ScanRecord> {
        readableDatabase.rawQuery(sql, args).use { c -> return c.toScans() }
    }

    private fun Cursor.toScans(): List<ScanRecord> {
        val out = mutableListOf<ScanRecord>()
        while (moveToNext()) {
            out += ScanRecord(
                id = getLong(getColumnIndexOrThrow("id")),
                packageName = getString(getColumnIndexOrThrow("package_name")),
                appLabel = getStringOrNull("app_label"),
                versionName = getStringOrNull("version_name"),
                apkSha256 = getStringOrNull("apk_sha256"),
                submissionId = getStringOrNull("submission_id"),
                status = getString(getColumnIndexOrThrow("status")),
                label = getStringOrNull("label"),
                confidence = if (isNull(getColumnIndexOrThrow("confidence"))) null else getDouble(getColumnIndexOrThrow("confidence")),
                summary = getStringOrNull("summary"),
                remediationId = getStringOrNull("remediation_id"),
                remediationState = getStringOrNull("remediation_state"),
                createdAt = getLong(getColumnIndexOrThrow("created_at")),
                updatedAt = getLong(getColumnIndexOrThrow("updated_at")),
                detailJson = getStringOrNull("detail_json"),
            )
        }
        return out
    }

    private fun Cursor.getStringOrNull(name: String): String? {
        val idx = getColumnIndexOrThrow(name)
        return if (isNull(idx)) null else getString(idx)
    }
}
