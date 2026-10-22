package com.sentinel.soc.inspect

import android.content.Context
import android.content.pm.ApplicationInfo
import android.content.pm.PackageManager
import androidx.core.content.pm.PackageInfoCompat
import org.json.JSONArray
import org.json.JSONObject
import java.io.File
import java.security.MessageDigest
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import java.util.TimeZone

/** Metadata the server needs (Stage 1 section 3, PackageInspector). Nothing about the user is read. */
data class PackageMeta(
    val packageName: String,
    val appLabel: String,
    val versionName: String?,
    val versionCode: Long,
    val installer: String?,
    val firstInstallTime: Long,
    val permissions: List<String>,
    val apkPath: String,
    val apkSizeBytes: Long,
    val splitCount: Int,
    val isSystem: Boolean,
) {
    fun toSubmissionJson(sha256: String): JSONObject {
        val iso = SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss'Z'", Locale.US).apply {
            timeZone = TimeZone.getTimeZone("UTC")
        }.format(Date(firstInstallTime))
        return JSONObject()
            .put("package_name", packageName)
            .put("app_label", appLabel)
            .put("version_name", versionName ?: "")
            .put("version_code", versionCode)
            .put("installer_package", installer)
            .put("first_install_time", iso)
            .put("requested_permissions", JSONArray(permissions))
            .put("apk_sha256", sha256)
            .put("apk_size_bytes", apkSizeBytes)
            .put("split_count", splitCount)
    }
}

object PackageInspector {

    /** Returns null when the package is gone (the scan becomes `skipped_removed`). */
    @Suppress("DEPRECATION")
    fun inspect(context: Context, pkg: String): PackageMeta? {
        val pm = context.packageManager
        return try {
            val info = pm.getPackageInfo(pkg, PackageManager.GET_PERMISSIONS)
            val ai: ApplicationInfo = info.applicationInfo ?: return null
            PackageMeta(
                packageName = pkg,
                appLabel = pm.getApplicationLabel(ai).toString(),
                versionName = info.versionName,
                versionCode = PackageInfoCompat.getLongVersionCode(info),
                installer = installerOf(context, pkg),
                firstInstallTime = info.firstInstallTime,
                permissions = info.requestedPermissions?.toList().orEmpty(),
                apkPath = ai.sourceDir,
                apkSizeBytes = File(ai.sourceDir).length(),
                splitCount = ai.splitSourceDirs?.size ?: 0,
                isSystem = (ai.flags and ApplicationInfo.FLAG_SYSTEM) != 0,
            )
        } catch (_: PackageManager.NameNotFoundException) {
            null
        }
    }

    fun isInstalled(context: Context, pkg: String): Boolean = try {
        @Suppress("DEPRECATION")
        context.packageManager.getPackageInfo(pkg, 0)
        true
    } catch (_: PackageManager.NameNotFoundException) {
        false
    }

    @Suppress("DEPRECATION")
    private fun installerOf(context: Context, pkg: String): String? = try {
        val pm = context.packageManager
        if (android.os.Build.VERSION.SDK_INT >= 30) pm.getInstallSourceInfo(pkg).installingPackageName
        else pm.getInstallerPackageName(pkg)
    } catch (_: Exception) {
        null
    }
}

/** SHA-256 of the file, streamed in 8 KB chunks (Stage 1 section 9). Lowercase hex, 64 characters. */
object ApkHasher {
    fun sha256(file: File): String {
        val md = MessageDigest.getInstance("SHA-256")
        file.inputStream().use { input ->
            val buf = ByteArray(8192)
            while (true) {
                val n = input.read(buf)
                if (n < 0) break
                md.update(buf, 0, n)
            }
        }
        return md.digest().joinToString("") { "%02x".format(it) }
    }
}
