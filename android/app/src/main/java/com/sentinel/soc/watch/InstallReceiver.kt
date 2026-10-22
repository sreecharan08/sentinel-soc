package com.sentinel.soc.watch

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent

data class InstallEvent(val packageName: String, val replacing: Boolean, val kind: Kind) {
    enum class Kind { ADDED, REPLACED, REMOVED }
}

/**
 * Registered at runtime inside WatchService (manifest registration of package broadcasts is unreliable on API 26+).
 * Does no I/O here: it only hands the event to the service (Stage 1 section 3, rules 1-4).
 */
class InstallReceiver(private val onInstall: (InstallEvent) -> Unit) : BroadcastReceiver() {

    override fun onReceive(context: Context, intent: Intent) {
        val pkg = intent.data?.schemeSpecificPart ?: return
        if (pkg == context.packageName) return
        when (intent.action) {
            Intent.ACTION_PACKAGE_ADDED -> {
                // An update sends REMOVED + ADDED(replacing) + REPLACED. Handle only REPLACED for updates.
                if (intent.getBooleanExtra(Intent.EXTRA_REPLACING, false)) return
                onInstall(InstallEvent(pkg, replacing = false, kind = InstallEvent.Kind.ADDED))
            }
            Intent.ACTION_PACKAGE_REPLACED -> onInstall(InstallEvent(pkg, replacing = true, kind = InstallEvent.Kind.REPLACED))
            // A real uninstall (not an update, which also sends REMOVED with EXTRA_REPLACING).
            Intent.ACTION_PACKAGE_REMOVED -> {
                if (intent.getBooleanExtra(Intent.EXTRA_REPLACING, false)) return
                onInstall(InstallEvent(pkg, replacing = false, kind = InstallEvent.Kind.REMOVED))
            }
        }
    }
}
