package com.sentinel.soc.remediate

import android.content.Context
import android.content.Intent
import android.net.Uri
import com.sentinel.soc.inspect.PackageInspector

/**
 * Starts Android's own uninstall dialog. The user always confirms there; the app never removes anything silently
 * (Stage 1 section 5, UninstallLauncher). Outcome is verified with isInstalled() before it is trusted.
 */
object UninstallLauncher {

    fun intent(pkg: String): Intent = Intent(Intent.ACTION_UNINSTALL_PACKAGE).apply {
        data = Uri.parse("package:$pkg")
        putExtra(Intent.EXTRA_RETURN_RESULT, true)
    }

    /** Maps the result to the contract outcome: uninstalled | declined | failed. */
    fun outcome(context: Context, pkg: String, resultCode: Int): String = when {
        !PackageInspector.isInstalled(context, pkg) -> "uninstalled"
        resultCode == android.app.Activity.RESULT_CANCELED -> "declined"
        else -> "failed"
    }
}
