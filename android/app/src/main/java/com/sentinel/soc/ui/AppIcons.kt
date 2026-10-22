package com.sentinel.soc.ui

import android.content.Context
import android.content.pm.PackageManager
import android.graphics.drawable.Drawable
import android.view.View
import android.widget.ImageView
import android.widget.TextView

/**
 * The real launcher icon of an installed app, cached per package. An app that is no longer on the phone has no
 * icon, so its row keeps the coloured initials.
 */
object AppIcons {

    private val cache = android.util.LruCache<String, Any>(64)
    private val NONE = Any()

    fun get(context: Context, pkg: String): Drawable? {
        val hit = cache.get(pkg)
        if (hit != null) return hit as? Drawable
        val icon = try {
            context.packageManager.getApplicationIcon(pkg)
        } catch (_: PackageManager.NameNotFoundException) {
            null
        }
        cache.put(pkg, icon ?: NONE)
        return icon
    }

    /** Forget a package (installed or removed since it was cached). */
    fun evict(pkg: String) { cache.remove(pkg) }

    /** Shows the icon over the initials badge when the app is installed; otherwise the initials. */
    fun bind(icon: ImageView, initials: TextView, pkg: String) {
        val d = get(icon.context, pkg)
        icon.setImageDrawable(d)
        icon.visibility = if (d != null) View.VISIBLE else View.GONE
        initials.text = if (d != null) "" else ScanAdapter.initialsFor(pkg)
    }
}
