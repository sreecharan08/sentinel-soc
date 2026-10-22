package com.sentinel.soc.ui

import android.content.res.ColorStateList
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.TextView
import androidx.core.content.ContextCompat
import androidx.recyclerview.widget.RecyclerView
import com.sentinel.soc.R
import com.sentinel.soc.data.ScanRecord

/** An app that is installed on this phone right now, with its newest scan if there is one. */
data class InstalledApp(val packageName: String, val label: String, val versionName: String?, val scan: ScanRecord?)

/**
 * "Apps on this phone": everything that can be scanned. Built from the package manager, so an app that was
 * uninstalled is simply not here (it stays in Recent scans as REMOVED).
 */
class InstalledAdapter(
    private val onClick: (InstalledApp) -> Unit,
    private val onLongClick: (InstalledApp, View) -> Unit = { _, _ -> },
) : RecyclerView.Adapter<InstalledAdapter.Holder>() {

    private var items: List<InstalledApp> = emptyList()

    fun submit(list: List<InstalledApp>) {
        items = list
        notifyDataSetChanged()
    }

    override fun onCreateViewHolder(parent: ViewGroup, viewType: Int): Holder =
        Holder(LayoutInflater.from(parent.context).inflate(R.layout.item_scan, parent, false))

    override fun getItemCount(): Int = items.size

    override fun onBindViewHolder(holder: Holder, position: Int) {
        val item = items[position]
        val ctx = holder.itemView.context
        val scan = item.scan?.takeIf { it.status != "skipped_removed" }
        holder.label.text = item.label
        holder.pkg.text = item.packageName
        val (text, iconRes, colorRes) = when {
            scan == null -> Triple(ctx.getString(R.string.not_scanned), R.drawable.ic_help_circle, R.color.v_unknown)
            scan.label == "malicious" -> Triple("MALICIOUS", R.drawable.ic_alert, R.color.v_malicious)
            scan.label == "suspicious" -> Triple("SUSPICIOUS", R.drawable.ic_alert, R.color.v_suspicious)
            scan.label == "benign" -> Triple("SAFE", R.drawable.ic_check_circle, R.color.v_benign)
            scan.label == "unknown" -> Triple("UNKNOWN", R.drawable.ic_help_circle, R.color.v_unknown)
            scan.status == "uploading" -> Triple("UPLOADING", R.drawable.ic_upload, R.color.info)
            scan.status in setOf("upload_failed", "error") -> Triple("FAILED", R.drawable.ic_alert, R.color.v_malicious)
            scan.status == "skipped_too_large" -> Triple("TOO LARGE", R.drawable.ic_help_circle, R.color.v_unknown)
            else -> Triple("ANALYZING", R.drawable.ic_clock, R.color.info)
        }
        holder.chip.text = text
        holder.chip.setCompoundDrawablesRelativeWithIntrinsicBounds(iconRes, 0, 0, 0)
        holder.chip.setTextColor(ContextCompat.getColor(ctx, colorRes))
        holder.chip.backgroundTintList = ColorStateList.valueOf(ContextCompat.getColor(ctx, ScanAdapter.softFor(colorRes)))
        AppIcons.bind(holder.icon, holder.avatar, item.packageName)
        holder.avatar.setTextColor(ContextCompat.getColor(ctx, colorRes))
        holder.avatar.backgroundTintList = ColorStateList.valueOf(ContextCompat.getColor(ctx, ScanAdapter.softFor(colorRes)))
        holder.time.text = if (scan == null) ctx.getString(R.string.tap_to_scan) else ScanAdapter.relative(scan.updatedAt)
        holder.itemView.contentDescription = ctx.getString(R.string.scan_row_description, text, item.label)
        holder.itemView.setOnClickListener { onClick(item) }
        holder.itemView.setOnLongClickListener { onLongClick(item, it); true }
    }

    class Holder(view: View) : RecyclerView.ViewHolder(view) {
        val label: TextView = view.findViewById(R.id.scanLabel)
        val pkg: TextView = view.findViewById(R.id.scanPackage)
        val time: TextView = view.findViewById(R.id.scanTime)
        val chip: TextView = view.findViewById(R.id.scanChip)
        val avatar: TextView = view.findViewById(R.id.scanAvatar)
        val icon: android.widget.ImageView = view.findViewById(R.id.scanIcon)
    }
}
