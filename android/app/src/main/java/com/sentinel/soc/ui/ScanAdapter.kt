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

/** One row per scan: app label, package, status chip (icon + text, never colour alone), relative time. */
class ScanAdapter(
    private val onClick: (ScanRecord) -> Unit,
    private val onLongClick: (ScanRecord, View) -> Unit = { _, _ -> },
) : RecyclerView.Adapter<ScanAdapter.Holder>() {

    private var items: List<ScanRecord> = emptyList()

    fun submit(list: List<ScanRecord>) {
        items = list
        notifyDataSetChanged()
    }

    override fun onCreateViewHolder(parent: ViewGroup, viewType: Int): Holder {
        val view = LayoutInflater.from(parent.context).inflate(R.layout.item_scan, parent, false)
        return Holder(view)
    }

    override fun getItemCount(): Int = items.size

    override fun onBindViewHolder(holder: Holder, position: Int) {
        val scan = items[position]
        val ctx = holder.itemView.context
        holder.label.text = scan.appLabel ?: scan.packageName
        holder.pkg.text = scan.packageName
        val removed = scan.status == "skipped_removed"
        val never = scan.status == "never_scanned"
        holder.time.text = if (removed) {
            (if (scan.label != null) ctx.getString(R.string.removed_was, scan.label) + " · " else "") + relativeTime(scan.updatedAt)
        } else if (never) "" else relativeTime(scan.createdAt)
        val (text, iconRes, colorRes) = chip(scan.label, scan.status)
        holder.chip.text = text
        holder.chip.setCompoundDrawablesRelativeWithIntrinsicBounds(iconRes, 0, 0, 0)
        holder.chip.setTextColor(ContextCompat.getColor(ctx, colorRes))
        holder.chip.backgroundTintList = ColorStateList.valueOf(ContextCompat.getColor(ctx, softFor(colorRes)))
        AppIcons.bind(holder.icon, holder.avatar, scan.packageName)
        holder.avatar.setTextColor(ContextCompat.getColor(ctx, colorRes))
        holder.avatar.backgroundTintList = ColorStateList.valueOf(ContextCompat.getColor(ctx, softFor(colorRes)))
        holder.itemView.contentDescription = ctx.getString(R.string.scan_row_description, text, holder.label.text)
        holder.itemView.setOnClickListener { onClick(scan) }
        holder.itemView.setOnLongClickListener { onLongClick(scan, it); true }
    }

    private fun chip(label: String?, status: String): Triple<String, Int, Int> = when {
        status == "never_scanned" -> Triple("NOT SCANNED", R.drawable.ic_help_circle, R.color.v_unknown)
        status == "skipped_removed" -> Triple("REMOVED", R.drawable.ic_check_circle, R.color.v_benign)
        label == "malicious" -> Triple("MALICIOUS", R.drawable.ic_alert, R.color.v_malicious)
        label == "suspicious" -> Triple("SUSPICIOUS", R.drawable.ic_alert, R.color.v_suspicious)
        label == "benign" -> Triple("SAFE", R.drawable.ic_check_circle, R.color.v_benign)
        label == "unknown" -> Triple("UNKNOWN", R.drawable.ic_help_circle, R.color.v_unknown)
        status == "skipped_too_large" -> Triple("TOO LARGE", R.drawable.ic_help_circle, R.color.v_unknown)
        status == "upload_failed" || status == "error" -> Triple("FAILED", R.drawable.ic_alert, R.color.v_malicious)
        status == "uploading" -> Triple("UPLOADING", R.drawable.ic_upload, R.color.info)
        status == "analyzing" || status == "submitted" -> Triple("ANALYZING", R.drawable.ic_clock, R.color.info)
        else -> Triple("SENDING", R.drawable.ic_clock, R.color.info)
    }

    private fun relativeTime(ms: Long): String = relative(ms)

    companion object {
        fun relative(ms: Long): String {
            val s = (System.currentTimeMillis() - ms) / 1000
            return when {
                s < 60 -> "${s}s"
                s < 3600 -> "${s / 60}m"
                s < 86400 -> "${s / 3600}h"
                else -> "${s / 86400}d"
            }
        }

        /** The last two letters of the package's final segment, e.g. "com.lumen.flashlightpro" -> "FL". */
        fun initialsFor(packageName: String): String =
            packageName.substringAfterLast('.').take(2).uppercase()

        fun colorFor(label: String?): Int = when (label) {
            "malicious" -> R.color.v_malicious
            "suspicious" -> R.color.v_suspicious
            "benign" -> R.color.v_benign
            else -> R.color.v_unknown
        }

        fun softFor(strong: Int): Int = when (strong) {
            R.color.v_malicious -> R.color.v_malicious_soft
            R.color.v_suspicious -> R.color.v_suspicious_soft
            R.color.v_benign -> R.color.v_benign_soft
            R.color.info -> R.color.info_soft
            else -> R.color.v_unknown_soft
        }
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
