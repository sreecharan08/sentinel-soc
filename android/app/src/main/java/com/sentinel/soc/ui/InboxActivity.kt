package com.sentinel.soc.ui

import android.content.res.ColorStateList
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.view.animation.DecelerateInterpolator
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import androidx.core.content.ContextCompat
import androidx.recyclerview.widget.LinearLayoutManager
import androidx.recyclerview.widget.RecyclerView
import com.sentinel.soc.R
import com.sentinel.soc.SentinelApp
import com.sentinel.soc.data.ScanRecord
import com.sentinel.soc.databinding.ActivityInboxBinding
import com.sentinel.soc.databinding.ItemRequestBinding
import com.sentinel.soc.inspect.PackageInspector
import com.sentinel.soc.remediate.Remediation
import java.util.concurrent.Executors

/** Uninstall requests from the SOC analyst: approve (Android's uninstall dialog) or keep (reported as declined). */
class InboxActivity : AppCompatActivity() {

    private lateinit var binding: ActivityInboxBinding
    private lateinit var app: SentinelApp
    private val worker = Executors.newSingleThreadExecutor()
    private val main = Handler(Looper.getMainLooper())
    private val openAdapter = RequestAdapter(actionable = true)
    private val resolvedAdapter = RequestAdapter(actionable = false)
    private val live: (com.sentinel.soc.sync.LiveEvent?) -> Unit = { runOnUiThread { render() } }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        app = application as SentinelApp
        binding = ActivityInboxBinding.inflate(layoutInflater)
        setContentView(binding.root)
        binding.openList.layoutManager = LinearLayoutManager(this)
        binding.openList.adapter = openAdapter
        binding.resolvedList.layoutManager = LinearLayoutManager(this)
        binding.resolvedList.adapter = resolvedAdapter
        BottomNav.wire(this, binding.bottomNav, BottomNav.Tab.INBOX)
    }

    private val swipe by lazy { BottomNav.Swipe(this, BottomNav.Tab.INBOX) }

    override fun dispatchTouchEvent(ev: android.view.MotionEvent): Boolean {
        swipe.onTouch(ev)
        return super.dispatchTouchEvent(ev)
    }

    override fun onResume() {
        super.onResume()
        app.live.listen(live)
        render()
        // Pick up analyst-side changes (cancelled, expired) for the open requests.
        worker.execute {
            Remediation.openRequests(app).forEach { com.sentinel.soc.sync.VerdictDetail.refresh(app, it) }
            main.post { if (!isFinishing) render() }
        }
    }

    override fun onPause() {
        super.onPause()
        app.live.unlisten(live)
    }

    override fun onDestroy() {
        worker.shutdownNow()
        super.onDestroy()
    }

    private fun render() {
        val all = app.db.remediations()
        val open = all.filter { Remediation.isOpen(this, it) }
        val resolved = all - open.toSet()
        openAdapter.submit(open)
        resolvedAdapter.submit(resolved)
        binding.openTitle.text = getString(R.string.inbox_open, open.size)
        binding.resolvedTitle.text = getString(R.string.inbox_resolved, resolved.size)
        binding.emptyOpen.visibility = if (open.isEmpty()) View.VISIBLE else View.GONE
        binding.resolvedTitle.visibility = if (resolved.isEmpty()) View.GONE else View.VISIBLE
        BottomNav.setInboxBadge(binding.bottomNav, open.size)
    }

    @Suppress("DEPRECATION")
    private fun remove(scan: ScanRecord) {
        startActivity(VerdictActivity.intent(this, scan.id).putExtra(VerdictActivity.EXTRA_AUTO_UNINSTALL, true))
        overridePendingTransition(0, 0)  // the sheet animates itself
    }

    private fun keep(scan: ScanRecord) {
        worker.execute {
            val ok = Remediation.decline(app, scan)
            main.post {
                Toast.makeText(this, if (ok) R.string.inbox_kept else R.string.inbox_keep_failed, Toast.LENGTH_SHORT).show()
                render()
            }
        }
    }

    private inner class RequestAdapter(private val actionable: Boolean) : RecyclerView.Adapter<RequestAdapter.Holder>() {
        private var items: List<ScanRecord> = emptyList()

        fun submit(list: List<ScanRecord>) {
            items = list
            notifyDataSetChanged()
        }

        override fun getItemCount() = items.size

        override fun onCreateViewHolder(parent: ViewGroup, viewType: Int) =
            Holder(ItemRequestBinding.inflate(LayoutInflater.from(parent.context), parent, false))

        override fun onBindViewHolder(holder: Holder, position: Int) {
            val scan = items[position]
            val b = holder.b
            val color = ScanAdapter.colorFor(scan.label)
            val strong = ContextCompat.getColor(this@InboxActivity, color)
            val soft = ColorStateList.valueOf(ContextCompat.getColor(this@InboxActivity, ScanAdapter.softFor(color)))
            b.reqName.text = scan.appLabel ?: scan.packageName
            b.reqPkg.text = scan.packageName
            AppIcons.bind(b.reqIcon, b.reqAvatar, scan.packageName)
            b.reqAvatar.setTextColor(strong); b.reqAvatar.backgroundTintList = soft
            b.reqChip.text = (scan.label ?: "unknown").uppercase()
            b.reqChip.setTextColor(strong); b.reqChip.backgroundTintList = soft
            b.reqMessage.text = scan.summary?.takeIf { it.isNotBlank() } ?: getString(R.string.inbox_message)
            val installed = PackageInspector.isInstalled(this@InboxActivity, scan.packageName)
            // An open request for an app that's already gone is effectively done: it was removed.
            val state = if (!installed && scan.remediationState in Remediation.OPEN_STATES) "removed"
                else scan.remediationState ?: "pending"
            b.reqState.text = getString(R.string.rem_state, state.uppercase(), ScanAdapter.relative(scan.createdAt))
            b.reqState.setTextColor(ContextCompat.getColor(this@InboxActivity, stateColor(state)))
            b.reqActions.visibility = if (actionable) View.VISIBLE else View.GONE
            b.reqRemove.setOnClickListener { remove(scan) }
            b.reqKeep.setOnClickListener { keep(scan) }
            b.root.setOnClickListener { startActivity(VerdictActivity.intent(this@InboxActivity, scan.id)) }
            b.root.alpha = 0f
            b.root.translationY = 24f
            b.root.animate().alpha(1f).translationY(0f).setStartDelay(position * 60L).setDuration(260)
                .setInterpolator(DecelerateInterpolator()).start()
        }

        private fun stateColor(state: String) = when (state) {
            "completed", "removed" -> R.color.v_benign
            "pending", "delivered" -> R.color.v_suspicious
            "failed", "expired" -> R.color.v_malicious
            else -> R.color.text_3
        }

        inner class Holder(val b: ItemRequestBinding) : RecyclerView.ViewHolder(b.root)
    }
}
