package com.sentinel.soc.ui

import android.app.Activity
import android.content.Intent
import android.content.res.ColorStateList
import android.os.Bundle
import android.text.SpannableStringBuilder
import android.text.style.ForegroundColorSpan
import android.view.HapticFeedbackConstants
import android.view.View
import androidx.appcompat.app.AppCompatActivity
import androidx.core.content.ContextCompat
import com.sentinel.soc.R
import com.sentinel.soc.SentinelApp
import com.sentinel.soc.databinding.ActivityThreatGraphBinding
import com.sentinel.soc.sync.VerdictDetail
import com.sentinel.soc.ui.ThreatGraph.Kind
import com.sentinel.soc.ui.ThreatGraph.Tone
import org.json.JSONObject

/** One app's evidence as a 3D graph: app -> MITRE techniques -> signals, and app -> network hosts. */
class ThreatGraphActivity : AppCompatActivity() {

    private lateinit var binding: ActivityThreatGraphBinding
    private var graph: ThreatGraph.Graph? = null

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        binding = ActivityThreatGraphBinding.inflate(layoutInflater)
        setContentView(binding.root)
        binding.backButton.setOnClickListener { finish() }
        binding.graph.labels = binding.labels
        binding.graph.onSelect = { i -> runOnUiThread { select(i) } }
        binding.graphLegend.text = legend()

        val app = application as SentinelApp
        val scan = app.db.scan(intent.getLongExtra(EXTRA_SCAN_ID, -1L))
        val detail = scan?.let(VerdictDetail::parse)
        binding.graphTitle.text = getString(R.string.graph_title) + " · " + (scan?.appLabel ?: scan?.packageName ?: "")
        if (scan == null || detail == null) {
            binding.graphEmpty.visibility = View.VISIBLE
            return
        }
        val g = ThreatGraph.build(input(scan.appLabel ?: scan.packageName, scan.label, detail))
        graph = g
        val colors = IntArray(g.nodes.size) { color(g.nodes[it].tone) }
        binding.labels.titles = g.nodes.map { it.title }
        binding.labels.colors = colors
        binding.labels.alwaysLabelled = BooleanArray(g.nodes.size) { g.nodes[it].kind != Kind.SIGNAL }
        binding.graph.setGraph(g, colors)
    }

    override fun onResume() { super.onResume(); binding.graph.onResume() }
    override fun onPause() { super.onPause(); binding.graph.onPause() }

    private fun select(i: Int) {
        binding.graph.select(i)
        binding.labels.selected = i
        val n = graph?.nodes?.getOrNull(i)
        if (n == null) {
            binding.nodeCard.animate().alpha(0f).setDuration(150).withEndAction {
                binding.nodeCard.visibility = View.INVISIBLE
            }.start()
            return
        }
        binding.graph.performHapticFeedback(HapticFeedbackConstants.CLOCK_TICK)
        val c = color(n.tone)
        binding.nodeKind.text = getString(when (n.kind) {
            Kind.APP -> R.string.node_app
            Kind.TECHNIQUE -> R.string.node_technique
            Kind.SIGNAL -> R.string.node_signal
            Kind.HOST -> R.string.node_host
        }).uppercase()
        binding.nodeKind.setTextColor(c)
        binding.nodeKind.backgroundTintList = ColorStateList.valueOf(c and 0x00FFFFFF or 0x29000000)
        binding.nodeTitle.text = n.title
        binding.nodeDetail.text = n.detail
        binding.nodeDetail.visibility = if (n.detail.isEmpty()) View.GONE else View.VISIBLE
        binding.nodeCard.visibility = View.VISIBLE
        binding.nodeCard.alpha = 0f
        binding.nodeCard.translationY = 30f
        binding.nodeCard.animate().alpha(1f).translationY(0f).setDuration(220).start()
    }

    private fun input(name: String, label: String?, d: JSONObject): ThreatGraph.Input {
        val techniques = d.optJSONArray("techniques")?.let { a ->
            List(a.length()) { i ->
                val t = a.getJSONObject(i)
                val ev = t.optJSONArray("evidence_ids")
                ThreatGraph.Technique(t.optString("id"), t.optString("name"), List(ev?.length() ?: 0) { ev!!.getString(it) })
            }
        }.orEmpty()
        val signals = d.optJSONArray("signals")?.let { a ->
            List(a.length()) { i ->
                val s = a.getJSONObject(i)
                ThreatGraph.Signal(s.optString("id"), s.optString("name"), s.optString("severity"), s.optString("detail"))
            }
        }.orEmpty()
        val iocs = d.optJSONObject("iocs")
        val flagged = iocs?.optJSONObject("flagged_hosts")
        val telegram = iocs?.optBoolean("telegram_bot") == true
        val hostNames = listOf("domains", "ips").flatMap { k ->
            iocs?.optJSONArray(k)?.let { a -> List(a.length()) { a.getString(it) } }.orEmpty()
        }.distinct()
        val hosts = hostNames.map { h ->
            ThreatGraph.Host(h, flagged?.optString(h)?.takeIf { it.isNotEmpty() },
                c2 = (telegram && h.contains("telegram")) || h.firstOrNull()?.isDigit() == true)
        }
        val tone = when (label) {
            "malicious" -> Tone.MALICIOUS; "suspicious" -> Tone.SUSPICIOUS; "benign" -> Tone.BENIGN; else -> Tone.UNKNOWN
        }
        return ThreatGraph.Input(name, tone, techniques, signals, hosts)
    }

    private fun color(t: Tone) = ContextCompat.getColor(this, when (t) {
        Tone.MALICIOUS -> R.color.v_malicious
        Tone.SUSPICIOUS -> R.color.v_suspicious
        Tone.BENIGN -> R.color.v_benign
        Tone.UNKNOWN -> R.color.v_unknown
        Tone.INFO -> R.color.info
        Tone.ACCENT -> R.color.accent
    })

    private fun legend(): CharSequence {
        val s = SpannableStringBuilder()
        for ((label, c) in listOf("app" to R.color.text_1, "technique" to R.color.info, "signal" to R.color.v_suspicious,
            "host" to R.color.accent, "flagged" to R.color.v_malicious)) {
            val start = s.length
            s.append("● ")
            s.setSpan(ForegroundColorSpan(ContextCompat.getColor(this, c)), start, start + 1, 0)
            s.append(label).append("   ")
        }
        return s
    }

    companion object {
        private const val EXTRA_SCAN_ID = "scan_id"
        fun intent(activity: Activity, scanId: Long): Intent =
            Intent(activity, ThreatGraphActivity::class.java).putExtra(EXTRA_SCAN_ID, scanId)
    }
}
