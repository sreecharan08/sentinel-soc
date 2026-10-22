package com.sentinel.soc.ui

import android.animation.ValueAnimator
import android.content.Context
import android.graphics.Canvas
import android.graphics.Color
import android.graphics.Paint
import android.graphics.RectF
import android.graphics.Typeface
import android.util.AttributeSet
import android.view.View
import android.view.animation.DecelerateInterpolator
import androidx.core.content.ContextCompat
import com.sentinel.soc.R

private fun View.dp(v: Float) = v * resources.displayMetrics.density

/**
 * Animated arc gauge: the security score (270 degrees) or a verdict's confidence ring (360). The arc sweeps to the
 * new value whenever it changes, with a soft glow in the value's colour.
 */
class GaugeView @JvmOverloads constructor(context: Context, attrs: AttributeSet? = null) : View(context, attrs) {

    var sweepDegrees = 270f
    var centerText = ""
    var subText = ""
    var color = Color.CYAN
        set(v) { field = v; invalidate() }

    private var shown = 0f
    private var animator: ValueAnimator? = null
    private val track = Paint(Paint.ANTI_ALIAS_FLAG).apply {
        style = Paint.Style.STROKE; strokeCap = Paint.Cap.ROUND; color = ContextCompat.getColor(context, R.color.bg_2)
    }
    private val arc = Paint(Paint.ANTI_ALIAS_FLAG).apply { style = Paint.Style.STROKE; strokeCap = Paint.Cap.ROUND }
    private val glow = Paint(Paint.ANTI_ALIAS_FLAG).apply { style = Paint.Style.STROKE; strokeCap = Paint.Cap.ROUND }
    private val big = Paint(Paint.ANTI_ALIAS_FLAG).apply {
        textAlign = Paint.Align.CENTER; typeface = Typeface.create(Typeface.MONOSPACE, Typeface.BOLD)
        color = ContextCompat.getColor(context, R.color.text_1)
    }
    private val small = Paint(Paint.ANTI_ALIAS_FLAG).apply {
        textAlign = Paint.Align.CENTER; letterSpacing = 0.12f; color = ContextCompat.getColor(context, R.color.text_3)
    }
    private val box = RectF()

    /** [value] in 0..1. */
    fun setValue(value: Float, animate: Boolean = true) {
        val target = value.coerceIn(0f, 1f)
        animator?.cancel()
        if (!animate) { shown = target; invalidate(); return }
        animator = ValueAnimator.ofFloat(shown, target).apply {
            duration = 900
            interpolator = DecelerateInterpolator(1.6f)
            addUpdateListener { shown = it.animatedValue as Float; invalidate() }
            start()
        }
    }

    override fun onDetachedFromWindow() {
        animator?.cancel()
        super.onDetachedFromWindow()
    }

    override fun onDraw(canvas: Canvas) {
        val stroke = minOf(width, height) * 0.085f
        val pad = stroke * 1.4f
        box.set(pad, pad, width - pad, height - pad)
        val start = if (sweepDegrees >= 360f) -90f else 90f + (360f - sweepDegrees) / 2f
        track.strokeWidth = stroke
        arc.strokeWidth = stroke; arc.color = color
        glow.strokeWidth = stroke * 2.2f; glow.color = color; glow.alpha = 40
        canvas.drawArc(box, start, sweepDegrees, false, track)
        if (shown > 0.001f) {
            canvas.drawArc(box, start, sweepDegrees * shown, false, glow)
            canvas.drawArc(box, start, sweepDegrees * shown, false, arc)
        }
        big.textSize = minOf(width, height) * 0.26f
        small.textSize = minOf(width, height) * 0.085f
        val cy = height / 2f + big.textSize * 0.3f
        canvas.drawText(centerText, width / 2f, cy, big)
        if (subText.isNotEmpty()) canvas.drawText(subText.uppercase(), width / 2f, cy + small.textSize * 2f, small)
    }
}

/** Stacked bars: scans per day by verdict, growing in when the data changes. Oldest day on the left. */
class HistoryChartView @JvmOverloads constructor(context: Context, attrs: AttributeSet? = null) : View(context, attrs) {

    private var days: List<Map<String, Int>> = emptyList()
    private var grow = 1f
    private val order = listOf("malicious", "suspicious", "benign", "unknown", "pending")
    private val colors = mapOf(
        "malicious" to ContextCompat.getColor(context, R.color.v_malicious),
        "suspicious" to ContextCompat.getColor(context, R.color.v_suspicious),
        "benign" to ContextCompat.getColor(context, R.color.v_benign),
        "unknown" to ContextCompat.getColor(context, R.color.v_unknown),
        "pending" to ContextCompat.getColor(context, R.color.info),
    )
    private val bar = Paint(Paint.ANTI_ALIAS_FLAG)
    private val empty = Paint(Paint.ANTI_ALIAS_FLAG).apply { color = ContextCompat.getColor(context, R.color.bg_2) }
    private val label = Paint(Paint.ANTI_ALIAS_FLAG).apply {
        color = ContextCompat.getColor(context, R.color.text_3); textSize = dp(9f); textAlign = Paint.Align.CENTER
        typeface = Typeface.MONOSPACE
    }
    private val r = RectF()

    fun setData(data: List<Map<String, Int>>) {
        if (data == days) return
        days = data
        ValueAnimator.ofFloat(0f, 1f).apply {
            duration = 700; interpolator = DecelerateInterpolator()
            addUpdateListener { grow = it.animatedValue as Float; invalidate() }
            start()
        }
    }

    override fun onDraw(canvas: Canvas) {
        if (days.isEmpty()) return
        val labelH = dp(14f)
        val chartH = height - labelH
        val slot = width / days.size.toFloat()
        val barW = slot * 0.56f
        val max = maxOf(1, days.maxOf { it.values.sum() })
        val corner = dp(3f)
        days.forEachIndexed { i, day ->
            val x = i * slot + (slot - barW) / 2f
            r.set(x, chartH - dp(3f), x + barW, chartH)
            canvas.drawRoundRect(r, corner, corner, empty)
            var top = chartH
            for (k in order) {
                val n = day[k] ?: 0
                if (n == 0) continue
                val h = (chartH - dp(4f)) * n / max * grow
                r.set(x, top - h, x + barW, top)
                bar.color = colors.getValue(k)
                canvas.drawRoundRect(r, corner, corner, bar)
                top -= h
            }
            val text = when (i) {
                days.lastIndex -> "today"
                0 -> "-${days.size - 1}d"
                days.size / 2 -> "-${days.size - 1 - i}d"
                else -> null
            }
            if (text != null) canvas.drawText(text, x + barW / 2f, height - dp(2f), label)
        }
    }
}
