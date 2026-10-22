package com.sentinel.soc.ui

import android.animation.ValueAnimator
import android.content.Context
import android.graphics.Canvas
import android.graphics.Color
import android.graphics.LinearGradient
import android.graphics.Matrix
import android.graphics.Paint
import android.graphics.RadialGradient
import android.graphics.RectF
import android.graphics.Shader
import android.graphics.Typeface
import android.os.Build
import android.os.VibrationEffect
import android.os.Vibrator
import android.os.VibratorManager
import android.util.AttributeSet
import android.view.View
import android.view.animation.LinearInterpolator
import androidx.core.content.ContextCompat
import com.sentinel.soc.R

private fun View.dp(v: Float) = v * resources.displayMetrics.density

/** Five-step scan stepper: finished steps filled, the running one pulses, a failed one turns red. */
class TimelineView @JvmOverloads constructor(context: Context, attrs: AttributeSet? = null) : View(context, attrs) {

    private var states: List<ScanTimeline.State> = List(5) { ScanTimeline.State.PENDING }
    private val titles = context.resources.getStringArray(R.array.timeline_steps)
    private var pulse = 0f
    private val anim = ValueAnimator.ofFloat(0f, 1f).apply {
        duration = 1100; repeatCount = ValueAnimator.INFINITE; interpolator = LinearInterpolator()
        addUpdateListener { pulse = it.animatedValue as Float; invalidate() }
    }
    private val done = ContextCompat.getColor(context, R.color.v_benign)
    private val active = ContextCompat.getColor(context, R.color.accent)
    private val failed = ContextCompat.getColor(context, R.color.v_malicious)
    private val idle = ContextCompat.getColor(context, R.color.border)
    private val fill = Paint(Paint.ANTI_ALIAS_FLAG)
    private val stroke = Paint(Paint.ANTI_ALIAS_FLAG).apply { style = Paint.Style.STROKE }
    private val line = Paint(Paint.ANTI_ALIAS_FLAG)
    private val text = Paint(Paint.ANTI_ALIAS_FLAG).apply { textAlign = Paint.Align.CENTER; textSize = dp(9.5f) }
    private val mark = Paint(Paint.ANTI_ALIAS_FLAG).apply {
        style = Paint.Style.STROKE; strokeCap = Paint.Cap.ROUND; strokeWidth = dp(1.8f); color = Color.WHITE
    }

    fun setStates(s: List<ScanTimeline.State>) {
        if (s == states) return
        states = s
        if (ScanTimeline.State.ACTIVE in s && isAttachedToWindow) anim.start() else anim.cancel()
        invalidate()
    }

    override fun onAttachedToWindow() {
        super.onAttachedToWindow()
        if (ScanTimeline.State.ACTIVE in states) anim.start()
    }

    override fun onDetachedFromWindow() {
        anim.cancel()
        super.onDetachedFromWindow()
    }

    override fun onMeasure(widthMeasureSpec: Int, heightMeasureSpec: Int) =
        setMeasuredDimension(MeasureSpec.getSize(widthMeasureSpec), dp(58f).toInt())

    override fun onDraw(canvas: Canvas) {
        val n = states.size
        val slot = width / n.toFloat()
        val cy = dp(16f)
        val r = dp(9f)
        line.strokeWidth = dp(2f)
        for (i in 0 until n - 1) {
            line.color = if (states[i + 1] == ScanTimeline.State.DONE || states[i + 1] == ScanTimeline.State.ACTIVE) done else idle
            canvas.drawLine(slot * i + slot / 2 + r, cy, slot * (i + 1) + slot / 2 - r, cy, line)
        }
        for (i in 0 until n) {
            val cx = slot * i + slot / 2
            val c = when (states[i]) {
                ScanTimeline.State.DONE -> done
                ScanTimeline.State.ACTIVE -> active
                ScanTimeline.State.FAILED -> failed
                ScanTimeline.State.PENDING -> idle
            }
            when (states[i]) {
                ScanTimeline.State.ACTIVE -> {
                    fill.color = c; fill.alpha = (110 * (1f - pulse)).toInt()
                    canvas.drawCircle(cx, cy, r + dp(9f) * pulse, fill)
                    stroke.color = c; stroke.strokeWidth = dp(2.2f); canvas.drawCircle(cx, cy, r, stroke)
                    fill.alpha = 255; canvas.drawCircle(cx, cy, r * 0.42f, fill)
                }
                ScanTimeline.State.PENDING -> {
                    stroke.color = c; stroke.strokeWidth = dp(2f); canvas.drawCircle(cx, cy, r, stroke)
                }
                else -> {
                    fill.color = c; fill.alpha = 255; canvas.drawCircle(cx, cy, r, fill)
                    if (states[i] == ScanTimeline.State.DONE) {
                        canvas.drawLine(cx - r * 0.4f, cy, cx - r * 0.08f, cy + r * 0.32f, mark)
                        canvas.drawLine(cx - r * 0.08f, cy + r * 0.32f, cx + r * 0.42f, cy - r * 0.3f, mark)
                    } else {
                        canvas.drawLine(cx - r * 0.35f, cy - r * 0.35f, cx + r * 0.35f, cy + r * 0.35f, mark)
                        canvas.drawLine(cx + r * 0.35f, cy - r * 0.35f, cx - r * 0.35f, cy + r * 0.35f, mark)
                    }
                }
            }
            text.color = if (states[i] == ScanTimeline.State.PENDING) ContextCompat.getColor(context, R.color.text_3) else c
            text.typeface = if (states[i] == ScanTimeline.State.ACTIVE) Typeface.DEFAULT_BOLD else Typeface.DEFAULT
            canvas.drawText(titles[i], cx, cy + r + dp(17f), text)
        }
    }
}

/** Skeleton placeholder: rounded bars with a light sweep running across, shown while content loads. */
class ShimmerView @JvmOverloads constructor(context: Context, attrs: AttributeSet? = null) : View(context, attrs) {

    var rows = 3
    private var shift = 0f
    private val base = ContextCompat.getColor(context, R.color.bg_2)
    private val bar = Paint(Paint.ANTI_ALIAS_FLAG)
    private val shine = Paint(Paint.ANTI_ALIAS_FLAG)
    private val m = Matrix()
    private val rect = RectF()
    private val anim = ValueAnimator.ofFloat(-1f, 2f).apply {
        duration = 1300; repeatCount = ValueAnimator.INFINITE; interpolator = LinearInterpolator()
        addUpdateListener { shift = it.animatedValue as Float; invalidate() }
    }

    override fun onAttachedToWindow() { super.onAttachedToWindow(); anim.start() }
    override fun onDetachedFromWindow() { anim.cancel(); super.onDetachedFromWindow() }

    override fun onVisibilityChanged(changedView: View, visibility: Int) {
        super.onVisibilityChanged(changedView, visibility)
        if (visibility == VISIBLE && isAttachedToWindow) anim.start() else anim.cancel()
    }

    override fun onMeasure(widthMeasureSpec: Int, heightMeasureSpec: Int) =
        setMeasuredDimension(MeasureSpec.getSize(widthMeasureSpec), (rows * dp(64f)).toInt())

    override fun onDraw(canvas: Canvas) {
        if (shine.shader == null) {
            shine.shader = LinearGradient(0f, 0f, width * 0.4f, 0f,
                intArrayOf(Color.TRANSPARENT, 0x22FFFFFF, Color.TRANSPARENT), null, Shader.TileMode.CLAMP)
        }
        m.setTranslate(shift * width, 0f)
        shine.shader.setLocalMatrix(m)
        bar.color = base
        val rowH = dp(64f)
        for (i in 0 until rows) {
            val top = i * rowH + dp(8f)
            val cy = top + dp(20f)
            canvas.drawCircle(dp(18f), cy, dp(18f), bar); canvas.drawCircle(dp(18f), cy, dp(18f), shine)
            rect.set(dp(48f), top + dp(6f), width * (0.85f - i * 0.12f), top + dp(18f))
            canvas.drawRoundRect(rect, dp(6f), dp(6f), bar); canvas.drawRoundRect(rect, dp(6f), dp(6f), shine)
            rect.set(dp(48f), top + dp(24f), width * (0.55f - i * 0.06f), top + dp(33f))
            canvas.drawRoundRect(rect, dp(5f), dp(5f), bar); canvas.drawRoundRect(rect, dp(5f), dp(5f), shine)
        }
    }
}

/** Full-screen red edge glow for the "threat found" moment. Invisible until [flash] is called. */
class VignetteView @JvmOverloads constructor(context: Context, attrs: AttributeSet? = null) : View(context, attrs) {

    private val paint = Paint()
    private val red = ContextCompat.getColor(context, R.color.v_malicious)

    init {
        alpha = 0f
        isClickable = false
    }

    override fun onSizeChanged(w: Int, h: Int, oldw: Int, oldh: Int) {
        // Unit circle stretched to an ellipse through the corners, so the long side edges glow too on tall screens.
        paint.shader = RadialGradient(0f, 0f, 1f,
            intArrayOf(Color.TRANSPARENT, Color.TRANSPARENT, (red and 0x00FFFFFF) or (0xC0 shl 24)),
            floatArrayOf(0f, 0.5f, 1f), Shader.TileMode.CLAMP).apply {
            setLocalMatrix(android.graphics.Matrix().apply {
                setScale(w * 0.7071f, h * 0.7071f)
                postTranslate(w / 2f, h / 2f)
            })
        }
    }

    override fun onDraw(canvas: Canvas) = canvas.drawRect(0f, 0f, width.toFloat(), height.toFloat(), paint)

    /** Two red pulses with a strong vibration pattern. */
    fun flash() {
        animate().cancel()
        alpha = 0f
        animate().alpha(1f).setDuration(180).withEndAction {
            animate().alpha(0.25f).setDuration(260).withEndAction {
                animate().alpha(1f).setDuration(180).withEndAction {
                    animate().alpha(0f).setDuration(900).start()
                }.start()
            }.start()
        }.start()
        vibrate()
    }

    private fun vibrate() {
        val v: Vibrator? = if (Build.VERSION.SDK_INT >= 31) {
            context.getSystemService(VibratorManager::class.java)?.defaultVibrator
        } else {
            @Suppress("DEPRECATION") context.getSystemService(Vibrator::class.java)
        }
        if (v?.hasVibrator() != true) return
        v.vibrate(VibrationEffect.createWaveform(longArrayOf(0, 90, 70, 90, 70, 260), intArrayOf(0, 255, 0, 255, 0, 200), -1))
    }
}
