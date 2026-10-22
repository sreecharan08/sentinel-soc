package com.sentinel.soc.ui

import android.annotation.SuppressLint
import android.content.Context
import android.graphics.Canvas
import android.graphics.Color
import android.util.AttributeSet
import android.view.MotionEvent
import android.view.VelocityTracker
import android.view.View
import android.view.ViewConfiguration
import android.view.animation.DecelerateInterpolator
import android.view.animation.OvershootInterpolator
import android.widget.FrameLayout
import kotlin.math.abs

/**
 * A bottom sheet over a dimmed scrim. Its only child is the sheet. Drag it by the top strip (or anywhere once its
 * scroll view is at the top): release past a quarter to rest at half height, past 70% (or flick down) to dismiss;
 * drag up from half to go full again. Tapping the scrim dismisses.
 */
class SheetLayout @JvmOverloads constructor(context: Context, attrs: AttributeSet? = null) : FrameLayout(context, attrs) {

    /** The sheet's scroll view: a downward drag only moves the sheet when this is scrolled to the top. */
    var scrollTarget: View? = null
    var onDismissed: () -> Unit = {}

    private val slop = ViewConfiguration.get(context).scaledTouchSlop
    private val handleZone = 72 * resources.displayMetrics.density
    private var downX = 0f
    private var downY = 0f
    private var startOffset = 0f
    private var dragging = false
    private var fromHandle = false
    private var velocity: VelocityTracker? = null
    private var opened = false
    private var dismissing = false

    private val sheet: View get() = getChildAt(0)
    private val offset: Float get() = sheet.translationY

    init {
        setWillNotDraw(false)
    }

    override fun onLayout(changed: Boolean, l: Int, t: Int, r: Int, b: Int) {
        super.onLayout(changed, l, t, r, b)
        if (!opened && sheet.height > 0) {
            opened = true
            sheet.translationY = sheet.height.toFloat()
            settle(0f, open = true)
        }
    }

    override fun onDraw(canvas: Canvas) {
        // Scrim darkens with how much of the sheet is showing.
        val shown = if (sheet.height == 0) 0f else 1f - (offset / sheet.height).coerceIn(0f, 1f)
        canvas.drawColor(Color.argb((165 * shown).toInt(), 2, 4, 7))
    }

    override fun onInterceptTouchEvent(e: MotionEvent): Boolean {
        when (e.actionMasked) {
            MotionEvent.ACTION_DOWN -> {
                downX = e.x; downY = e.y; dragging = false
                fromHandle = e.y >= sheet.top + offset && e.y <= sheet.top + offset + handleZone
                if (e.y < sheet.top + offset) return true  // scrim tap
            }
            MotionEvent.ACTION_MOVE -> {
                val dy = e.y - downY
                val vertical = abs(dy) > slop && abs(dy) > abs(e.x - downX) * 1.2f
                val atTop = scrollTarget?.canScrollVertically(-1) != true
                if (vertical && (fromHandle || (dy > 0 && atTop) || (dy < 0 && offset > 0f))) {
                    startDrag(e)
                    return true
                }
            }
        }
        return false
    }

    @SuppressLint("ClickableViewAccessibility")
    override fun onTouchEvent(e: MotionEvent): Boolean {
        when (e.actionMasked) {
            MotionEvent.ACTION_DOWN -> return true
            MotionEvent.ACTION_MOVE -> {
                if (!dragging) startDrag(e)
                velocity?.addMovement(e)
                sheet.translationY = (startOffset + e.y - downY).coerceAtLeast(0f)
                invalidate()
            }
            MotionEvent.ACTION_UP, MotionEvent.ACTION_CANCEL -> {
                if (!dragging) {
                    if (e.y < sheet.top + offset && abs(e.y - downY) < slop) dismiss()
                    return true
                }
                velocity?.addMovement(e)
                velocity?.computeCurrentVelocity(1000)
                val vy = velocity?.yVelocity ?: 0f
                velocity?.recycle(); velocity = null
                dragging = false
                val h = sheet.height.toFloat()
                when {
                    offset > h * 0.7f || (vy > 2500f && offset > h * 0.1f) -> dismiss()
                    offset > h * 0.25f && vy > -1500f -> settle(h * 0.45f)
                    else -> settle(0f)
                }
            }
        }
        return true
    }

    private fun startDrag(e: MotionEvent) {
        dragging = true
        downY = e.y
        startOffset = offset
        sheet.animate().cancel()
        velocity = VelocityTracker.obtain().also { it.addMovement(e) }
    }

    private fun settle(target: Float, open: Boolean = false) {
        sheet.animate().translationY(target)
            .setDuration(if (open) 380 else 260)
            .setInterpolator(if (open) OvershootInterpolator(0.7f) else DecelerateInterpolator())
            .setUpdateListener { invalidate() }
            .start()
    }

    fun dismiss() {
        if (dismissing) return
        dismissing = true
        sheet.animate().translationY(sheet.height.toFloat()).setDuration(220)
            .setInterpolator(DecelerateInterpolator())
            .setUpdateListener { invalidate() }
            .withEndAction { onDismissed() }
            .start()
    }
}
