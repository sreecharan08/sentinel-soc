package com.sentinel.soc.ui

import android.app.Activity
import android.content.Intent
import android.graphics.Rect
import android.view.GestureDetector
import android.view.MotionEvent
import android.view.View
import android.widget.ImageView
import android.widget.TextView
import androidx.core.content.ContextCompat
import com.sentinel.soc.R
import com.sentinel.soc.databinding.ViewBottomNavBinding
import kotlin.math.abs

/**
 * The Home/Activity/Inbox/Settings footer. "Activity" is a scroll position on Home, not a separate screen.
 * Inbox and Settings sit above Home in the back stack; switching between them replaces the current one.
 * The three screens also swipe left/right into each other ([Swipe]).
 */
object BottomNav {
    enum class Tab { HOME, INBOX, SETTINGS }

    fun wire(activity: Activity, nav: ViewBottomNavBinding, current: Tab, onHomeTap: () -> Unit = {}, onActivityTap: () -> Unit = {}) {
        val on = ContextCompat.getColor(activity, R.color.accent)
        val off = ContextCompat.getColor(activity, R.color.text_3)
        tint(nav.navHomeIcon, nav.navHomeLabel, if (current == Tab.HOME) on else off)
        tint(nav.navActivityIcon, nav.navActivityLabel, off)
        tint(nav.navInboxIcon, nav.navInboxLabel, if (current == Tab.INBOX) on else off)
        tint(nav.navSettingsIcon, nav.navSettingsLabel, if (current == Tab.SETTINGS) on else off)

        val fade = android.R.anim.fade_in to android.R.anim.fade_out
        nav.navHome.setOnClickListener { if (current == Tab.HOME) onHomeTap() else go(activity, current, Tab.HOME, fade) }
        nav.navActivity.setOnClickListener { if (current == Tab.HOME) onActivityTap() else goHome(activity, true, fade) }
        nav.navInbox.setOnClickListener { if (current != Tab.INBOX) go(activity, current, Tab.INBOX, fade) }
        nav.navSettings.setOnClickListener { if (current != Tab.SETTINGS) go(activity, current, Tab.SETTINGS, fade) }
    }

    fun setInboxBadge(nav: ViewBottomNavBinding, count: Int) {
        nav.navInboxBadge.visibility = if (count > 0) View.VISIBLE else View.GONE
        nav.navInboxBadge.text = if (count > 9) "9+" else count.toString()
    }

    private fun tint(icon: ImageView, label: TextView, color: Int) {
        icon.setColorFilter(color)
        label.setTextColor(color)
    }

    @Suppress("DEPRECATION")
    private fun go(activity: Activity, current: Tab, target: Tab, anim: Pair<Int, Int>) {
        when (target) {
            Tab.HOME -> { goHome(activity, false, anim); return }
            Tab.INBOX -> activity.startActivity(Intent(activity, InboxActivity::class.java))
            Tab.SETTINGS -> activity.startActivity(Intent(activity, SettingsActivity::class.java))
        }
        activity.overridePendingTransition(anim.first, anim.second)
        if (current != Tab.HOME) activity.finish()
    }

    @Suppress("DEPRECATION")
    private fun goHome(activity: Activity, scrollToActivity: Boolean, anim: Pair<Int, Int>) {
        activity.startActivity(Intent(activity, MainActivity::class.java)
            .addFlags(Intent.FLAG_ACTIVITY_CLEAR_TOP)
            .putExtra(MainActivity.EXTRA_SCROLL_TO_ACTIVITY, scrollToActivity))
        activity.overridePendingTransition(anim.first, anim.second)
    }

    /**
     * Horizontal fling between Home, Inbox and Settings. Feed every touch from the activity's dispatchTouchEvent;
     * touches that start on an [excluded] view (the draggable 3D orb) never switch tabs.
     */
    class Swipe(private val activity: Activity, private val current: Tab, private val excluded: () -> List<View> = { emptyList() }) {
        private val minDistance = 90 * activity.resources.displayMetrics.density
        private val box = Rect()
        private val detector = GestureDetector(activity, object : GestureDetector.SimpleOnGestureListener() {
            override fun onFling(e1: MotionEvent?, e2: MotionEvent, vx: Float, vy: Float): Boolean {
                if (e1 == null) return false
                val dx = e2.x - e1.x
                val dy = e2.y - e1.y
                if (abs(dx) < minDistance || abs(dx) < abs(dy) * 1.8f || abs(vx) < 700f) return false
                if (excluded().any { it.isShown && it.getGlobalVisibleRect(box) && box.contains(e1.rawX.toInt(), e1.rawY.toInt()) }) {
                    return false
                }
                val order = Tab.entries
                val target = order.getOrNull(order.indexOf(current) + if (dx < 0) 1 else -1) ?: return false
                val anim = if (dx < 0) R.anim.tab_in_right to R.anim.tab_out_left else R.anim.tab_in_left to R.anim.tab_out_right
                go(activity, current, target, anim)
                return true
            }
        })

        fun onTouch(e: MotionEvent) { detector.onTouchEvent(e) }
    }
}
