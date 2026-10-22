package com.sentinel.soc.ui

import com.sentinel.soc.R

/** The phone's 0-100 security score: starts at 100 and loses points for each open risk. */
object SecurityScore {

    data class Inputs(
        val maliciousInstalled: Int,
        val suspiciousInstalled: Int,
        val protectionOn: Boolean,
        val alertsOn: Boolean,
        val online: Boolean,
        val openRequests: Int,
    )

    fun of(i: Inputs): Int {
        var s = 100
        s -= 35 * i.maliciousInstalled
        s -= 12 * i.suspiciousInstalled
        if (!i.protectionOn) s -= 20
        if (!i.alertsOn) s -= 10
        if (!i.online) s -= 8
        s -= 5 * i.openRequests
        return s.coerceIn(0, 100)
    }

    /** String resource for the grade, and the verdict colour that goes with it. */
    fun grade(score: Int): Pair<Int, Int> = when {
        score >= 85 -> R.string.grade_excellent to R.color.v_benign
        score >= 65 -> R.string.grade_good to R.color.accent
        score >= 40 -> R.string.grade_at_risk to R.color.v_suspicious
        else -> R.string.grade_critical to R.color.v_malicious
    }
}
