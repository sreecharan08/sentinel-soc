package com.sentinel.soc.ui

/**
 * The five steps a scan goes through, and where this scan is: Detected -> Uploaded -> Static analysis ->
 * Reasoning -> Verdict. Built from the phone's own status plus the server's pipeline events.
 */
object ScanTimeline {

    enum class State { DONE, ACTIVE, PENDING, FAILED }

    const val DETECTED = 0
    const val UPLOADED = 1
    const val STATIC = 2
    const val REASONING = 3
    const val VERDICT = 4

    private val FAILED_LOCAL = setOf("upload_failed", "error")

    fun states(localStatus: String, label: String?, events: List<Pair<String, String>>): List<State> {
        if (label != null) return List(5) { State.DONE }
        fun has(stage: String, vararg steps: String) = events.any { it.first == stage && it.second in steps }
        fun any(stage: String) = events.any { it.first == stage }

        val s = MutableList(5) { State.PENDING }
        s[DETECTED] = State.DONE
        s[UPLOADED] = when {
            has("intake", "upload_received", "cache_hit") || any("static_analysis") || any("reasoning") || any("verdict") ||
                localStatus in setOf("submitted", "analyzing") -> State.DONE
            has("intake", "upload_rejected") || localStatus in FAILED_LOCAL || localStatus == "skipped_too_large" -> State.FAILED
            else -> State.PENDING
        }
        s[STATIC] = when {
            has("static_analysis", "finished", "signals_extracted") || any("reasoning") || any("verdict") -> State.DONE
            has("static_analysis", "failed") -> State.FAILED
            any("static_analysis") -> State.ACTIVE
            else -> State.PENDING
        }
        s[REASONING] = when {
            has("reasoning", "finished") || any("verdict") -> State.DONE
            has("reasoning", "failed") && !has("reasoning", "fallback_used") -> State.FAILED
            any("reasoning") -> State.ACTIVE
            else -> State.PENDING
        }
        s[VERDICT] = if (has("verdict", "stored")) State.DONE else State.PENDING

        // Still running (nothing failed, not skipped or removed): the first pending step after a finished one is
        // the one in progress.
        if (State.FAILED !in s && localStatus !in FAILED_LOCAL && !localStatus.startsWith("skipped")) {
            val next = s.indexOfFirst { it != State.DONE }
            if (next > 0 && s[next] == State.PENDING) s[next] = State.ACTIVE
        }
        return s
    }
}
