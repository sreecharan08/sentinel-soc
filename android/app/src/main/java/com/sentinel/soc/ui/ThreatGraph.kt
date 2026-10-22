package com.sentinel.soc.ui

import kotlin.math.cos
import kotlin.math.sin
import kotlin.math.sqrt

/**
 * Nodes and edges of one app's threat graph: the app in the centre, MITRE techniques on an inner shell, the
 * signals that evidence each technique just outside it, and network hosts on an outer shell.
 */
object ThreatGraph {

    enum class Kind { APP, TECHNIQUE, SIGNAL, HOST }
    enum class Tone { MALICIOUS, SUSPICIOUS, BENIGN, UNKNOWN, INFO, ACCENT }

    data class Technique(val id: String, val name: String, val evidenceIds: List<String>)
    data class Signal(val id: String, val name: String, val severity: String, val detail: String)
    data class Host(val name: String, val flaggedReason: String?, val c2: Boolean)
    data class Input(val appName: String, val appTone: Tone, val techniques: List<Technique>,
                     val signals: List<Signal>, val hosts: List<Host>)

    data class Node(val kind: Kind, val title: String, val detail: String, val tone: Tone,
                    val x: Float, val y: Float, val z: Float, val size: Float)
    data class Graph(val nodes: List<Node>, val edges: List<Pair<Int, Int>>)

    /** Low-severity signals that no technique cites are left out: they add clutter, not meaning. */
    fun build(input: Input, maxSignals: Int = 16): Graph {
        val nodes = mutableListOf(Node(Kind.APP, input.appName, "", input.appTone, 0f, 0f, 0f, 46f))
        val edges = mutableListOf<Pair<Int, Int>>()
        val cited = input.techniques.flatMap { it.evidenceIds }.toSet()
        val signals = input.signals.filter { it.id in cited || it.severity != "low" }.take(maxSignals)
        val placedSignals = mutableSetOf<String>()

        input.techniques.forEachIndexed { i, t ->
            val (x, y, z) = sphere(i, input.techniques.size, 1.0f, 0.3f)
            val ti = nodes.size
            nodes += Node(Kind.TECHNIQUE, t.id, t.name, Tone.INFO, x, y, z, 30f)
            edges += 0 to ti
            val own = signals.filter { it.id in t.evidenceIds && it.id !in placedSignals }
            own.forEachIndexed { k, s ->
                placedSignals += s.id
                // Fan the technique's signals out around it, a step further from the centre.
                val a = k * 2.399963f
                val off = 0.32f
                nodes += signalNode(s, x * 1.7f + cos(a) * off, y * 1.7f + sin(a) * off, z * 1.7f + sin(a * 1.3f) * off)
                edges += ti to nodes.lastIndex
            }
        }
        val loose = signals.filter { it.id !in placedSignals }
        loose.forEachIndexed { i, s ->
            val (x, y, z) = sphere(i, loose.size, 1.85f, 1.1f)
            nodes += signalNode(s, x, y, z)
            edges += 0 to nodes.lastIndex
        }
        input.hosts.forEachIndexed { i, h ->
            val (x, y, z) = sphere(i, input.hosts.size, 1.45f, 2.2f)
            val tone = when {
                h.flaggedReason != null || h.c2 -> Tone.MALICIOUS
                else -> Tone.ACCENT
            }
            nodes += Node(Kind.HOST, h.name, h.flaggedReason ?: "", tone, x, y, z, 26f)
            edges += 0 to nodes.lastIndex
        }
        return Graph(nodes, edges)
    }

    private fun signalNode(s: Signal, x: Float, y: Float, z: Float) = Node(
        Kind.SIGNAL, s.name, s.detail,
        when (s.severity) { "high" -> Tone.MALICIOUS; "medium" -> Tone.SUSPICIOUS; else -> Tone.UNKNOWN },
        x, y, z, 18f)

    /** Point [i] of [n] spread evenly over a sphere of radius [r] (golden-angle spiral). */
    private fun sphere(i: Int, n: Int, r: Float, phase: Float): Triple<Float, Float, Float> {
        if (n == 1) return Triple(r, 0f, 0f)
        val y = 1f - (i + 0.5f) / n * 2f
        val rr = sqrt(1f - y * y)
        val th = i * 2.399963f + phase
        return Triple(cos(th) * rr * r, y * r * 0.85f, sin(th) * rr * r)
    }
}
