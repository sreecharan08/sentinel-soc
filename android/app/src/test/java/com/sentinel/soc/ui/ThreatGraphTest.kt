package com.sentinel.soc.ui

import com.sentinel.soc.ui.ThreatGraph.Kind
import com.sentinel.soc.ui.ThreatGraph.Tone
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class ThreatGraphTest {

    private val input = ThreatGraph.Input(
        appName = "Malware test", appTone = Tone.MALICIOUS,
        techniques = listOf(ThreatGraph.Technique("T1636", "Protected User Data", listOf("sig_2", "sig_3"))),
        signals = listOf(
            ThreatGraph.Signal("sig_1", "Sends SMS from code", "high", ""),
            ThreatGraph.Signal("sig_2", "SMS access", "high", ""),
            ThreatGraph.Signal("sig_3", "Contacts access", "low", ""),   // low but cited -> kept
            ThreatGraph.Signal("sig_9", "Debuggable", "low", ""),        // low and uncited -> dropped
        ),
        hosts = listOf(ThreatGraph.Host("bit.ly", "url shortener", false), ThreatGraph.Host("example.org", null, false)),
    )

    @Test fun appIsTheCentre() {
        val g = ThreatGraph.build(input)
        assertEquals(Kind.APP, g.nodes[0].kind)
        assertEquals(0f, g.nodes[0].x)
    }

    @Test fun citedSignalsHangOffTheirTechnique() {
        val g = ThreatGraph.build(input)
        val t = g.nodes.indexOfFirst { it.kind == Kind.TECHNIQUE }
        val sms = g.nodes.indexOfFirst { it.title == "SMS access" }
        val contacts = g.nodes.indexOfFirst { it.title == "Contacts access" }
        assertTrue((t to sms) in g.edges)
        assertTrue((t to contacts) in g.edges)
        // Uncited high signal hangs off the app instead.
        assertTrue((0 to g.nodes.indexOfFirst { it.title == "Sends SMS from code" }) in g.edges)
    }

    @Test fun uncitedLowSignalsAreDropped() =
        assertTrue(ThreatGraph.build(input).nodes.none { it.title == "Debuggable" })

    @Test fun flaggedHostsAreRed() {
        val g = ThreatGraph.build(input)
        assertEquals(Tone.MALICIOUS, g.nodes.first { it.title == "bit.ly" }.tone)
        assertEquals(Tone.ACCENT, g.nodes.first { it.title == "example.org" }.tone)
    }

    @Test fun everyEdgePointsAtARealNode() {
        val g = ThreatGraph.build(input)
        assertEquals(g.nodes.size - 1, g.edges.size)  // a tree: one parent per non-centre node
        assertTrue(g.edges.all { (a, b) -> a in g.nodes.indices && b in g.nodes.indices })
    }
}
