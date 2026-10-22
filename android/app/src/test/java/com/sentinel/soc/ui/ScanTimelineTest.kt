package com.sentinel.soc.ui

import com.sentinel.soc.ui.ScanTimeline.State.ACTIVE
import com.sentinel.soc.ui.ScanTimeline.State.DONE
import com.sentinel.soc.ui.ScanTimeline.State.FAILED
import com.sentinel.soc.ui.ScanTimeline.State.PENDING
import org.junit.Assert.assertEquals
import org.junit.Test

class ScanTimelineTest {

    @Test fun justDetectedIsUploading() =
        assertEquals(listOf(DONE, ACTIVE, PENDING, PENDING, PENDING), ScanTimeline.states("detected", null, emptyList()))

    @Test fun midStaticAnalysis() = assertEquals(
        listOf(DONE, DONE, ACTIVE, PENDING, PENDING),
        ScanTimeline.states("analyzing", null, listOf("intake" to "upload_received", "static_analysis" to "analyzer_started")))

    @Test fun staticDoneMeansReasoningNext() = assertEquals(
        listOf(DONE, DONE, DONE, ACTIVE, PENDING),
        ScanTimeline.states("analyzing", null, listOf("static_analysis" to "finished")))

    @Test fun storedVerdictWithoutLocalLabelYet() = assertEquals(
        List(5) { DONE },
        ScanTimeline.states("analyzing", null, listOf("reasoning" to "finished", "verdict" to "stored")))

    @Test fun labelMeansEverythingDone() = assertEquals(List(5) { DONE }, ScanTimeline.states("verdict_ready", "benign", emptyList()))

    @Test fun uploadFailureStopsTheLine() = assertEquals(
        listOf(DONE, FAILED, PENDING, PENDING, PENDING), ScanTimeline.states("upload_failed", null, emptyList()))

    @Test fun removedBeforeAnyResultIsNotInProgress() = assertEquals(
        listOf(DONE, PENDING, PENDING, PENDING, PENDING), ScanTimeline.states("skipped_removed", null, emptyList()))

    @Test fun tooLargeNeverUploaded() = assertEquals(
        listOf(DONE, FAILED, PENDING, PENDING, PENDING), ScanTimeline.states("skipped_too_large", null, emptyList()))

    @Test fun reasonerFallbackIsNotAFailure() = assertEquals(
        listOf(DONE, DONE, DONE, ACTIVE, PENDING),
        ScanTimeline.states("analyzing", null, listOf("static_analysis" to "finished", "reasoning" to "failed",
            "reasoning" to "fallback_used")))
}
