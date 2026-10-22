package com.sentinel.soc.ui

import com.sentinel.soc.R
import org.junit.Assert.assertEquals
import org.junit.Test

class SecurityScoreTest {

    private val clean = SecurityScore.Inputs(0, 0, protectionOn = true, alertsOn = true, online = true, openRequests = 0)

    @Test fun cleanPhoneScoresFull() = assertEquals(100, SecurityScore.of(clean))

    @Test fun eachRiskCosts() {
        assertEquals(65, SecurityScore.of(clean.copy(maliciousInstalled = 1)))
        assertEquals(88, SecurityScore.of(clean.copy(suspiciousInstalled = 1)))
        assertEquals(80, SecurityScore.of(clean.copy(protectionOn = false)))
        // 100 - 35 - 12 - 5 (request) - 8 (offline) - 10 (alerts off)
        assertEquals(30, SecurityScore.of(clean.copy(maliciousInstalled = 1, suspiciousInstalled = 1, openRequests = 1,
            online = false, alertsOn = false)))
    }

    @Test fun neverBelowZero() = assertEquals(0, SecurityScore.of(clean.copy(maliciousInstalled = 5)))

    @Test fun grades() {
        assertEquals(R.string.grade_excellent, SecurityScore.grade(85).first)
        assertEquals(R.string.grade_good, SecurityScore.grade(84).first)
        assertEquals(R.string.grade_at_risk, SecurityScore.grade(40).first)
        assertEquals(R.string.grade_critical, SecurityScore.grade(39).first)
    }
}
