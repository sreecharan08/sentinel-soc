package com.demo.expfixture

/**
 * Indicator strings only. Referenced from a function nothing calls, so the string stays in the DEX.
 * The reserved .invalid TLD never resolves, and no code path here opens a connection.
 */
object Indicators {
    const val BEACON = "http://c2.demo-sentinel.invalid/beacon"

    @Suppress("unused")
    fun unusedBeaconDemo(): String = BEACON
}
