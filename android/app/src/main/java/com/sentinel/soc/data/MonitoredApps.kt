package com.sentinel.soc.data

/**
 * The only apps this build watches, scans and lists. Everything else on the phone is ignored: no install events,
 * no device-wide scan, no rows. Edit this map to change the set (package name -> display name).
 */
object MonitoredApps {
    val labels: Map<String, String> = linkedMapOf(
        "com.happymod.apk" to "HappyMod",
        "com.demo.malwaretest" to "Sentinel MALWARE-TEST (harmless)",
        "com.demo.expfixture" to "Sentinel FIXTURE (harmless)",
        "com.duosecurity.duomobile" to "Duo Mobile",
    )

    val packages: Set<String> get() = labels.keys

    fun isMonitored(packageName: String): Boolean = packageName in labels
}
