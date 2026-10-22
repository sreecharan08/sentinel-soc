package com.demo.expfixture

import android.os.Bundle
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity

/** The only UI: a harmless banner. No network, no permission use, no background work. */
class MainActivity : AppCompatActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val view = TextView(this).apply {
            text = "Sentinel test fixture - harmless"
            textSize = 18f
            setPadding(48, 48, 48, 48)
        }
        setContentView(view)
    }
}
