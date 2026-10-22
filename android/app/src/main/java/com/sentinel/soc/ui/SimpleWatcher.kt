package com.sentinel.soc.ui

import android.text.Editable
import android.text.TextWatcher

/** TextWatcher with only the callback most screens need. */
class SimpleWatcher(private val onChange: () -> Unit) : TextWatcher {
    override fun beforeTextChanged(s: CharSequence?, start: Int, count: Int, after: Int) = Unit
    override fun onTextChanged(s: CharSequence?, start: Int, before: Int, count: Int) = Unit
    override fun afterTextChanged(s: Editable?) = onChange()
}
