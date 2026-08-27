package com.demo

import android.util.Log
import android.webkit.WebView

// A hard-coded backend credential, compiled into the shipped APK.
const val API_KEY = "a3F7kR9tPx2Lm5Qz8Wv1Nb4Hc6Yd0Jg7Ue"
const val BACKEND = "http://api.demo.example/v1"

class MainActivity {
    // A hard-coded session token (the classic example JWT). Shipped in the APK,
    // it is readable by anyone who unzips it.
    private val secretKey = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"

    fun setup(web: WebView) {
        web.settings.javaScriptEnabled = true
        web.addJavascriptInterface(Bridge(), "android")
        web.settings.setAllowUniversalAccessFromFileURLs(true)
        Log.d("auth", "user token = $secretKey")
    }
}

class Bridge
