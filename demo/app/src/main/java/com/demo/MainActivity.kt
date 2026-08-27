package com.demo

import android.util.Log
import android.webkit.WebView

const val API_KEY = "AIzaSyD-9tSrke72PouQMnMX-a7eZSW0jkFMBWY"
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
