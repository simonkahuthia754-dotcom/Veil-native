package com.veil.app

import android.os.Bundle
import android.view.WindowManager
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import com.veil.app.state.VeilSession
import com.veil.app.ui.VeilApp

class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        // Blocks screenshots and the recents-tray thumbnail from showing
        // message content. Skipped only in debug builds, where it would
        // also block Android Studio's layout inspector from capturing the
        // screen — BuildConfig.DEBUG is the real, build-type-driven switch
        // for that, not a manually-flipped flag someone could forget to
        // set back before a release build.
        if (!BuildConfig.DEBUG) {
            window.setFlags(WindowManager.LayoutParams.FLAG_SECURE, WindowManager.LayoutParams.FLAG_SECURE)
        }
        val session = VeilSession(applicationContext)
        setContent {
            VeilApp(session)
        }
    }
}
