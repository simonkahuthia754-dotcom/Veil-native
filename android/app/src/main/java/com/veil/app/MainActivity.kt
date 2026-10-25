package com.veil.app

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import com.veil.app.state.VeilSession
import com.veil.app.ui.VeilApp

class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        // FLAG_SECURE would belong here for a release build — blocks
        // screenshots and the recents-tray thumbnail from showing message
        // content. Deliberately not added yet because it also breaks
        // Android Studio's layout inspector during development; tracked in
        // README as a must-do before any real-world install, not an
        // oversight to discover later.
        val session = VeilSession(applicationContext)
        setContent {
            VeilApp(session)
        }
    }
}
