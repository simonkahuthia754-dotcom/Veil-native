package com.veil.app.ui

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.unit.dp
import androidx.navigation.NavHostController
import androidx.navigation.compose.NavHost
import androidx.navigation.compose.composable
import androidx.navigation.compose.rememberNavController
import com.veil.app.crypto.AppLock
import com.veil.app.net.ApiClient
import com.veil.app.net.Chamber
import com.veil.app.state.VeilSession

private val BG = Color(0xFF07050E)
private val PANEL = Color(0xFF1A122A)
private val FG = Color(0xFFFBF8FF)
private val MUTED = Color(0xFF9C8BC2)
private val SIGNAL = Color(0xFFFF3FA4)

@Composable
fun VeilApp(session: VeilSession) {
    val nav = rememberNavController()
    MaterialTheme(colorScheme = darkColorScheme(background = BG, surface = PANEL, primary = SIGNAL, onBackground = FG, onSurface = FG)) {
        Surface(color = BG, modifier = Modifier.fillMaxSize()) {
            NavHost(navController = nav, startDestination = if (session.isLockSet()) "lock" else "setup") {
                composable("setup") { SetupScreen(session) { nav.navigate("lock") { popUpTo("setup") { inclusive = true } } } }
                composable("lock") { LockScreen(session) { nav.navigate("chambers") { popUpTo("lock") { inclusive = true } } } }
                composable("chambers") { ChambersScreen(session, nav) }
                composable("chat/{chamberId}") { backStackEntry ->
                    val id = backStackEntry.arguments?.getString("chamberId") ?: ""
                    ChatScreen(session, id)
                }
            }
        }
    }
}

@Composable
private fun SetupScreen(session: VeilSession, onDone: () -> Unit) {
    var pass by remember { mutableStateOf("") }
    var confirm by remember { mutableStateOf("") }
    var error by remember { mutableStateOf<String?>(null) }

    Column(
        modifier = Modifier.fillMaxSize().padding(24.dp),
        verticalArrangement = Arrangement.Center,
    ) {
        Text("Set your passphrase", color = FG, style = MaterialTheme.typography.headlineSmall)
        Text(
            "8–64 characters. There is no recovery if you forget it — Veil cannot reset it for you, by design.",
            color = MUTED,
            modifier = Modifier.padding(top = 8.dp, bottom = 24.dp),
        )
        OutlinedTextField(
            value = pass, onValueChange = { pass = it }, label = { Text("Passphrase") },
            visualTransformation = PasswordVisualTransformation(),
            keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Password),
            modifier = Modifier.fillMaxWidth(),
        )
        Spacer(Modifier.height(12.dp))
        OutlinedTextField(
            value = confirm, onValueChange = { confirm = it }, label = { Text("Confirm") },
            visualTransformation = PasswordVisualTransformation(),
            keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Password),
            modifier = Modifier.fillMaxWidth(),
        )
        error?.let { Text(it, color = SIGNAL, modifier = Modifier.padding(top = 8.dp)) }
        Spacer(Modifier.height(20.dp))
        Button(onClick = {
            when {
                pass.length < 8 -> error = "Too short — minimum 8 characters."
                pass != confirm -> error = "Passphrases don't match."
                else -> {
                    session.createLock(pass)
                    onDone()
                }
            }
        }, modifier = Modifier.fillMaxWidth()) {
            Text("Create vault")
        }
    }
}

@Composable
private fun LockScreen(session: VeilSession, onUnlocked: () -> Unit) {
    var pass by remember { mutableStateOf("") }
    var status by remember { mutableStateOf<String?>(null) }

    Column(
        modifier = Modifier.fillMaxSize().padding(24.dp),
        verticalArrangement = Arrangement.Center,
        horizontalAlignment = Alignment.CenterHorizontally,
    ) {
        Text("Veil", color = SIGNAL, style = MaterialTheme.typography.displaySmall)
        Spacer(Modifier.height(32.dp))
        OutlinedTextField(
            value = pass, onValueChange = { pass = it }, label = { Text("Passphrase") },
            visualTransformation = PasswordVisualTransformation(),
            keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Password),
            modifier = Modifier.fillMaxWidth(),
        )
        status?.let { Text(it, color = MUTED, modifier = Modifier.padding(top = 12.dp)) }
        Spacer(Modifier.height(20.dp))
        Button(onClick = {
            when (val v = session.unlock(pass)) {
                is AppLock.Verdict.Unlocked -> onUnlocked()
                is AppLock.Verdict.Duress -> {
                    // Real unlock into a decoy/empty state — never the real
                    // vault. The duress passphrase is a legitimate
                    // coercion-resistance feature; it is also, if misused,
                    // a way to create fake "proof of innocence." Veil does
                    // not claim to solve that tension, only to implement
                    // the standard well (see README duress section).
                    session.enterDuress()
                    onUnlocked()
                }
                is AppLock.Verdict.WrongPassphrase -> status = "Wrong passphrase — ${v.attemptsLeft} attempts left."
                is AppLock.Verdict.Locked -> status = "Locked. Try again in ${v.retryAfterMs / 1000}s."
            }
        }, modifier = Modifier.fillMaxWidth()) {
            Text("Unlock")
        }
    }
}

@Composable
private fun ChambersScreen(session: VeilSession, nav: NavHostController) {
    var chambers by remember { mutableStateOf<List<Chamber>>(emptyList()) }
    var error by remember { mutableStateOf<String?>(null) }

    LaunchedEffect(Unit) {
        session.listChambers(
            onSuccess = { chambers = it },
            onError = { error = it },
        )
    }

    Column(Modifier.fillMaxSize().padding(16.dp)) {
        Text("Chambers", color = FG, style = MaterialTheme.typography.headlineSmall, modifier = Modifier.padding(bottom = 16.dp))
        error?.let { Text(it, color = SIGNAL) }
        LazyColumn {
            items(chambers) { chamber ->
                Surface(
                    color = PANEL,
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(vertical = 4.dp),
                ) {
                    TextButton(
                        onClick = { nav.navigate("chat/${chamber.id}") },
                        modifier = Modifier.fillMaxWidth().padding(8.dp),
                    ) {
                        Text(chamber.name, color = FG, modifier = Modifier.fillMaxWidth())
                    }
                }
            }
        }
    }
}

@Composable
private fun ChatScreen(session: VeilSession, chamberId: String) {
    var messages by remember { mutableStateOf(listOf<String>()) }
    var draft by remember { mutableStateOf("") }

    LaunchedEffect(chamberId) {
        session.loadInbox(onSuccess = { messages = it }, onError = {})
    }

    Column(Modifier.fillMaxSize().padding(16.dp)) {
        Box(Modifier.weight(1f).fillMaxWidth().background(BG)) {
            LazyColumn {
                items(messages) { m -> Text(m, color = FG, modifier = Modifier.padding(6.dp)) }
            }
        }
        Row(Modifier.fillMaxWidth().padding(top = 8.dp)) {
            OutlinedTextField(
                value = draft, onValueChange = { draft = it },
                modifier = Modifier.weight(1f), label = { Text("Message") },
            )
            Spacer(Modifier.width(8.dp))
            Button(onClick = {
                if (draft.isNotBlank()) {
                    session.send(chamberId, draft)
                    draft = ""
                }
            }) { Text("Send") }
        }
    }
}
