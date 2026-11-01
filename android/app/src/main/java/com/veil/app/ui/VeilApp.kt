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
                composable("lock") {
                    LockScreen(session) {
                        val dest = if (session.isLoggedIn()) "chambers" else "account"
                        nav.navigate(dest) { popUpTo("lock") { inclusive = true } }
                    }
                }
                composable("account") { AccountScreen(session) { nav.navigate("chambers") { popUpTo("account") { inclusive = true } } } }
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

/**
 * The screen this app has never had: collects a handle and a backend PIN
 * and actually calls [VeilSession.register]/[VeilSession.login] — the
 * previously-dead code path named as the #1 gap in the README. The local
 * vault/passphrase (set up on [SetupScreen]/[LockScreen]) is a separate
 * concept from this backend account: the vault protects this device's
 * keys at rest; registering/logging in is what lets this device actually
 * reach other people through the backend at all.
 *
 * PIN here means the same 4–8 digit backend PIN the CLI's `cmd_register`/
 * `cmd_login` already use (`PIN_PATTERN` in `backend/src/app.js`) — not
 * the vault passphrase from setup, and deliberately not reusing that
 * passphrase as the PIN (different secrets, different threat models: the
 * PIN only ever has to resist the backend's own rate limiting, not an
 * offline brute force against a stolen device).
 */
@Composable
private fun AccountScreen(session: VeilSession, onDone: () -> Unit) {
    var mode by remember { mutableStateOf(true) } // true = register, false = login
    var handle by remember { mutableStateOf("") }
    var pin by remember { mutableStateOf("") }
    var busy by remember { mutableStateOf(false) }
    var error by remember { mutableStateOf<String?>(null) }

    fun submit() {
        error = null
        if (handle.isBlank()) { error = "Enter a handle."; return }
        if (!pin.matches(Regex("^\\d{4,8}$"))) { error = "PIN must be 4–8 digits."; return }
        busy = true
        val onSuccess = { busy = false; onDone() }
        val onError = { msg: String -> busy = false; error = msg }
        if (mode) session.register(handle, pin, onSuccess, onError) else session.login(handle, pin, onSuccess, onError)
    }

    Column(
        modifier = Modifier.fillMaxSize().padding(24.dp),
        verticalArrangement = Arrangement.Center,
    ) {
        Text(if (mode) "Create your account" else "Log in", color = FG, style = MaterialTheme.typography.headlineSmall)
        Text(
            "Your handle is how others find you. The PIN protects this account on the backend — separate from your vault passphrase.",
            color = MUTED,
            modifier = Modifier.padding(top = 8.dp, bottom = 24.dp),
        )
        OutlinedTextField(
            value = handle, onValueChange = { handle = it }, label = { Text("Handle") },
            enabled = !busy,
            modifier = Modifier.fillMaxWidth(),
        )
        Spacer(Modifier.height(12.dp))
        OutlinedTextField(
            value = pin, onValueChange = { if (it.length <= 8) pin = it.filter(Char::isDigit) }, label = { Text("PIN (4–8 digits)") },
            visualTransformation = PasswordVisualTransformation(),
            keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.NumberPassword),
            enabled = !busy,
            modifier = Modifier.fillMaxWidth(),
        )
        error?.let { Text(it, color = SIGNAL, modifier = Modifier.padding(top = 8.dp)) }
        Spacer(Modifier.height(20.dp))
        Button(onClick = { submit() }, enabled = !busy, modifier = Modifier.fillMaxWidth()) {
            Text(if (busy) "Working…" else if (mode) "Register" else "Log in")
        }
        Spacer(Modifier.height(12.dp))
        TextButton(onClick = { mode = !mode; error = null }, enabled = !busy, modifier = Modifier.fillMaxWidth()) {
            Text(if (mode) "Already have an account? Log in" else "Need an account? Register", color = MUTED)
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
