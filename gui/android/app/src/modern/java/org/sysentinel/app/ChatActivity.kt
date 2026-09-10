// SPDX-License-Identifier: Apache-2.0
package org.sysentinel.app

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.lazy.rememberLazyListState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

/**
 * The modern face: Material 3, dark, message bubbles.
 *
 * Deliberately shaped like a messaging app rather than a dashboard, because
 * that is what it is for — the machine talks, the owner answers, and the whole
 * point is that this conversation does not have to happen in a third party's
 * chat app in front of colleagues.
 *
 * # It does not notify
 *
 * No notification channel is created and none is posted, here or anywhere in
 * this app. Same reasoning as `daemon/src/facenn.rs`: a phone that lights up
 * with "ROSTRO NO REGISTRADO" while somebody is standing over its owner has
 * announced that the machine informed on them. Alerts are read when the app is
 * opened, on purpose.
 */
class ChatActivity : ComponentActivity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        val identity = DeviceIdentity.ensureKey()

        setContent {
            MaterialTheme(colorScheme = darkColorScheme(primary = Accent)) {
                ChatScreen(identity)
            }
        }
    }
}

private val Accent = Color(0xFF7FD4FF)
private val Ground = Color(0xFF0B0F14)
private val Mine = Color(0xFF17313D)
private val Theirs = Color(0xFF161C24)

@Composable
private fun ChatScreen(identity: DeviceIdentity.Identity) {
    var draft by remember { mutableStateOf("") }
    val messages = remember {
        mutableStateListOf(
            Message(
                "Estoy despierta. Los P-cores van a IPC 3.13 y no hay nada raro por acá.",
                fromMe = false,
            ),
        )
    }
    val listState = rememberLazyListState()

    LaunchedEffect(messages.size) {
        if (messages.isNotEmpty()) listState.animateScrollToItem(messages.lastIndex)
    }

    Scaffold(
        containerColor = Ground,
        topBar = { IdentityBar(identity) },
        bottomBar = {
            Composer(
                draft = draft,
                onDraft = { draft = it },
                onSend = {
                    if (draft.isNotBlank()) {
                        messages.add(Message(draft, fromMe = true))
                        draft = ""
                    }
                },
            )
        },
    ) { padding ->
        LazyColumn(
            state = listState,
            modifier = Modifier
                .padding(padding)
                .fillMaxSize()
                .background(Ground),
            contentPadding = PaddingValues(12.dp),
            verticalArrangement = Arrangement.spacedBy(6.dp),
        ) {
            items(messages) { Bubble(it) }
        }
    }
}

/**
 * The header states what this handset can actually prove, not what it wishes
 * it could. A phone with no secure element says so plainly.
 */
@Composable
private fun IdentityBar(identity: DeviceIdentity.Identity) {
    val (label, colour) = when (identity.backing) {
        DeviceIdentity.Backing.STRONGBOX ->
            "Elemento seguro dedicado · huella" to Color(0xFF4ADE80)
        DeviceIdentity.Backing.TEE ->
            "TrustZone · huella" to Color(0xFF4ADE80)
        DeviceIdentity.Backing.SOFTWARE ->
            "Sin respaldo de hardware — confirmaciones débiles" to Color(0xFFF87171)
        DeviceIdentity.Backing.NONE ->
            "Sin identidad de dispositivo" to Color(0xFFF87171)
    }
    Column(Modifier.background(Ground).fillMaxWidth().padding(14.dp)) {
        Text("sysentinel", color = Accent, fontSize = 18.sp)
        Text(label, color = colour, fontSize = 11.sp)
        Text(
            "cifrado: " + if (identity.aead == DeviceIdentity.Aead.AES_256_GCM)
                "AES-256-GCM (extensiones ARM)" else "ChaCha20-Poly1305 (sin AES por hardware)",
            color = Color(0xFF6B7C8F),
            fontSize = 10.sp,
        )
    }
}

@Composable
private fun Bubble(m: Message) {
    val time = SimpleDateFormat("HH:mm", Locale.getDefault()).format(Date(m.timestamp))
    Row(
        Modifier.fillMaxWidth(),
        horizontalArrangement = if (m.fromMe) Arrangement.End else Arrangement.Start,
    ) {
        Surface(
            color = if (m.fromMe) Mine else Theirs,
            shape = RoundedCornerShape(
                topStart = 14.dp,
                topEnd = 14.dp,
                bottomStart = if (m.fromMe) 14.dp else 4.dp,
                bottomEnd = if (m.fromMe) 4.dp else 14.dp,
            ),
            modifier = Modifier.widthIn(max = 300.dp),
        ) {
            Column(Modifier.padding(horizontal = 12.dp, vertical = 8.dp)) {
                Text(m.text, color = Color(0xFFC8D6E5), fontSize = 14.sp)
                Text(
                    time,
                    color = Color(0xFF6B7C8F),
                    fontSize = 10.sp,
                    textAlign = TextAlign.End,
                    modifier = Modifier.align(Alignment.End),
                )
            }
        }
    }
}

@Composable
private fun Composer(draft: String, onDraft: (String) -> Unit, onSend: () -> Unit) {
    Row(
        Modifier.background(Ground).fillMaxWidth().padding(10.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        OutlinedTextField(
            value = draft,
            onValueChange = onDraft,
            placeholder = { Text("Escribe un mensaje…", color = Color(0xFF6B7C8F)) },
            modifier = Modifier.weight(1f),
            shape = RoundedCornerShape(22.dp),
            singleLine = false,
            maxLines = 4,
        )
        Spacer(Modifier.width(8.dp))
        FilledIconButton(onClick = onSend) { Text("→") }
    }
}
