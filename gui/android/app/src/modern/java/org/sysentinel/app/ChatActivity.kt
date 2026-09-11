// SPDX-License-Identifier: Apache-2.0
package org.sysentinel.app

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.compose.setContent
import com.journeyapps.barcodescanner.ScanContract
import com.journeyapps.barcodescanner.ScanOptions
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
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

    private lateinit var engine: ChatEngine
    private lateinit var pairing: Pairing

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        val identity = DeviceIdentity.ensureKey()
        pairing = Pairing(this)
        engine = ChatEngine(pairing, BuildConfig.VERSION_NAME)

        setContent {
            MaterialTheme(colorScheme = darkColorScheme(primary = Accent)) {
                ChatScreen(identity, engine, pairing)
            }
        }
    }

    override fun onDestroy() {
        super.onDestroy()
        engine.stop()
    }
}

private val Accent = Color(0xFF7FD4FF)
private val Ground = Color(0xFF0B0F14)
private val Mine = Color(0xFF17313D)
private val Theirs = Color(0xFF161C24)

@Composable
private fun ChatScreen(
    identity: DeviceIdentity.Identity,
    engine: ChatEngine,
    pairing: Pairing,
) {
    var draft by remember { mutableStateOf("") }
    var status by remember { mutableStateOf("conectando…") }
    var statusOk by remember { mutableStateOf(false) }
    var showPairing by remember { mutableStateOf(!pairing.isPaired) }
    val messages = remember { mutableStateListOf<Message>() }
    val listState = rememberLazyListState()

    val listener = remember {
        object : ChatEngine.Listener {
            override fun onMessages(m: List<Message>) { messages.addAll(m) }
            override fun onStatus(text: String, ok: Boolean) {
                status = text; statusOk = ok
            }
        }
    }

    // Poll while the screen is open. Never pushed to: see the class docs.
    LaunchedEffect(showPairing) {
        if (!showPairing) {
            engine.start(listener)
            while (true) {
                kotlinx.coroutines.delay(15_000)
                engine.refresh(listener)
            }
        }
    }

    LaunchedEffect(messages.size) {
        if (messages.isNotEmpty()) listState.animateScrollToItem(messages.lastIndex)
    }

    if (showPairing) {
        PairingScreen(pairing) { showPairing = false }
        return
    }

    Scaffold(
        containerColor = Ground,
        topBar = {
            IdentityBar(identity, status, statusOk, pairing.host, pairing.port) {
                showPairing = true
            }
        },
        bottomBar = {
            Composer(
                draft = draft,
                onDraft = { draft = it },
                onSend = {
                    if (draft.isNotBlank()) {
                        messages.add(Message(draft, fromMe = true))
                        engine.send(draft, listener)
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
 *
 * It also shows the address it is dialing, and lets you tap it to change it.
 * That matters away from home: the pairing is between this handset and that
 * machine and does not expire, but the *route* to the machine does change —
 * the LAN address you scanned in the living room is not reachable from another
 * country. Editing the address is not re-pairing; the key and the device
 * identity stay exactly as they were.
 */
@Composable
private fun IdentityBar(
    identity: DeviceIdentity.Identity,
    status: String,
    statusOk: Boolean,
    host: String,
    port: Int,
    onEditAddress: () -> Unit,
) {
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
        Text(
            status,
            color = if (statusOk) Color(0xFF4ADE80) else Color(0xFFF87171),
            fontSize = 11.sp,
        )
        Text(
            "equipo: $host:$port · cambiar",
            color = Accent,
            fontSize = 10.sp,
            modifier = Modifier.clickable { onEditAddress() },
        )
    }
}

/**
 * Pairing: the machine's address and the key it printed.
 *
 * There is no discovery and no relay to look anyone up through — that absence
 * is the feature. The key is carried across by hand, once.
 */
@Composable
private fun PairingScreen(pairing: Pairing, onDone: () -> Unit) {
    var host by remember { mutableStateOf(pairing.host) }
    var port by remember { mutableStateOf(pairing.port.toString()) }
    var key by remember { mutableStateOf(pairing.keyHex) }
    var scanError by remember { mutableStateOf<String?>(null) }
    val keyLooksRight = PhoneLink.parseKey(key) != null

    // Scanning fills all three fields at once. Typing 64 hex characters on a
    // phone is how people end up pairing once with a weak key and never
    // rotating it.
    val scanner = rememberLauncherForActivityResult(ScanContract()) { result ->
        val raw = result.contents
        if (raw == null) {
            scanError = null // cancelled, not failed
            return@rememberLauncherForActivityResult
        }
        val parsed = PairingUri.parse(raw)
        if (parsed == null) {
            scanError = "Ese QR no es de sysentinel, o le falta algo. " +
                "Si el equipo escucha en 0.0.0.0, cámbialo por la IP concreta."
        } else {
            host = parsed.host
            port = parsed.port.toString()
            key = parsed.keyHex
            scanError = null
        }
    }

    Column(
        Modifier.background(Ground).fillMaxSize().padding(20.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        Text("Emparejar", color = Accent, fontSize = 22.sp)
        Text(
            "Conexión directa con tu equipo: no hay relay ni servidor de por medio. " +
                "La primera vez, ponte en el mismo WiFi que el PC y escanea su QR. " +
                "Después da igual dónde estés: el vínculo no caduca, sólo hace falta " +
                "que puedas llegar al equipo — misma red, o tu VPN. Si cambia la " +
                "dirección, corrígela aquí; no hay que volver a emparejar.",
            color = Color(0xFF6B7C8F),
            fontSize = 12.sp,
        )
        Button(onClick = {
            scanner.launch(
                ScanOptions()
                    .setDesiredBarcodeFormats(ScanOptions.QR_CODE)
                    .setPrompt("Apunta al QR que muestra el equipo")
                    .setBeepEnabled(false)
                    .setOrientationLocked(false)
            )
        }) { Text("Escanear el QR del equipo") }
        scanError?.let {
            Text(it, color = Color(0xFFF87171), fontSize = 12.sp)
        }
        Text(
            "…o escríbelo a mano:",
            color = Color(0xFF6B7C8F),
            fontSize = 11.sp,
        )
        OutlinedTextField(
            value = host,
            onValueChange = { host = it },
            label = { Text("Equipo (IP o nombre)") },
            singleLine = true,
        )
        OutlinedTextField(
            value = port,
            onValueChange = { port = it.filter { c -> c.isDigit() } },
            label = { Text("Puerto") },
            singleLine = true,
        )
        OutlinedTextField(
            value = key,
            onValueChange = { key = it },
            label = { Text("Clave de emparejamiento (64 hex)") },
            supportingText = {
                Text(
                    if (keyLooksRight) "formato correcto"
                    else "faltan caracteres: son 64 hexadecimales",
                    color = if (keyLooksRight) Color(0xFF4ADE80) else Color(0xFF6B7C8F),
                )
            },
        )
        Button(
            onClick = {
                pairing.host = host
                pairing.port = port.toIntOrNull() ?: 8443
                pairing.keyHex = key
                onDone()
            },
            enabled = keyLooksRight && host.isNotBlank(),
        ) { Text("Guardar y conectar") }
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
