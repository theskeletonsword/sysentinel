// SPDX-License-Identifier: Apache-2.0
package org.sysentinel.app

import android.Manifest
import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import android.os.Bundle
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.compose.setContent
import androidx.activity.result.contract.ActivityResultContracts
import androidx.core.content.ContextCompat
import com.journeyapps.barcodescanner.ScanContract
import com.journeyapps.barcodescanner.ScanOptions
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.lazy.rememberLazyListState
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.foundation.ExperimentalFoundationApi
import androidx.compose.foundation.combinedClickable
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Visibility
import androidx.compose.material.icons.filled.VisibilityOff
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.input.VisualTransformation
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.sp
import androidx.fragment.app.FragmentActivity
import kotlinx.coroutines.launch
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

/**
 * The modern face: Material 3, dark, message bubbles, with a navigation drawer
 * (the three-bar menu) for language, monitoring toggles, the AI provider and
 * models, the persona prompt, and notifications.
 *
 * # Notifications
 *
 * The app used to promise it never notifies (see [ChatEngine] / [AlertService]).
 * That is now an owner choice: off by default, turned on from the drawer, which
 * requests POST_NOTIFICATIONS and starts the background poller.
 */
class ChatActivity : FragmentActivity() {

    private lateinit var engine: ChatEngine
    private lateinit var pairing: Pairing

    // Force the chosen UI language (English by default) regardless of the phone's
    // own locale — see LocaleManager.
    override fun attachBaseContext(newBase: Context) {
        super.attachBaseContext(LocaleManager.wrap(newBase))
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        val identity = DeviceIdentity.ensureKey()
        pairing = Pairing(this)
        engine = ChatEngine(this, pairing, BuildConfig.VERSION_NAME)
        AlertService.ensureChannels(this)
        // If the owner had notifications on, resume the poller on launch.
        if (AppPrefs(this).notificationsEnabled && pairing.isPaired) AlertService.start(this)

        setContent {
            MaterialTheme(colorScheme = darkColorScheme(primary = Accent)) {
                AppRoot(identity, engine, pairing)
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
private val Muted = Color(0xFF6B7C8F)

/** Which configuration screen the drawer has opened, if any. */
private enum class Screen { CHAT, LANGUAGE, TOGGLES, PROVIDER, APIKEYS, PERSONA, NOTIFICATIONS, OWNERSHIP, MULTIMEDIA, LOGS }

@Composable
private fun AppRoot(
    identity: DeviceIdentity.Identity,
    engine: ChatEngine,
    pairing: Pairing,
) {
    var draft by remember { mutableStateOf("") }
    val ctx = LocalContext.current
    var status by remember { mutableStateOf(ctx.getString(R.string.state_connecting)) }
    var statusOk by remember { mutableStateOf(false) }
    var showPairing by remember { mutableStateOf(!pairing.isPaired) }
    var screen by remember { mutableStateOf(Screen.CHAT) }
    val messages = remember { mutableStateListOf<Message>() }
    val listState = rememberLazyListState()
    val activity = ctx as? FragmentActivity
    var pending by remember { mutableStateOf<Message?>(null) }
    var confirming by remember { mutableStateOf(false) }
    val drawerState = rememberDrawerState(DrawerValue.Closed)
    val scope = rememberCoroutineScope()
    // Message context menu (long-press)
    var ctxMsg by remember { mutableStateOf<Message?>(null) }

    val listener = remember {
        object : ChatEngine.Listener {
            override fun onMessages(m: List<Message>) {
                messages.addAll(m)
                m.lastOrNull { it.confirmNonce != null }?.let { pending = it }
            }
            override fun onStatus(text: String, ok: Boolean) {
                status = text; statusOk = ok
            }
        }
    }

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

    // Send a slash-command to the daemon, show it and its reply in the chat,
    // and return to the conversation. This is how every settings screen acts:
    // it never models the daemon's state, it asks and shows the answer.
    fun runCommand(cmd: String) {
        messages.add(Message(cmd, fromMe = true))
        engine.send(cmd, listener)
        scope.launch { drawerState.close() }
        screen = Screen.CHAT
    }

    ModalNavigationDrawer(
        drawerState = drawerState,
        drawerContent = {
            DrawerContent(
                onSelect = { s ->
                    screen = s
                    scope.launch { drawerState.close() }
                },
                onReport = { cmd -> runCommand(cmd) },
            )
        },
    ) {
        Scaffold(
            containerColor = Ground,
            topBar = {
                IdentityBar(
                    identity, status, statusOk, pairing.host, pairing.port,
                    onMenu = { scope.launch { drawerState.open() } },
                    onEditAddress = { showPairing = true },
                )
            },
            bottomBar = {
                if (screen == Screen.CHAT) {
                    Column {
                        val order = pending
                        if (order?.confirmNonce != null && activity != null) {
                            ConfirmBar(
                                nonce = order.confirmNonce,
                                busy = confirming,
                                canSign = Confirmation.available(activity),
                            ) {
                                confirming = true
                                Confirmation.confirm(
                                    activity = activity,
                                    engine = engine,
                                    nonce = order.confirmNonce,
                                    orderLabel = orderLabelFrom(order.text),
                                ) { answer ->
                                    confirming = false
                                    pending = null
                                    messages.add(Message(answer, fromMe = false))
                                }
                            }
                        }
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
                            onAttach = { filename, bytes, markitdown ->
                                messages.add(Message("📎 $filename", fromMe = true))
                                engine.sendDocument(filename, bytes, markitdown, listener)
                            },
                            onCommand = { runCommand(it) },
                        )
                    }
                }
            },
        ) { padding ->
            Box(Modifier.padding(padding).fillMaxSize().background(Ground)) {
                when (screen) {
                    Screen.CHAT -> LazyColumn(
                        state = listState,
                        modifier = Modifier.fillMaxSize(),
                        contentPadding = PaddingValues(12.dp),
                        verticalArrangement = Arrangement.spacedBy(6.dp),
                    ) {
                        items(messages) { msg ->
                            Bubble(msg,
                                onLongClick = { ctxMsg = msg },
                            )
                        }
                    }
                    Screen.LANGUAGE -> LanguageScreen { screen = Screen.CHAT }
                    Screen.TOGGLES -> TogglesScreen(onCommand = { runCommand(it) })
                    Screen.PROVIDER -> ProviderScreen(
                        onCommand = { runCommand(it) },
                        onOpenApiKeys = { screen = Screen.APIKEYS },
                    )
                    Screen.APIKEYS -> ApiKeysScreen()
                    Screen.PERSONA -> PersonaScreen(onCommand = { runCommand(it) })
                    Screen.OWNERSHIP -> OwnershipScreen(engine, listener) { runCommand(it) }
                    Screen.NOTIFICATIONS -> NotificationsScreen(pairing)
                    Screen.MULTIMEDIA -> MultimediaScreen(engine, listener) { screen = Screen.CHAT }
                    Screen.LOGS -> LogsScreen(messages, engine, listener) { screen = Screen.CHAT }  // listener passed but unused (local listener used inside)
                }

                // Long-press message context menu
                val ctx2 = ctxMsg
                if (ctx2 != null) {
                    AlertDialog(
                        onDismissRequest = { ctxMsg = null },
                        containerColor = Theirs,
                        title = null,
                        text = {
                            Text(
                                ctx2.text.take(120) + if (ctx2.text.length > 120) "…" else "",
                                color = Color(0xFFC8D6E5), fontSize = 12.sp,
                            )
                        },
                        confirmButton = {
                            TextButton(onClick = {
                                val cm = ctx.getSystemService(android.content.ClipboardManager::class.java)
                                cm?.setPrimaryClip(android.content.ClipData.newPlainText("message", ctx2.text))
                                ctxMsg = null
                            }) { Text(stringResource(R.string.msg_copy), color = Accent) }
                        },
                        dismissButton = {
                            TextButton(onClick = {
                                messages.remove(ctx2)
                                ctxMsg = null
                            }) { Text(stringResource(R.string.msg_delete), color = Color(0xFFF87171)) }
                        },
                    )
                }
            }
        }
    }
}

@Composable
private fun DrawerContent(onSelect: (Screen) -> Unit, onReport: (String) -> Unit) {
    // The sheet must scroll: the Configuration and Reports sections together
    // are taller than most screens, and an unscrollable drawer would silently
    // hide the entries at the bottom.
    ModalDrawerSheet(
        drawerContainerColor = Theirs,
        modifier = Modifier.verticalScroll(rememberScrollState()),
    ) {
        Text(
            "sysentinel",
            color = Accent,
            fontSize = 20.sp,
            modifier = Modifier.padding(20.dp),
        )
        Section(stringResource(R.string.menu_section_config))
        DrawerRow(stringResource(R.string.menu_conversation)) { onSelect(Screen.CHAT) }
        DrawerRow(stringResource(R.string.menu_language)) { onSelect(Screen.LANGUAGE) }
        DrawerRow(stringResource(R.string.menu_settings)) { onSelect(Screen.TOGGLES) }
        DrawerRow(stringResource(R.string.menu_provider)) { onSelect(Screen.PROVIDER) }
        DrawerRow(stringResource(R.string.menu_apikeys)) { onSelect(Screen.APIKEYS) }
        DrawerRow(stringResource(R.string.menu_persona)) { onSelect(Screen.PERSONA) }
        DrawerRow(stringResource(R.string.menu_ownership)) { onSelect(Screen.OWNERSHIP) }
        DrawerRow(stringResource(R.string.menu_notifications)) { onSelect(Screen.NOTIFICATIONS) }
        DrawerRow(stringResource(R.string.menu_multimedia)) { onSelect(Screen.MULTIMEDIA) }
        DrawerRow(stringResource(R.string.menu_logs)) { onSelect(Screen.LOGS) }
        Divider(color = Ground)
        Section(stringResource(R.string.menu_section_reports))
        DrawerRow(stringResource(R.string.menu_status)) { onReport(DaemonSettings.STATUS) }
        DrawerRow(stringResource(R.string.menu_selinux)) { onReport(DaemonSettings.SELINUX) }
        DrawerRow(stringResource(R.string.menu_hardware)) { onReport(DaemonSettings.HARDWARE) }
        DrawerRow(stringResource(R.string.menu_firmware)) { onReport(DaemonSettings.FIRMWARE) }
    }
}

@Composable
private fun Section(text: String) {
    Text(text, color = Muted, fontSize = 11.sp,
        modifier = Modifier.padding(start = 20.dp, top = 12.dp, bottom = 4.dp))
}

@Composable
private fun DrawerRow(label: String, onClick: () -> Unit) {
    NavigationDrawerItem(
        label = { Text(label, color = Color(0xFFC8D6E5)) },
        selected = false,
        onClick = onClick,
        colors = NavigationDrawerItemDefaults.colors(unselectedContainerColor = Color.Transparent),
        modifier = Modifier.padding(horizontal = 8.dp),
    )
}

@Composable
private fun ScreenScaffold(title: String, blurb: String, content: @Composable ColumnScope.() -> Unit) {
    Column(
        Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(20.dp),
        verticalArrangement = Arrangement.spacedBy(14.dp),
    ) {
        Text(title, color = Accent, fontSize = 20.sp)
        Text(blurb, color = Muted, fontSize = 12.sp)
        content()
    }
}

@Composable
private fun LanguageScreen(onChanged: () -> Unit) {
    val ctx = LocalContext.current
    val current = remember { AppPrefs(ctx).language }
    ScreenScaffold(stringResource(R.string.lang_title), stringResource(R.string.lang_blurb)) {
        AppPrefs.SUPPORTED.forEach { (tag, name) ->
            Row(
                Modifier.fillMaxWidth().clickable {
                    if (LocaleManager.setLanguage(ctx, tag)) {
                        (ctx as? FragmentActivity)?.recreate()
                    }
                    onChanged()
                }.padding(vertical = 12.dp),
                horizontalArrangement = Arrangement.SpaceBetween,
            ) {
                Text(name, color = Color(0xFFC8D6E5), fontSize = 16.sp)
                if (tag == current) Text("✓", color = Color(0xFF4ADE80), fontSize = 16.sp)
            }
        }
    }
}

@Composable
private fun TogglesScreen(onCommand: (String) -> Unit) {
    ScreenScaffold(stringResource(R.string.settings_title), stringResource(R.string.settings_blurb)) {
        DaemonSettings.TOGGLES.forEach { t ->
            Row(
                Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically,
            ) {
                Text(labelFor(t.labelKey), color = Color(0xFFC8D6E5), fontSize = 14.sp,
                    modifier = Modifier.weight(1f))
                FilledTonalButton(onClick = { onCommand(DaemonSettings.toggle(t.category, true)) }) {
                    Text(stringResource(R.string.toggle_on))
                }
                Spacer(Modifier.width(6.dp))
                OutlinedButton(onClick = { onCommand(DaemonSettings.toggle(t.category, false)) }) {
                    Text(stringResource(R.string.toggle_off))
                }
            }
        }
    }
}

/** Resolve a toggle's label string by its resource name. */
@Composable
private fun labelFor(key: String): String {
    val ctx = LocalContext.current
    val id = ctx.resources.getIdentifier(key, "string", ctx.packageName)
    return if (id != 0) stringResource(id) else key
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun ProviderScreen(onCommand: (String) -> Unit, onOpenApiKeys: () -> Unit) {
    var provider by remember { mutableStateOf(DaemonSettings.PROVIDERS.first()) }
    var textModel by remember { mutableStateOf("") }
    var visionModel by remember { mutableStateOf("") }
    var expanded by remember { mutableStateOf(false) }

    ScreenScaffold(stringResource(R.string.provider_title), stringResource(R.string.provider_blurb)) {
        Text(stringResource(R.string.provider_select), color = Muted, fontSize = 12.sp)
        ExposedDropdownMenuBox(expanded = expanded, onExpandedChange = { expanded = it }) {
            OutlinedTextField(
                value = provider,
                onValueChange = {},
                readOnly = true,
                trailingIcon = { ExposedDropdownMenuDefaults.TrailingIcon(expanded = expanded) },
                modifier = Modifier.menuAnchor().fillMaxWidth(),
            )
            ExposedDropdownMenu(expanded = expanded, onDismissRequest = { expanded = false }) {
                DaemonSettings.PROVIDERS.forEach { name ->
                    DropdownMenuItem(text = { Text(name) }, onClick = {
                        provider = name; expanded = false
                    })
                }
            }
        }
        OutlinedTextField(
            value = textModel,
            onValueChange = { textModel = it },
            label = { Text(stringResource(R.string.provider_text_model)) },
            supportingText = { Text(stringResource(R.string.provider_text_hint), color = Muted) },
            singleLine = true,
            modifier = Modifier.fillMaxWidth(),
        )
        OutlinedTextField(
            value = visionModel,
            onValueChange = { visionModel = it },
            label = { Text(stringResource(R.string.provider_vision_model)) },
            supportingText = { Text(stringResource(R.string.provider_vision_hint), color = Muted) },
            singleLine = true,
            modifier = Modifier.fillMaxWidth(),
        )
        Button(
            onClick = {
                onCommand(DaemonSettings.setProvider(provider))
                if (textModel.isNotBlank() || visionModel.isNotBlank()) {
                    onCommand(DaemonSettings.setModels(provider, textModel, visionModel))
                }
            },
            modifier = Modifier.fillMaxWidth(),
        ) { Text(stringResource(R.string.provider_apply)) }

        Divider(color = Theirs)
        OutlinedButton(onClick = onOpenApiKeys, modifier = Modifier.fillMaxWidth()) {
            Text(stringResource(R.string.provider_manage_keys))
        }
        Text(stringResource(R.string.provider_manage_keys_hint), color = Muted, fontSize = 11.sp)
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun ApiKeysScreen() {
    val ctx = LocalContext.current
    val store = remember { ApiKeys(ctx) }
    var keys by remember { mutableStateOf(store.list()) }
    val revealed = remember { mutableStateMapOf<String, Boolean>() }

    // Editor state. `editingAlias` is null for a brand-new key, set for an edit.
    var editorOpen by remember { mutableStateOf(false) }
    var editingAlias by remember { mutableStateOf<String?>(null) }
    var alias by remember { mutableStateOf("") }
    var provider by remember { mutableStateOf(DaemonSettings.PROVIDERS.first()) }
    var providerOpen by remember { mutableStateOf(false) }
    var key by remember { mutableStateOf("") }
    var keyShown by remember { mutableStateOf(false) }
    var keyError by remember { mutableStateOf<String?>(null) }

    fun mask(k: ApiKeys.Key): String =
        if (k.unreadable) "•••" else "•".repeat(k.apiKey.length.coerceIn(1, 40))

    fun openEditor(existing: ApiKeys.Key?) {
        editingAlias = existing?.alias
        alias = existing?.alias ?: ""
        provider = existing?.provider
            ?.takeIf { DaemonSettings.PROVIDERS.contains(it) }
            ?: DaemonSettings.PROVIDERS.first()
        key = existing?.apiKey ?: ""
        keyShown = false
        keyError = null
        editorOpen = true
    }

    // Validation can only be decided from read state, never mutated mid-draw.
    val aliasConflict = alias.trim().isNotEmpty() &&
        store.aliasExists(alias) && !alias.trim().equals(editingAlias, ignoreCase = true)
    val canSave = alias.isNotBlank() && key.isNotBlank() && !aliasConflict
    val shownError = keyError ?: when {
        alias.isNotBlank() && aliasConflict -> stringResource(R.string.apikeys_err_dup)
        else -> null
    }

    ScreenScaffold(stringResource(R.string.apikeys_title), stringResource(R.string.apikeys_blurb)) {
        if (keys.isEmpty()) {
            Text(stringResource(R.string.apikeys_empty), color = Muted, fontSize = 13.sp)
        }
        keys.forEach { k ->
            val show = revealed[k.alias] ?: false
            Surface(
                color = Theirs,
                shape = RoundedCornerShape(12.dp),
                modifier = Modifier.fillMaxWidth().clickable { openEditor(k) },
            ) {
                Column(Modifier.padding(horizontal = 14.dp, vertical = 10.dp)) {
                    Row(
                        Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.SpaceBetween,
                        verticalAlignment = Alignment.CenterVertically,
                    ) {
                        Text(k.provider, color = Accent, fontSize = 11.sp)
                        Text(k.alias, color = Color(0xFFC8D6E5), fontSize = 15.sp)
                    }
                    Row(
                        Modifier.fillMaxWidth(),
                        verticalAlignment = Alignment.CenterVertically,
                    ) {
                        Text(
                            if (show) k.apiKey.ifEmpty { "•" } else mask(k),
                            color = if (show) Color(0xFFC8D6E5) else Muted,
                            fontSize = 13.sp,
                            maxLines = 1,
                            softWrap = false,
                            modifier = Modifier.weight(1f),
                        )
                        IconButton(onClick = { revealed[k.alias] = !show }) {
                            Icon(
                                imageVector = if (show) Icons.Filled.VisibilityOff else Icons.Filled.Visibility,
                                contentDescription = stringResource(
                                    if (show) R.string.apikeys_hide else R.string.apikeys_show
                                ),
                                tint = Muted,
                            )
                        }
                        TextButton(onClick = { store.remove(k.alias); keys = store.list() }) {
                            Text(stringResource(R.string.apikeys_delete), color = Color(0xFFF87171), fontSize = 12.sp)
                        }
                    }
                    if (k.unreadable) {
                        Text(stringResource(R.string.apikeys_unreadable), color = Color(0xFFFBBF24), fontSize = 11.sp)
                    } else if (!k.wrappedInHardware) {
                        Text(stringResource(R.string.apikeys_plaintext), color = Color(0xFFFBBF24), fontSize = 11.sp)
                    }
                }
            }
        }

        Divider(color = Theirs)
        Button(onClick = { openEditor(null) }, modifier = Modifier.fillMaxWidth()) {
            Text(stringResource(R.string.apikeys_add))
        }
    }

    if (editorOpen) {
        AlertDialog(
            onDismissRequest = { editorOpen = false },
            containerColor = Theirs,
            title = { Text(
                if (editingAlias == null) stringResource(R.string.apikeys_add)
                else stringResource(R.string.apikeys_edit),
                color = Accent,
            ) },
            text = {
                // Bounded height + scroll: with the keyboard up, three fields
                // plus the save bar exceed the dialog window on small screens,
                // and an unscrollable dialog would hide the Save button.
                BoxWithConstraints(Modifier.fillMaxWidth()) {
                    Column(
                        Modifier.fillMaxWidth()
                            .heightIn(max = maxHeight * 0.7f)
                            .verticalScroll(rememberScrollState()),
                        verticalArrangement = Arrangement.spacedBy(12.dp),
                    ) {
                    OutlinedTextField(
                        value = alias,
                        onValueChange = { alias = it; keyError = null },
                        label = { Text(stringResource(R.string.apikeys_alias)) },
                        singleLine = true,
                        modifier = Modifier.fillMaxWidth(),
                    )
                    ExposedDropdownMenuBox(expanded = providerOpen, onExpandedChange = { providerOpen = it }) {
                        OutlinedTextField(
                            value = provider,
                            onValueChange = {},
                            readOnly = true,
                            trailingIcon = { ExposedDropdownMenuDefaults.TrailingIcon(expanded = providerOpen) },
                            modifier = Modifier.menuAnchor().fillMaxWidth(),
                        )
                        ExposedDropdownMenu(expanded = providerOpen, onDismissRequest = { providerOpen = false }) {
                            DaemonSettings.PROVIDERS.forEach { name ->
                                DropdownMenuItem(text = { Text(name) }, onClick = {
                                    provider = name; providerOpen = false
                                })
                            }
                        }
                    }
                    OutlinedTextField(
                        value = key,
                        onValueChange = { key = it; keyError = null },
                        label = { Text(stringResource(R.string.apikeys_key)) },
                        singleLine = true,
                        visualTransformation = if (keyShown) VisualTransformation.None else PasswordVisualTransformation(),
                        trailingIcon = {
                            IconButton(onClick = { keyShown = !keyShown }) {
                                Icon(
                                    imageVector = if (keyShown) Icons.Filled.VisibilityOff else Icons.Filled.Visibility,
                                    contentDescription = stringResource(
                                        if (keyShown) R.string.apikeys_hide else R.string.apikeys_show
                                    ),
                                    tint = Muted,
                                )
                            }
                        },
                        modifier = Modifier.fillMaxWidth(),
                    )
                    if (shownError != null) {
                        Text(shownError, color = Color(0xFFF87171), fontSize = 12.sp)
                    }
                    }
                }
            },
            confirmButton = {
                TextButton(
                    enabled = canSave,
                    onClick = {
                        if (editingAlias != null && !editingAlias.equals(alias.trim(), ignoreCase = true)) {
                            store.remove(editingAlias!!)
                        }
                        store.save(alias, provider, key)
                        keys = store.list()
                        editorOpen = false
                    },
                ) { Text(stringResource(R.string.apikeys_save)) }
            },
            dismissButton = {
                TextButton(onClick = { editorOpen = false }) {
                    Text(stringResource(R.string.apikeys_cancel))
                }
            },
        )
    }
}

@Composable
private fun PersonaScreen(onCommand: (String) -> Unit) {
    var text by remember { mutableStateOf("") }
    ScreenScaffold(stringResource(R.string.persona_title), stringResource(R.string.persona_blurb)) {
        OutlinedTextField(
            value = text,
            onValueChange = { text = it },
            label = { Text(stringResource(R.string.persona_hint)) },
            modifier = Modifier.fillMaxWidth().heightIn(min = 120.dp),
            maxLines = 10,
        )
        Row(horizontalArrangement = Arrangement.spacedBy(10.dp)) {
            Button(
                onClick = { onCommand(DaemonSettings.setPersona(text)) },
                enabled = text.isNotBlank(),
            ) { Text(stringResource(R.string.persona_apply)) }
            OutlinedButton(onClick = { onCommand(DaemonSettings.setPersona("")) }) {
                Text(stringResource(R.string.persona_clear))
            }
        }
    }
}

@Composable
private fun NotificationsScreen(pairing: Pairing) {
    val ctx = LocalContext.current
    val prefs = remember { AppPrefs(ctx) }
    var enabled by remember { mutableStateOf(prefs.notificationsEnabled) }
    var denied by remember { mutableStateOf(false) }

    val permLauncher = rememberLauncherForActivityResult(
        ActivityResultContracts.RequestPermission()
    ) { granted ->
        if (granted) {
            prefs.notificationsEnabled = true
            enabled = true
            AlertService.start(ctx)
        } else {
            denied = true
            enabled = false
        }
    }

    fun enable() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU &&
            ContextCompat.checkSelfPermission(ctx, Manifest.permission.POST_NOTIFICATIONS)
            != PackageManager.PERMISSION_GRANTED
        ) {
            permLauncher.launch(Manifest.permission.POST_NOTIFICATIONS)
        } else {
            prefs.notificationsEnabled = true
            enabled = true
            AlertService.start(ctx)
        }
    }

    ScreenScaffold(stringResource(R.string.notif_title), stringResource(R.string.notif_blurb)) {
        Row(
            Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Text(stringResource(R.string.notif_toggle), color = Color(0xFFC8D6E5),
                fontSize = 14.sp, modifier = Modifier.weight(1f))
            Switch(
                checked = enabled,
                onCheckedChange = { want ->
                    if (want) {
                        enable()
                    } else {
                        prefs.notificationsEnabled = false
                        enabled = false
                        AlertService.stop(ctx)
                    }
                },
            )
        }
        if (denied) {
            Text(stringResource(R.string.notif_permission_denied),
                color = Color(0xFFF87171), fontSize = 12.sp)
        }
    }
}

@Composable
private fun ConfirmBar(
    nonce: String,
    busy: Boolean,
    canSign: Boolean,
    onConfirm: () -> Unit,
) {
    Surface(color = Color(0xFF2A1D10)) {
        Row(
            Modifier.fillMaxWidth().padding(horizontal = 14.dp, vertical = 10.dp),
            horizontalArrangement = Arrangement.spacedBy(12.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Column(Modifier.weight(1f)) {
                Text(stringResource(R.string.confirm_waiting), color = Color(0xFFF5C271), fontSize = 13.sp)
                Text(
                    if (canSign) stringResource(R.string.confirm_can_sign)
                    else stringResource(R.string.confirm_cannot_sign, nonce),
                    color = Color(0xFFB99A6B),
                    fontSize = 11.sp,
                )
            }
            if (canSign) {
                Button(onClick = onConfirm, enabled = !busy) {
                    Text(if (busy) "…" else stringResource(R.string.confirm_button))
                }
            }
        }
    }
}

@Composable
private fun IdentityBar(
    identity: DeviceIdentity.Identity,
    status: String,
    statusOk: Boolean,
    host: String,
    port: Int,
    onMenu: () -> Unit,
    onEditAddress: () -> Unit,
) {
    val (label, colour) = when (identity.backing) {
        DeviceIdentity.Backing.STRONGBOX ->
            stringResource(R.string.backing_strongbox) to Color(0xFF4ADE80)
        DeviceIdentity.Backing.TEE ->
            stringResource(R.string.backing_tee) to Color(0xFF4ADE80)
        DeviceIdentity.Backing.SOFTWARE ->
            stringResource(R.string.backing_software) to Color(0xFFF87171)
        DeviceIdentity.Backing.NONE ->
            stringResource(R.string.backing_none) to Color(0xFFF87171)
    }
    Row(
        Modifier.background(Ground).fillMaxWidth().padding(horizontal = 8.dp, vertical = 10.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        IconButton(onClick = onMenu) {
            Text("☰", color = Accent, fontSize = 22.sp)
        }
        Column(Modifier.weight(1f)) {
            Text("sysentinel", color = Accent, fontSize = 18.sp)
            Text(label, color = colour, fontSize = 11.sp)
            Text(
                if (identity.aead == DeviceIdentity.Aead.AES_256_GCM)
                    stringResource(R.string.crypto_aes) else stringResource(R.string.crypto_chacha),
                color = Muted, fontSize = 10.sp,
            )
            Text(status, color = if (statusOk) Color(0xFF4ADE80) else Color(0xFFF87171), fontSize = 11.sp)
            Text(
                stringResource(R.string.machine_change, host, port),
                color = Accent, fontSize = 10.sp,
                modifier = Modifier.clickable { onEditAddress() },
            )
        }
    }
}

@Composable
private fun PairingScreen(pairing: Pairing, onDone: () -> Unit) {
    var host by remember { mutableStateOf(pairing.host) }
    var port by remember { mutableStateOf(pairing.port.toString()) }
    var key by remember { mutableStateOf(pairing.keyHex) }
    var certPin by remember { mutableStateOf(pairing.certPin) }
    var scanError by remember { mutableStateOf<String?>(null) }
    val ctx = LocalContext.current
    val keyLooksRight = PhoneLink.parseKey(key) != null

    val scanner = rememberLauncherForActivityResult(ScanContract()) { result ->
        val raw = result.contents
        if (raw == null) {
            scanError = null
            return@rememberLauncherForActivityResult
        }
        val parsed = PairingUri.parse(raw)
        if (parsed == null) {
            scanError = ctx.getString(R.string.pair_scan_error)
        } else {
            host = parsed.host
            port = parsed.port.toString()
            key = parsed.keyHex
            certPin = parsed.certPin
            scanError = null
        }
    }

    Column(
        Modifier.background(Ground).fillMaxSize().verticalScroll(rememberScrollState()).padding(20.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        Text(stringResource(R.string.pair_title), color = Accent, fontSize = 22.sp)
        Text(stringResource(R.string.pair_blurb), color = Muted, fontSize = 12.sp)
        Button(onClick = {
            scanner.launch(
                ScanOptions()
                    .setDesiredBarcodeFormats(ScanOptions.QR_CODE)
                    .setPrompt(ctx.getString(R.string.pair_scan_prompt))
                    .setBeepEnabled(false)
                    .setOrientationLocked(false)
            )
        }) { Text(stringResource(R.string.pair_scan)) }
        scanError?.let { Text(it, color = Color(0xFFF87171), fontSize = 12.sp) }
        Text(stringResource(R.string.pair_or_by_hand), color = Muted, fontSize = 11.sp)
        OutlinedTextField(
            value = host, onValueChange = { host = it },
            label = { Text(stringResource(R.string.pair_host)) }, singleLine = true,
        )
        OutlinedTextField(
            value = port, onValueChange = { port = it.filter { c -> c.isDigit() } },
            label = { Text(stringResource(R.string.pair_port)) }, singleLine = true,
        )
        OutlinedTextField(
            value = key, onValueChange = { key = it },
            label = { Text(stringResource(R.string.pair_key)) },
            supportingText = {
                Text(
                    if (keyLooksRight) stringResource(R.string.pair_key_ok)
                    else stringResource(R.string.pair_key_short),
                    color = if (keyLooksRight) Color(0xFF4ADE80) else Muted,
                )
            },
        )
        Button(
            onClick = {
                pairing.host = host
                pairing.port = port.toIntOrNull() ?: 8443
                pairing.keyHex = key
                pairing.certPin = certPin
                onDone()
            },
            enabled = keyLooksRight && host.isNotBlank() && certPin.isNotBlank(),
        ) { Text(stringResource(R.string.pair_save)) }
    }
}

@OptIn(ExperimentalFoundationApi::class)
@Composable
private fun Bubble(m: Message, onLongClick: () -> Unit = {}) {
    val time = SimpleDateFormat("HH:mm", Locale.getDefault()).format(Date(m.timestamp))
    Row(
        Modifier.fillMaxWidth(),
        horizontalArrangement = if (m.fromMe) Arrangement.End else Arrangement.Start,
    ) {
        Surface(
            color = if (m.fromMe) Mine else Theirs,
            shape = RoundedCornerShape(
                topStart = 14.dp, topEnd = 14.dp,
                bottomStart = if (m.fromMe) 14.dp else 4.dp,
                bottomEnd = if (m.fromMe) 4.dp else 14.dp,
            ),
            modifier = Modifier
                .widthIn(max = 300.dp)
                .combinedClickable(onLongClick = onLongClick, onClick = {}),
        ) {
            Column(Modifier.padding(horizontal = 12.dp, vertical = 8.dp)) {
                Text(m.text, color = Color(0xFFC8D6E5), fontSize = 14.sp)
                Text(
                    time, color = Muted, fontSize = 10.sp,
                    textAlign = TextAlign.End, modifier = Modifier.align(Alignment.End),
                )
            }
        }
    }
}

private val QUICK_COMMANDS = listOf(
    "/status", "/selinux", "/hardware", "/firmware", "/help",
    "/evidence list", "/face keygen", "/face register",
    "/settings", "/llm", "/systemprompt clear",
    "/reboot", "/poweroff",
)

@Composable
private fun Composer(
    draft: String,
    onDraft: (String) -> Unit,
    onSend: () -> Unit,
    onAttach: (filename: String, bytes: ByteArray, markitdown: Boolean) -> Unit,
    onCommand: (String) -> Unit,
) {
    val ctx = LocalContext.current
    var attachMenuOpen by remember { mutableStateOf(false) }
    var cmdMenuOpen by remember { mutableStateOf(false) }
    var markitdown by remember { mutableStateOf(true) }

    var pickMime by remember { mutableStateOf("*/*") }
    val picker = rememberLauncherForActivityResult(ActivityResultContracts.GetContent()) { uri ->
        if (uri != null) {
            val (name, bytes) = readUri(ctx, uri)
            if (bytes != null) {
                // Images are compressed to fit the 1 MB frame limit before being sent.
                val finalBytes = if (pickMime.startsWith("image/")) {
                    compressImageForChannel(bytes)
                } else bytes
                onAttach(name, finalBytes, markitdown)
            }
        }
    }

    Row(
        Modifier.background(Ground).fillMaxWidth().padding(10.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        // "+" attach menu
        Box {
            FilledIconButton(onClick = { attachMenuOpen = true }) { Text("+") }
            DropdownMenu(expanded = attachMenuOpen, onDismissRequest = { attachMenuOpen = false }) {
                DropdownMenuItem(
                    text = {
                        Row(verticalAlignment = Alignment.CenterVertically) {
                            Checkbox(checked = markitdown, onCheckedChange = { markitdown = it })
                            Text(stringResource(R.string.attach_markitdown), fontSize = 13.sp)
                        }
                    },
                    onClick = { markitdown = !markitdown },
                )
                Divider(color = Ground)
                DropdownMenuItem(text = { Text(stringResource(R.string.attach_image)) }, onClick = {
                    attachMenuOpen = false; pickMime = "image/*"; picker.launch("image/*")
                })
                DropdownMenuItem(text = { Text(stringResource(R.string.attach_pdf)) }, onClick = {
                    attachMenuOpen = false; pickMime = "application/pdf"; picker.launch("application/pdf")
                })
                DropdownMenuItem(text = { Text(stringResource(R.string.attach_document)) }, onClick = {
                    attachMenuOpen = false; pickMime = "*/*"; picker.launch("*/*")
                })
            }
        }

        // "/" command palette
        Box {
            FilledIconButton(onClick = { cmdMenuOpen = true }) { Text("/") }
            DropdownMenu(expanded = cmdMenuOpen, onDismissRequest = { cmdMenuOpen = false }) {
                QUICK_COMMANDS.forEach { cmd ->
                    DropdownMenuItem(
                        text = { Text(cmd, fontSize = 13.sp, fontFamily = androidx.compose.ui.text.font.FontFamily.Monospace) },
                        onClick = { cmdMenuOpen = false; onCommand(cmd) },
                    )
                }
            }
        }

        Spacer(Modifier.width(6.dp))
        OutlinedTextField(
            value = draft,
            onValueChange = onDraft,
            placeholder = { Text(stringResource(R.string.hint_message), color = Muted) },
            modifier = Modifier.weight(1f),
            shape = RoundedCornerShape(22.dp),
            singleLine = false,
            maxLines = 4,
        )
        Spacer(Modifier.width(8.dp))
        FilledIconButton(onClick = onSend) { Text("→") }
    }
}

@Composable
private fun OwnershipScreen(
    engine: ChatEngine,
    listener: ChatEngine.Listener,
    onCommand: (String) -> Unit,
) {
    val ctx = LocalContext.current
    val activity = ctx as? FragmentActivity
    var saveLocal by remember { mutableStateOf(false) }
    var localNote by remember { mutableStateOf<String?>(null) }
    var defineWorking by remember { mutableStateOf(false) }
    var defineNote by remember { mutableStateOf<String?>(null) }
    // The picked photo, held until the fingerprint gate passes. It is never
    // armed nor sent early: the enrolment only crosses the wire after the
    // owner's finger confirms it.
    var pendingFace by remember { mutableStateOf<ByteArray?>(null) }

    val facePicker = rememberLauncherForActivityResult(ActivityResultContracts.GetContent()) { uri ->
        if (uri != null) {
            val (_, bytes) = readUri(ctx, uri)
            // Validate now (decodes + re-encodes cheaply) so a hand with a
            // non-image does not waste a fingerprint prompt on nothing.
            if (bytes == null || FacePhoto.forEnrolment(bytes) == null) {
                localNote = ctx.getString(R.string.own_enroll_unreadable)
            } else {
                pendingFace = bytes
            }
        }
    }

    // The fingerprint gate: only after it passes do we arm and send.
    pendingFace?.let { original ->
        LaunchedEffect(original) {
            val act = activity
            if (act == null) {
                pendingFace = null
                localNote = ctx.getString(R.string.own_enroll_no_window)
                return@LaunchedEffect
            }
            Confirmation.gate(
                activity = act,
                onSuccess = {
                    pendingFace = null
                    // A camera JPEG is megabytes and the channel refuses frames
                    // over 1 MB — the machine would close the connection mid-write
                    // and the phone would die of "broken pipe". A face template
                    // needs no such resolution: scale down, then arm and send.
                    val jpeg = FacePhoto.forEnrolment(original)
                    if (jpeg == null) {
                        localNote = ctx.getString(R.string.own_enroll_unreadable)
                    } else {
                        onCommand("/face register")
                        engine.enrollFace(jpeg, listener)
                        if (saveLocal) {
                            saveFaceLocally(ctx, original)
                            localNote = ctx.getString(R.string.own_saved_local)
                        }
                    }
                },
                onDone = { message ->
                    pendingFace = null
                    if (message.isNotEmpty()) localNote = message
                },
            )
        }
    }

    ScreenScaffold(stringResource(R.string.own_title), stringResource(R.string.own_blurb)) {
        Button(onClick = { facePicker.launch("image/*") }, modifier = Modifier.fillMaxWidth()) {
            Text(stringResource(R.string.own_enroll))
        }
        Text(stringResource(R.string.own_enroll_hint), color = Muted, fontSize = 11.sp)
        Text(stringResource(R.string.own_enroll_fingerprint_hint), color = Accent, fontSize = 11.sp)

        Row(
            Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Text(stringResource(R.string.own_save_local), color = Color(0xFFC8D6E5),
                fontSize = 14.sp, modifier = Modifier.weight(1f))
            Switch(checked = saveLocal, onCheckedChange = { saveLocal = it })
        }
        Text(stringResource(R.string.own_save_local_hint), color = Muted, fontSize = 11.sp)
        localNote?.let { Text(it, color = Color(0xFF4ADE80), fontSize = 12.sp) }

        Divider(color = Theirs)
        OutlinedButton(
            onClick = { onCommand("/definehome") },
            modifier = Modifier.fillMaxWidth(),
        ) { Text(stringResource(R.string.own_definehome)) }
        Text(stringResource(R.string.own_definehome_hint), color = Muted, fontSize = 11.sp)

        Divider(color = Theirs)
        Button(
            onClick = {
                defineWorking = true
                defineNote = null
                // The whole exchange runs on the engine's background thread;
                // the verdict is the daemon's text, shown verbatim.
                engine.definePhone(listener) { verdict ->
                    defineWorking = false
                    defineNote = verdict
                }
            },
            enabled = !defineWorking,
            modifier = Modifier.fillMaxWidth(),
        ) {
            Text(
                if (defineWorking) stringResource(R.string.own_definephone_working)
                else stringResource(R.string.own_definephone)
            )
        }
        if (defineWorking) {
            Text(stringResource(R.string.own_definephone_hint), color = Muted, fontSize = 11.sp)
        }
        defineNote?.let { Text(it, color = Color(0xFFC8D6E5), fontSize = 12.sp) }
    }
}

/** Read a picked file's display name and bytes; bytes null on any failure. */
private fun readUri(ctx: android.content.Context, uri: android.net.Uri): Pair<String, ByteArray?> {
    val name = runCatching {
        ctx.contentResolver.query(uri, null, null, null, null)?.use { c ->
            val idx = c.getColumnIndex(android.provider.OpenableColumns.DISPLAY_NAME)
            if (idx >= 0 && c.moveToFirst()) c.getString(idx) else null
        }
    }.getOrNull() ?: uri.lastPathSegment ?: "attachment"
    val bytes = runCatching {
        ctx.contentResolver.openInputStream(uri)?.use { it.readBytes() }
    }.getOrNull()
    return name to bytes
}

/** Keep a copy of the enrolment photo in the app's private data folder. */
private fun saveFaceLocally(ctx: android.content.Context, jpeg: ByteArray) {
    runCatching {
        val dir = java.io.File(ctx.filesDir, "faces").apply { mkdirs() }
        java.io.File(dir, "owner-${jpeg.size}.jpg").writeBytes(jpeg)
    }
}

/**
 * Scale and re-compress an image to fit under the channel's 1 MB frame limit.
 * Uses a square-root scale so area — and thus byte count — decreases proportionally.
 */
/**
 * Resize by homothety so the longest side is at most [maxDim] px, then encode
 * as JPEG at quality 85. Aspect ratio is preserved exactly (no cropping).
 * Images already within the limit pass through untouched.
 */
private fun compressImageForChannel(bytes: ByteArray, maxDim: Int = 900): ByteArray {
    return try {
        // First pass: read dimensions without decoding pixels.
        val opts = android.graphics.BitmapFactory.Options().apply { inJustDecodeBounds = true }
        android.graphics.BitmapFactory.decodeByteArray(bytes, 0, bytes.size, opts)
        val srcW = opts.outWidth.takeIf { it > 0 } ?: return bytes
        val srcH = opts.outHeight.takeIf { it > 0 } ?: return bytes

        val longest = maxOf(srcW, srcH)
        if (longest <= maxDim) return bytes  // already fits, send as-is

        // Homothety: scale factor k such that max(dstW, dstH) == maxDim.
        val k = maxDim.toFloat() / longest
        val dstW = (srcW * k).toInt().coerceAtLeast(1)
        val dstH = (srcH * k).toInt().coerceAtLeast(1)

        val bmp = android.graphics.BitmapFactory.decodeByteArray(bytes, 0, bytes.size)
            ?: return bytes
        val scaled = android.graphics.Bitmap.createScaledBitmap(bmp, dstW, dstH, true)
        val out = java.io.ByteArrayOutputStream()
        scaled.compress(android.graphics.Bitmap.CompressFormat.JPEG, 85, out)
        out.toByteArray()
    } catch (_: Exception) { bytes }
}

// ── Logs screen ───────────────────────────────────────────────────────────────

/**
 * A parsed daemon message split into:
 *  - [analysis]  Human-readable prose lines (LLM output)
 *  - [raw]       Technical log lines (avc:, pid=, kmod, hex addresses, etc.)
 *  - [summary]   First prose sentence, or a simplified form of the first raw line
 *  - [category]  selinux | kernel | hardware | alert | info
 *  - [ownership] "mine" | "unknown" | "different" — from TPM identity lines
 */
private data class LogEntry(
    val ts: Long,
    val category: String,
    val summary: String,
    val analysis: String,   // LLM prose
    val raw: String,        // technical log lines
    val ownership: String,  // TPM-derived machine ownership
)

private val CAT_COLOR = mapOf(
    "selinux"  to Color(0xFFF59E0B),
    "kernel"   to Color(0xFFEF4444),
    "hardware" to Color(0xFF60A5FA),
    "alert"    to Color(0xFFF87171),
    "info"     to Color(0xFF6B7C8F),
)
private val CAT_LABEL = mapOf(
    "selinux"  to "SELinux / AppArmor",
    "kernel"   to "Kernel",
    "hardware" to "Hardware",
    "alert"    to "Alert",
    "info"     to "Info",
)

/** True when the line looks like a raw log / technical line rather than prose. */
private fun isRawLine(line: String): Boolean {
    val l = line.trim()
    val lower = l.lowercase()
    return lower.contains("avc:") || lower.contains("pid=") ||
        lower.contains("comm=") || lower.contains("path=") ||
        lower.contains("scontext=") || lower.contains("tcontext=") ||
        lower.contains("0x") || Regex("""0[xX][0-9a-fA-F]{4,}""").containsMatchIn(l) ||
        (l.startsWith("[") && l.contains("]") && Regex("""\d+\.\d+""").containsMatchIn(l)) ||
        lower.matches(Regex(""".*\w+=\w+.*""")) && l.count { it == '=' } >= 2
}

private fun categorizeText(text: String): String {
    val lower = text.lowercase()
    return when {
        lower.contains("selinux") || lower.contains("apparmor") ||
            lower.contains("avc:") || (lower.contains("denied") && lower.contains("access")) -> "selinux"
        lower.contains("kernel") || lower.contains("kmod") ||
            lower.contains("rootkit") || lower.contains("dmesg") -> "kernel"
        lower.contains("cpu") || lower.contains("pmu") ||
            lower.contains("hardware") || lower.contains("thermal") -> "hardware"
        lower.contains("alert") || lower.contains("luks") ||
            lower.contains("burst") || lower.contains("intrusion") -> "alert"
        else -> "info"
    }
}

private fun extractOwnership(text: String): String {
    val lower = text.lowercase()
    return when {
        lower.contains("different_device") || lower.contains("different phone") ||
            lower.contains("NOT the phone") -> "different"
        lower.contains("recognised") || lower.contains("registered") ||
            lower.contains("tpm") && lower.contains("ok") -> "mine"
        else -> "unknown"
    }
}

/**
 * Turn a selinux raw line into a one-sentence summary, e.g.:
 *   "avc: denied { write } for pid=1 comm="sh" path="/etc/foo""
 *   → "sh tried to write /etc/foo — SELinux denied"
 */
private fun selinuxSummary(line: String): String? {
    if (!line.lowercase().contains("avc:") && !line.lowercase().contains("denied")) return null
    val action = Regex("""\{\s*(\w+)\s*\}""").find(line)?.groupValues?.getOrNull(1) ?: return null
    val comm   = Regex("""comm="([^"]+)"""").find(line)?.groupValues?.getOrNull(1) ?: "process"
    val path   = Regex("""(?:path|name|dev)="([^"]+)"""").find(line)?.groupValues?.getOrNull(1)
    return if (path != null) "$comm tried to $action "$path" — SELinux denied"
    else "$comm tried $action — SELinux denied"
}

private fun parseMessage(text: String, ts: Long): LogEntry {
    val lines = text.lines().map { it.trim() }.filter { it.isNotBlank() }
    val rawLines = mutableListOf<String>()
    val prosLines = mutableListOf<String>()

    for (line in lines) {
        if (isRawLine(line)) rawLines.add(line)
        else prosLines.add(line)
    }

    val cat = categorizeText(text)
    val ownership = extractOwnership(text)

    // Build the summary: prefer first prose line, else synthesize from first raw line.
    val summary: String = prosLines.firstOrNull()?.take(120)
        ?: rawLines.firstOrNull()?.let { selinuxSummary(it) }
        ?: rawLines.firstOrNull()?.take(100)
        ?: "—"

    return LogEntry(
        ts = ts,
        category = cat,
        summary = summary,
        analysis = prosLines.joinToString("\n"),
        raw = rawLines.joinToString("\n"),
        ownership = ownership,
    )
}

@Composable
private fun LogsScreen(
    allMessages: List<Message>,
    engine: ChatEngine,
    @Suppress("UNUSED_PARAMETER") mainListener: ChatEngine.Listener,
    onBack: () -> Unit,
) {
    val scope = rememberCoroutineScope()
    val entries = remember { mutableStateListOf<LogEntry>() }
    var loading by remember { mutableStateOf(false) }
    var filter by remember { mutableStateOf("all") }
    var expandedIdx by remember { mutableStateOf<Int?>(null) }
    // Collapsible machine-info panel at the top
    var machineInfoText by remember { mutableStateOf("") }
    var machineInfoExpanded by remember { mutableStateOf(false) }

    // LOCAL listener — responses stay in this screen, never touch the main chat.
    val localListener = remember {
        object : ChatEngine.Listener {
            override fun onMessages(msgs: List<Message>) {
                val newEntries = msgs
                    .filter { !it.fromMe && it.text.isNotBlank() }
                    .map { parseMessage(it.text, it.timestamp) }
                entries.addAll(0, newEntries)
            }
            override fun onStatus(text: String, ok: Boolean) = Unit
        }
    }

    // Also seed from existing chat messages on first enter (historical context).
    LaunchedEffect(Unit) {
        val historical = allMessages
            .filter { !it.fromMe && it.text.isNotBlank() }
            .map { parseMessage(it.text, it.timestamp) }
            .reversed()
        entries.addAll(historical)

        // Auto-fetch fresh status + selinux on open.
        loading = true
        kotlinx.coroutines.withContext(kotlinx.coroutines.Dispatchers.IO) {
            engine.send(DaemonSettings.STATUS, localListener)
            engine.send(DaemonSettings.SELINUX, localListener)
            engine.send(DaemonSettings.HARDWARE, object : ChatEngine.Listener {
                override fun onMessages(msgs: List<Message>) {
                    machineInfoText = msgs.lastOrNull()?.text.orEmpty()
                }
                override fun onStatus(text: String, ok: Boolean) = Unit
            })
        }
        loading = false
    }

    fun doRefresh() {
        loading = true
        scope.launch(kotlinx.coroutines.Dispatchers.IO) {
            engine.send(DaemonSettings.STATUS, localListener)
            engine.send(DaemonSettings.SELINUX, localListener)
            kotlinx.coroutines.withContext(kotlinx.coroutines.Dispatchers.Main) { loading = false }
        }
    }

    val filtered = remember(entries.size, filter) {
        if (filter == "all") entries.toList()
        else entries.filter { it.category == filter }
    }

    Column(Modifier.fillMaxSize().background(Ground)) {

        // ── Top bar ───────────────────────────────────────────────────────────
        Row(
            Modifier.fillMaxWidth().background(Color(0xFF161C24))
                .padding(horizontal = 16.dp, vertical = 12.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            IconButton(onClick = onBack) { Text("←", color = Accent, fontSize = 20.sp) }
            Text(
                stringResource(R.string.logs_title),
                color = Accent, fontSize = 18.sp,
                fontWeight = androidx.compose.ui.text.font.FontWeight.SemiBold,
                modifier = Modifier.weight(1f).padding(start = 8.dp),
            )
            if (loading) {
                CircularProgressIndicator(modifier = Modifier.size(18.dp), color = Accent, strokeWidth = 2.dp)
                Spacer(Modifier.width(8.dp))
            }
            TextButton(onClick = ::doRefresh) {
                Text(stringResource(R.string.logs_refresh), color = Accent, fontSize = 13.sp)
            }
        }

        // ── Machine fingerprint / ownership banner ────────────────────────────
        if (machineInfoText.isNotBlank()) {
            val tpmOwner = extractOwnership(machineInfoText)
            val (ownerColor, ownerLabel) = when (tpmOwner) {
                "mine"      -> Color(0xFF4ADE80) to "✓ Your machine (TPM verified)"
                "different" -> Color(0xFFF87171) to "⚠ Different machine — TPM mismatch"
                else        -> Muted to "Machine identity unknown"
            }
            Surface(
                color = Color(0xFF0F1A24),
                modifier = Modifier
                    .fillMaxWidth()
                    .clickable { machineInfoExpanded = !machineInfoExpanded },
            ) {
                Column(Modifier.padding(horizontal = 16.dp, vertical = 10.dp)) {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Text(ownerLabel, color = ownerColor, fontSize = 12.sp, modifier = Modifier.weight(1f))
                        Text(if (machineInfoExpanded) "▲" else "▼", color = Muted, fontSize = 10.sp)
                    }
                    if (machineInfoExpanded) {
                        Spacer(Modifier.height(8.dp))
                        Divider(color = Accent.copy(alpha = 0.15f))
                        Spacer(Modifier.height(6.dp))
                        Text(
                            machineInfoText,
                            color = Color(0xFFB0C4D8),
                            fontSize = 11.sp,
                            fontFamily = androidx.compose.ui.text.font.FontFamily.Monospace,
                        )
                    }
                }
            }
        }

        // ── Filter chips ──────────────────────────────────────────────────────
        androidx.compose.foundation.lazy.LazyRow(
            Modifier.fillMaxWidth().background(Color(0xFF0F1520)).padding(8.dp),
            horizontalArrangement = Arrangement.spacedBy(8.dp),
        ) {
            val chips = listOf("all", "selinux", "kernel", "hardware", "alert", "info")
            items(chips) { cat ->
                val active = cat == filter
                Surface(
                    color = if (active) Accent else Color(0xFF1E2A38),
                    shape = RoundedCornerShape(16.dp),
                    modifier = Modifier.clickable { filter = cat; expandedIdx = null },
                ) {
                    Text(
                        if (cat == "all") stringResource(R.string.logs_filter_all) else CAT_LABEL[cat] ?: cat,
                        color = if (active) Ground else Color(0xFFC8D6E5),
                        fontSize = 12.sp,
                        modifier = Modifier.padding(horizontal = 12.dp, vertical = 6.dp),
                    )
                }
            }
        }

        // ── Entry list ────────────────────────────────────────────────────────
        if (filtered.isEmpty()) {
            Box(Modifier.fillMaxSize(), contentAlignment = Alignment.Center) {
                Column(horizontalAlignment = Alignment.CenterHorizontally) {
                    Text(stringResource(R.string.logs_empty), color = Muted, fontSize = 14.sp,
                        modifier = Modifier.padding(horizontal = 24.dp))
                    Spacer(Modifier.height(12.dp))
                    OutlinedButton(onClick = ::doRefresh) { Text(stringResource(R.string.logs_fetch)) }
                }
            }
        } else {
            LazyColumn(
                Modifier.fillMaxSize(),
                contentPadding = PaddingValues(12.dp),
                verticalArrangement = Arrangement.spacedBy(6.dp),
            ) {
                items(filtered.size) { i ->
                    val e = filtered[i]
                    val catColor = CAT_COLOR[e.category] ?: Muted
                    val expanded = expandedIdx == i

                    Surface(
                        color = Color(0xFF161C24),
                        shape = RoundedCornerShape(10.dp),
                        modifier = Modifier.fillMaxWidth().clickable {
                            expandedIdx = if (expanded) null else i
                        },
                    ) {
                        Column(Modifier.padding(12.dp)) {

                            // Header row: category dot + label + time
                            Row(verticalAlignment = Alignment.CenterVertically) {
                                Box(Modifier.size(8.dp).background(catColor, CircleShape))
                                Spacer(Modifier.width(8.dp))
                                Text(CAT_LABEL[e.category] ?: e.category, color = catColor, fontSize = 10.sp)
                                if (e.ownership == "mine") {
                                    Spacer(Modifier.width(6.dp))
                                    Text("· Tu equipo", color = Color(0xFF4ADE80), fontSize = 10.sp)
                                } else if (e.ownership == "different") {
                                    Spacer(Modifier.width(6.dp))
                                    Text("· ⚠ Equipo ajeno", color = Color(0xFFF87171), fontSize = 10.sp)
                                }
                                Spacer(Modifier.weight(1f))
                                Text(
                                    SimpleDateFormat("HH:mm:ss", Locale.getDefault())
                                        .format(java.util.Date(e.ts)),
                                    color = Muted, fontSize = 10.sp,
                                )
                            }

                            Spacer(Modifier.height(4.dp))

                            // Summary line (human-readable, from LLM prose or synthesized)
                            Text(
                                e.summary,
                                color = Color(0xFFE2E8F0), fontSize = 13.sp,
                                maxLines = if (expanded) Int.MAX_VALUE else 2,
                                overflow = if (expanded) androidx.compose.ui.text.style.TextOverflow.Visible
                                           else androidx.compose.ui.text.style.TextOverflow.Ellipsis,
                            )

                            if (expanded) {
                                // ── LLM analysis section ──────────────────────
                                if (e.analysis.isNotBlank()) {
                                    Spacer(Modifier.height(8.dp))
                                    Text("Análisis LLM", color = Accent.copy(alpha = 0.7f), fontSize = 10.sp)
                                    Spacer(Modifier.height(4.dp))
                                    Text(
                                        e.analysis,
                                        color = Color(0xFFC8D6E5), fontSize = 12.sp,
                                    )
                                }

                                // ── Raw log section ───────────────────────────
                                if (e.raw.isNotBlank()) {
                                    Spacer(Modifier.height(8.dp))
                                    Text("Log crudo", color = Muted, fontSize = 10.sp)
                                    Spacer(Modifier.height(4.dp))
                                    Surface(
                                        color = Color(0xFF0B1018),
                                        shape = RoundedCornerShape(6.dp),
                                    ) {
                                        Text(
                                            e.raw,
                                            color = Color(0xFF88C0A0),
                                            fontSize = 10.sp,
                                            fontFamily = androidx.compose.ui.text.font.FontFamily.Monospace,
                                            modifier = Modifier
                                                .fillMaxWidth()
                                                .padding(8.dp),
                                        )
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}
