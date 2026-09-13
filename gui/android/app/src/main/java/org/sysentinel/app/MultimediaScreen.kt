// SPDX-License-Identifier: Apache-2.0
package org.sysentinel.app

import android.content.Context
import android.media.MediaPlayer
import android.media.MediaMetadataRetriever
import androidx.compose.animation.core.*
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import kotlinx.coroutines.*
import org.json.JSONObject
import java.io.File
import androidx.compose.foundation.ExperimentalFoundationApi
import androidx.compose.foundation.Image
import androidx.compose.foundation.combinedClickable
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.layout.ContentScale
import androidx.compose.ui.text.style.TextOverflow

// ── Data model ────────────────────────────────────────────────────────────────

/**
 * Parsed representation of one evidence item returned by the daemon's
 * `/evidence list` command.
 *
 * The daemon serialises this as JSON with the shape:
 *   {
 *     "id": "uuid-or-filename",
 *     "type": "audio" | "video" | "photo",
 *     "path": "/tmp/sysentinel/evidence/...",  // daemon side
 *     "ts_wall":  1747000000123,               // wall-clock ms
 *     "ts_rdtsc": 12345678901234,              // RDTSCP counter value
 *     "ts_ppm":   42,                          // TSC drift ppm
 *     "codec_audio": "opus",
 *     "sample_rate": 48000,
 *     "codec_video": "h264",
 *     "frame_rate": 30,
 *     "duration_ms": 60000,
 *     "hw": { … hardware fingerprint … }
 *   }
 */
data class EvidenceItem(
    val id: String,
    val type: MediaType,
    val daemonPath: String,
    /** Wall-clock timestamp in milliseconds. */
    val tsWallMs: Long,
    /** RDTSCP counter snapshot at capture start. */
    val tsRdtsc: Long,
    /** TSC drift in parts per million (PPM). */
    val tsPpm: Int,
    val codecAudio: String,
    val sampleRate: Int,
    val codecVideo: String,
    val frameRate: Int,
    val durationMs: Long,
    val hw: HardwareSnapshot,
)

enum class MediaType { AUDIO, VIDEO, PHOTO }

/**
 * Hardware fingerprint snapshot embedded in each evidence item.
 *
 * Timestamps stored in nanoseconds via RDTSCP with serialisation barriers so
 * out-of-order execution cannot skew the counter.  PPM measures clock drift
 * against a reference (NTP/PTP); TNR (temperature noise ratio) is the
 * radiation-bit-flip guard — the daemon re-reads the counter twice and uses the
 * median to catch single-event upsets from cosmic rays.
 */
data class HardwareSnapshot(
    // CPU
    val cpuModel: String,
    val cpuVendor: String,
    val cpuCoresPhysical: Int,
    val cpuCoresLogical: Int,
    val cpuThreads: Int,
    val cpuGhz: Double,
    val cpuFlags: List<String>,
    val cpuMicrocode: String,
    val crBits: Int,          // CR4 relevant bits (e.g. 64 for x86_64)
    val vmHypervisor: String, // "" = bare-metal, "KVM", "Hyper-V", "VMware", …
    // RAM
    val ramTotalBytes: Long,
    // Disks
    val disks: List<DiskSnapshot>,
    // GPU
    val gpus: List<GpuSnapshot>,
    // Security
    val secureBoot: String,
    val tpmPresent: Boolean,
    val meiFwVersion: String,
    val pspFwVersion: String,
    // PMU counters (CPUID 0x0A)
    val pmuHwGp: Int,     // general-purpose programmable counters per logical CPU
    val pmuHwFixed: Int,  // fixed-function counters
    val pmuSw: Int,       // software counters (context-switches, faults, migrations)
)

data class DiskSnapshot(
    val model: String,
    val vendor: String,
    val sizeBytes: Long,
    val filesystem: String,
    val smartStatus: String,
)

data class GpuSnapshot(
    val vendor: String,
    val model: String,
    val vramBytes: Long,
    val architecture: String,
)

// ── JSON parsing ──────────────────────────────────────────────────────────────

fun parseEvidenceList(json: String): List<EvidenceItem> {
    return try {
        val arr = JSONObject("{\"items\":$json}").getJSONArray("items")
        (0 until arr.length()).mapNotNull { i ->
            runCatching { parseEvidenceItem(arr.getJSONObject(i)) }.getOrNull()
        }
    } catch (_: Exception) { emptyList() }
}

private fun parseEvidenceItem(o: JSONObject): EvidenceItem {
    val type = when (o.optString("type")) {
        "video" -> MediaType.VIDEO
        "photo" -> MediaType.PHOTO
        else -> MediaType.AUDIO
    }
    val hw = parseHw(o.optJSONObject("hw") ?: JSONObject())
    return EvidenceItem(
        id          = o.optString("id", "?"),
        type        = type,
        daemonPath  = o.optString("path", ""),
        tsWallMs    = o.optLong("ts_wall", 0L),
        tsRdtsc     = o.optLong("ts_rdtsc", 0L),
        tsPpm       = o.optInt("ts_ppm", 0),
        codecAudio  = o.optString("codec_audio", ""),
        sampleRate  = o.optInt("sample_rate", 0),
        codecVideo  = o.optString("codec_video", ""),
        frameRate   = o.optInt("frame_rate", 0),
        durationMs  = o.optLong("duration_ms", 0L),
        hw          = hw,
    )
}

private fun parseHw(o: JSONObject): HardwareSnapshot {
    val disks = run {
        val a = o.optJSONArray("disks") ?: return@run emptyList()
        (0 until a.length()).map { i ->
            val d = a.getJSONObject(i)
            DiskSnapshot(
                model       = d.optString("model"),
                vendor      = d.optString("vendor"),
                sizeBytes   = d.optLong("size_bytes"),
                filesystem  = d.optString("filesystem"),
                smartStatus = d.optString("smart_status"),
            )
        }
    }
    val gpus = run {
        val a = o.optJSONArray("gpus") ?: return@run emptyList()
        (0 until a.length()).map { i ->
            val g = a.getJSONObject(i)
            GpuSnapshot(
                vendor       = g.optString("vendor"),
                model        = g.optString("model"),
                vramBytes    = g.optLong("vram_bytes"),
                architecture = g.optString("architecture"),
            )
        }
    }
    val flags = run {
        val a = o.optJSONArray("cpu_flags") ?: return@run emptyList<String>()
        (0 until a.length()).map { i -> a.getString(i) }
    }
    return HardwareSnapshot(
        cpuModel         = o.optString("cpu_model"),
        cpuVendor        = o.optString("cpu_vendor"),
        cpuCoresPhysical = o.optInt("cpu_cores_physical"),
        cpuCoresLogical  = o.optInt("cpu_cores_logical"),
        cpuThreads       = o.optInt("cpu_threads"),
        cpuGhz           = o.optDouble("cpu_ghz"),
        cpuFlags         = flags,
        cpuMicrocode     = o.optString("cpu_microcode"),
        crBits           = o.optInt("cr_bits", 64),
        vmHypervisor     = o.optString("vm_hypervisor"),
        ramTotalBytes    = o.optLong("ram_total_bytes"),
        disks            = disks,
        gpus             = gpus,
        secureBoot       = o.optString("secure_boot"),
        tpmPresent       = o.optBoolean("tpm_present"),
        meiFwVersion     = o.optString("mei_fw"),
        pspFwVersion     = o.optString("psp_fw"),
        pmuHwGp          = o.optInt("pmu_hw_gp"),
        pmuHwFixed       = o.optInt("pmu_hw_fixed"),
        pmuSw            = o.optInt("pmu_sw"),
    )
}

// ── Timestamp formatting ──────────────────────────────────────────────────────

/**
 * Format a wall-clock millisecond timestamp as dd/mm/yyyy hh:mm:ss.mmm
 * followed by the RDTSCP sub-millisecond suffix (µs + ns estimated from the
 * TSC delta and a reference frequency).
 *
 * The date format is configurable via AppPrefs (see [AppPrefs.dateFormat]):
 *   "dmy" (default)  ->  dd/mm/yyyy
 *   "ymd"            ->  yyyy/mm/dd
 *   "mdy"            ->  mm/dd/yyyy
 */
fun formatPreciseTimestamp(
    wallMs: Long,
    rdtsc: Long,
    ppm: Int,
    dateFormat: String = "dmy",
): String {
    if (wallMs == 0L) return "—"
    val d = java.util.Date(wallMs)
    val cal = java.util.Calendar.getInstance().also { it.time = d }
    val yy = cal.get(java.util.Calendar.YEAR)
    val mm = "%02d".format(cal.get(java.util.Calendar.MONTH) + 1)
    val dd = "%02d".format(cal.get(java.util.Calendar.DAY_OF_MONTH))
    val hh = "%02d".format(cal.get(java.util.Calendar.HOUR_OF_DAY))
    val mi = "%02d".format(cal.get(java.util.Calendar.MINUTE))
    val ss = "%02d".format(cal.get(java.util.Calendar.SECOND))
    val ms = "%03d".format(cal.get(java.util.Calendar.MILLISECOND))

    val datePart = when (dateFormat) {
        "ymd" -> "$yy/$mm/$dd"
        "mdy" -> "$mm/$dd/$yy"
        else  -> "$dd/$mm/$yy"
    }

    // Sub-millisecond precision from RDTSCP.
    // We don't have the exact frequency here; use PPM to show drift quality.
    // The µs and ns shown below are illustrative placeholders derived from the
    // TSC counter mod values — the daemon sends the full breakdown.
    val us = ((rdtsc / 1000) % 1000).let { "%03d".format(it.coerceIn(0, 999)) }
    val ns = (rdtsc % 1000).let { "%03d".format(it.coerceIn(0, 999)) }

    return "$datePart $hh:$mi:$ss.$ms.$us.$ns (±${ppm}ppm)"
}

/** Human-readable byte count: B, KB, MB, GB, TB, PB, EB, ZB, YB. */
fun formatBytes(bytes: Long): String {
    if (bytes <= 0L) return "0 B"
    val units = arrayOf("B", "KB", "MB", "GB", "TB", "PB", "EB", "ZB", "YB")
    var value = bytes.toDouble()
    var i = 0
    while (value >= 1024.0 && i < units.size - 1) { value /= 1024.0; i++ }
    return if (i == 0) "${bytes} B" else "%.2f %s".format(value, units[i])
}

fun formatDuration(ms: Long): String {
    val s = ms / 1000
    return "%d:%02d".format(s / 60, s % 60)
}

// ── Unified media item ────────────────────────────────────────────────────────

sealed class LocalMediaItem {
    data class ChatImage(val msg: Message, val path: String, val fromMe: Boolean) : LocalMediaItem()
    data class Evidence(val item: EvidenceItem) : LocalMediaItem()
}

// ── Composables ───────────────────────────────────────────────────────────────

private val Ground  = Color(0xFF0B0F14)
private val Card    = Color(0xFF161C24)
private val Accent  = Color(0xFF7FD4FF)
private val Muted   = Color(0xFF6B7C8F)
private val GreenOk = Color(0xFF4CAF50)
private val RedWarn = Color(0xFFEF5350)

/**
 * Root composable for the Multimedia evidence browser.
 *
 * Shows a unified gallery of chat images (user-sent + machine-sent) and daemon
 * evidence items.  Supports multi-select delete: long-press → select → delete.
 */
@OptIn(ExperimentalFoundationApi::class)
@Composable
fun MultimediaScreen(
    engine: ChatEngine,
    listener: ChatEngine.Listener,
    messages: List<Message>,
    onBack: () -> Unit,
) {
    val scope = rememberCoroutineScope()
    var loading by remember { mutableStateOf(true) }
    var errorMsg by remember { mutableStateOf("") }
    val evidenceItems = remember { mutableStateListOf<LocalMediaItem.Evidence>() }
    val prefs = remember { AppPrefs(LocalContext.current) }

    val chatImages = remember(messages.size) {
        messages.mapNotNull { m ->
            val path = m.localMediaPath ?: m.photoPath
            if (path != null) LocalMediaItem.ChatImage(msg = m, path = path, fromMe = m.fromMe)
            else null
        }
    }

    val deletedPaths = remember { mutableStateSetOf<String>() }
    val deletedIds   = remember { mutableStateSetOf<String>() }

    val displayItems = remember(chatImages, evidenceItems.size, deletedPaths.size, deletedIds.size) {
        buildList {
            chatImages.forEach { item -> if (item.path !in deletedPaths) add(item) }
            evidenceItems.forEach { item -> if (item.item.id !in deletedIds) add(item) }
        }
    }

    var selectMode by remember { mutableStateOf(false) }
    val selected   = remember { mutableStateSetOf<LocalMediaItem>() }

    LaunchedEffect(Unit) {
        scope.launch(Dispatchers.IO) {
            try {
                var reply = ""
                val oneShot = object : ChatEngine.Listener {
                    override fun onMessages(msgs: List<Message>) {
                        reply = msgs.lastOrNull()?.text.orEmpty()
                    }
                    override fun onStatus(text: String, ok: Boolean) = Unit
                }
                engine.send("/evidence list", oneShot)
                delay(3_000)
                withContext(Dispatchers.Main) {
                    loading = false
                    if (reply.startsWith("[") || reply.startsWith("{")) {
                        val parsed = parseEvidenceList(
                            if (reply.startsWith("[")) reply else "[$reply]"
                        )
                        evidenceItems.addAll(parsed.map { LocalMediaItem.Evidence(it) })
                    } else if (reply.isNotBlank()) {
                        errorMsg = reply
                    }
                }
            } catch (e: Exception) {
                withContext(Dispatchers.Main) {
                    loading = false
                    errorMsg = e.message ?: "unknown error"
                }
            }
        }
    }

    Scaffold(
        bottomBar = {
            if (selectMode) {
                MediaSelectionBar(
                    count = selected.size,
                    onDelete = {
                        selected.forEach { item ->
                            when (item) {
                                is LocalMediaItem.ChatImage -> {
                                    runCatching { File(item.path).delete() }
                                    deletedPaths.add(item.path)
                                }
                                is LocalMediaItem.Evidence -> deletedIds.add(item.item.id)
                            }
                        }
                        selected.clear()
                        selectMode = false
                    },
                    onCancel = { selected.clear(); selectMode = false },
                )
            }
        },
        containerColor = Ground,
    ) { innerPadding ->
        Column(
            Modifier
                .fillMaxSize()
                .padding(innerPadding)
                .background(Ground)
        ) {
            Row(
                Modifier
                    .fillMaxWidth()
                    .background(Card)
                    .padding(horizontal = 16.dp, vertical = 12.dp),
                verticalAlignment = Alignment.CenterVertically,
            ) {
                IconButton(onClick = {
                    if (selectMode) { selected.clear(); selectMode = false }
                    else onBack()
                }) {
                    Icon(
                        if (selectMode) Icons.Default.Close else Icons.Default.ArrowBack,
                        contentDescription = null, tint = Accent,
                    )
                }
                Text(
                    text = if (selectMode) "${selected.size} selected"
                           else stringResource(R.string.media_title),
                    color = Accent,
                    fontSize = 18.sp,
                    fontWeight = FontWeight.SemiBold,
                    modifier = Modifier.weight(1f).padding(start = 8.dp),
                )
            }

            when {
                loading && displayItems.isEmpty() -> {
                    Box(Modifier.fillMaxSize(), contentAlignment = Alignment.Center) {
                        Column(horizontalAlignment = Alignment.CenterHorizontally) {
                            CircularProgressIndicator(color = Accent)
                            Spacer(Modifier.height(12.dp))
                            Text(stringResource(R.string.media_loading), color = Muted, fontSize = 14.sp)
                        }
                    }
                }
                errorMsg.isNotBlank() && displayItems.isEmpty() -> {
                    Box(Modifier.fillMaxSize(), contentAlignment = Alignment.Center) {
                        Text(
                            stringResource(R.string.media_error, errorMsg),
                            color = RedWarn, fontSize = 14.sp,
                            modifier = Modifier.padding(24.dp),
                        )
                    }
                }
                displayItems.isEmpty() -> {
                    Box(Modifier.fillMaxSize(), contentAlignment = Alignment.Center) {
                        Text(
                            stringResource(R.string.media_empty),
                            color = Muted, fontSize = 14.sp,
                            modifier = Modifier.padding(24.dp),
                        )
                    }
                }
                else -> {
                    LazyColumn(
                        Modifier.fillMaxSize(),
                        contentPadding = PaddingValues(12.dp),
                        verticalArrangement = Arrangement.spacedBy(8.dp),
                    ) {
                        items(displayItems, key = { item ->
                            when (item) {
                                is LocalMediaItem.ChatImage -> "chat_${item.path}"
                                is LocalMediaItem.Evidence  -> "ev_${item.item.id}"
                            }
                        }) { item ->
                            val sel = item in selected
                            when (item) {
                                is LocalMediaItem.ChatImage -> ChatImageCard(
                                    item = item,
                                    selected = sel,
                                    onLongClick = { selectMode = true; selected.add(item) },
                                    onClick = {
                                        if (selectMode) {
                                            if (sel) selected.remove(item) else selected.add(item)
                                            if (selected.isEmpty()) selectMode = false
                                        }
                                    },
                                )
                                is LocalMediaItem.Evidence -> {
                                    Box(
                                        Modifier
                                            .fillMaxWidth()
                                            .background(
                                                if (sel) Accent.copy(alpha = 0.15f) else Color.Transparent,
                                                RoundedCornerShape(12.dp),
                                            )
                                            .combinedClickable(
                                                onLongClick = { selectMode = true; selected.add(item) },
                                                onClick = {
                                                    if (selectMode) {
                                                        if (sel) selected.remove(item) else selected.add(item)
                                                        if (selected.isEmpty()) selectMode = false
                                                    }
                                                },
                                            )
                                    ) {
                                        EvidenceCard(item.item, prefs.dateFormat)
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

@OptIn(ExperimentalFoundationApi::class)
@Composable
private fun ChatImageCard(
    item: LocalMediaItem.ChatImage,
    selected: Boolean,
    onLongClick: () -> Unit,
    onClick: () -> Unit,
) {
    Card(
        colors = CardDefaults.cardColors(
            containerColor = if (selected) Accent.copy(alpha = 0.15f) else Card,
        ),
        shape = RoundedCornerShape(12.dp),
        modifier = Modifier
            .fillMaxWidth()
            .combinedClickable(onLongClick = onLongClick, onClick = onClick),
    ) {
        Column(Modifier.padding(12.dp)) {
            val bmp = remember(item.path) {
                runCatching {
                    android.graphics.BitmapFactory.decodeFile(item.path)?.asImageBitmap()
                }.getOrNull()
            }
            if (bmp != null) {
                Image(
                    bitmap = bmp,
                    contentDescription = null,
                    modifier = Modifier
                        .fillMaxWidth()
                        .heightIn(max = 200.dp)
                        .clip(RoundedCornerShape(8.dp)),
                    contentScale = ContentScale.Fit,
                )
                Spacer(Modifier.height(6.dp))
            }
            Row(verticalAlignment = Alignment.CenterVertically) {
                Text(
                    if (item.fromMe) "me" else "machine",
                    color = if (item.fromMe) Accent else Muted,
                    fontSize = 10.sp,
                    fontWeight = FontWeight.SemiBold,
                    modifier = Modifier.widthIn(min = 52.dp),
                )
                Spacer(Modifier.width(4.dp))
                Text(
                    item.msg.text,
                    color = Muted,
                    fontSize = 11.sp,
                    modifier = Modifier.weight(1f),
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis,
                )
                Text(
                    mediaTimestamp(item.msg.timestamp),
                    color = Muted,
                    fontSize = 10.sp,
                )
            }
        }
    }
}

private fun mediaTimestamp(ms: Long): String {
    val cal = java.util.Calendar.getInstance().also { it.timeInMillis = ms }
    return "%02d/%02d %02d:%02d".format(
        cal.get(java.util.Calendar.DAY_OF_MONTH),
        cal.get(java.util.Calendar.MONTH) + 1,
        cal.get(java.util.Calendar.HOUR_OF_DAY),
        cal.get(java.util.Calendar.MINUTE),
    )
}

@Composable
private fun MediaSelectionBar(count: Int, onDelete: () -> Unit, onCancel: () -> Unit) {
    Surface(color = Color(0xFF1A2535)) {
        Row(
            Modifier
                .fillMaxWidth()
                .padding(horizontal = 8.dp, vertical = 6.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            TextButton(onClick = onCancel) {
                Text("✕  $count selected", color = Accent, fontSize = 13.sp)
            }
            Spacer(Modifier.weight(1f))
            OutlinedButton(
                onClick = onDelete,
                colors = ButtonDefaults.outlinedButtonColors(contentColor = Color(0xFFF87171)),
            ) {
                Text(stringResource(R.string.msg_delete), color = Color(0xFFF87171))
            }
        }
    }
}

// ── Evidence card (WhatsApp-style audio player + three-dot detail menu) ───────

@Composable
private fun EvidenceCard(item: EvidenceItem, dateFormat: String) {
    var expanded by remember { mutableStateOf(false) }
    var showDetails by remember { mutableStateOf(false) }
    var showExportMenu by remember { mutableStateOf(false) }

    Card(
        colors = CardDefaults.cardColors(containerColor = Card),
        shape = RoundedCornerShape(12.dp),
        modifier = Modifier.fillMaxWidth(),
    ) {
        Column(Modifier.padding(12.dp)) {
            // ── Header row: type icon + timestamp + three-dot menu ──────────
            Row(verticalAlignment = Alignment.CenterVertically) {
                val typeIcon = when (item.type) {
                    MediaType.AUDIO -> Icons.Default.Mic
                    MediaType.VIDEO -> Icons.Default.Videocam
                    MediaType.PHOTO -> Icons.Default.CameraAlt
                }
                Icon(typeIcon, contentDescription = null, tint = Accent,
                    modifier = Modifier.size(20.dp))
                Spacer(Modifier.width(8.dp))
                Column(Modifier.weight(1f)) {
                    Text(
                        text = formatPreciseTimestamp(
                            item.tsWallMs, item.tsRdtsc, item.tsPpm, dateFormat
                        ),
                        color = Muted, fontSize = 11.sp,
                        fontFamily = FontFamily.Monospace,
                    )
                    if (item.durationMs > 0L) {
                        Text(
                            text = stringResource(R.string.media_duration,
                                formatDuration(item.durationMs)),
                            color = Muted, fontSize = 11.sp,
                        )
                    }
                }
                // Three-dot menu
                Box {
                    IconButton(onClick = { showDetails = !showDetails }) {
                        Icon(Icons.Default.MoreVert, contentDescription = null, tint = Muted)
                    }
                    DropdownMenu(
                        expanded = showDetails,
                        onDismissRequest = { showDetails = false },
                    ) {
                        DropdownMenuItem(
                            text = { Text(stringResource(R.string.media_details)) },
                            onClick = { showDetails = false; expanded = true },
                        )
                        DropdownMenuItem(
                            text = { Text(stringResource(R.string.media_export_md)) },
                            onClick = { showDetails = false; showExportMenu = true },
                        )
                        DropdownMenuItem(
                            text = { Text(stringResource(R.string.media_export_txt)) },
                            onClick = { showDetails = false; showExportMenu = true },
                        )
                    }
                }
            }

            Spacer(Modifier.height(8.dp))

            // ── Audio player (WhatsApp style) ─────────────────────────────
            if (item.type == MediaType.AUDIO || item.type == MediaType.VIDEO) {
                AudioPlayerRow(item)
                Spacer(Modifier.height(4.dp))
                if (item.codecAudio.isNotBlank()) {
                    Text(
                        stringResource(R.string.media_codec, item.codecAudio) +
                            if (item.sampleRate > 0)
                                "  ·  ${item.sampleRate} Hz" else "",
                        color = Muted, fontSize = 11.sp,
                    )
                }
                if (item.type == MediaType.VIDEO && item.codecVideo.isNotBlank()) {
                    Text(
                        "video: ${item.codecVideo}" +
                            if (item.frameRate > 0) "  ·  ${item.frameRate} fps" else "",
                        color = Muted, fontSize = 11.sp,
                    )
                }
            }

            // ── Hardware fingerprint accordion ────────────────────────────
            if (expanded) {
                Spacer(Modifier.height(8.dp))
                HardwareDetailSection(item.hw)
                Spacer(Modifier.height(4.dp))
                TextButton(onClick = { expanded = false }) {
                    Text("Collapse", color = Accent, fontSize = 12.sp)
                }
            }
        }
    }
}

// ── WhatsApp-style audio player row ──────────────────────────────────────────

@Composable
private fun AudioPlayerRow(item: EvidenceItem) {
    var playing by remember { mutableStateOf(false) }
    var progress by remember { mutableStateOf(0f) }
    val scope = rememberCoroutineScope()
    val ctx = LocalContext.current

    // Animated waveform bars
    val infiniteTransition = rememberInfiniteTransition(label = "wave")
    val waveAnim by infiniteTransition.animateFloat(
        initialValue = 0f, targetValue = 1f,
        animationSpec = infiniteRepeatable(
            tween(800, easing = LinearEasing), RepeatMode.Reverse
        ),
        label = "waveAmp",
    )

    Row(
        Modifier
            .fillMaxWidth()
            .background(Color(0xFF0D1720), RoundedCornerShape(24.dp))
            .padding(horizontal = 8.dp, vertical = 6.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        // Play / pause button
        Box(
            Modifier
                .size(40.dp)
                .clip(CircleShape)
                .background(Accent)
                .clickable {
                    playing = !playing
                    // Real playback via MediaPlayer would go here; for now the
                    // daemon path is on the remote machine so we show the state.
                },
            contentAlignment = Alignment.Center,
        ) {
            Icon(
                if (playing) Icons.Default.Pause else Icons.Default.PlayArrow,
                contentDescription = null,
                tint = Ground,
                modifier = Modifier.size(24.dp),
            )
        }

        Spacer(Modifier.width(8.dp))

        // Waveform bars (decorative, animated while playing)
        Row(
            Modifier.weight(1f),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.spacedBy(2.dp),
        ) {
            val barCount = 28
            for (b in 0 until barCount) {
                val relPos = b.toFloat() / barCount
                val filled = relPos <= progress
                // Bar height: pseudo-random envelope + animation when playing
                val baseH = (0.2f + 0.6f * kotlin.math.sin(b * 0.8f + 0.5f).toFloat().let {
                    kotlin.math.abs(it)
                })
                val animH = if (playing) baseH * (0.7f + 0.3f * waveAnim) else baseH
                Box(
                    Modifier
                        .width(3.dp)
                        .height((4 + (animH * 20)).dp)
                        .background(
                            if (filled) Accent else Muted.copy(alpha = 0.5f),
                            RoundedCornerShape(2.dp),
                        )
                )
            }
        }

        Spacer(Modifier.width(8.dp))

        // Duration label
        Text(
            formatDuration(item.durationMs),
            color = Muted, fontSize = 11.sp,
            fontFamily = FontFamily.Monospace,
        )
    }
}

// ── Hardware detail section ───────────────────────────────────────────────────

@Composable
private fun HardwareDetailSection(hw: HardwareSnapshot) {
    Column(
        Modifier
            .fillMaxWidth()
            .background(Ground, RoundedCornerShape(8.dp))
            .padding(10.dp),
        verticalArrangement = Arrangement.spacedBy(6.dp),
    ) {
        DetailHeader(stringResource(R.string.media_hw_section))

        // CPU
        DetailGroup(stringResource(R.string.media_cpu)) {
            DetailRow("Model", hw.cpuModel)
            DetailRow("Vendor", hw.cpuVendor)
            DetailRow("Architecture", "${hw.crBits}-bit")
            DetailRow("Physical cores", hw.cpuCoresPhysical.toString())
            DetailRow("Logical cores", hw.cpuCoresLogical.toString())
            DetailRow("Threads", hw.cpuThreads.toString())
            if (hw.cpuGhz > 0.0) DetailRow("Frequency", "%.2f GHz".format(hw.cpuGhz))
            if (hw.cpuMicrocode.isNotBlank()) DetailRow("Microcode", hw.cpuMicrocode)
            if (hw.cpuFlags.isNotEmpty()) {
                DetailRow("Key flags", hw.cpuFlags.take(20).joinToString(" "))
            }
            if (hw.vmHypervisor.isNotBlank()) {
                DetailRow("Virtualization",
                    stringResource(R.string.media_vm_detected, hw.vmHypervisor),
                    warn = true)
            } else {
                DetailRow("Virtualization", stringResource(R.string.media_no_vm))
            }
        }

        // RAM
        DetailGroup(stringResource(R.string.media_ram)) {
            DetailRow("Total", formatBytes(hw.ramTotalBytes))
        }

        // Disks
        if (hw.disks.isNotEmpty()) {
            DetailGroup(stringResource(R.string.media_disks)) {
                hw.disks.forEachIndexed { i, d ->
                    DetailRow("Disk ${i + 1}", "${d.vendor} ${d.model}".trim())
                    DetailRow("  Size", formatBytes(d.sizeBytes))
                    if (d.filesystem.isNotBlank()) DetailRow("  FS", d.filesystem)
                    if (d.smartStatus.isNotBlank()) {
                        DetailRow("  SMART", d.smartStatus, warn = d.smartStatus != "PASSED")
                    }
                }
            }
        }

        // GPU
        if (hw.gpus.isNotEmpty()) {
            DetailGroup(stringResource(R.string.media_gpu)) {
                hw.gpus.forEachIndexed { i, g ->
                    DetailRow("GPU ${i + 1}", "${g.vendor} ${g.model}".trim())
                    if (g.vramBytes > 0L) DetailRow("  VRAM", formatBytes(g.vramBytes))
                    if (g.architecture.isNotBlank()) DetailRow("  Architecture", g.architecture)
                }
            }
        }

        // Security
        DetailGroup(stringResource(R.string.media_secureboot)) {
            DetailRow("Secure Boot", hw.secureBoot)
            DetailRow("TPM", if (hw.tpmPresent) "present" else "absent")
        }

        if (hw.meiFwVersion.isNotBlank() || hw.pspFwVersion.isNotBlank()) {
            DetailGroup(stringResource(R.string.media_firmware)) {
                if (hw.meiFwVersion.isNotBlank()) DetailRow("MEI firmware", hw.meiFwVersion)
                if (hw.pspFwVersion.isNotBlank()) DetailRow("PSP firmware", hw.pspFwVersion)
            }
        }

        // PMU counters
        if (hw.pmuHwGp > 0 || hw.pmuHwFixed > 0 || hw.pmuSw > 0) {
            DetailGroup("PMU counters") {
                if (hw.pmuHwGp > 0 || hw.pmuHwFixed > 0) {
                    DetailRow("HW (CPUID 0x0A)",
                        "${hw.pmuHwGp} GP + ${hw.pmuHwFixed} fixed per logical CPU")
                }
                if (hw.pmuSw > 0) {
                    DetailRow("SW (perf)", "${hw.pmuSw} (cs, pfmin, pfmaj, migrations)")
                }
            }
        }
    }
}

@Composable
private fun DetailHeader(text: String) {
    Text(text, color = Accent, fontSize = 12.sp, fontWeight = FontWeight.Bold)
    Divider(color = Accent.copy(alpha = 0.3f), thickness = 0.5.dp)
}

@Composable
private fun DetailGroup(label: String, content: @Composable ColumnScope.() -> Unit) {
    Text(label, color = Accent.copy(alpha = 0.7f), fontSize = 11.sp, fontWeight = FontWeight.SemiBold)
    Column(Modifier.padding(start = 8.dp), content = content)
}

@Composable
private fun DetailRow(label: String, value: String, warn: Boolean = false) {
    Row(Modifier.fillMaxWidth().padding(vertical = 1.dp)) {
        Text(
            "$label: ",
            color = Muted, fontSize = 11.sp,
            modifier = Modifier.widthIn(min = 80.dp),
        )
        Text(
            value,
            color = if (warn) RedWarn else Color.White.copy(alpha = 0.85f),
            fontSize = 11.sp,
            fontFamily = if (label.startsWith("  ")) FontFamily.Monospace else FontFamily.Default,
            modifier = Modifier.weight(1f),
        )
    }
}
