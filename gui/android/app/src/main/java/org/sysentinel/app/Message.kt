// SPDX-License-Identifier: Apache-2.0
package org.sysentinel.app

/** One line of the conversation with the machine. */
data class Message(
    val text: String,
    val fromMe: Boolean,
    val timestamp: Long = System.currentTimeMillis(),
    /**
     * The armed order's nonce, when this message is asking to have one
     * confirmed. The reply is a fingerprint, not the code typed back — see
     * [Confirmation] — so the nonce is carried here rather than left for the
     * reader to copy off the screen, which is the habit this exists to end.
     */
    val confirmNonce: String? = null,
    /** The daemon's queue id, so receipt can be acknowledged. Zero for local. */
    val serverId: Long = 0L,
    /** Evidence the daemon attached, as a path on the watched machine. */
    val photoPath: String? = null,
    /**
     * The same evidence, already recompressed and base64-encoded by the daemon
     * so the phone can actually render it. Consumed by [materializePhoto] on
     * arrival and dropped once decoded — never persisted in that form.
     */
    val photoBase64: String? = null,
    /**
     * Path to a locally-saved image file (in app's private storage).
     * Set when the user sends an image — the compressed JPEG is written to
     * filesDir/sysentinel_media/ so it can be displayed inline in the chat
     * bubble and listed in the Multimedia screen.
     */
    val localMediaPath: String? = null,
)

/**
 * Turn the daemon's base64 evidence photo into a decodable file on this
 * handset, so the chat renders it inline exactly like a user-picked image.
 *
 * Safe on any thread a [Message] arrives on (the background fetch loop or the
 * foreground drain): the file lands in the same app-private directory as
 * user-picked media, so history persistence and inline rendering need nothing
 * new. On any failure the message comes back unchanged — an undecodable image
 * must cost the attachment, never the caption it rides on.
 */
fun materializePhoto(ctx: android.content.Context, m: Message): Message {
    val b64 = m.photoBase64 ?: return m
    val bytes = runCatching {
        android.util.Base64.decode(b64, android.util.Base64.DEFAULT)
    }.getOrNull() ?: return m
    return runCatching {
        val dir = java.io.File(ctx.filesDir, "sysentinel_media").apply { mkdirs() }
        val file = java.io.File(dir, "incoming_${System.currentTimeMillis()}.jpg")
        file.writeBytes(bytes)
        m.copy(localMediaPath = file.absolutePath, photoBase64 = null)
    }.getOrElse { m }
}
