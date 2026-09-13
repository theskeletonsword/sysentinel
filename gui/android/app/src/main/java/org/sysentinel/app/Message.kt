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
)
