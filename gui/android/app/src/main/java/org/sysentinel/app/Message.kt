// SPDX-License-Identifier: Apache-2.0
package org.sysentinel.app

/** One line of the conversation with the machine. */
data class Message(
    val text: String,
    val fromMe: Boolean,
    val timestamp: Long = System.currentTimeMillis(),
    /**
     * Set when this message is asking for a confirmation. The reply is a
     * fingerprint, not a typed code — see [DeviceIdentity].
     */
    val awaitingConfirmation: Boolean = false,
    /** The daemon's queue id, so receipt can be acknowledged. Zero for local. */
    val serverId: Long = 0L,
    /** Evidence the daemon attached, as a path on the watched machine. */
    val photoPath: String? = null,
)
