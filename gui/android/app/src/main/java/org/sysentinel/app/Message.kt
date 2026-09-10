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
)
