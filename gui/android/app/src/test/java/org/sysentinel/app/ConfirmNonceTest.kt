// SPDX-License-Identifier: Apache-2.0
package org.sysentinel.app

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

/**
 * Finding the armed order's code in what the daemon sent.
 *
 * This is what lets the app offer a fingerprint instead of asking the owner to
 * type the code back, so it has to find a real one and — more importantly —
 * must not invent one out of ordinary conversation, which would put a
 * "confirm" button in front of somebody with nothing armed behind it.
 */
class ConfirmNonceTest {

    @Test
    fun `finds the code in the daemon's armed notice`() {
        val armed = """
            ⚠️ *Control armed:* `reboot (kernel_restart)`
            This is a privileged, irreversible action. To execute, reply exactly:

            `CONFIRM-7K4M2Q`

            It expires in 60 s — just ignore this message to cancel it.
        """.trimIndent()
        assertEquals("CONFIRM-7K4M2Q", confirmNonceIn(armed))
        assertEquals("reboot (kernel_restart)", orderLabelFrom(armed))
    }

    @Test
    fun `ordinary messages carry no order`() {
        assertNull(confirmNonceIn("Todo tranquilo por aquí."))
        assertNull(confirmNonceIn("la palabra confirm no basta"))
        // Lowercase is not the daemon's format; the alphabet is fixed.
        assertNull(confirmNonceIn("confirm-7k4m2q"))
        assertNull(confirmNonceIn(""))
    }

    @Test
    fun `a label is always something a person can read`() {
        // No marker: fall back to the first line rather than an empty prompt,
        // because the prompt naming the order is the point of it.
        assertEquals("Se cayó la red", orderLabelFrom("Se cayó la red\nsegunda línea"))
        assertEquals("la orden armada", orderLabelFrom(""))
    }
}
