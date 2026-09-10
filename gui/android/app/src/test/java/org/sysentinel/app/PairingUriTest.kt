// SPDX-License-Identifier: Apache-2.0
package org.sysentinel.app

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

class PairingUriTest {

    private val key = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"

    @Test
    fun `parses what the daemon draws`() {
        val p = PairingUri.parse("sysentinel://pair?addr=10.0.0.5:8443&key=$key")!!
        assertEquals("10.0.0.5", p.host)
        assertEquals(8443, p.port)
        assertEquals(key, p.keyHex)
    }

    @Test
    fun `an ipv6 literal keeps its colons`() {
        // Splitting on the first colon would turn "[::1]:8443" into host "["
        // and a port that does not parse.
        val p = PairingUri.parse("sysentinel://pair?addr=[fd00::1]:8443&key=$key")!!
        assertEquals("fd00::1", p.host)
        assertEquals(8443, p.port)
    }

    @Test
    fun `a listen address is refused rather than half-working`() {
        // 0.0.0.0 is where the daemon listens, not somewhere to dial. Accepting
        // it would produce an app that pairs and then never connects.
        assertNull(PairingUri.parse("sysentinel://pair?addr=0.0.0.0:8443&key=$key"))
        assertNull(PairingUri.parse("sysentinel://pair?addr=[::]:8443&key=$key"))
    }

    @Test
    fun `anything malformed is null, never an exception`() {
        // This runs inside a camera callback: a throw there is a crash on scan.
        assertNull(PairingUri.parse(""))
        assertNull(PairingUri.parse("https://example.com"))
        assertNull(PairingUri.parse("sysentinel://pair?addr=10.0.0.5:8443"))
        assertNull(PairingUri.parse("sysentinel://pair?key=$key"))
        assertNull(PairingUri.parse("sysentinel://pair?addr=10.0.0.5&key=$key"))
        assertNull(PairingUri.parse("sysentinel://pair?addr=10.0.0.5:99999&key=$key"))
        assertNull(PairingUri.parse("sysentinel://pair?addr=10.0.0.5:8443&key=corta"))
        assertNull(PairingUri.parse("sysentinel://pair?addr=10.0.0.5:0&key=$key"))
    }
}
