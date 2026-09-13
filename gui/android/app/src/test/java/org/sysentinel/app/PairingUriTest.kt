// SPDX-License-Identifier: Apache-2.0
package org.sysentinel.app

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

class PairingUriTest {

    private val key = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"

    /** A pin the daemon would print: sha256 + base64 of 32 bytes. */
    private val pin = "sha256/" + "A".repeat(43) + "="
    private val encodedPin = "sha256%2F" + "A".repeat(43) + "%3D"

    @Test
    fun `parses what the daemon draws`() {
        val p = PairingUri.parse(
            "sysentinel://pair?addr=10.0.0.5:8443&key=$key&cert=$encodedPin"
        )!!
        assertEquals("10.0.0.5", p.host)
        assertEquals(8443, p.port)
        assertEquals(key, p.keyHex)
        // The pin is percent-encoded on the wire — '/' and '=' would otherwise
        // end the parameter — and has to come back exactly as the daemon
        // computed it, or the handshake compares two different strings.
        assertEquals(pin, p.certPin)
    }

    @Test
    fun `a QR with no certificate pin is refused`() {
        // That QR comes from a daemon older than TLS on this channel.
        // Accepting it would mean connecting with no way to tell whether the
        // thing answering is the machine — a silent downgrade, which is how a
        // security property disappears.
        assertNull(PairingUri.parse("sysentinel://pair?addr=10.0.0.5:8443&key=$key"))
        // And a truncated scan is caught here rather than at the handshake,
        // where the error would be less useful.
        assertNull(
            PairingUri.parse("sysentinel://pair?addr=10.0.0.5:8443&key=$key&cert=sha256%2FAAA")
        )
        assertNull(
            PairingUri.parse("sysentinel://pair?addr=10.0.0.5:8443&key=$key&cert=nonsense")
        )
    }

    @Test
    fun `an ipv6 literal keeps its colons`() {
        // Splitting on the first colon would turn "[::1]:8443" into host "["
        // and a port that does not parse.
        val p = PairingUri.parse(
            "sysentinel://pair?addr=[fd00::1]:8443&key=$key&cert=$encodedPin"
        )!!
        assertEquals("fd00::1", p.host)
        assertEquals(8443, p.port)
    }

    @Test
    fun `a listen address is refused rather than half-working`() {
        // 0.0.0.0 is where the daemon listens, not somewhere to dial. Accepting
        // it would produce an app that pairs and then never connects.
        assertNull(PairingUri.parse("sysentinel://pair?addr=0.0.0.0:8443&key=$key&cert=$encodedPin"))
        assertNull(PairingUri.parse("sysentinel://pair?addr=[::]:8443&key=$key&cert=$encodedPin"))
    }

    @Test
    fun `anything malformed is null, never an exception`() {
        // This runs inside a camera callback: a throw there is a crash on scan.
        assertNull(PairingUri.parse(""))
        assertNull(PairingUri.parse("https://example.com"))
        assertNull(PairingUri.parse("sysentinel://pair?addr=10.0.0.5:8443&cert=$encodedPin"))
        assertNull(PairingUri.parse("sysentinel://pair?key=$key&cert=$encodedPin"))
        assertNull(PairingUri.parse("sysentinel://pair?addr=10.0.0.5&key=$key&cert=$encodedPin"))
        assertNull(PairingUri.parse("sysentinel://pair?addr=10.0.0.5:99999&key=$key&cert=$encodedPin"))
        assertNull(PairingUri.parse("sysentinel://pair?addr=10.0.0.5:8443&key=corta&cert=$encodedPin"))
        assertNull(PairingUri.parse("sysentinel://pair?addr=10.0.0.5:0&key=$key&cert=$encodedPin"))
    }
}
