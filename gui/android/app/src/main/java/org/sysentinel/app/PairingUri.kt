// SPDX-License-Identifier: Apache-2.0
package org.sysentinel.app

/**
 * The `sysentinel://pair?addr=…&key=…&cert=…` URI the daemon draws as a QR.
 *
 * Parsed by hand rather than with `Uri.parse` so it can be unit-tested off a
 * device, and so a malformed scan is a `null` rather than an exception thrown
 * from inside a camera callback.
 */
data class PairingUri(
    val host: String,
    val port: Int,
    val keyHex: String,
    /**
     * SHA-256 of the machine's TLS public key, as `sha256/…`.
     *
     * Required. A QR without it is from a daemon that predates TLS on this
     * channel, and accepting one would mean connecting with no way to tell
     * whether the thing answering is the machine — see [PinnedTls].
     */
    val certPin: String,
) {

    companion object {
        private const val SCHEME = "sysentinel://pair?"

        /** Undo the percent-encoding the daemon applies to the pin. */
        private fun percentDecode(s: String): String {
            if (!s.contains('%')) return s
            val out = StringBuilder(s.length)
            var i = 0
            while (i < s.length) {
                val c = s[i]
                if (c == '%' && i + 2 < s.length) {
                    val hex = s.substring(i + 1, i + 3).toIntOrNull(16)
                    if (hex != null) {
                        out.append(hex.toChar())
                        i += 3
                        continue
                    }
                }
                out.append(c)
                i++
            }
            return out.toString()
        }

        /** `null` when this is not one of ours, or is missing something. */
        fun parse(raw: String): PairingUri? {
            val text = raw.trim()
            if (!text.startsWith(SCHEME)) return null

            val params = text.removePrefix(SCHEME)
                .split("&")
                .mapNotNull { part ->
                    val i = part.indexOf('=')
                    if (i <= 0) null else part.substring(0, i) to part.substring(i + 1)
                }
                .toMap()

            val addr = params["addr"]?.trim().orEmpty()
            val key = params["key"]?.trim().orEmpty()
            val cert = percentDecode(params["cert"]?.trim().orEmpty())
            if (addr.isEmpty()) return null
            if (PhoneLink.parseKey(key) == null) return null
            // `sha256/` plus base64 of a 32-byte digest: 44 characters with
            // padding. Checked here so a truncated scan fails at the QR rather
            // than at the handshake, where the message is less useful.
            if (!cert.startsWith("sha256/") || cert.length != "sha256/".length + 44) {
                return null
            }

            // Split host:port from the right, so an IPv6 literal in brackets
            // survives — "[::1]:8443" must not split on its first colon.
            val sep = addr.lastIndexOf(':')
            if (sep <= 0 || sep == addr.length - 1) return null
            val host = addr.substring(0, sep).removeSurrounding("[", "]")
            val port = addr.substring(sep + 1).toIntOrNull() ?: return null
            if (host.isEmpty() || port !in 1..65535) return null

            // A listen address is not somewhere to dial. The daemon warns about
            // this on its side too, but a QR made before that warning existed
            // should not silently produce an app that cannot connect.
            if (host == "0.0.0.0" || host == "::") return null

            return PairingUri(host, port, key, cert)
        }
    }
}
