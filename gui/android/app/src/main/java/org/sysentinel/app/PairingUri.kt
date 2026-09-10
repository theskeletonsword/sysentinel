// SPDX-License-Identifier: Apache-2.0
package org.sysentinel.app

/**
 * The `sysentinel://pair?addr=…&key=…` URI the daemon draws as a QR.
 *
 * Parsed by hand rather than with `Uri.parse` so it can be unit-tested off a
 * device, and so a malformed scan is a `null` rather than an exception thrown
 * from inside a camera callback.
 */
data class PairingUri(val host: String, val port: Int, val keyHex: String) {

    companion object {
        private const val SCHEME = "sysentinel://pair?"

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
            if (addr.isEmpty()) return null
            if (PhoneLink.parseKey(key) == null) return null

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

            return PairingUri(host, port, key)
        }
    }
}
