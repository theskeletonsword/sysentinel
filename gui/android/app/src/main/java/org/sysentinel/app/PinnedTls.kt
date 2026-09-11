// SPDX-License-Identifier: Apache-2.0
package org.sysentinel.app

import android.os.Build
import android.util.Log
import java.net.Socket
import java.security.MessageDigest
import java.security.cert.CertificateException
import java.security.cert.X509Certificate
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLSocket
import javax.net.ssl.X509TrustManager

/**
 * TLS 1.3 to the machine, trusting exactly one public key.
 *
 * # Why a pin and not a certificate authority
 *
 * The daemon answers on a LAN address, a VPN address or a tunnel. No public CA
 * will ever certify any of those, so it signs its own certificate — and a
 * self-signed certificate validated the normal way proves nothing at all.
 *
 * What it is validated against instead is the SHA-256 of its public key, which
 * the machine printed in the pairing QR and this handset wrote down at pairing
 * time. That is a stronger introduction than a name signed by one of the
 * hundred-odd authorities in the system store: nobody but that machine holds
 * the private half, and no authority can be persuaded to issue for it.
 *
 * The name is therefore not checked, deliberately. It would be checking the
 * wrong thing — the address changes when the owner travels, and the key does
 * not.
 *
 * # Why the sealed frames stay inside this
 *
 * TLS proves the *machine* to this phone and makes the conversation private
 * and forward-secret. It says nothing about which phone is calling. That is
 * what the pairing key and the device signature answer, one layer up, and they
 * keep doing it inside the tunnel.
 */
object PinnedTls {

    private const val TAG = "sysentinel"

    /**
     * Wrap a connected socket in TLS, refusing anything but the pinned key.
     *
     * @param pin the `sha256/…` fingerprint from the pairing QR.
     */
    fun wrap(plain: Socket, host: String, port: Int, pin: String): SSLSocket {
        val ctx = SSLContext.getInstance("TLS")
        ctx.init(null, arrayOf(PinnedTrustManager(pin)), java.security.SecureRandom())
        val socket = ctx.socketFactory.createSocket(plain, host, port, true) as SSLSocket

        // TLS 1.3 where the platform has it. Android 10 (API 29) enables it by
        // default; older handsets top out at 1.2, and the legacy flavour of
        // this app deliberately supports them. Asking for a protocol the
        // platform does not implement throws, so the list is filtered to what
        // this device actually offers — and 1.2 is a floor, never an offer of
        // anything older.
        val wanted = listOf("TLSv1.3", "TLSv1.2")
        val available = socket.supportedProtocols.toSet()
        val enabled = wanted.filter { it in available }
        if (enabled.isEmpty()) {
            throw PhoneLinkException(
                "Este teléfono no ofrece TLS 1.2 ni 1.3. Es demasiado viejo para " +
                    "hablar con el equipo de forma segura."
            )
        }
        socket.enabledProtocols = enabled.toTypedArray()

        socket.startHandshake()
        val negotiated = socket.session.protocol
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q && negotiated != "TLSv1.3") {
            // Not fatal — 1.2 with a pinned key is still sound — but a handset
            // that *can* do 1.3 and did not is worth a line in the log.
            Log.w(TAG, "negotiated $negotiated on a device that supports 1.3")
        }
        Log.i(TAG, "TLS $negotiated with ${socket.session.cipherSuite}")
        return socket
    }

    /** `sha256/<base64 of the SPKI>`, the same string the daemon prints. */
    fun pinOf(cert: X509Certificate): String {
        val spki = cert.publicKey.encoded
        val digest = MessageDigest.getInstance("SHA-256").digest(spki)
        return "sha256/" + android.util.Base64.encodeToString(
            digest, android.util.Base64.NO_WRAP,
        )
    }

    /**
     * Trusts one key. Not a relaxed trust manager — a narrower one.
     *
     * Every method that could accept something else refuses: there is no
     * client-certificate path, no accepted-issuers list, and no branch that
     * falls back to the system store.
     */
    private class PinnedTrustManager(private val pin: String) : X509TrustManager {

        override fun checkServerTrusted(chain: Array<out X509Certificate>?, authType: String?) {
            val leaf = chain?.firstOrNull()
                ?: throw CertificateException("el equipo no presentó certificado")
            val seen = pinOf(leaf)
            if (seen != pin) {
                throw CertificateException(
                    "La llave del equipo no es la que guardaste al emparejar.\n\n" +
                        "Esperaba $pin\ny llegó $seen.\n\n" +
                        "O reinstalaron el daemon (y hay que volver a emparejar), o " +
                        "alguien está respondiendo en su lugar."
                )
            }
        }

        override fun checkClientTrusted(chain: Array<out X509Certificate>?, authType: String?) {
            // This side never acts as a server.
            throw CertificateException("no soy un servidor")
        }

        override fun getAcceptedIssuers(): Array<X509Certificate> = emptyArray()
    }
}
