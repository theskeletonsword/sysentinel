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
    fun wrap(
        ctx: android.content.Context,
        plain: Socket,
        host: String,
        port: Int,
        pin: String,
    ): SSLSocket {
        val ssl = SSLContext.getInstance("TLS")
        ssl.init(null, arrayOf(PinnedTrustManager(ctx, pin)), java.security.SecureRandom())
        val socket = ssl.socketFactory.createSocket(plain, host, port, true) as SSLSocket

        // TLS 1.3 ONLY. Not "1.3 preferred": TLS 1.2 sends the server's
        // certificate in the clear during the handshake, so a passive observer
        // on the path learns that this is a sysentinel machine and sees its
        // pinned key — exactly the information this design works to not reveal.
        // TLS 1.3 encrypts the certificate, so an attacker watching the wire
        // learns only that two endpoints spoke. The daemon already refuses
        // anything but 1.3, so offering 1.2 here never bought a connection — it
        // only widened what a watcher could see on the attempt.
        //
        // The cost is honest: a handset with no TLS 1.3 (Android's default
        // provider gains it at API 29) cannot talk to the daemon at all, and is
        // told so rather than downgraded into leaking.
        if ("TLSv1.3" !in socket.supportedProtocols.toSet()) {
            throw PhoneLinkException(ctx.getString(R.string.err_tls_too_old))
        }
        socket.enabledProtocols = arrayOf("TLSv1.3")

        socket.startHandshake()
        val negotiated = socket.session.protocol
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
    private class PinnedTrustManager(
        private val ctx: android.content.Context,
        private val pin: String,
    ) : X509TrustManager {

        override fun checkServerTrusted(chain: Array<out X509Certificate>?, authType: String?) {
            val leaf = chain?.firstOrNull()
                ?: throw CertificateException(ctx.getString(R.string.err_no_cert))
            val seen = pinOf(leaf)
            if (seen != pin) {
                throw CertificateException(
                    ctx.getString(R.string.err_pin_mismatch, pin, seen)
                )
            }
        }

        override fun checkClientTrusted(chain: Array<out X509Certificate>?, authType: String?) {
            // This side never acts as a server.
            throw CertificateException("this side is never a server")
        }

        override fun getAcceptedIssuers(): Array<X509Certificate> = emptyArray()
    }
}
