// SPDX-License-Identifier: Apache-2.0
package org.sysentinel.app

import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Log
import java.io.File
import java.security.KeyStore
import java.security.KeyPairGenerator
import java.security.PrivateKey
import java.security.Signature
import java.security.spec.ECGenParameterSpec
import javax.crypto.KeyGenerator

/**
 * The phone's half of "prove it is really you".
 *
 * The daemon already knows a machine by its TPM-sealed fingerprint. This is the
 * same idea on the other end of the conversation: a key the phone holds, that
 * its owner has to be physically present to use, so a confirmation cannot be
 * produced by somebody who merely knows a code.
 *
 * # Why a code was not good enough
 *
 * The desktop currently confirms destructive operations with a typed
 * `CONFIRM-XXXXXX`. That is fine as a floor and weak as a ceiling: it can be
 * read over a shoulder, and it can be demanded out loud by whoever is standing
 * there. Once spoken, anyone can type it. A key released by a fingerprint
 * cannot travel that way.
 *
 * # The ladder, and why claiming is not proving
 *
 * Three rungs, best first, mirroring `daemon/src/confirm.rs`:
 *
 *  - **StrongBox** — a discrete secure element (Titan M on Pixels). API 28+,
 *    and not every device has one even then.
 *  - **TEE** — a key inside ARM TrustZone. The common case on modern handsets.
 *  - **Software** — an ordinary key. Better than nothing, proves little.
 *
 * What this class reports is what it *asked for* and what the platform said it
 * got. That is still only the phone talking about itself, which is worth
 * nothing to a daemon on its own — whoever controls the handset controls what
 * it says. The proof is the attestation chain in [attestationChain], which the
 * secure element signs and the daemon verifies. Until that is checked, the
 * daemon downgrades the claim; see `ConfirmMethod::proven`.
 */
object DeviceIdentity {

    private const val TAG = "sysentinel"
    private const val KEY_ALIAS = "sysentinel-owner-key"
    private const val KEYSTORE = "AndroidKeyStore"

    /** What actually backed the key, as the platform reported it. */
    enum class Backing { STRONGBOX, TEE, SOFTWARE, NONE }

    data class Identity(
        val backing: Backing,
        /** True when using the key requires a fresh biometric. */
        val biometricBound: Boolean,
        /** AEAD chosen for payloads, from what the CPU can do quickly. */
        val aead: Aead,
        /** Certificate chain proving the above, for the daemon to verify. */
        val attestationChain: List<ByteArray>,
    ) {
        /** The string the daemon's ladder expects. */
        fun claimedMethod(): String = when {
            backing == Backing.STRONGBOX && biometricBound -> "strong_box"
            backing == Backing.TEE && biometricBound -> "tee"
            backing != Backing.SOFTWARE && backing != Backing.NONE -> "device_credential"
            else -> "software_key"
        }
    }

    /**
     * Payload cipher.
     *
     * The same rule the daemon applies on x86 in `tpmkey.rs`, moved to ARM:
     * hardware AES where the CPU has it, ChaCha20-Poly1305 where it does not.
     *
     * Note this is about *payloads*, not the Keystore key itself — the Android
     * Keystore offers AES and RSA, not ChaCha, so on a CPU without the crypto
     * extensions the ChaCha key is one the Keystore key wraps rather than one
     * the Keystore holds. Saying otherwise would be claiming hardware backing
     * this does not have.
     */
    enum class Aead { AES_256_GCM, CHACHA20_POLY1305 }

    /**
     * Whether this CPU has the ARMv8 crypto extensions, read from
     * `/proc/cpuinfo`. Without them AES is a software routine and ChaCha is
     * both faster and easier to keep constant-time — which is the case it was
     * designed for, and the usual one on `armeabi-v7a`.
     */
    fun hasArmAes(): Boolean = try {
        File("/proc/cpuinfo").readLines().any { line ->
            line.startsWith("Features") && line.split(Regex("\\s+")).contains("aes")
        }
    } catch (e: Exception) {
        Log.w(TAG, "cannot read /proc/cpuinfo: ${e.message}")
        false
    }

    fun preferredAead(): Aead =
        if (hasArmAes()) Aead.AES_256_GCM else Aead.CHACHA20_POLY1305

    /**
     * Create or load the owner key, taking the strongest backing this handset
     * will actually give.
     *
     * StrongBox is requested first and its absence is not an error: most
     * devices do not have one, and falling back is the normal path rather than
     * a failure. Each fall is logged, so a device that quietly lost StrongBox
     * after an update does not look the same as one that never had it.
     */
    fun ensureKey(requireBiometric: Boolean = true): Identity {
        val aead = preferredAead()

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            tryGenerate(strongBox = true, requireBiometric = requireBiometric)?.let {
                return Identity(Backing.STRONGBOX, requireBiometric, aead, it)
            }
            Log.i(TAG, "no StrongBox on this device — falling back to the TEE")
        }

        tryGenerate(strongBox = false, requireBiometric = requireBiometric)?.let {
            return Identity(Backing.TEE, requireBiometric, aead, it)
        }

        // A key that needs a biometric is useless on a phone with none enrolled;
        // retry without that requirement rather than leaving the owner unable
        // to answer at all.
        Log.w(TAG, "hardware key with biometric binding failed — retrying unbound")
        tryGenerate(strongBox = false, requireBiometric = false)?.let {
            return Identity(Backing.TEE, false, aead, it)
        }

        Log.e(TAG, "no hardware-backed key available on this device")
        return Identity(Backing.SOFTWARE, false, aead, emptyList())
    }

    /**
     * Generate a key with the requested properties, returning its attestation
     * chain, or `null` when the platform refuses.
     */
    private fun tryGenerate(strongBox: Boolean, requireBiometric: Boolean): List<ByteArray>? {
        return try {
            val alias = KEY_ALIAS + if (strongBox) "-sb" else ""
            val gen = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, KEYSTORE)
            val spec = KeyGenParameterSpec.Builder(
                alias,
                KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT,
            )
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setKeySize(256)
                .apply {
                    // The challenge is what makes the attestation about *this*
                    // exchange rather than a chain the phone could have kept
                    // from any earlier one.
                    setAttestationChallenge(freshChallenge())
                    if (requireBiometric) {
                        setUserAuthenticationRequired(true)
                        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                            setUserAuthenticationParameters(
                                0, // every use needs a fresh authentication
                                KeyProperties.AUTH_BIOMETRIC_STRONG,
                            )
                        } else {
                            @Suppress("DEPRECATION")
                            setUserAuthenticationValidityDurationSeconds(-1)
                        }
                    }
                    if (strongBox && Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                        setIsStrongBoxBacked(true)
                    }
                }
                .build()
            gen.init(spec)
            gen.generateKey()

            val ks = KeyStore.getInstance(KEYSTORE).apply { load(null) }
            val chain = ks.getCertificateChain(alias) ?: return emptyList()
            chain.map { it.encoded }
        } catch (e: Exception) {
            Log.i(TAG, "key generation refused (strongBox=$strongBox): ${e.message}")
            null
        }
    }

    /** Random per-exchange challenge, so an attestation cannot be replayed. */
    private fun freshChallenge(): ByteArray =
        ByteArray(32).also { java.security.SecureRandom().nextBytes(it) }

    // ── The device key: "this handset", not "a handset like it" ──────────────
    //
    // The daemon binds a PC by things that are per-unit — board and chassis
    // serials, the ring -3 silicon contract. Almost nothing a phone reports
    // about itself is per-unit: two Pixel 8s agree on MODEL, MANUFACTURER,
    // BOARD and the build fingerprint, and Android deliberately stopped handing
    // out per-device identifiers years ago.
    //
    // What *is* per-unit is a key generated inside this handset's TEE or secure
    // element, which cannot be read out of it. A friend's identical phone does
    // not have it, and copying this app's storage does not produce it.

    private const val SIGN_ALIAS = "sysentinel-device-key"

    /**
     * The device signing key, created on first use inside the strongest
     * available backing.
     *
     * Deliberately **not** bound to a biometric. This answers "which handset is
     * this", which the daemon needs on every connection including ones the
     * owner is not watching; requiring a fingerprint to say your own name would
     * make an unattended reconnect impossible. Confirming a destructive
     * operation is a separate question and a separate key — that one does
     * require the finger.
     */
    fun deviceSigningKey(): PrivateKey? {
        val ks = KeyStore.getInstance(KEYSTORE).apply { load(null) }
        (ks.getKey(SIGN_ALIAS, null) as? PrivateKey)?.let { return it }

        for (strongBox in listOf(true, false)) {
            if (strongBox && Build.VERSION.SDK_INT < Build.VERSION_CODES.P) continue
            try {
                val gen = KeyPairGenerator.getInstance(
                    KeyProperties.KEY_ALGORITHM_EC, KEYSTORE,
                )
                gen.initialize(
                    KeyGenParameterSpec.Builder(SIGN_ALIAS, KeyProperties.PURPOSE_SIGN)
                        .setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
                        .setDigests(KeyProperties.DIGEST_SHA256)
                        .apply {
                            setAttestationChallenge(freshChallenge())
                            if (strongBox && Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                                setIsStrongBoxBacked(true)
                            }
                        }
                        .build()
                )
                gen.generateKeyPair()
                Log.i(TAG, "device key created (strongBox=$strongBox)")
                return ks.getKey(SIGN_ALIAS, null) as? PrivateKey
            } catch (e: Exception) {
                Log.i(TAG, "device key refused (strongBox=$strongBox): ${e.message}")
            }
        }
        Log.e(TAG, "no hardware-backed device key on this handset")
        return null
    }

    /** SubjectPublicKeyInfo DER of the device key — what the daemon records. */
    fun devicePublicKey(): ByteArray? {
        val ks = KeyStore.getInstance(KEYSTORE).apply { load(null) }
        return ks.getCertificate(SIGN_ALIAS)?.publicKey?.encoded
    }

    /**
     * Sign the daemon's challenge.
     *
     * This is the step that makes the public key worth anything: the key itself
     * travels, so anyone could present it. Only this handset can sign with it.
     */
    fun signChallenge(challenge: ByteArray): ByteArray? {
        val key = deviceSigningKey() ?: return null
        return try {
            Signature.getInstance("SHA256withECDSA").run {
                initSign(key)
                update(challenge)
                sign()
            }
        } catch (e: Exception) {
            Log.e(TAG, "cannot sign the challenge: ${e.message}")
            null
        }
    }

    // ── Wrapping the pairing key ─────────────────────────────────────────────
    //
    // The pairing key is the whole secret for the channel: sealing a frame with
    // it is the authentication. Left in SharedPreferences it is *private*
    // storage, not *hardware-backed* storage, and on a rooted handset the two
    // are not the same thing.
    //
    // So it is stored encrypted under a key that lives in the TEE or the secure
    // element and cannot be read out. An attacker who copies the app's data
    // directory gets ciphertext and a key handle that is useless anywhere else.
    //
    // Deliberately NOT biometric-bound: the pairing key is needed to open every
    // frame, including on a reconnect nobody is watching. Requiring a
    // fingerprint to receive an alert would mean alerts only arrive when the
    // owner happens to be looking, which defeats the point. The biometric
    // belongs on the confirmation key, where it gates an action rather than a
    // read.

    private const val WRAP_ALIAS = "sysentinel-secret-wrap"
    private const val GCM_TAG_BITS = 128
    private const val GCM_NONCE_LEN = 12

    /** The wrapping key, created on first use in the strongest backing available. */
    private fun wrappingKey(): javax.crypto.SecretKey? {
        val ks = KeyStore.getInstance(KEYSTORE).apply { load(null) }
        (ks.getKey(WRAP_ALIAS, null) as? javax.crypto.SecretKey)?.let { return it }

        for (strongBox in listOf(true, false)) {
            if (strongBox && Build.VERSION.SDK_INT < Build.VERSION_CODES.P) continue
            try {
                val gen = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, KEYSTORE)
                gen.init(
                    KeyGenParameterSpec.Builder(
                        WRAP_ALIAS,
                        KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT,
                    )
                        .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                        .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                        .setKeySize(256)
                        .apply {
                            if (strongBox && Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                                setIsStrongBoxBacked(true)
                            }
                        }
                        .build()
                )
                gen.generateKey()
                Log.i(TAG, "secret-wrapping key created (strongBox=$strongBox)")
                return ks.getKey(WRAP_ALIAS, null) as? javax.crypto.SecretKey
            } catch (e: Exception) {
                Log.i(TAG, "wrapping key refused (strongBox=$strongBox): ${e.message}")
            }
        }
        return null
    }

    /**
     * Encrypt a secret under the hardware key. Returns `nonce || ciphertext`,
     * base64, or `null` on a handset with no usable Keystore — the caller then
     * has to decide, and [Pairing] stores it in the clear and says so rather
     * than refusing to work at all.
     */
    fun wrapSecret(plaintext: String): String? {
        val key = wrappingKey() ?: return null
        return try {
            val c = javax.crypto.Cipher.getInstance("AES/GCM/NoPadding")
            // No IV is passed in, and that is deliberate: for a Keystore AES
            // key the platform *refuses* a caller-supplied IV on encryption and
            // generates a fresh one itself, precisely so an application cannot
            // reuse a nonce under one key — which for GCM is a total break, not
            // a weakness. `c.iv` below is that generated value.
            c.init(javax.crypto.Cipher.ENCRYPT_MODE, key)
            val body = c.doFinal(plaintext.toByteArray(Charsets.UTF_8))
            android.util.Base64.encodeToString(c.iv + body, android.util.Base64.NO_WRAP)
        } catch (e: Exception) {
            Log.e(TAG, "cannot wrap the secret: ${e.message}")
            null
        }
    }

    /** Undo [wrapSecret]. `null` when the blob is not ours or the key is gone. */
    fun unwrapSecret(wrapped: String): String? {
        val key = wrappingKey() ?: return null
        return try {
            val raw = android.util.Base64.decode(wrapped, android.util.Base64.NO_WRAP)
            if (raw.size <= GCM_NONCE_LEN) return null
            val c = javax.crypto.Cipher.getInstance("AES/GCM/NoPadding")
            c.init(
                javax.crypto.Cipher.DECRYPT_MODE,
                key,
                javax.crypto.spec.GCMParameterSpec(
                    GCM_TAG_BITS, raw.copyOfRange(0, GCM_NONCE_LEN),
                ),
            )
            String(c.doFinal(raw.copyOfRange(GCM_NONCE_LEN, raw.size)), Charsets.UTF_8)
        } catch (e: Exception) {
            // A factory reset or an app reinstall destroys the Keystore key, and
            // then the stored blob is simply unreadable. That is re-pair, not a
            // bug, and it is what makes wrapping worth having.
            Log.w(TAG, "cannot unwrap the stored secret: ${e.message}")
            null
        }
    }

    /** Whether secrets are being protected by hardware on this handset. */
    fun hardwareWrappingAvailable(): Boolean = wrappingKey() != null

    // ── The confirmation key ─────────────────────────────────────────────────
    //
    // Separate from the device key on purpose, and the difference is the point
    // of the whole feature.
    //
    // The device key answers "which handset is this", which the daemon needs on
    // every reconnect including ones nobody is watching — so it must not need a
    // finger. This one authorises an action, so it must: it is created with
    // setUserAuthenticationRequired(true) and a validity of zero, meaning the
    // Keystore releases it for exactly one operation after a fresh biometric
    // and never caches that authorisation.
    //
    // That is what makes it better than typing a code back. A code can be read
    // over a shoulder or demanded out loud, and once spoken anyone can type it.
    // A signature from this key requires the owner's finger on this handset, at
    // that moment.

    private const val CONFIRM_ALIAS = "sysentinel-confirm-key"

    /** Create the confirmation key if it does not exist. */
    fun ensureConfirmKey(): Boolean {
        val ks = KeyStore.getInstance(KEYSTORE).apply { load(null) }
        if (ks.containsAlias(CONFIRM_ALIAS)) return true

        for (strongBox in listOf(true, false)) {
            if (strongBox && Build.VERSION.SDK_INT < Build.VERSION_CODES.P) continue
            try {
                val gen = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, KEYSTORE)
                gen.initialize(
                    KeyGenParameterSpec.Builder(CONFIRM_ALIAS, KeyProperties.PURPOSE_SIGN)
                        .setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
                        .setDigests(KeyProperties.DIGEST_SHA256)
                        .setUserAuthenticationRequired(true)
                        .apply {
                            setAttestationChallenge(freshChallenge())
                            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                                // 0 = every single use needs a fresh
                                // authentication. Anything else would let one
                                // fingerprint authorise a second action the
                                // owner never saw.
                                setUserAuthenticationParameters(
                                    0, KeyProperties.AUTH_BIOMETRIC_STRONG,
                                )
                            } else {
                                @Suppress("DEPRECATION")
                                setUserAuthenticationValidityDurationSeconds(-1)
                            }
                            if (strongBox && Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                                setIsStrongBoxBacked(true)
                            }
                        }
                        .build()
                )
                gen.generateKeyPair()
                Log.i(TAG, "confirmation key created (strongBox=$strongBox)")
                return true
            } catch (e: Exception) {
                Log.i(TAG, "confirmation key refused (strongBox=$strongBox): ${e.message}")
            }
        }
        return false
    }

    /**
     * A [Signature] initialised with the confirmation key, to hand to
     * `BiometricPrompt`.
     *
     * The prompt unlocks *this object*, which is what ties the fingerprint to
     * this specific signature rather than to a window of time. Signing happens
     * in the prompt's success callback, not before it.
     */
    fun confirmSignature(): Signature? {
        if (!ensureConfirmKey()) return null
        return try {
            val ks = KeyStore.getInstance(KEYSTORE).apply { load(null) }
            val key = ks.getKey(CONFIRM_ALIAS, null) as? PrivateKey ?: return null
            Signature.getInstance("SHA256withECDSA").apply { initSign(key) }
        } catch (e: Exception) {
            Log.e(TAG, "cannot prepare a confirmation signature: ${e.message}")
            null
        }
    }

    /** Public half of the confirmation key, for the daemon to record. */
    fun confirmPublicKey(): ByteArray? {
        val ks = KeyStore.getInstance(KEYSTORE).apply { load(null) }
        return ks.getCertificate(CONFIRM_ALIAS)?.publicKey?.encoded
    }

    /** Whether this handset can do biometric confirmations at all. */
    fun biometricConfirmAvailable(context: android.content.Context): Boolean {
        val mgr = androidx.biometric.BiometricManager.from(context)
        return mgr.canAuthenticate(
            androidx.biometric.BiometricManager.Authenticators.BIOMETRIC_STRONG
        ) == androidx.biometric.BiometricManager.BIOMETRIC_SUCCESS
    }

    /** How the device key is backed, for the audit line. A claim, not a proof. */
    fun deviceKeyBacking(): String = when {
        devicePublicKey() == null -> "none"
        Build.VERSION.SDK_INT >= Build.VERSION_CODES.P -> "tee_or_strongbox"
        else -> "tee"
    }
}
