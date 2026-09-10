// SPDX-License-Identifier: Apache-2.0
package org.sysentinel.app

import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Log
import java.io.File
import java.security.KeyStore
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
}
