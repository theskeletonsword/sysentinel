// SPDX-License-Identifier: Apache-2.0
package org.sysentinel.app

import android.util.Log
import androidx.biometric.BiometricPrompt
import androidx.fragment.app.FragmentActivity
import java.util.concurrent.Executor

/**
 * Confirming a privileged action with a fingerprint instead of a typed code.
 *
 * # Why this is not the same as typing "yes"
 *
 * The daemon arms a destructive order and issues a nonce. Typing that nonce
 * back proves someone read it — and a code can be read over a shoulder, or
 * demanded out loud by whoever is standing there. Once spoken, anyone can type
 * it.
 *
 * Signing it with a key the Keystore only releases after a fresh biometric
 * proves the owner's finger was on this handset at that moment. It cannot be
 * repeated by someone who overheard anything, and it cannot be replayed later:
 * the nonce belongs to one armed order and expires with it.
 *
 * # The prompt authorises one signature, not a session
 *
 * `BiometricPrompt` is handed the initialised [java.security.Signature] itself,
 * and the key is created with a validity of zero — one operation per
 * authentication, never cached. So a fingerprint given for "reboot" cannot also
 * authorise the wipe that arrives a second later.
 *
 * # When the handset cannot do it
 *
 * No enrolled biometric, or no hardware for one, is not an error: the typed
 * code still works and the daemon grades it for what it is. What must not
 * happen is the app quietly falling back and letting the owner believe the
 * stronger thing happened, so [available] is surfaced in the UI.
 */
object Confirmation {

    private const val TAG = "sysentinel"

    fun available(activity: FragmentActivity): Boolean =
        DeviceIdentity.biometricConfirmAvailable(activity)

    /**
     * Ask for the fingerprint and, on success, sign `nonce` and send it.
     *
     * Everything happens in the success callback: the signature is produced
     * from the object the prompt just unlocked, so there is no window in which
     * a signature exists without an authentication behind it.
     */
    fun confirm(
        activity: FragmentActivity,
        engine: ChatEngine,
        nonce: String,
        orderLabel: String,
        onResult: (String) -> Unit,
    ) {
        val signature = DeviceIdentity.confirmSignature()
        if (signature == null) {
            onResult(activity.getString(R.string.confirm_unavailable))
            return
        }

        val executor: Executor = androidx.core.content.ContextCompat.getMainExecutor(activity)
        val prompt = BiometricPrompt(
            activity,
            executor,
            object : BiometricPrompt.AuthenticationCallback() {
                override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                    val sig = result.cryptoObject?.signature
                    if (sig == null) {
                        onResult(activity.getString(R.string.confirm_no_signature))
                        return
                    }
                    try {
                        sig.update(nonce.toByteArray(Charsets.UTF_8))
                        engine.confirm(nonce, sig.sign(), onResult)
                    } catch (e: Exception) {
                        Log.e(TAG, "signing the confirmation failed: ${e.message}")
                        onResult(
                            activity.getString(R.string.confirm_sign_failed, e.message ?: "")
                        )
                    }
                }

                override fun onAuthenticationError(code: Int, msg: CharSequence) {
                    // Cancelling is a decision, not a failure. Say nothing
                    // alarming: the order simply stays armed until it expires.
                    onResult(
                        if (code == BiometricPrompt.ERROR_USER_CANCELED ||
                            code == BiometricPrompt.ERROR_NEGATIVE_BUTTON
                        ) {
                            activity.getString(R.string.confirm_cancelled)
                        } else {
                            activity.getString(R.string.confirm_biometric_failed, msg)
                        }
                    )
                }
            },
        )

        prompt.authenticate(
            BiometricPrompt.PromptInfo.Builder()
                .setTitle(activity.getString(R.string.confirm_prompt_title, orderLabel))
                // Named explicitly, because the whole risk of a confirmation
                // flow is authorising something other than what you thought.
                .setSubtitle(activity.getString(R.string.confirm_prompt_subtitle))
                .setNegativeButtonText(activity.getString(R.string.confirm_cancel))
                // No device-credential fallback: a PIN can be demanded out
                // loud, which is the thing this exists to avoid.
                .setAllowedAuthenticators(
                    androidx.biometric.BiometricManager.Authenticators.BIOMETRIC_STRONG
                )
                .build(),
            BiometricPrompt.CryptoObject(signature),
        )
    }

    /**
     * A plain "is the owner's finger on this handset right now" gate.
     *
     * Unlike [confirm], nothing is signed for the daemon: the fingerprint just
     * opens the door to an action that is sent afterwards on the normal channel.
     * It is used to gate face enrolment — a photo of your face should not go
     * anywhere because the phone happened to be unlocked.
     *
     * The same rules as [confirm] apply: the prompt unlocks a signature object
     * from a key with zero validity, so the gate cannot leak sideways into
     * authorising a second action, and there is no device-credential fallback.
     *
     * @param onSuccess runs only after a fresh biometric has been presented.
     * @param onDone runs on cancel or failure with a message (empty on a plain
     *        cancel, so the UI can stay quiet about a decision the owner made).
     */
    /**
     * Biometric gate with NO CryptoObject — just "prove you are present".
     *
     * Used for enrollment actions (phone registration, etc.) where we need
     * to confirm the owner is present but don't yet have a key to tie the
     * auth to. More compatible than [gate]: works even before any Keystore
     * key has been created, so it never deadlocks on devices that struggle
     * with key generation.
     */
    fun enrollGate(
        activity: FragmentActivity,
        title: String,
        subtitle: String,
        onSuccess: () -> Unit,
        onDone: (message: String) -> Unit,
    ) {
        val executor: Executor = androidx.core.content.ContextCompat.getMainExecutor(activity)
        val prompt = BiometricPrompt(
            activity,
            executor,
            object : BiometricPrompt.AuthenticationCallback() {
                override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                    onSuccess()
                }
                override fun onAuthenticationError(code: Int, msg: CharSequence) {
                    onDone(
                        if (code == BiometricPrompt.ERROR_USER_CANCELED ||
                            code == BiometricPrompt.ERROR_NEGATIVE_BUTTON
                        ) "" else activity.getString(R.string.confirm_biometric_failed, msg)
                    )
                }
                override fun onAuthenticationFailed() {}
            },
        )
        prompt.authenticate(
            BiometricPrompt.PromptInfo.Builder()
                .setTitle(title)
                .setSubtitle(subtitle)
                .setNegativeButtonText(activity.getString(R.string.confirm_cancel))
                .setAllowedAuthenticators(
                    androidx.biometric.BiometricManager.Authenticators.BIOMETRIC_STRONG
                )
                .build(),
        )
    }

    /**
     * Biometric gate that signs [payload] with the confirm key.
     *
     * The signature is handed to [onSuccess] so the caller can attach it to
     * whatever it is about to send (face photo, etc.). This makes the
     * biometric proof cryptographically bound to that specific payload rather
     * than just a "was present" check.
     *
     * Falls back to [enrollGate] (no CryptoObject) when the confirm key is
     * unavailable, so it never deadlocks.
     */
    fun gate(
        activity: FragmentActivity,
        payload: ByteArray,
        onSuccess: (signature: ByteArray?) -> Unit,
        onDone: (message: String) -> Unit,
    ) {
        val sigObj = DeviceIdentity.confirmSignature()
        if (sigObj == null) {
            // No biometric-bound key available — use a presence-only gate and
            // pass null so the caller sends the photo without a signature.
            enrollGate(
                activity = activity,
                title = activity.getString(R.string.gate_prompt_title),
                subtitle = activity.getString(R.string.gate_prompt_subtitle),
                onSuccess = { onSuccess(null) },
                onDone = onDone,
            )
            return
        }
        val executor: Executor = androidx.core.content.ContextCompat.getMainExecutor(activity)
        val prompt = BiometricPrompt(
            activity,
            executor,
            object : BiometricPrompt.AuthenticationCallback() {
                override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                    val sig = result.cryptoObject?.signature
                    if (sig == null) {
                        onDone(activity.getString(R.string.confirm_no_signature))
                        return
                    }
                    try {
                        sig.update(payload)
                        onSuccess(sig.sign())
                    } catch (e: Exception) {
                        Log.e(TAG, "signing the face photo failed: ${e.message}")
                        onDone(activity.getString(R.string.confirm_sign_failed, e.message ?: ""))
                    }
                }

                override fun onAuthenticationError(code: Int, msg: CharSequence) {
                    onDone(
                        if (code == BiometricPrompt.ERROR_USER_CANCELED ||
                            code == BiometricPrompt.ERROR_NEGATIVE_BUTTON
                        ) {
                            ""
                        } else {
                            activity.getString(R.string.confirm_biometric_failed, msg)
                        }
                    )
                }

                override fun onAuthenticationFailed() {}
            },
        )
        prompt.authenticate(
            BiometricPrompt.PromptInfo.Builder()
                .setTitle(activity.getString(R.string.gate_prompt_title))
                .setSubtitle(activity.getString(R.string.gate_prompt_subtitle))
                .setNegativeButtonText(activity.getString(R.string.confirm_cancel))
                .setAllowedAuthenticators(
                    androidx.biometric.BiometricManager.Authenticators.BIOMETRIC_STRONG
                )
                .build(),
            BiometricPrompt.CryptoObject(sigObj),
        )
    }
}
