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
}
