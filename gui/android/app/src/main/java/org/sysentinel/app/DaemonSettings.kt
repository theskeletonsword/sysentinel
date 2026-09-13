// SPDX-License-Identifier: Apache-2.0
package org.sysentinel.app

/**
 * The slash-commands the daemon already understands, expressed as typed
 * builders so the settings UI can drive them without hand-writing strings that
 * might not match what the daemon parses.
 *
 * Everything here maps to a REAL command in `daemon/src/bot.rs`; there are no
 * invented endpoints. The settings screens send these over the ordinary chat
 * channel ([PhoneLink.say]) and show the daemon's own reply, so the phone never
 * has to model the daemon's state — it asks, and the machine answers.
 */
object DaemonSettings {

    /** Providers the daemon will accept for `/llm` and `/model <provider>`.
     *  Mirrors `llm::PROVIDER_NAMES` in the daemon. */
    val PROVIDERS = listOf("deepseek", "anthropic", "openai", "gemini", "llama", "local", "none")

    /**
     * The on/off categories `/settings <cat> on|off` accepts, with the labels
     * the drawer shows. Mirrors the list in `daemon/src/config.rs`.
     */
    val TOGGLES = listOf(
        Toggle("hypercall", "toggle_hypercall"),
        Toggle("selinux", "toggle_selinux"),
        Toggle("pmu", "toggle_pmu"),
        Toggle("kernel", "toggle_kernel"),
        Toggle("modwatch", "toggle_modwatch"),
        Toggle("login", "toggle_login"),
        Toggle("battery", "toggle_battery"),
        Toggle("thermal", "toggle_thermal"),
        Toggle("tsc", "toggle_tsc"),
        Toggle("proactive", "toggle_proactive"),
    )

    data class Toggle(val category: String, val labelKey: String)

    /** Switch the whole active provider (single). */
    fun setProvider(name: String) = "/llm $name"

    /**
     * Set the model(s) for a provider.
     *
     * The daemon reaches a vision-capable model by name — it has one model slot
     * per provider and an ordered chain (`/model <provider> m1,m2`). So when the
     * text and vision models differ we send both as the chain (text preferred,
     * the vision-capable one as its companion); when they are the same, as they
     * are for a unified model like Gemini, we send it once.
     */
    fun setModels(provider: String, textModel: String, visionModel: String): String {
        val t = textModel.trim()
        val v = visionModel.trim()
        val chain = when {
            t.isEmpty() && v.isEmpty() -> ""            // clear → back to [llm].model
            v.isEmpty() || v == t -> t                  // one model (unified/text-only)
            t.isEmpty() -> v
            else -> "$t,$v"                             // distinct text + vision
        }
        return "/model $provider $chain".trimEnd()
    }

    /** Replace the entire persona / system prompt. */
    fun setPersona(text: String): String {
        val t = text.trim()
        return if (t.isEmpty()) "/systemprompt clear" else "/systemprompt $t"
    }

    /** Toggle a category on or off. */
    fun toggle(category: String, on: Boolean) = "/settings $category ${if (on) "on" else "off"}"

    // ── Read-only reports the drawer can pull ─────────────────────────────────
    const val STATUS = "/status"
    const val SELINUX = "/selinux"
    const val HARDWARE = "/hardware"
    const val FIRMWARE = "/firmware"
    const val SETTINGS = "/settings"
    const val MODEL = "/model"
    const val SYSTEMPROMPT = "/systemprompt"
    const val HELP = "/help"
}
