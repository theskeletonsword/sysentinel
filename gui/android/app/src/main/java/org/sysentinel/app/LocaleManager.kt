// SPDX-License-Identifier: Apache-2.0
package org.sysentinel.app

import android.content.Context
import android.content.res.Configuration
import java.util.Locale

/**
 * Forces the UI language to the owner's choice instead of the phone's locale.
 *
 * English is the source language and the default; Spanish is the one optional
 * translation. Android's default behaviour is to follow the handset's locale,
 * so a Spanish phone got a Spanish app whether or not that was wanted — the
 * screenshots that prompted this were exactly that. We override it: the app
 * starts in English and switches to Spanish only when the owner picks it in the
 * language menu.
 *
 * Applied in [android.app.Activity.attachBaseContext] by wrapping the context
 * with a configuration carrying the chosen locale, which works for any Activity
 * type (this app's is a FragmentActivity, not an AppCompatActivity, so the
 * AppCompatDelegate per-app locale path is not guaranteed here).
 */
object LocaleManager {

    /** Wrap [base] so every resource lookup resolves in the chosen language. */
    fun wrap(base: Context): Context {
        val tag = AppPrefs(base).language
        val locale = Locale.forLanguageTag(tag)
        Locale.setDefault(locale)
        val config = Configuration(base.resources.configuration)
        config.setLocale(locale)
        return base.createConfigurationContext(config)
    }

    /** Persist a new language and report whether it actually changed, so the
     *  caller can recreate the Activity only when needed. */
    fun setLanguage(context: Context, tag: String): Boolean {
        val prefs = AppPrefs(context)
        if (prefs.language == tag) return false
        prefs.language = tag
        return true
    }
}
