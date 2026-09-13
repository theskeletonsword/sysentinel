// SPDX-License-Identifier: Apache-2.0
package org.sysentinel.app

import android.content.Context
import org.json.JSONArray
import org.json.JSONObject

/** Persists the last [MAX_STORED] chat messages across app restarts. */
class MessageHistory(context: Context) {

    private val prefs = context.getSharedPreferences("sysentinel-chat", Context.MODE_PRIVATE)

    fun load(): List<Message> {
        val raw = prefs.getString(KEY, null) ?: return emptyList()
        return try {
            val arr = JSONArray(raw)
            List(arr.length()) { i ->
                val o = arr.getJSONObject(i)
                Message(
                    text          = o.optString("text"),
                    fromMe        = o.optBoolean("fromMe"),
                    timestamp     = o.optLong("ts", System.currentTimeMillis()),
                    photoPath     = o.optString("photoPath").takeIf { it.isNotEmpty() },
                    localMediaPath= o.optString("localMedia").takeIf { it.isNotEmpty() },
                )
            }
        } catch (_: Exception) {
            emptyList()
        }
    }

    fun save(messages: List<Message>) {
        val tail = if (messages.size > MAX_STORED) messages.takeLast(MAX_STORED) else messages
        val arr = JSONArray()
        for (m in tail) {
            // Never persist confirmNonce — it is a one-time security token.
            if (m.confirmNonce != null) continue
            arr.put(
                JSONObject()
                    .put("text",       m.text)
                    .put("fromMe",     m.fromMe)
                    .put("ts",         m.timestamp)
                    .apply { if (m.photoPath     != null) put("photoPath",  m.photoPath) }
                    .apply { if (m.localMediaPath != null) put("localMedia", m.localMediaPath) }
            )
        }
        prefs.edit().putString(KEY, arr.toString()).apply()
    }

    fun clear() {
        prefs.edit().remove(KEY).apply()
    }

    private companion object {
        const val KEY = "messages"
        const val MAX_STORED = 200
    }
}
