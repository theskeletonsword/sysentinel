// SPDX-License-Identifier: Apache-2.0
package org.sysentinel.app

import android.content.Context
import android.content.SharedPreferences
import org.json.JSONArray
import org.json.JSONObject

/**
 * The phone's own list of LLM API keys, each under an alias.
 *
 * The daemon keeps the *active* keys on the machine, in its local TOML file,
 * and never prints them. This list is the owner's reference copy on the phone:
 * every key is stored alone under the alias the owner chose, tagged with which
 * provider it belongs to, so it can be matched to the model list.
 *
 * # Secrecy
 *
 * Each key is **wrapped under a key held in the TEE or the secure element**
 * ([DeviceIdentity.wrapSecret]) before it touches disk. Private storage is not
 * the same as hardware-backed storage, and on a rooted handset that difference
 * is the whole question. On a device with no usable Keystore the key is stored
 * in the clear and [Key.wrappedInHardware] says so, rather than the app
 * refusing to work — the owner can then decide, and the UI tells them.
 *
 * A factory reset or a reinstall destroys the wrapping key, which leaves the
 * stored blob unreadable: that entry reads as "unreadable" and the owner
 * re-enters it. Same rule as the pairing secret, for the same reason.
 *
 * Entries are stored as a JSON array of `{ alias, provider, key_wrapped?,
 * key_plain? }`. Writes replace entries in place and never re-wrap the entries
 * that already exist, so a partially-unwrappable store (a Keystore reset while
 * some keys were plaintext) is not garbled by the act of editing one key.
 */
class ApiKeys(context: Context) {

    private val prefs: SharedPreferences =
        context.getSharedPreferences("sysentinel-apikeys", Context.MODE_PRIVATE)

    /** One saved key. [apiKey] is empty when it exists but can no longer be
     *  unwrapped (a Keystore reset since it was saved). */
    data class Key(
        val alias: String,
        val provider: String,
        val apiKey: String,
        val wrappedInHardware: Boolean,
    ) {
        /** The value shown behind the mask: the real characters or a blank. */
        val unreadable: Boolean get() = wrappedInHardware && apiKey.isEmpty()
    }

    /** All saved keys, in the order they were added. */
    fun list(): List<Key> {
        val raw = prefs.getString(KEY_STORE, null) ?: return emptyList()
        val out = mutableListOf<Key>()
        return try {
            for (i in 0 until JSONArray(raw).length()) {
                val obj = JSONArray(raw).optJSONObject(i) ?: continue
                val alias = obj.optString("alias", "").trim()
                if (alias.isEmpty()) continue
                val provider = obj.optString("provider", "")
                val wrapped = obj.optString("key_wrapped", "").takeIf { it.isNotEmpty() }
                val plain = obj.optString("key_plain", "").takeIf { it.isNotEmpty() }
                when {
                    wrapped != null -> out.add(
                        Key(alias, provider, DeviceIdentity.unwrapSecret(wrapped) ?: "", true)
                    )
                    plain != null -> out.add(Key(alias, provider, plain, false))
                }
            }
            out
        } catch (e: Exception) {
            emptyList()
        }
    }

    /** True when `alias` is already taken by another entry. */
    fun aliasExists(alias: String): Boolean {
        val a = alias.trim()
        if (a.isEmpty()) return false
        return rows().any { it.optString("alias", "").equals(a, ignoreCase = true) }
    }

    /** Add a key, or replace the entry with the same (case-insensitive) alias. */
    fun save(alias: String, provider: String, apiKey: String) {
        val a = alias.trim()
        if (a.isEmpty()) return

        val existing = rows().toMutableList()
        existing.removeAll { it.optString("alias", "").equals(a, ignoreCase = true) }

        val new = JSONObject()
            .put("alias", a)
            .put("provider", provider.trim())
        val wrapped = DeviceIdentity.wrapSecret(apiKey)
        if (wrapped != null) new.put("key_wrapped", wrapped)
        else new.put("key_plain", apiKey) // no Keystore: store it, and say so

        existing.add(new)
        write(existing)
    }

    /** Remove a key by alias. */
    fun remove(alias: String) {
        val rows = rows().filterNot { it.optString("alias", "").equals(alias.trim(), ignoreCase = true) }
        write(rows.toMutableList())
    }

    /** Raw stored rows, in order. Callers never mutate these and never re-wrap them. */
    private fun rows(): List<JSONObject> {
        val raw = prefs.getString(KEY_STORE, null) ?: return emptyList()
        return try {
            List(JSONArray(raw).length()) { i -> JSONArray(raw).optJSONObject(i) }
                .filterNotNull()
        } catch (e: Exception) {
            emptyList()
        }
    }

    private fun write(rows: MutableList<JSONObject>) {
        val arr = JSONArray()
        rows.forEach { arr.put(it) }
        prefs.edit().putString(KEY_STORE, arr.toString()).apply()
    }

    private companion object {
        const val KEY_STORE = "keys"
    }
}