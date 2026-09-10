// SPDX-License-Identifier: Apache-2.0
package org.sysentinel.app

import android.os.Bundle
import android.view.View
import android.view.ViewGroup
import android.widget.ArrayAdapter
import android.widget.Button
import android.widget.EditText
import android.widget.ListView
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

/**
 * The plain face, for the 32-bit flavour.
 *
 * Same conversation, built out of Views that have existed since Android 4:
 * a ListView of bubbles, an EditText and a Button. No Compose, no Material 3,
 * nothing that needs an API a device on this flavour might not have.
 *
 * The bubbles still sit left and right the way a messaging app's do, because
 * that is what makes a conversation readable — the styling is what is plain
 * here, not the shape.
 *
 * Like the modern flavour, it posts no notifications, ever. See
 * `ChatActivity` in `src/modern` for why that is a security property.
 */
class ChatActivity : AppCompatActivity() {

    private val messages = ArrayList<Message>()
    private lateinit var adapter: BubbleAdapter

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_chat)

        val identity = DeviceIdentity.ensureKey()
        findViewById<TextView>(R.id.identity).text = describe(identity)

        messages.add(
            Message(
                "Estoy despierta. Sin novedades por acá.",
                fromMe = false,
            )
        )

        val list = findViewById<ListView>(R.id.messages)
        adapter = BubbleAdapter(this, messages)
        list.adapter = adapter

        val draft = findViewById<EditText>(R.id.draft)
        findViewById<Button>(R.id.send).setOnClickListener {
            val text = draft.text.toString()
            if (text.isNotBlank()) {
                messages.add(Message(text, fromMe = true))
                adapter.notifyDataSetChanged()
                draft.setText("")
            }
        }
    }

    /** Says what this handset can prove, in the same words the modern one uses. */
    private fun describe(id: DeviceIdentity.Identity): String {
        val backing = when (id.backing) {
            DeviceIdentity.Backing.STRONGBOX -> "elemento seguro dedicado"
            DeviceIdentity.Backing.TEE -> "TrustZone"
            DeviceIdentity.Backing.SOFTWARE -> "SIN respaldo de hardware"
            DeviceIdentity.Backing.NONE -> "sin identidad"
        }
        val aead = if (id.aead == DeviceIdentity.Aead.AES_256_GCM)
            "AES-256-GCM" else "ChaCha20-Poly1305"
        return "$backing · $aead"
    }
}

/** Left/right bubbles without a layout manager, the way it used to be done. */
private class BubbleAdapter(
    activity: AppCompatActivity,
    private val items: List<Message>,
) : ArrayAdapter<Message>(activity, 0, items) {

    override fun getView(position: Int, convertView: View?, parent: ViewGroup): View {
        val m = items[position]
        val tv = (convertView as? TextView) ?: TextView(context).apply {
            setPadding(24, 16, 24, 16)
        }
        val time = SimpleDateFormat("HH:mm", Locale.getDefault()).format(Date(m.timestamp))
        tv.text = "${m.text}\n$time"
        tv.setTextColor(0xFFC8D6E5.toInt())
        tv.setBackgroundColor(if (m.fromMe) 0xFF17313D.toInt() else 0xFF161C24.toInt())
        tv.textAlignment = if (m.fromMe) View.TEXT_ALIGNMENT_VIEW_END
                           else View.TEXT_ALIGNMENT_VIEW_START
        return tv
    }
}
