// SPDX-License-Identifier: Apache-2.0
package org.sysentinel.app

import android.graphics.Bitmap
import android.graphics.BitmapFactory
import android.util.Log
import java.io.ByteArrayOutputStream

/**
 * The phone's side of the "keep it small" rule.
 *
 * The machine reads face photos only to build a 128-D template and a pair of
 * perceptual hashes — nothing there needs more than a modest frame, and the
 * channel refuses frames over 1 MB ([PhoneLink] against `MAX_FRAME` in the
 * daemon). A modern camera hands over a 12 MP JPEG that is 3-6 MB, which dies
 * on that cap as a raw "broken pipe": the machine closes a frame it declared
 * too big while the phone is still writing it.
 *
 * So enrolment photos are decoded once, scaled so their longest edge is at most
 * [MAX_DIM] pixels, and re-encoded as JPEG. A face survives that easily — this
 * is what an enrolment template needs — and the frame comes out a few tens of
 * kilobytes.
 */
object FacePhoto {

    const val MAX_DIM = 800

    /**
     * A JPEG fit for `/face register`, or `null` when the bytes were not an
     * image the phone can decode — in which case [sendPhoto] never runs and the
     * daemon is not told to arm either.
     */
    fun forEnrolment(bytes: ByteArray): ByteArray? {
        val options = BitmapFactory.Options().apply { inJustDecodeBounds = true }
        BitmapFactory.decodeByteArray(bytes, 0, bytes.size, options)
        val w = options.outWidth
        val h = options.outHeight
        if (w <= 0 || h <= 0) {
            Log.w("sysentinel", "face: bytes are not a decodable image")
            return null
        }

        // Step the sample size down in two-powers so the intermediate decode is
        // bounded: a 12000×9000 RAW is risk for the phone's own memory manager,
        // not just for the wire.
        var sample = 1
        while (w / sample > MAX_DIM * 2 || h / sample > MAX_DIM * 2) sample *= 2
        val scaled = BitmapFactory.decodeByteArray(
            bytes, 0, bytes.size,
            BitmapFactory.Options().apply { inSampleSize = sample },
        ) ?: return null

        val longest = maxOf(scaled.width, scaled.height)
        val bitmap = if (longest > MAX_DIM) {
            val ratio = MAX_DIM / longest.toFloat()
            Bitmap.createScaledBitmap(
                scaled,
                (scaled.width * ratio).toInt().coerceAtLeast(1),
                (scaled.height * ratio).toInt().coerceAtLeast(1),
                true,
            )
        } else {
            scaled
        }

        return try {
            val out = ByteArrayOutputStream()
            bitmap.compress(Bitmap.CompressFormat.JPEG, 90, out)
            out.toByteArray()
        } catch (e: Exception) {
            Log.w("sysentinel", "face: could not encode the enrolment photo: ${e.message}")
            null
        } finally {
            if (bitmap !== scaled) bitmap.recycle()
            scaled.recycle()
        }
    }
}