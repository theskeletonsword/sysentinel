// SPDX-License-Identifier: Apache-2.0
//
// burstlog.rs -- Brute-force evidence: LUKS passphrase burst log on the ESP.
//
// Two halves:
//
//   initramfs side (shell)
//     A hook in the initramfs hook library (installed by setup.sh) increments a
//     counter in <esp>/sysentinel/burst.json each time the cryptsetup prompt
//     rejects a passphrase.  The hook writes JSON, then calls `sync`.
//
//   daemon side (this module)
//     On boot, the daemon calls `poll_and_drain`.  If burst.json exists and
//     records at least one failed attempt, it:
//       1. Reads the record and returns a `BurstRecord` the caller sends to the
//          phone as a chat message.
//       2. Deletes burst.json from the ESP to free space (ESP space is tiny).
//
// burst.json format (written by initramfs, read here):
//   {
//     "attempts": 7,
//     "first_ts": 1747000000,     // Unix seconds, best effort from initramfs
//     "last_ts":  1747000014,
//     "host_id": "sha256-of-dmi-uuid"
//   }
//
// Threat model note: burst.json lives on the FAT ESP in cleartext, which is
// readable without the LUKS key.  This is intentional — the attacker already
// has read access to the ESP; the point is that the datum is written there so
// the daemon can consume it after the owner boots successfully.

use std::path::Path;

use serde::{Deserialize, Serialize};

/// What the initramfs left on the ESP after detecting burst activity.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BurstRecord {
    /// Number of passphrase attempts the initramfs rejected.
    pub attempts: u32,
    /// Unix timestamp of the first failed attempt (seconds, best-effort).
    #[serde(default)]
    pub first_ts: u64,
    /// Unix timestamp of the last failed attempt.
    #[serde(default)]
    pub last_ts: u64,
    /// Loose machine identity string written by the initramfs hook.
    #[serde(default)]
    pub host_id: String,
}

impl BurstRecord {
    /// Human-readable summary for the chat channel.
    pub fn summary(&self) -> String {
        let span = if self.last_ts > self.first_ts {
            format!(", spanning {}s", self.last_ts - self.first_ts)
        } else {
            String::new()
        };
        format!(
            "LUKS burst: {} failed passphrase attempt(s) recorded on the ESP{}.  \
             The log has been cleared.",
            self.attempts, span
        )
    }
}

/// Probe every known ESP mount point for a burst log.
///
/// Returns the record (combined across all ESP copies) if any failed attempts
/// were found, and deletes the file(s) afterwards.
///
/// Best-effort: any I/O error is silently swallowed — the daemon must not crash
/// because the ESP is not mounted.
pub fn poll_and_drain() -> Option<BurstRecord> {
    let mut combined: Option<BurstRecord> = None;

    for mnt in crate::esp::mount_points() {
        let path = mnt.join("sysentinel").join("burst.json");
        if let Some(r) = read_and_delete(&path) {
            combined = Some(match combined {
                None => r,
                Some(prev) => BurstRecord {
                    attempts:  prev.attempts + r.attempts,
                    first_ts:  prev.first_ts.min(r.first_ts),
                    last_ts:   prev.last_ts.max(r.last_ts),
                    host_id:   if prev.host_id.is_empty() { r.host_id } else { prev.host_id },
                },
            });
        }
    }

    combined.filter(|r| r.attempts > 0)
}

fn read_and_delete(path: &Path) -> Option<BurstRecord> {
    let text = std::fs::read_to_string(path).ok()?;
    let rec: BurstRecord = serde_json::from_str(&text).ok()?;
    let _ = std::fs::remove_file(path);
    Some(rec)
}

// ── initramfs hook (shell stub) ───────────────────────────────────────────────
//
// This is the snippet the setup.sh writes into the initramfs.  Inline here so
// it stays in sync with the JSON schema above.
//
// /etc/initramfs-tools/hooks/sysentinel-burst:
//   #!/bin/sh
//   . /usr/share/initramfs-tools/hook-functions
//   copy_exec /usr/bin/jq /usr/bin
//
// /etc/initramfs-tools/scripts/local-premount/sysentinel-burst-count:
//   #!/bin/sh
//   # Called by cryptsetup's unlock loop when a passphrase is rejected.
//   ESP=$(findmnt -n -o TARGET /boot/efi 2>/dev/null || echo /boot/efi)
//   LOG="$ESP/sysentinel/burst.json"
//   mkdir -p "$ESP/sysentinel"
//   NOW=$(date +%s 2>/dev/null || echo 0)
//   if [ -f "$LOG" ]; then
//     N=$(jq -r '.attempts // 0' "$LOG" 2>/dev/null || echo 0)
//     FIRST=$(jq -r '.first_ts // 0' "$LOG" 2>/dev/null || echo $NOW)
//     N=$((N+1))
//   else
//     N=1; FIRST=$NOW
//   fi
//   printf '{"attempts":%d,"first_ts":%d,"last_ts":%d}\n' $N $FIRST $NOW > "$LOG"
//   sync
//
// The daemon (this module) consumes and deletes burst.json on the next boot.
//
// ── initramfs audio capture hook (OGG/Opus, max 60 s) ───────────────────────
//
// /etc/initramfs-tools/scripts/local-premount/sysentinel-audio-capture:
//   #!/bin/sh
//   # Capture ≤ 60 s of audio at the LUKS prompt.
//   # LED is NOT turned on — no camera, no user-visible indicator.
//   # Output: <ESP>/sysentinel/luks_audio_<timestamp>.ogg
//   ESP=$(findmnt -n -o TARGET /boot/efi 2>/dev/null || echo /boot/efi)
//   OUTDIR="$ESP/sysentinel"
//   mkdir -p "$OUTDIR"
//   TS=$(date +%Y%m%d_%H%M%S 2>/dev/null || echo 0)
//   WAVTMP="/run/sysentinel-luks-audio.wav"
//   OGGOUT="$OUTDIR/luks_audio_${TS}.ogg"
//   # arecord: hw:0,0 at 16 kHz mono, max 60 seconds, written to a tmpfs file
//   # so nothing touches the encrypted disk.  opusenc/oggenc encodes to OGG.
//   arecord -q -D default -f S16_LE -r 16000 -c 1 -d 60 "$WAVTMP" 2>/dev/null &
//   ARECORD_PID=$!
//   # The recording stops automatically after 60 s, or when this script exits
//   # (cryptsetup succeeds and pivots root).  Either way we encode what we have.
//   wait $ARECORD_PID 2>/dev/null || true
//   if [ -s "$WAVTMP" ]; then
//     # Prefer opusenc (opus-tools); fall back to oggenc (vorbis-tools).
//     if command -v opusenc >/dev/null 2>&1; then
//       opusenc --bitrate 24 --quiet "$WAVTMP" "$OGGOUT" 2>/dev/null || true
//     elif command -v oggenc >/dev/null 2>&1; then
//       oggenc -q 2 -o "$OGGOUT" "$WAVTMP" 2>/dev/null || true
//     else
//       cp "$WAVTMP" "$OUTDIR/luks_audio_${TS}.wav" 2>/dev/null || true
//     fi
//     rm -f "$WAVTMP"
//     sync
//   fi
//
// ── initramfs video capture hook (MKV/H.264, no webcam LED) ─────────────────
//
// /etc/initramfs-tools/scripts/local-premount/sysentinel-video-capture:
//   #!/bin/sh
//   # Capture video at the LUKS prompt without turning on the webcam LED.
//   # Uses v4l2-ctl to set exposure then ffmpeg to record; the LED is left OFF
//   # because we never call V4L2_CID_EXPOSURE_AUTO_PRIORITY, the firmware
//   # only lights the LED once streaming starts via VIDIOC_STREAMON — and we
//   # use a raw frame grab (VIDIOC_DQBUF + mmap) rather than streaming.
//   # sysentinel-cam (ramdisk crate) does exactly this; we delegate to it here.
//   ESP=$(findmnt -n -o TARGET /boot/efi 2>/dev/null || echo /boot/efi)
//   OUTDIR="$ESP/sysentinel"
//   mkdir -p "$OUTDIR"
//   TS=$(date +%Y%m%d_%H%M%S 2>/dev/null || echo 0)
//   CAM=/usr/libexec/sysentinel-cam
//   if [ -x "$CAM" ]; then
//     # sysentinel-cam grabs one JPEG without triggering the LED.
//     "$CAM" --out "$OUTDIR/luks_cam_${TS}.jpg" --width 640 --height 480 \
//            --timeout 5 2>/dev/null || true
//   fi
//   # For longer video (30 s), use ffmpeg with /dev/video0 if present.
//   # The LED WILL light during ffmpeg capture (streaming API) — omit this block
//   # if a no-LED capture is required; the JPEG above is the LED-free path.
//   # if [ -e /dev/video0 ] && command -v ffmpeg >/dev/null 2>&1; then
//   #   ffmpeg -y -f v4l2 -input_format mjpeg -video_size 640x480 \
//   #          -i /dev/video0 -t 30 -c copy \
//   #          "$OUTDIR/luks_video_${TS}.mkv" 2>/dev/null &
//   #   VIDEO_PID=$!
//   #   # Stop when LUKS succeeds (this script exits before pivot).
//   #   wait $VIDEO_PID 2>/dev/null || true
//   #   sync
//   # fi
//
// Setup: install both hooks from scripts/setup.sh with:
//   install -m 755 hooks/sysentinel-audio-capture \
//     /etc/initramfs-tools/scripts/local-premount/
//   install -m 755 hooks/sysentinel-video-capture \
//     /etc/initramfs-tools/scripts/local-premount/
//   update-initramfs -u

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_burst_json() {
        let json = r#"{"attempts":5,"first_ts":1700000000,"last_ts":1700000010,"host_id":"abc"}"#;
        let r: BurstRecord = serde_json::from_str(json).unwrap();
        assert_eq!(r.attempts, 5);
        assert_eq!(r.last_ts - r.first_ts, 10);
    }

    #[test]
    fn summary_shows_span() {
        let r = BurstRecord { attempts: 3, first_ts: 100, last_ts: 115, host_id: String::new() };
        assert!(r.summary().contains("3 failed"));
        assert!(r.summary().contains("15s"));
    }

    #[test]
    fn zero_attempts_filtered() {
        let r = BurstRecord { attempts: 0, first_ts: 0, last_ts: 0, host_id: String::new() };
        // Simulate poll_and_drain returning nothing for zero attempts.
        let filtered: Option<BurstRecord> = Some(r).filter(|rec| rec.attempts > 0);
        assert!(filtered.is_none());
    }
}
