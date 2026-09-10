#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR GPL-2.0-or-later
#
# Prove the daemon's frame format and the Android client's agree.
#
# Two AEAD implementations "both being AES-256-GCM" is not enough: a different
# tag length or nonce convention gives you two halves that each pass their own
# tests and never interoperate once. So this seals on each side and opens on
# the other, for real, using the same javax.crypto calls the app makes.
#
# Needs a JDK. Skips cleanly without one.

set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."

if ! command -v javac >/dev/null || ! command -v java >/dev/null; then
    echo "phone-interop: no JDK — skipping"
    exit 0
fi

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

cat > "$work/Interop.java" <<'JAVA'
import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.security.SecureRandom;

/** The Android client's crypto path, standing alone. */
public class Interop {
    static final int NONCE = 12, TAG_BITS = 128;

    public static void main(String[] a) throws Exception {
        byte[] key = new byte[32];
        java.util.Arrays.fill(key, (byte) 0x42);

        // Open what Rust sealed.
        byte[] frame = fromHex(Files.readString(Path.of(a[0])).trim());
        byte[] nonce = java.util.Arrays.copyOfRange(frame, 0, NONCE);
        byte[] body  = java.util.Arrays.copyOfRange(frame, NONCE, frame.length);
        Cipher dec = Cipher.getInstance("AES/GCM/NoPadding");
        dec.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, "AES"),
                 new GCMParameterSpec(TAG_BITS, nonce));
        String opened = new String(dec.doFinal(body), StandardCharsets.UTF_8);
        if (!opened.equals("desde rust")) {
            throw new IllegalStateException("opened '" + opened + "'");
        }
        System.out.println("interop: opened Rust's frame");

        // Seal one for Rust.
        byte[] n2 = new byte[NONCE];
        new SecureRandom().nextBytes(n2);
        Cipher enc = Cipher.getInstance("AES/GCM/NoPadding");
        enc.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"),
                 new GCMParameterSpec(TAG_BITS, n2));
        byte[] sealed = enc.doFinal("desde java".getBytes(StandardCharsets.UTF_8));
        byte[] out = new byte[NONCE + sealed.length];
        System.arraycopy(n2, 0, out, 0, NONCE);
        System.arraycopy(sealed, 0, out, NONCE, sealed.length);
        Files.writeString(Path.of(a[1]), toHex(out));
    }

    static byte[] fromHex(String s) {
        byte[] b = new byte[s.length() / 2];
        for (int i = 0; i < b.length; i++)
            b[i] = (byte) Integer.parseInt(s.substring(i * 2, i * 2 + 2), 16);
        return b;
    }
    static String toHex(byte[] b) {
        StringBuilder sb = new StringBuilder();
        for (byte x : b) sb.append(String.format("%02x", x));
        return sb.toString();
    }
}
JAVA

echo "==> rust seals"
SYSENTINEL_INTEROP_OUT="$work/from_rust.hex" \
    cargo test --manifest-path daemon/Cargo.toml \
    phone::tests::frames_interoperate_with_the_jvm -- --nocapture >/dev/null

echo "==> jvm opens it, and seals a reply"
javac -d "$work" "$work/Interop.java"
java -cp "$work" Interop "$work/from_rust.hex" "$work/from_java.hex"

echo "==> rust opens the jvm's reply"
SYSENTINEL_INTEROP_IN="$work/from_java.hex" \
    cargo test --manifest-path daemon/Cargo.toml \
    phone::tests::frames_interoperate_with_the_jvm -- --nocapture 2>&1 | grep -E "interop:|test result"

echo "phone-interop: OK — both sides open each other's frames"
