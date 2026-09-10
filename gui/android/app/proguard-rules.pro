# SPDX-License-Identifier: Apache-2.0
#
# R8 keep rules.
#
# This app reflects on almost nothing — the wire format is hand-built org.json
# rather than a reflective serialiser — so the default rules cover most of it.
# What is kept below is kept for a reason, each stated.

# Crypto providers are looked up by name at runtime ("AES/GCM/NoPadding",
# "SHA256withECDSA", "ChaCha20-Poly1305"). R8 cannot see those strings reach a
# class, so without this the provider machinery can be stripped and the app
# fails at the first frame instead of at build time.
-keep class javax.crypto.** { *; }
-keep class java.security.** { *; }
-dontwarn javax.crypto.**

# Our own message and protocol types are constructed reflectively by neither
# side, but they carry the wire contract; keeping their names makes a crash
# report from a released build readable.
-keepnames class org.sysentinel.app.Message
-keepnames class org.sysentinel.app.PhoneLink$Welcome
-keepnames class org.sysentinel.app.PhoneLink$Identity
-keepnames class org.sysentinel.app.DeviceIdentity$Identity

# Line numbers in stack traces, with the source file hidden. A released build
# should not name its files, but a trace nobody can read is a bug that never
# gets fixed.
-keepattributes SourceFile,LineNumberTable
-renamesourcefileattribute SourceFile
