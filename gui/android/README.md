# gui/android — phone front-end

Apache-2.0. Two ABIs from one source tree, and they are not the same product:

| ABI | UI | Hardware identity |
|---|---|---|
| `arm64-v8a` | modern (Material 3) | TEE or StrongBox key + biometric |
| `armeabi-v7a` | plain, low-API | whatever the device actually has, often nothing |

## The conflict worth knowing about before you build this

A genuinely old device cannot do the interesting half. The APIs this design
rests on arrived long after the UI style the `armeabi-v7a` build is aiming at:

| Feature | Minimum Android |
|---|---|
| Hardware-backed Keystore | 6.0 (API 23) |
| Fingerprint API | 6.0 (API 23) |
| `BiometricPrompt` | 9.0 (API 28) |
| **StrongBox** (`setIsStrongBoxBacked`) | **9.0 (API 28)** |
| Key attestation | 7.0 (API 24), reliable from 8.0 |

So "Android 4.0-era UI" and "TrustZone-backed biometric confirmation" cannot
both be true of the same handset. Android 4.0 is API 14–15: no biometrics, no
hardware keystore, no attestation.

What `armeabi-v7a` **is** good for is a 32-bit device running a modern-enough
Android with a deliberately plain UI — those exist, and they can still hold a
TEE key. What it cannot do is turn a 2011 phone into a security token.

The daemon already assumes this. `daemon/src/confirm.rs` grades every
confirmation by what actually backed it and never assumes the best case, so a
phone that can only manage a typed code still works — it just says so.

## Claiming StrongBox is not the same as using it

A phone reporting "I used StrongBox" over the network is telling the daemon
something about itself, which is worth nothing on its own: whoever controls the
phone controls what it says. What is worth something is **key attestation** — a
certificate chain, rooted in a key Google signed at the factory, in which the
*secure element itself* states the security level of the key, whether user
authentication was required to use it, and whether that authentication was
biometric.

That chain is what the daemon verifies. Until it does, a confirmation is graded
at the level it can prove, not the level the phone asserts.

## Building

Verified building with **Gradle 8.13 + JDK 21 + AGP 8.13.0 + SDK 34**, which is
the supported combination and the one to use:

```sh
export JAVA_HOME=/usr/lib/jvm/temurin-21-jdk    # any JDK 17-21
export ANDROID_HOME=$HOME/Android/Sdk
gradle assembleDebug          # both flavours
gradle assembleModernDebug    # arm64-v8a, minSdk 28
gradle assembleLegacyDebug    # armeabi-v7a, minSdk 21
```

**On JDK versions**, because this costs an afternoon otherwise: Gradle 8.13
cannot parse Java 25 and fails with the version string as its entire error
message — no mention of Java, no hint. If the only JDK on the machine is 25 or
newer (including the one bundled in the Android Studio flatpak, which is also
25), either install a JDK 17-21 or use Gradle 9.1+. Both were verified here.

`local.properties` (holding `sdk.dir`) is machine-local and gitignored.

Output, as built here:

| APK | Size | ABI | minSdk |
|---|---|---|---|
| `app-modern-debug.apk` | 28 MB | arm64-v8a | 28 |
| `app-legacy-debug.apk` | 6.7 MB | — | 21 |

The legacy APK carries no `lib/` directory yet because there is no native code
in it; the `abiFilters` take effect once there is. The size gap is Compose,
which is why it is scoped to one flavour.

## Release builds

`assembleRelease` works out of the box and produces an **unsigned** APK, so CI
can check that a release build compiles without holding the key. Unsigned means
it will not install — `apksigner verify` says so plainly.

To sign it, create a key once and point a gitignored properties file at it:

```sh
keytool -genkeypair -v -keystore ~/sysentinel-release.jks \
    -alias sysentinel -keyalg RSA -keysize 4096 -validity 10000
```

```properties
# gui/android/keystore.properties — gitignored, never commit
storeFile=/home/you/sysentinel-release.jks
storePassword=…
keyAlias=sysentinel
keyPassword=…
```

Then `gradle assembleRelease`, or `make apk-release` from the repository root.

**Guard that key.** On Android the signing key *is* the app's identity: lose
control of it and somebody else can ship updates as you; lose the key itself
and you never can again. It matters more than usual here, because `ANDROID_ID`
is scoped per signing key and key attestation binds to the app — so replacing
it does not merely break updates, it re-pairs every handset.

R8 shrinks and obfuscates release builds, which is most of the size:

| APK | debug | release |
|---|---|---|
| modern | 28 MB | 3.1 MB |
| legacy | 6.7 MB | 1.5 MB |

`proguard-rules.pro` keeps `javax.crypto` and `java.security`, because the
providers are looked up by *name* at runtime (`AES/GCM/NoPadding`,
`SHA256withECDSA`, `ChaCha20-Poly1305`). R8 cannot see a string reach a class,
so without those rules the app would build cleanly and then fail on its first
frame. Verified after minification by checking those strings survive in the
DEX of both flavours.

## Cipher choice

The same rule the daemon already applies on x86 (`daemon/src/tpmkey.rs`), moved
to ARM: **AES-256-GCM** where the CPU has the ARMv8 crypto extensions, and
**ChaCha20-Poly1305** where it does not. `armeabi-v7a` devices usually fall in
the second group, which is exactly the case ChaCha was designed for.
