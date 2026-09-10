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

## Cipher choice

The same rule the daemon already applies on x86 (`daemon/src/tpmkey.rs`), moved
to ARM: **AES-256-GCM** where the CPU has the ARMv8 crypto extensions, and
**ChaCha20-Poly1305** where it does not. `armeabi-v7a` devices usually fall in
the second group, which is exactly the case ChaCha was designed for.
