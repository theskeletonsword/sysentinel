# gui/ — front-ends

> ## ⚠️ LICENCE: these follow the root, **not** the daemon ⚠️
>
> Everything under `gui/` is **Apache-2.0**, like `daemon/`. Neither front-end
> links against the kernel or against `kernel_module/`, so nothing here inherits
> the GPL obligation that the built `.ko` carries. See the root
> [`NOTICE`](../NOTICE) for the per-directory map.

Two front-ends, one daemon. Both exist for the same reason: so the owner does
not have to type into a chat window in a room full of colleagues.

| Path | Target | Talks to the daemon over |
|---|---|---|
| [`linux/`](linux/) | GTK4 desktop app | the local Unix socket (`[ipc]`) |
| [`android/`](android/) | APK, `arm64-v8a` + `armeabi-v7a` | the network, with a hardware-backed identity |

## They are quiet

Neither front-end raises a notification, a popup, a badge or a sound. That is a
security property and it is deliberate — the same reasoning as the duress
handling in `daemon/src/facenn.rs`:

> If somebody is standing over the owner, a machine (or a phone) that pops
> **"ROSTRO NO REGISTRADO"** onto the screen has just announced that it informed
> on them, and the owner is the one who pays for it.

Alerts stay on the out-of-band channel. A front-end is somewhere you *go and
look*, on purpose and in your own time.

## The phone is not just another screen

The Linux GUI is a convenience: it runs on the machine being watched, so it
proves nothing about who is using it. If someone is sitting at an unlocked
session, the GUI is theirs.

The Android app can be much more than that, because a phone can hold a key that
the machine cannot reach and that its owner must be *present* to use. That is
what makes it worth replacing a typed one-time code with a fingerprint: a code
can be read over a shoulder or demanded out loud, and a key bound to a secure
element with user authentication cannot be replayed by anyone who is not there.

See [`android/README.md`](android/README.md) for what the phone actually has to
prove, and `daemon/src/confirm.rs` for what the daemon accepts as proof.
