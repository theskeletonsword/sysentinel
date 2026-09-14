# gui/ — front-ends

> ## ⚠️ LICENCE: these follow the root, **not** the daemon ⚠️
>
> Everything under `gui/` is **Apache-2.0**, like `daemon/`. Neither front-end
> links against the kernel or against `kernel/linux/`, so nothing here inherits
> the GPL obligation that the built `.ko` carries. See the root
> [`NOTICE`](../NOTICE) for the per-directory map.

Two front-ends, one daemon. Both exist for the same reason: so the owner does
not have to type into a chat window in a room full of colleagues.

| Path | Target | Talks to the daemon over |
|---|---|---|
| [`linux/`](linux/) | GTK4 desktop app | the local Unix socket (`[ipc]`), or — as the **client** GUI — the network console over pinned TLS 1.3 + token |
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

## The desktop as a client

For years the Unix socket made the GTK app a *local* console only — fine for a
machine you sit in front of, useless for watching it from somewhere else. With
the network console (`[ipc] net_bind` in the daemon) the same window is also the
**client GUI**: run it on any machine with `SYSENTINEL_CONNECT` pointing at the
daemon's connect string, and it shows the exact same panels over TLS 1.3.

Two proofs, both mandatory:

- **pin** — the GUI only accepts the machine whose certificate it was given, so
  an attacker on the path cannot substitute their own key (no CA certifies a
  LAN/VPN address; the key IS the identity, same reasoning as the phone QR).
- **token** — after the handshake the daemon demands the `[ipc] net_token`
  before a byte of system state moves, so whoever found the port but not the
  secret learns nothing.

That is what makes the Windows `.ko` port realistic: the GUI `gui/linux` is
the exact client. Details and the printed connect string are in
[`linux/README.md`](linux/README.md).
