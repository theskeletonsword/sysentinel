<!-- SPDX-License-Identifier: Apache-2.0 -->
<!-- Spanish version: lang/es/tutorial-tailscale.md -->

# Linking the host and the phone over Tailscale

This is the recommended way to reach your machine from outside, for one reason:
**the Tailscale address is the same on your sofa and on Mars.** The QR you scan
once still works from another continent, nothing needs reconfiguring when you
travel, and the daemon's port does not exist outside your private network —
internet-wide scans never even see it. It also works under CGNAT, which is
where port forwarding is simply not possible.

If you prefer the other two routes (port forward + DDNS, or a tunnel like
ngrok), they are in `daemon/config/config.example.toml` with their costs
written down plainly. This is the one that will bother you least.

> **What it costs, before you start.** Tailscale coordinates keys through a
> server of theirs. The traffic does **not** pass through it — it is WireGuard
> point to point, and when there is no direct route the DERP relay only sees
> ciphertext — but that server does know which machines you have, what they are
> called, and when they connect. If that is too much, there is a section at the
> end with the alternatives.

---

## What you end up with

```
   Phone (client)                           PC (host)
   ┌────────────────┐                       ┌────────────────────────┐
   │ sysentinel app │                       │ sysentinel-daemon      │
   │ Tailscale app  │                       │ tailscaled             │
   └───────┬────────┘                       └───────────┬────────────┘
           │  100.x.y.z:8443                            │
           │  TLS 1.3 + sealed frames                   │
           └──────────── WireGuard ─────────────────────┘
                   (direct, or an encrypted DERP relay)
```

Four things have to be true at once, and this tutorial is mostly checking them
in order:

1. Both machines are on **the same Tailscale account** (mistake number one).
2. `[phone] bind` points at the **PC's Tailscale IP**, not its LAN address.
3. `tailscaled` starts **before** the daemon.
4. The phone scanned the QR **after** all of the above.

---

## 1. Tailscale on the PC

On Fedora:

```sh
sudo dnf install tailscale
sudo systemctl enable --now tailscaled
sudo tailscale up
```

`tailscale up` prints a URL. Open it, sign in, and **note which account you
used** — that is the detail you have to repeat on the phone.

Check it came up, and note your address:

```sh
tailscale status
tailscale ip -4        # => 100.101.102.103   ← this is the one that matters
```

That `100.x` is yours for as long as the machine stays in the tailnet. It does
not change from network to network: that is the whole trick.

## 2. Tailscale on the phone

Install the Tailscale app from Play Store (or the APK from tailscale.com if you
do not use Play), open it, and sign in **with the same account as above**. That
is all — no exit nodes, no subnet routers, no MagicDNS needed.

From the PC, check the phone has joined:

```sh
tailscale status        # the phone has to appear in the list
tailscale ping <phone-name>
```

If `tailscale ping` reports a direct address, they are talking point to point.
If it says `via DERP`, that works too — the relay only moves ciphertext it
cannot read — but latency is worse. Neither case needs fixing.

## 3. Point the daemon at the Tailscale address

Quickest, without opening the config:

```sh
sudo ./scripts/configure-credentials.sh --bind "$(tailscale ip -4):8443"
```

Or by hand, in `/etc/sysentinel/config.toml`:

```toml
[phone]
enabled = true
bind    = "100.101.102.103:8443"   # the 100.x from `tailscale ip -4`
```

Three things people get wrong here:

- **`bind` is the Tailscale IP, not the LAN one.** Put the 192.168.x there and
  it works at home and stops working the moment you leave, which is exactly
  what this was meant to avoid.
- **Do not use `0.0.0.0`.** That is a listen address, not a destination; the QR
  carries it verbatim and the phone would not know where to dial. The daemon
  tells you.
- **You do not need `advertise`.** That is for when the QR has to say something
  other than where you listen — a tunnel, a DDNS name. Here you listen exactly
  where the phone dials.

With MagicDNS you can put the name in `advertise` if you prefer reading it
(`advertise = "my-pc.tailnet-1234.ts.net:8443"`), but `bind` stays the IP: that
is what the machine actually has, and what can actually be listened on.

## 4. Start it, and scan the QR

```sh
sudo systemctl restart sysentinel
sudo journalctl -u sysentinel -f
```

If you have never started it, `enable --now` rather than `restart`.

With no phone registered, the daemon draws the QR on the machine's own console.
Scan it **from the sysentinel app**, not from the Tailscale one.

That QR carries three things: the address, the pairing key, and the **machine's
TLS fingerprint**. The app requires all three — a QR without the fingerprint is
refused rather than connecting blind. If you are coming from an earlier version
of this project, your old pairing is not valid: scan again.

Right after scanning, the phone generates a key inside its TEE (StrongBox/Titan
where the model has one) and registers it. From then on the machine also
demands a signature from *that* handset and refuses any other, even the same
model with a copied pairing key.

---

## Checking it worked

First, before blaming anything: both machines on the same tailnet.

```sh
tailscale status
# 100.101.102.103  my-pc     your-account@  linux    -
# 100.104.105.106  my-phone  your-account@  android  -

tailscale ping my-phone
# pong from my-phone (100.104.105.106) via 203.0.113.9:39380 in 117ms
```

`pong … via <IP>:<port>` is a direct connection. `via DERP` is fine too.

From the PC, that the port is listening on the right address:

```sh
ss -ltnp | grep 8443
# LISTEN 0 128 100.101.102.103:8443 ...
```

From the phone, before blaming the app: open the Tailscale app and check the PC
shows as connected. With Termux, `nc -vz 100.101.102.103 8443` answers in one
line.

And in the daemon's log, the line that confirms both layers:

```
phone: listening on 100.101.102.103:8443 — direct, no relay, no third party
phone: authenticated client (app 0.1.0)
```

---

## When something does not work

| Symptom | What is happening |
|---|---|
| `phone: 100.x.y.z:8443 does not exist yet — waiting for the interface` | The daemon started before `tailscaled`. It waits up to a minute on its own and the unit already orders itself after `tailscaled.service`, so this normally resolves itself. If it persists: `systemctl is-active tailscaled`. |
| `phone: cannot listen on … Cannot assign requested address` | The `100.x` in the config is not this machine's (or Tailscale is down). `tailscale ip -4` and fix it. |
| The app says it cannot connect | Check the Tailscale app on the phone: if the tailnet is down there, this is not a sysentinel problem. Then `tailscale status` on the PC to see whether the phone appears. |
| The app says the machine's key is not the one it saved | Either you reinstalled the daemon (and it minted a new certificate), or something else is answering in its place. If it was you: delete the pairing in the app and scan again. If it was not you, that message is exactly what this tool exists to give you. |
| Everything works but it is slow | `tailscale ping <phone>`: `via DERP` means you are going through a relay. Opening outbound UDP 41641 on the router usually fixes it; if not, it still works, just slower. |
| Different accounts | Mistake number one. `tailscale status` on the PC does not list the phone. Sign out in the phone app and sign in with the same account. |

**About the firewall, on Fedora specifically:** Fedora Workstation's default
`FedoraWorkstation` zone already allows inbound TCP 1025-65535, so 8443 is open
and there is nothing to do. On Fedora **Server** (the `FedoraServer` zone) or
with the `public` zone it is not, and then:

```sh
# The right move is opening it ONLY on the Tailscale interface, not everywhere:
sudo firewall-cmd --permanent --zone=trusted --change-interface=tailscale0
sudo firewall-cmd --reload
```

Putting `tailscale0` in the `trusted` zone is what Tailscale itself recommends,
and it beats opening the port outright: the port becomes reachable from your
tailnet and from nowhere else.

---

## Tightening it further (optional, and worth it)

By default, on a personal tailnet **every one of your devices can talk to every
other**. If you have more machines in there, you can let only the phone reach
the daemon's port, by editing the ACLs in the Tailscale console:

```jsonc
{
  "acls": [
    // Your phone to the daemon's port, and nothing else towards that machine.
    { "action": "accept", "src": ["tag:phone"], "dst": ["tag:watched-pc:8443"] }
  ],
  "tagOwners": {
    "tag:phone":       ["autogroup:admin"],
    "tag:watched-pc":  ["autogroup:admin"]
  }
}
```

Then tag each machine (`tailscale up --advertise-tags=tag:watched-pc`). It is
not essential — the pairing key and the phone's signature already decide who
gets to speak — but it narrows who the socket even answers, and that is one
surface fewer.

Two more, free:

- **Key expiry.** Node keys expire every 180 days by default and need
  reauthenticating. For the PC watching your house that is an outage at the
  worst possible moment: disable it for that node in the console (*Disable key
  expiry*).
- **Tailnet lock**, if you are serious: a new node has to be signed by a
  trusted one, so not even somebody with access to your Tailscale account can
  add a machine to your tailnet without touching your key.

---

## If you do not want somebody else's coordinator

As said at the top: the traffic does not go through Tailscale, but their
coordination server does know which nodes you have and when they connect. Two
ways out:

- **Headscale** — Tailscale's control plane, reimplemented in the open, running
  on your own machine. The official Tailscale apps work against it. This is the
  option if you want exactly this setup without the third party.
- **Plain WireGuard** — no coordinator at all. You lose the automatic
  discovery, the NAT traversal and the roaming, which is precisely what makes
  Tailscale comfortable; in exchange nobody else is in the picture. Configure
  the tunnel, put `bind` on the PC's WireGuard address, and the rest of this
  tutorial applies unchanged.

Either way, nothing changes for sysentinel: `bind` points at the tunnel
interface's address and the QR is scanned the same.

---

## What still protects you if the tunnel fails

Tailscale is how you *reach* the machine, not how whoever reaches it is
*authenticated*. Even inside your tailnet, three things have to be true at once
before anything talks to your daemon:

1. Complete a **TLS 1.3** handshake whose key the phone pinned at pairing.
2. Open a frame sealed with the **pairing key**.
3. Sign a challenge with the key living **inside that phone's TEE**.

Any other node on your tailnet — or Tailscale itself — has none of the three.
That is why the channel does not lean on the VPN for its security: it leans on
it for its reach.

See also: [`tutorial.md`](tutorial.md) for the full install,
[`SECURITY.md`](SECURITY.md) for what is in scope and what is not, and the
`[phone]` section of `daemon/config/config.example.toml` for the other two
remote-access routes with their costs.
