<!-- SPDX-License-Identifier: Apache-2.0 -->
<!-- Spanish version: lang/es/tutorial.md -->

# Installation tutorial — sysentinel

Installs **everything**: the daemon (kernel-log watchdog + AI companion that
talks to your phone), its systemd service, and the kernel module behind
`/proc/sysentinel_metrics`.

> Aimed at systems with a Rust-enabled kernel (`CONFIG_RUST=y`) — Fedora 44
> with `kernel-devel` ≥ 7.1.8, for example. The flow is the same on other
> distributions; adapt the package names (`dnf` → `apt`/`pacman`) and the path
> to the kernel tree.

---

## 0. Requirements

```sh
# Fedora / RHEL:
sudo dnf install git gcc make pkgconfig openssl-devel rust-up rust-std-static \
                 systemd-devel kernel-devel kernel-headers bindgen rust-bindgen

# Python 3.10+ (kernel support tooling, if you need it)
```

You also need **Rust** for the daemon (via `rustup`):

```sh
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```

**Important:** for the kernel module, the `rustc` you use must be the **same
`rustc` that built your kernel** (see [Step 4 — kernel
module](#4-kernel-module-optional)).

---

## 1. Clone and build the daemon

```sh
git clone https://github.com/your-user/sysentinel
cd sysentinel
make daemon        # => cargo build --release (in daemon/)
```

The binary lands in `daemon/target/release/sysentinel-daemon`.

To check it all compiles and passes its tests:

```sh
cd daemon && cargo test
```

---

## 2. The phone app (the way out)

There is no bot on any public network: the only channel is your own phone,
connected directly to the daemon. Build and install the APK before going on, so
it is to hand when the pairing QR appears:

```sh
make apk-release          # both flavours, from the repository root
# or, with more control:
cd gui/android && gradle assembleModernRelease   # armv8a, modern UI
cd gui/android && gradle assembleLegacyRelease   # armeabi-v7a, plain UI

adb install -r gui/android/app/build/outputs/apk/modern/release/app-modern-release.apk
```

Needs a JDK, the Android SDK and **Gradle 9+** (8 cannot parse Java 25). There
is no wrapper in the repository: use your own `gradle`, or `make apk-release`,
which is the same thing with a configurable `GRADLE=`.

Release signing: `gui/android/keystore.properties` (kept out of git) points at
your `.jks`. Without that file the APKs come out UNSIGNED and `apksigner` will
say so.

> **Pairing and reaching are two different things.** Pairing happens ONCE, at
> home, with the phone on the same WiFi as the PC (section 6). From then on the
> link does not expire and does not depend on the network: Italy, Spain or Mars,
> it is still your PC. What does change with where you are is whether the phone
> can REACH the machine: on your own network it just works, and from outside you
> need a route you provide. Three of them work:
>
> - **VPN** (Tailscale/WireGuard) — the recommended one, with its own guide in
>   [`tutorial-tailscale.md`](tutorial-tailscale.md): `sudo tailscale up` on the
>   PC and the Tailscale app on the phone under the same account, `tailscale ip
>   -4` gives you the `100.x`, and that goes in `bind`. The same address works
>   at home and away, so nothing changes when you travel, and the port does not
>   exist outside your private network. Works under CGNAT too.
> - **Port forward + DDNS**: `bind` on the LAN IP and
>   `advertise = "home.duckdns.org:45678"` (the router's EXTERNAL port). Watch
>   out for *hairpin NAT*: on many routers this works from the street and fails
>   when you test it at home.
> - **A TCP tunnel** (`ngrok tcp 8443`, Cloudflare, SSH): `bind =
>   "127.0.0.1:8443"` and `advertise` = whatever the tunnel gives you. This is
>   the way out under CGNAT.
>
> The costs of each are written down plainly in `config.example.toml`. With no
> route at all the daemon queues the alerts and delivers them whole when you
> reconnect: it does not lose them.

---

## 3. Configure the daemon

```sh
cp daemon/config/config.example.toml daemon/config/config.toml
nano daemon/config/config.toml
```

> **Shortcut:** `sudo ./scripts/configure-credentials.sh` does this whole
> section without opening the file — it asks for the provider, reads the key
> without echoing it, generates the pairing key and validates the result. If you
> have no API and no credit, answer "none" and everything still works except the
> explanation.

At minimum, set these:

| Key | What to put |
|---|---|
| `[phone] enabled` | `true`, to bring the phone channel up |
| `[phone] bind` | The address the PHONE sees this machine on (e.g. `10.0.0.5:8443`). **Not `0.0.0.0`**: the QR carries it verbatim and the phone would not know where to dial |
| `[llm] backend` | `deepseek`, `openai`, `anthropic`, `gemini`, `local` or `none` |
| `[llm.deepseek] api_key` (or whichever backend you use) | Your provider's API key |
| `[persona] tone` / `language` | Tone and language of the answers |
| `[memory] memory_file` / `context_file` | Memory files; leave them under `/var/lib/sysentinel/*` |

Protect the file (it holds secrets):

```sh
chmod 600 daemon/config/config.toml
```

> Do **not** commit a `config.toml` with real secrets. The repository should
> only ever contain `config.example.toml` with placeholders.

---

## 4. Kernel module (optional)

> The daemon works without it (reading `/dev/kmsg` alone). The module exposes
> `/proc/sysentinel_metrics` with a metrics snapshot, and doubles as a worked
> example of a Rust module against `rust-for-linux`.

### 4.1 Check your kernel supports Rust

```sh
grep CONFIG_RUST /boot/config-$(uname -r)
# => CONFIG_RUST=y
```

If it says `# CONFIG_RUST is not set`, your kernel cannot load Rust modules:
build a kernel with `CONFIG_RUST=y`, or skip this step.

### 4.2 Use the kernel's exact `rustc`

The kernel's precompiled bindings (`/usr/src/kernels/<version>/rust/*.rmeta`)
**require the `rustc` they were built with**. A `rustc` of the same version from
a *different* source (rustup, say) fails with `E0514 "found crate core compiled
by an incompatible version of rustc"`.

On Fedora 44 this is not a problem: the exact compiler is already installed as
**`/usr/bin/rustc`**, and the module's `Makefile` pins `RUSTC`/`HOSTRUSTC` to
that path automatically. Just build (without touching `PATH`):

```sh
cd kernel_module
make
# => sysentinel: using rustc: /usr/bin/rustc
```

On other distributions: find out which one your kernel demands and make sure
that `rustc` is on `PATH` (or pass it explicitly: `make RUSTC=/path/to/rustc`):

```sh
grep CONFIG_RUSTC_VERSION_TEXT /boot/config-$(uname -r)
# => CONFIG_RUSTC_VERSION_TEXT="rustc 1.97.1 (…)(Fedora 1.97.1-1.fc44)"
```

### 4.3 Build and load

```sh
cd kernel_module
make            # MEI enabled by default (uses the tree at /lib/modules/$(uname -r)/build)
sudo make modules_install
sudo modprobe sysentinel_metrics write_gid=$(id -g sysentinel)
cat /proc/sysentinel_metrics
# uptime_s=12345 modules=64 mem_free_kb=204800 mem_total_kb=8388608 hypervisor=... ring3=intel-me me_fw=18.1.2204.0
#   - ring3=   … the module's HAL dispatcher result: intel-me | amd-psp | none
#   - me_fw=   … only when ring3=intel-me (ME reached over the kernel's MEI bus)
#   - psp=     … only when ring3=amd-psp (HSTI handshake via ccp platform-access)
sudo rmmod sysentinel_metrics
```

The file lives in `/proc` (not `/dev`) and **anyone can read it** — but not all
of it: `cr2` and `cr3` come back as `restricted` for anyone who is neither root
nor in `write_gid`. Those two are addresses — `cr2` is the last faulting address
and `cr3` the physical base of the page tables — and publishing them to every
local process is exactly what an exploit needs to defeat kernel address
randomisation. The rest of the line (uptime, ME version, PSP, SMM) is visible as
before.

It also accepts **privileged control commands on write** (`reboot`, `poweroff`,
`cr0_wp on|off`, `cr3=0x…`), gated by the `write_gid` group:

```sh
# Hand control to the service's group (the 'sysentinel' group id):
sudo modprobe sysentinel_metrics write_gid=$(id -g sysentinel)
# NEVER test with a bare reboot: confirm first. The bot demands a confirmation.
```

To load it at boot, install a `modprobe.d` entry:

```sh
echo 'sysentinel_metrics' | sudo tee /etc/modules-load.d/sysentinel.conf
```

### 4.4 If you change kernels

Rebuild against the new tree:

```sh
make clean && make
sudo make modules_install
sudo depmod -a
```

---

## 5. Install the daemon as a service

```sh
make install        # builds + scripts/install.sh (needs sudo)
```

`scripts/install.sh`:

1. Copies `sysentinel-daemon` to `/usr/local/bin/`, and the config **template**
   to `/etc/sysentinel/config.toml` (only if absent — **if you had already
   configured one, edit the copy under `/etc/sysentinel/`**).
2. Creates the `sysentinel` system user.
3. Creates `/var/lib/sysentinel` and `/var/log/sysentinel`.
4. Installs the `sysentinel.service` systemd unit.

> The unit carries real hardening: an unprivileged user,
> `NoNewPrivileges=true`, a read-only filesystem apart from the state paths, and
> only `CAP_SYSLOG` + `CAP_PERFMON` (ambient). It deliberately does not enable
> `PrivateNetwork`, because the daemon makes outbound HTTPS to the LLM provider
> and listens on `[phone] bind`.

### 5.1 Production configuration

```sh
sudo cp daemon/config/config.toml /etc/sysentinel/config.toml   # yours, with your secrets
sudo chown root:sysentinel /etc/sysentinel/config.toml
sudo chmod 640   /etc/sysentinel/config.toml   # the service user (group sysentinel) has to be able to READ it
```

ME/PSP needs no extra groups: the Intel ME version is read in ring-0 by the
`sysentinel_metrics` kernel module (through the kernel's MEI bus) and the daemon
picks it up from `/proc/sysentinel_metrics`; AMD's PSP/TPM is read from sysfs
with the right label per vendor. There is no udev rule and no group to set up.
On AMD hosts there is no MEI to query, and on Intel hosts no PSP is reported —
the code is platform-agnostic.

### 5.2 Privileged commands (optional, confirmation required)

The module also accepts control commands **on write**; the bot adds a two-step
confirmation (arm + `confirm` within 60 s) and is the only thing that writes. For
the service to be able to write, load the module with its group's GID:

```sh
sudo modprobe sysentinel_metrics write_gid=$(id -g sysentinel)
```

With that, from the app: `/cr0`, `/cr3`, `/cr4`, `/cr8` read control registers
(no confirmation, no tokens spent); `/reboot`, `/poweroff`, `/cr0 wp off`,
`/cr3=0x…` **arm** an action and demand `confirm`.

### 5.3 Start it

```sh
sudo systemctl enable --now sysentinel
systemctl status sysentinel
journalctl -u sysentinel -f
```

---

## 6. Pairing the phone

1. With no phone registered, the daemon draws a **QR on the machine's own
   console** at startup. If it has scrolled away, ask for it again:

   ```sh
   journalctl -u sysentinel -f | grep -i 'pair'
   ```

   `/pair` redraws it — always on the local console, never over the channel:
   sending the key through the channel that key opens would be backwards.

2. Scan it from the app. Nobody types 64 hex characters.
3. The app immediately generates a key inside the phone's TEE (StrongBox/Titan
   where the model has one) and registers it. From then on the machine also
   demands a signature from THAT handset and refuses any other, even the same
   model.
4. Once paired:
   - `/status` → system state (includes PMU context when `[pmu] enabled`).
   - `/resetcontext` → clears `context.txt` (the conversation context).
   - `/unpair` → forgets the registered phone.
   - Any plain message → asks the LLM, with memory and conversation.

5. **That is it, permanently.** From that moment you can go wherever you like:
   the link is between THIS machine and THAT phone, not between two IP
   addresses. If the address changes (you are away and coming in over the VPN),
   correct it in the app — tap `equipo: …` in the header — and everything else
   stays; there is no re-pairing. On the `legacy` flavour (armeabi-v7a) that is
   done over adb:

   ```sh
   adb shell am start -n org.sysentinel.app/.ChatActivity -e host 100.101.102.103 -e port 8443
   ```

Whoever can see the QR screen can read the key: that is why it stops being
enough as soon as a handset is registered. Privileged actions ask for your
fingerprint or your face on the phone, not a typed `YES` that somebody can
demand out loud or read over your shoulder.

If no QR appears: check `enabled = true` and that `bind` holds a real address
(not `0.0.0.0`) under `[phone]`.

---

## 7. Try it without a phone (optional)

```sh
RUST_LOG=debug /usr/local/bin/sysentinel-daemon \
    --config /etc/sysentinel/config.toml --dry-run --verbose
```

- `--dry-run` does not deliver alerts to the phone (useful for testing the LLM
  backend).
- `--verbose` prints every classified kmsg event to stdout.
- `RUST_LOG=debug` raises the log level.
- `--check-config` loads and validates the config, prints what it resolves to,
  and exits — without starting anything.

---

## 8. Troubleshooting

| Symptom | Cause / fix |
|---|---|
| `make[5]: *** No rule to make target 'sysentinel_metrics.o'` | The root `.rs` is not beside the `.o` (it must sit at the root of `kernel_module/`, rule `$(obj)/%.o: $(obj)/%.rs`). This repository already does that. |
| `E0514: found crate core compiled by an incompatible version of rustc` | `rustc` ≠ the kernel's (rustup vs `/usr/bin/rustc`). On Fedora the `Makefile` sorts it out; elsewhere use the kernel's exact build. |
| `error: no such file or directory: 'bindgen'` | Install `bindgen`: `cargo install bindgen-cli` or `sudo dnf install bindgen rust-bindgen`. |
| The app will not connect | `[phone] bind` points at an address the phone cannot reach (or is `0.0.0.0`). From the phone, check you can reach that `IP:port`. |
| The app says the machine rejects it | Another phone is already registered: the machine demands that one's signature. `/unpair` from the registered phone, or delete the registration on the machine, and scan again. |
| The app says the machine's key is not the one it saved | The daemon was reinstalled (new certificate), or something else is answering in its place. If it was you, delete the pairing and scan again. |
| No alerts arrive | Check `enabled = true`, `min_severity`, and that the LLM backend has a valid API key. |
| `error: while loading config` | A section or key is missing; compare against `config.example.toml`. |
| The module builds but `modprobe` says "invalid module format" | Built against a different kernel. `make clean && make && make modules_install && depmod -a`. |

---

## 9. Uninstall

```sh
make uninstall   # stops/removes the service + unloads the module (keeps secrets)
# also, if you want:
sudo rm -rf /etc/sysentinel /var/log/sysentinel
sudo userdel sysentinel
sudo rm -f /etc/modules-load.d/sysentinel.conf
```

---

## 10. Security (summary)

- `config.toml` at `chmod 640 root:sysentinel`; never commit it. The daemon
  refuses to start if it is writable by others, and warns loudly if it is
  world-readable. Rotate any API key you have ever exposed.
- The daemon runs unprivileged; only `CAP_SYSLOG` (kmsg), `CAP_PERFMON`
  (hardware PMU counters) and `CAP_KILL` (closing a session the owner denied).
  It degrades gracefully when `CAP_PERFMON` is missing.
- The kernel module exposes a world-readable snapshot with the address-bearing
  registers held back, and **only accepts control commands on write**, gated by
  the `write_gid` group (root only by default). Those commands sit behind the
  arm → `confirm` ritual: they never run on their own, and outside that flow the
  module refuses them on permissions.
- Pairing is bound to hardware. The QR's key gets a phone onto the channel; from
  the first registration onwards the machine also demands a signature from a key
  inside that handset's secure element, which cannot be copied out of it.
- Full policy, including what counts as a vulnerability here and what this tool
  admits it cannot protect you from: [`SECURITY.md`](SECURITY.md).
