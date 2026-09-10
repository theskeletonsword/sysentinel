# sysentinel

> ## ⚠️ LICENCE IS **PER-DIRECTORY** — READ THIS BEFORE YOU COPY ANYTHING ⚠️
>
> This repository is **not uniformly Apache-2.0.** Three directories are
> dual-licensed **MIT OR GPL-2.0-or-later**, and one of those is the kernel
> module — where the GPL half becomes binding the moment you build it.
>
> | Directory | Licence | Copying it into a proprietary/Apache-only product |
> |---|---|---|
> | `daemon/` | **Apache-2.0** | ✅ fine |
> | `gui/` | **Apache-2.0** | ✅ fine |
> | `scripts/` | **MIT OR GPL-2.0-or-later** | ✅ fine — take the MIT option |
> | `ramdisk/` | **MIT OR GPL-2.0-or-later** | ✅ fine — take the MIT option |
> | **`kernel_module/`** | **MIT OR GPL-2.0-or-later** | ⛔ **the built `.ko` is GPL — see below** |
>
> **The trap is `kernel_module/`.** The *source* is dual-licensed, so you may
> take the MIT option for the source alone. But the moment it is **built and
> linked against the Linux kernel** — which is the only way it is useful — the
> resulting `sysentinel_metrics.ko` is a work combined with GPL-2.0 code and
> **must be distributed under GPL-2.0**, with source. Do not ship that binary
> inside a proprietary product.
>
> Both halves of that dual licence are load-bearing and neither is decorative:
> the **GPL** half is what lets the module bind `EXPORT_SYMBOL_GPL` symbols (a
> module Linux does not consider free is refused them outright); the **MIT**
> half is what keeps the source permissively reusable.
>
> Licence texts live in the directories themselves: `kernel_module/LICENSE-GPL`
> + `kernel_module/LICENSE-MIT`, `ramdisk/LICENSE-GPL` + `ramdisk/LICENSE-MIT`,
> `daemon/LICENSE`. Every source file carries an `SPDX-License-Identifier`
> header, which is authoritative for that file. Full detail in
> [`NOTICE`](NOTICE) and in [Licence](#licence) below.
>
> **The daemon is not a derivative work of the kernel** — it is ordinary
> user-space talking over syscalls, sysfs and `/proc`. That is checked
> mechanically by `make licence-audit LINUX_SRC=/path/to/linux`.

**Your PC's AI companion** — a portable, transparent Linux system daemon that
watches your kernel in real-time and lets you talk to your machine over Telegram.

```
     Kernel (ring 0)                 User-space (ring 3)
  ┌─────────────────────┐         ┌─────────────────────────────────────────┐
  │ sysentinel_metrics  │──sysfs──│ sysentinel-daemon                       │
  │  ├─ hypercalls      │         │  ├─ kmsg watcher (OOM / panic / segfault)│
  │  │  vmcall/vmmcall  │         │  ├─ Intel ME (via /proc/sysentinel_metrics)│
  │  │  hvc (ARM64)     │         │  ├─ AMD PSP  (sysfs/TPM)                │
  │  └─ MEI mei_cl_drv  │         │  ├─ PMU  perf_event_open                │
  └─────────────────────┘         │  ├─ LLM backend switcher                │
                                  │  │   Anthropic · OpenAI · DeepSeek      │
  Intel ME (bus mei_me) ──────────│  │   Gemini · local GGUF                │
  AMD PSP  (CPUID/sysfs)──sysfs───│  └─ Telegram bot                        │
                                  │      pairing token · whitelist · chat    │
                                  └─────────────────────────────────────────┘
```

The repository is **Apache 2.0**, and the daemon follows it. The kernel
module is **MIT OR GPL-2.0-or-later**: it keeps a GPL option because it links
against GPL-only kernel symbols — declare the GPL flavour when building it.

---

## What it does

| Feature | Description |
|---|---|
| **Kernel event watching** | Tails `/dev/kmsg` in real-time; detects OOM kills, kernel panics, segfaults, and oopses |
| **LLM explanation** | Asks a configurable AI to explain the event in plain language, in your language and tone |
| **Telegram alerts** | Sends an alert to your paired Telegram chat |
| **Interactive chat** | Talk to your PC via Telegram — ask "why is my system slow?", "what happened last night?", "how's my CPU?" |
| **Pairing flow** | One-time 5-minute token pair; strict `chat_id` whitelist thereafter |
| **Intel ME status** | Live ring −3 alliance: the module binds the MKHI MEI client and re-runs `GET_FW_VERSION` over the HECI bus on every windowed `/proc` read (`me_live=ok(v18.1.2204.0,rt=…ms)`, `me_drift` flags version drift) |
| **AMD PSP status** | Real PSP handshake (`PSP_CMD_HSTI_QUERY` → fused HSTI word via the ccp driver's exported platform-access API), shown as `psp=up(hsti=…,flags=tsme,rt=…ms)`; degrades to vendor presence where the mailbox is firewalled |
| **Presence ladder (no camera needed)** | `/definehome presencia`. Face recognition answers "who is there" only while a camera exists. Without one it drops to voice; without a microphone either it stops claiming identity and describes the *situation* instead. Below all of it sits the only rung that is not a heuristic: asking the owner in the paired chat, which needs no sensor on the host at all |
| **Every input bus, not just USB** | Input devices come from `/proc/bus/input/devices`, so **PS/2 (i8042), I2C, Bluetooth, SPI and serial** are seen alongside USB. That is not a detail: this laptop's own keyboard is PS/2, and so is QEMU's default — a USB-only scan misses the keyboard on most laptops and every stock VM. "Can type" is decided by counting the `KEY=` bitmap (≥32 keys), because the `kbd` handler alone also matches the power button, the video-bus hotkeys and the PC speaker |
| **Device watcher — asks first** | A keyboard, disk or phone that appears after the accepted baseline raises a **question**, not an accusation: the likeliest reason a disk just appeared is that you plugged it in. Answering "yes" *is* the accept — the baseline is exactly the set you vouch for. Spoken in the configured persona like every other passive alert |
| **Volume identification** | An attached disk is identified by on-disk signature without mounting it: LUKS1/2, ext2/3/4, btrfs, XFS, F2FS, NTFS, exFAT, FAT32/16/12, HFS/HFS+, APFS, ISO 9660, UDF, SquashFS, swap, LVM2, ZFS. Android/camera **MTP** is caught on the USB side, since it is not a block device at all. VeraCrypt and plain dm-crypt write no signature by design, so they are found by entropy instead and reported as *opaque* — which a randomly-wiped disk also is, and the wording says so |
| **Face scene, not face count** | The camera verdict classifies *who is missing*, because that decides the response. Owner alone: nothing. **Owner + strangers: possible coercion** — the alert goes to the chat and the host deliberately does nothing visible, since a machine that powers itself off in front of whoever is standing over you has announced that it informed on you. One stranger with no owner: opportunistic access. **Two or more with no owner: loss of custody** — people don't gather around someone else's laptop by accident; two is the signature of a procedure. Faces far smaller than the largest are discarded as posters or screens |
| **Ring −3 service surface** | `/definehome mei` enumerates every MEI/HECI client the ME publishes — protocol version, max message size, connection limit, fixed-address clients — plus which kernel driver has claimed each one and who can open `/dev/mei0`. A client no driver claims is a firmware service nothing on the host uses yet anyone with the device node can reach. Read entirely from sysfs: no root, no HECI traffic, nothing disturbed |
| **Ring −3 HAL** | HAL dispatcher (kernel `ring3.rs` mirrors daemon `hal.rs`): **Intel → ME/HECI/MKHI**, **AMD → PSP** (ccp platform-access HSTI), **neither (old/VIA/ARM) → no ring −3 channel engaged**; stable silicon tokens reinforce `/definehome`, `platform_label()` + TPM/chipset evidence for the bootkit audit |
| **Ring −2 SMM** | Firmware **posture, not pokes**: the channel **provably never raises an SMI** — it only reads the tables the firmware publishes. `smm on` performs a read-only ACPI scan: FADT `smi_command` + documented command values (`smm_iface=fadt-smi@0x…`) and the WSMT SMM-mitigation table (`smm_wsmt=0x…(list)`); a firmwware with a published SMI bridge but no WSMT protections is exactly what an SMM bootkit needs. Latency instrument narrowed to the ring −1 hypercall (`hvm_lat=…us`); `ro=ok|dirty` passively watches module rodata. No outb/inb to any APM port exists in the code by construction |
| **TPM key** | A `/dev/urandom` AEAD key sealed inside the physical TPM accompanies the fingerprint — AES-256-GCM on AES-NI/VAES CPUs, else ChaCha20-Poly1305 (fresh nonce, never reused); fingerprint-only fallback when there's no TPM |
| **Bootkit audit** | `/bootkit` (or `/definehome audit`): UEFI vars, Secure Boot, kernel lockdown, taint, LSTAR hook, hypervisor, ME/PSP, dmesg + integrity, with hedged verdicts |
| **PMU counters** | Reads CPU cycles, IPC, LLC misses, branch mispredictions, context switches via `perf_event_open`. Adapts to `perf_event_paranoid` (and `CAP_PERFMON`) by probing rather than guessing, keeping the widest scope actually permitted instead of giving up |
| **Hybrid CPU split** | On a heterogeneous CPU (Intel P/E, ARM big.LITTLE) the counters are reported **per core type**, so a busy E-core cluster and an idle P-core cluster are not averaged into a number describing neither. Core types come from the silicon itself — `CPUID.1AH` per the Intel SDM, `MIDR_EL1` per the Arm ARM — which cross-checks the kernel's own PMU grouping |
| **Hypercalls** | Kernel module issues `vmcall`/`vmmcall`/`hvc` with CPUID-based hypervisor detection |
| **Persona** | Configure the AI's tone per `config.toml` — formal, colloquial, regional slang, whatever |
| **Multi-backend LLM** | Switch between Anthropic Claude, OpenAI, DeepSeek, Gemini, or a local GGUF model |

---

## Directory tree

```
sysentinel/
├── README.md
├── tutorial.md                     Step-by-step walkthrough
├── LICENSE                         Apache 2.0 licence text
├── NOTICE
├── Makefile                        Top-level: daemon + kernel module + ramdisk tools
│
├── kernel_module/                Ring 0 — Rust kernel module (MIT OR GPL-2.0-or-later)
│   ├── Kbuild · Makefile · README.md · LICENSE-MIT · LICENSE-GPL
│   ├── sysentinel_core.rs        Rust root: snapshot + rs_render_snapshot / rs_exec_command
│   ├── hypercall.rs              vmcall / vmmcall / hvc + CPUID detection
│   ├── ring3.rs                  Ring −3 HAL dispatcher: intel-me → MEI, amd-psp → PSP, none → neither
│   ├── smm.rs                    Ring −2 SMM posture (ACPI-only): FADT smi_command + WSMT scan, hvm_lat, rodata watch
│   ├── mei_driver.rs             Intel MEI mei_cl_driver (ring-0 ME access; live MKHI re-query)
│   ├── psp.rs                    AMD PSP: vendor presence + live HSTI handshake
│   └── src/                      C shims and watchers
│       ├── proc_entry.c          procfs shim: /proc/sysentinel_metrics (no /dev node)
│       ├── mei_shim.c            C glue for mei_cl_bus.h API
│       ├── psp_shim.c            C glue for the ccp driver's platform-access API
│       ├── smm_shim.c            Read-only ACPI table reader (acpi_gbl_FADT + WSMT) — zero port I/O
│       ├── hypercall_watcher.c   Hypercall/VM-exit observation
│       ├── rootkit_defender.c    Syscall-table / LSTAR integrity checks
│       └── triplefault.c         Triple-fault trip-wire
│
├── daemon/                       Ring 3 — user-space daemon (Apache-2.0)
│   ├── Cargo.toml · Cargo.lock · LICENSE · README.md
│   ├── config/config.example.toml
│   └── src/
│       ├── main.rs               Entry point, thread orchestration
│       ├── config.rs             TOML config loading + validation
│       ├── settings.rs           Live, chat-mutable runtime settings
│       ├── bot.rs                Interactive bot: pairing, whitelist, AI chat
│       ├── telegram.rs           Outbound sendMessage / sendPhoto helpers
│       ├── exec.rs               Gated `/exec` with ARM → confirm + process-group kills
│       │
│       ├── kmsg.rs               /dev/kmsg real-time reader
│       ├── dmesg.rs              Ring-buffer snapshots
│       ├── classify.rs           OOM / panic / segfault / oops classifier
│       ├── kernel_snap.rs        Kernel integrity snapshot (LSTAR, CR0.WP, taint)
│       ├── modulewatch.rs        Module load/unload watcher + on-disk .ko hunt
│       ├── hyperwatch.rs         Hypervisor presence / VM-exit watch
│       ├── selinux.rs            AVC denial watcher
│       ├── secureboot.rs         Secure Boot + lockdown state
│       ├── bootkit_audit.rs      Bootkit auditor: ring 3 → ring −3 boot-chain checks
│       │
│       ├── hal.rs                Ring −3 HAL dispatcher: ME/HECI/MKHI · PSP · TPM · chipset
│       ├── ring3.rs              Kernel-module channel (/proc/sysentinel_metrics)
│       ├── mei.rs                Intel ME (HECI /dev/mei0) + AMD PSP (sysfs)
│       ├── meiclients.rs         MEI client directory + who can reach the bus
│       ├── tpmkey.rs             TPM-sealed AEAD key (AES-256-GCM / ChaCha20-Poly1305)
│       ├── detecthome.rs         `/definehome` hardware fingerprint (serials + silicon tokens)
│       │
│       ├── luks.rs               LUKS-decrypt tripwire ("¿fui yo?") over initramfs evidence
│       ├── loginwatch.rs         Login success/failure watcher + intrusion capture
│       ├── camera.rs             Webcam evidence via sysentinel-cam
│       ├── fhash.rs              Perceptual face hashing (pHash/DCT + wHash/Haar) — fallback
│       ├── facenn.rs             Neural face verification: runs the musl tool from glibc
│       │
│       ├── pmu.rs                PMU counters via perf_event_open; paranoid ladder + hybrid dispatcher
│       ├── coretype.rs           Clean-room core-type oracle (CPUID.1AH / MIDR_EL1)
│       ├── procinfo.rs           /proc/stat + per-process CPU/RSS sampling
│       ├── hwinfo.rs             CPU / GPU / RAM / firmware inventory
│       ├── hwdiag.rs             lm-sensors + PCI + firmware periodic summary
│       ├── battery.rs            Battery health and charge watch
│       ├── memory.rs             Long-term memory + rolling conversation context
│       ├── mood.rs               Persona mood state
│       ├── undervolt.rs          Undervolt / voltage-shift evidence
│       └── llm/
│           ├── mod.rs            LlmBackend trait + factory + fallback chains
│           ├── models.rs         Per-provider model catalogue
│           ├── anthropic.rs      Anthropic Messages API
│           ├── openai.rs         OpenAI Chat Completions
│           ├── deepseek.rs       DeepSeek (OpenAI-compatible)
│           ├── gemini.rs         Google Gemini generateContent
│           └── local.rs          Local GGUF via llama-cpp-2 (feature-gated)
│
├── ramdisk/                      Initramfs tools — static musl binaries (MIT OR GPL-2.0-or-later)
│   ├── Cargo.toml                Workspace root (cam + face)
│   ├── cam/src/main.rs           sysentinel-cam: V4L2 snapshot, no external deps
│   ├── face/                     sysentinel-face: SCRFD detect + MobileFaceNet embed (tract/ONNX)
│   │   ├── src/{main,nn,scrfd,align}.rs
│   │   └── models/               ONNX weights (gitignored; fetch-face-models.sh)
│   └── 91sysentinel/             dracut module
│       ├── module-setup.sh       Hook installation + binary/module inclusion
│       ├── sysentinel-init.sh    pre-udev: load sysentinel_metrics + uvcvideo
│       ├── sysentinel-precrypt.sh pre-trigger: capture BEFORE the LUKS prompt
│       └── sysentinel-luks.sh    pre-pivot: fallback capture + evidence mirroring
│
└── scripts/
    ├── sysentinel.service        systemd unit
    ├── install.sh · uninstall.sh
    ├── install-dracut.sh         Stage 91sysentinel + regenerate the initramfs
    ├── fetch-face-models.sh      Download the ONNX face models
    └── llama-link.sh             Link a local llama.cpp build for the GGUF backend
```

---

## Quick start

### 1 — Daemon (user-space)

```sh
# Install Rust toolchain (https://rustup.rs) if not present.
cargo build --release -p sysentinel-daemon --manifest-path daemon/Cargo.toml

# Install binary, config template, systemd unit
sudo ./scripts/install.sh

# Edit config (Telegram token + LLM API key)
sudo $EDITOR /etc/sysentinel/config.toml

# Start service
sudo systemctl enable --now sysentinel

# Watch for the pairing token
journalctl -u sysentinel -f
# → Look for: "sysentinel PAIRING TOKEN: SYN-XXXXXXXX"
# → In Telegram, open your bot: it will ask for the token. Send it.
# → The bot answers "Token accepted", then asks you to type YES to confirm.
# → Reply YES, and you are paired.
```

### 2 — Kernel module (optional, ring 0)

Requires a kernel built with `CONFIG_RUST=y` (rust-for-linux).

```sh
# Default build (metrics device + hypervisor detection):
make KDIR=/lib/modules/$(uname -r)/build -C kernel_module

# With Intel ME kernel client (requires CONFIG_INTEL_MEI=y):
make KDIR=/lib/modules/$(uname -r)/build -C kernel_module MEI=y
# With live AMD PSP handshake via the ccp driver (default PSP=y):
make KDIR=/lib/modules/$(uname -r)/build -C kernel_module PSP=y
# Metric-only (no MEI/PSP): make MEI=n PSP=n -C kernel_module

# Load
sudo insmod kernel_module/sysentinel_metrics.ko
cat /proc/sysentinel_metrics
# → uptime_s=3600 modules=72 hypervisor=KVM/Intel_VT-x kvm_features=0x000001ff ring3=intel-me me_fw=18.0.1234.0 smm=off ro=ok(rt=0us)

# Unload
sudo rmmod sysentinel_metrics
```

---

## Interactive Telegram bot

Once paired, you can send any message to your bot:

| You send | Bot replies |
|---|---|
| `/start` | Options menu |
| `/status` | Uptime, load, memory, kernel version |
| `/hardware` | lscpu-style CPU, GPU (nvidia-smi if present), PCI bus, TSC/rdtscp |
| `/lsblk` `/lsusb` `/lsmod` `/pci` | Block devices, USB devices, kernel modules, display adapter |
| `/alerts` | Last 10 kernel alerts logged since daemon start (dmesg) |
| `/selinux` | List pending SELinux AVC denials |
| `/selinux explain <id>` | What a denial is about (`audit2allow` preview) |
| `/selinux allow <id>` | Permit it — ARMED, needs your `confirm` |
| `/selinux deny <id>` | Ignore a denial |
| `/memory` `/showmemory` | Show `context.txt` / `memory.txt` |
| `/remember <fact>` | Append a durable fact to `memory.txt` |
| `/dmesg` | Read the kernel ring buffer and report what matters (save the `dmesg`) |
| `/undervolt` | Honest V/F curve status — verified per vendor (Intel/AMD/Zhaoxin) |
| `/secureboot` | Firmware Secure Boot state + exact steps to load the module (signed/unsigned) |
| `/battery` | Battery status on a notebook; "no aplica" on a desktop tower |
| `/logins` | Recent sessions from `wtmp` |
| `/login list` | Same as `/logins` |
| `/login kill <pid>` | ARMED session kill — reply `no` to close it |
| `/mods` | Loaded modules; marks ones outside the official tree |
| `/definehome` | Bind/verify that THIS machine is your PC (hardware fingerprint + ring −3 silicon + TPM key) |
| `/definehome status` | Saved HOME profile + firmware drift (same PC, reflashes) + TPM key re-verify |
| `/definehome hal` | Ring −3 coprocessor detail (Intel ME/HECI/MKHI, AMD PSP, TPM, chipset) |
| `/definehome audit` | Bootkit audit (alias of `/bootkit`) |
| `/definehome delete` | Forget the saved HOME profile (you changed PCs) |
| `/bootkit` | Bootkit audit: UEFI vars, Secure Boot, lockdown, taint, LSTAR hook, ring −3 |
| `/settings` | View notification categories (kernel, selinux, thermal, memory, load, htop, pmu, battery, tsc, diag, control, login, hypercall, modwatch, proactive) |
| `/settings <cat> on\|off` | Flip one — decides what the daemon pushes to chat |
| `/settings login_timeout <s>` | Seconds to answer a login alert (0 = keep open) |
| `/cr0 /cr2 /cr3 /cr4 /cr8` | Read a control register (no confirm) |
| `/cr0 wp on\|off` | ARM a CR0 write-protect toggle |
| `/crX=0x…` (X=0,3,4,8) | ARM writing a control register |
| `/reboot` `/poweroff` | ARM reboot / shutdown |
| `/triplefault` `/triplefault restart` | ARM hard CPU reset (bogus IDT + `int3`) — fires once, never in a loop |
| `/triplefault shutdown` | ARM forced `kernel_power_off()` — once, no loop |
| `/triplefault allow` | Re-arm after one fired (still requires ARM + `confirm`) |
| `/kernelpanic` | ARM a deliberate kernel `panic()` (halt, or reboot per `panic=N`) |
| `confirm` | Execute the armed control or SELinux allow |
| `cancel` | Abort the armed control or SELinux allow |
| `/firmware` | Intel ME and AMD PSP firmware version (HAL ring −3) |
| `/resetcontext` | Clear conversation history (`context.txt`; `memory.txt` untouched) |
| `/help` | Command list |
| `/unpair` | Remove pairing (re-pair required) |
| Any question | LLM answers using live system context, `memory.txt`, and `context.txt` |

Example questions:
```
"Why is my system slow right now?"
"Did anything bad happen to the kernel overnight?"
"How's my CPU efficiency looking?"
"What's my Intel ME firmware version?"
"Explain the last OOM kill in simple terms"
```

---

## LLM backends

| Backend | Config key | Notes |
|---|---|---|
| Anthropic Claude | `anthropic` | Recommended. Use `claude-opus-5` for best results |
| OpenAI | `openai` | Compatible with any OpenAI-API-compatible service |
| DeepSeek | `deepseek` | OpenAI-compatible, very cost-effective |
| Google Gemini | `gemini` | `generateContent` REST endpoint |
| Local GGUF | `local` | Build with `--features local-llm`; needs llama.cpp |
| None | `none` | Sends raw kernel messages without LLM explanation |

---

## Persona configuration

The `[persona]` section in `config.toml` controls the AI's tone. The `tone`
string is injected verbatim into the system prompt:

```toml
[persona]
tone     = "colloquial Chilean Spanish, like a friend: wey, ¿qué fue lo que pasó?"
language = "es-CL"
```

```toml
[persona]
tone     = "formal incident report, concise, bullet points, no emojis"
language = "en"
```

```toml
[persona]
tone     = "friendly senior SRE explaining to a junior engineer, patient and encouraging"
language = "en"
```

---

## Privilege model

| Capability | Required for | Optional? |
|---|---|---|
| `CAP_SYSLOG` | Reading `/dev/kmsg` | No |
| `CAP_PERFMON` | Machine-wide hardware PMU counters (IPC, LLC misses) | Yes — falls back through per-process counters to software-only, reporting which scope it got |
| `CAP_KILL` | Ring-3 session kill (`no` on a login alert, `/login kill`, timeout auto-close) | Yes — only when the kernel module is loaded with `write_gid` do kills go through the module instead |
| None extra | ME/PSP queries read via the kernel-module devnode + sysfs (no `mei` group) | — |
| Network (HTTPS) | Telegram + LLM cloud APIs | Only if using cloud backends |

The systemd unit grants `CAP_SYSLOG`, `CAP_PERFMON` and `CAP_KILL` via
`AmbientCapabilities`, and applies strict filesystem sandboxing
(`ProtectSystem=strict`). `ProtectHome` and `PrivateTmp` are off on purpose so
the module analyser can find an intruder's `.ko` in `/home`/`/root`/`/tmp`.

---

## Security

Key properties:
- **No rootkit behaviour.** `lsmod`, `ps`, `find`, and standard monitoring tools always show this software plainly.
- **No hidden files or processes.**
- **Strictly outbound Telegram calls** — `sendMessage` and (when interactive) `getUpdates`. No inbound raw sockets.
- **Pairing is a two-step identity proof.** (1) A one-time token (~40-bit, bound to your `telegram_id`, 5-minute TTL, Argon2id-hashed with a random `/dev/urandom` salt — never stored in plaintext). (2) After the token is accepted, the bot demands an explicit **YES** confirmation before granting kernel-level chat access. Any other Telegram account is rejected outright at the gateway.
- **`telegram_id` whitelist** — enforced on every message before any logic runs; strangers get a terse "Access denied" with no information disclosure.
- **Anti brute-force** — after 5 invalid token attempts the token is burned; the daemon must be restarted to mint a new one.
- **No remote code execution path.** User messages are forwarded to the LLM API and the reply is returned; no shell commands are executed from Telegram. The only privileged actions are the fixed kernel-module control verbs (reboot/poweroff/triplefault/CR write), SELinux policy modules (`/selinux allow`), `rmmod` of a foreign module you ordered removed, and session kills you denied — all reachable exclusively through the paired chat and a confirmation ritual. **Every action that *can* require confirmation (reboot, poweroff, triplefault, control-register writes, SELinux policy changes, module removal, login-kill) always asks the user first** — nothing privileged is ever executed silently or by the LLM.
- **Triplefault is one-shot, never a loop.** `/triplefault` / `/triplefault restart` forces a hard CPU reset (bogus IDT descriptor loaded with `lidt`, then `int3` → `#BP` → `#NP` → `#DF` → triple fault → `RESET`); `/triplefault shutdown` forces `kernel_power_off()`. Both only apply when the module is loaded and travel the full ARM → `confirm` ritual **every time**, so you can use it whenever you want — but the machine never reboots in a loop: the module latches it per-boot (`-EBUSY` on any duplicate, and the reset path ends in `cli; hlt`, never a spin), and the daemon latches it per session (re-armed only by a fresh daemon start after reboot or by an explicit `/triplefault allow` — also human-confirmed). Conversational orders ("fuerza un apagado con triplefault") are recognized and armed the same way; a mere question («¿qué es triplefault?») is never treated as an order.
- **`/kernelpanic` is the ring-0 kill switch.** It calls the kernel's real `panic()` through the module — never ring-3 (`/proc/sysrq-trigger` needs `CAP_SYS_ADMIN`, which the unprivileged daemon doesn't have, plus `CONFIG_MAGIC_SYSRQ` + `sysrq=1`). `panic()` is terminal by definition: the machine halts, or the kernel reboots exactly once per its own `panic=N` policy — nothing in the module or daemon loops or retries. Same ARM → `confirm` ritual as the other fatal controls; conversational orders are recognized, questions aren't.
- **Login + module rituals.** A new login (GUI/SSH) is announced and armed; `si fui yo` keeps it, `no` closes it (SIGTERM→SIGKILL + `loginctl`, or the kernel module's `killsession` when loaded — see the `CAP_KILL` note in `scripts/sysentinel.service`). A **foreign** kernel module (one not in the official tree) is announced conversationally by the persona; you reply `sácalo` / `déjalo` / `no estoy seguro`. In the last case the bot runs `objdump` against the `.ko` and has the persona analyse the disassembly — **on API backends it warns conversationally that the analysis spends your tokens before running it**; on local backends it just does it.
- **`/dmesg` for the lazy.** One command reads the kernel ring buffer, filters the noise, and the persona tells you what matters — you never touch a terminal.
- **No undervolt hallucinations.** The persona only claims an undervolt/overvolt when a real V/F shift is verified: `intel-undervolt read` succeeds with a non-zero offset, or `/etc/intel-undervolt.conf` has non-zero offsets **and** its service is enabled — checked per vendor (Intel, AMD, Zhaoxin). Otherwise the persona states the machine runs at stock; `/undervolt` shows the live evidence and verdict. The old "RAPL powercap ⇒ undervolted" heuristic (which guessed `true` on almost every modern laptop) is gone.
- **Ring-3 fallbacks when the module isn't loaded.** If `sysentinel_metrics.ko` can't load (unsigned under Secure Boot, blacklisted, not insmod'd), nothing is silently missing and nothing is faked: `/status`, the persona prompt and `/firmware` switch to userspace truth — hypervisor from `systemd-detect-virt`/procfs, ME/PSP from sysfs, PMU/IPC from `perf_event_open` (system-wide with `perf_event_paranoid ≤ 0`, per-process otherwise), login kill via `SIGKILL`+`loginctl`, hypercalls via tracefs. `/cr*` says plainly that CR reads need ring-0 and shows the Secure Boot-aware load instructions.
- **Battery alerts, notebooks only.** `/battery` reports level and time-left on a laptop; on a desktop tower / "pc de mesa" it answers **no aplica** (there is no `power_supply Battery`). A watcher edge-triggers Telegram alerts as the battery drains: ≤20% low, ≤10% critical, ≤5% *agotándose* — re-armed above 25% or when charging. Toggle with `/settings battery`.
- **Kernel module** is fully visible (`/proc/modules`, `/sys/module/sysentinel_metrics`), no symbol hiding, unloadable with `rmmod`.
- **PMU counters** read hardware performance data only; no kernel memory access.
- **Intel ME / AMD PSP** queries use public interfaces: ME firmware is read via the standard kernel MEI bus (`mei_me`) in the module and only a version string crosses to user-space through `/proc/sysentinel_metrics`; AMD PSP/TPM info comes from the kernel's TPM sysfs, correctly labelled by CPU vendor. The daemon never talks raw protocol to `/dev/mei0`, so it needs no root or `mei` group.
- **Privileged controls are opt-in and confirmation-gated.** The kernel module only accepts a control command (`reboot`, `poweroff`, `crX=0x…`) from uid 0 or from the `write_gid` modparam group; the bot then requires an explicit `confirm` reply within 60 s from the paired chat before it writes. Control paths bypass the LLM entirely (zero token spend).

---

## Licence

**Licence is per-directory.** The `SPDX-License-Identifier` header on each file
is authoritative for that file; this map is the summary.

| Path | Licence | Licence text shipped at |
|---|---|---|
| `daemon/` | Apache-2.0 | `daemon/LICENSE` |
| `kernel_module/` | MIT OR GPL-2.0-or-later | `kernel_module/LICENSE-MIT`, `kernel_module/LICENSE-GPL` |
| `ramdisk/` | MIT OR GPL-2.0-or-later | `ramdisk/LICENSE-MIT`, `ramdisk/LICENSE-GPL` |
| `scripts/` | MIT OR GPL-2.0-or-later | `ramdisk/LICENSE-MIT`, `ramdisk/LICENSE-GPL` (same terms) |
| `ramdisk/face/models/` | Apache-2.0 (third-party weights) | `ramdisk/face/models/LICENSE`, `.../NOTICE` |
| everything else (root `README`, `Makefile`, …) | Apache-2.0 | `LICENSE` |

### The one that bites: `kernel_module/`

The source is dual-licensed, so the source alone may be taken under MIT. The
built module is a different matter:

> `sysentinel_metrics.ko` is produced by linking against the Linux kernel, which
> is GPL-2.0. The resulting binary is a combined work and **must be redistributed
> under GPL-2.0, with corresponding source**. The MIT option does not survive
> that link. If you ship the `.ko`, you ship it under the GPL.

Both halves of the dual licence are load-bearing:

- **GPL-2.0-or-later** is what lets the module bind `EXPORT_SYMBOL_GPL` symbols
  (the MEI client bus, the ccp platform-access API). A module Linux does not
  treat as free is refused those symbols outright.
- **MIT** keeps the source permissively reusable outside a kernel tree.

Every `MODULE_LICENSE` in the module reads `"Dual MIT/GPL"` — the ident Linux
defines for exactly that pair (`include/linux/module.h`) — and agrees with each
file's SPDX header. Plain `"GPL"` there would quietly drop the MIT half.

### The daemon is not a derivative work of the kernel

`daemon/` is ordinary user-space: it talks over syscalls, sysfs and `/proc`, and
links nothing from `kernel_module/`. The two communicate only through the text
tokens published on `/proc/sysentinel_metrics` — a protocol both sides must
spell the same way, not shared implementation.

That claim is checked mechanically rather than asserted:

```sh
make licence-audit LINUX_SRC=/path/to/linux
```

It reports every word sequence `daemon/` shares with a GPL reference tree and
fails on anything outside an allowlist of expected categories (syscall ABI
constant names, quoted licence identifiers) — each with a written reason. See
[`NOTICE`](NOTICE) for the full provenance statement, including the vendor
manuals the hybrid-CPU support is derived from.
