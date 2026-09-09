# sysentinel

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

Licensed under **MIT OR GPL-2.0-or-later** (daemon) and **GPL-2.0-only**
(kernel module — required for kernel linking).

---

## What it does

| Feature | Description |
|---|---|
| **Kernel event watching** | Tails `/dev/kmsg` in real-time; detects OOM kills, kernel panics, segfaults, and oopses |
| **LLM explanation** | Asks a configurable AI to explain the event in plain language, in your language and tone |
| **Telegram alerts** | Sends an alert to your paired Telegram chat |
| **Interactive chat** | Talk to your PC via Telegram — ask "why is my system slow?", "what happened last night?", "how's my CPU?" |
| **Pairing flow** | One-time 5-minute token pair; strict `chat_id` whitelist thereafter |
| **Intel ME status** | Reads ME firmware version via the kernel MEI bus (ring-0, exposed on `/proc/sysentinel_metrics`) |
| **AMD PSP status** | Reads PSP/TPM firmware info via sysfs, correctly labelled by CPU vendor |
| **PMU counters** | Reads CPU cycles, IPC, LLC misses, branch mispredictions, context switches via `perf_event_open` |
| **Hypercalls** | Kernel module issues `vmcall`/`vmmcall`/`hvc` with CPUID-based hypervisor detection |
| **Persona** | Configure the AI's tone per `config.toml` — formal, colloquial, regional slang, whatever |
| **Multi-backend LLM** | Switch between Anthropic Claude, OpenAI, DeepSeek, Gemini, or a local GGUF model |

---

## Directory tree

```
sysentinel/
├── README.md
├── LICENSE-MIT                   MIT licence text
├── LICENSE-GPL                   GPL-2.0 licence text
├── Makefile                      Top-level: builds daemon + kernel module
│
├── kernel_module/                Ring 0 — Rust kernel module (GPL-2.0-only)
│   ├── Kbuild
│   ├── Makefile
│   ├── LICENSE-GPL
│   ├── README.md
│   └── src/
│       ├── sysentinel_core.rs    Rust root: snapshot + rs_render_snapshot / rs_exec_command
│       ├── proc_entry.c          procfs shim: /proc/sysentinel_metrics (no /dev node)
│       ├── hypercall.rs            vmcall / vmmcall / hvc + CPUID detection
│       ├── mei_driver.rs           Intel MEI mei_cl_driver (ring-0 ME access)
│       └── mei_shim.c              C glue for mei_cl_bus.h API
│
├── daemon/                       Ring 3 — user-space daemon (MIT OR GPL-2.0-or-later)
│   ├── Cargo.toml
│   ├── LICENSE-MIT
│   ├── LICENSE-GPL
│   ├── README.md                 (daemon-specific build / run notes)
│   ├── config/
│   │   └── config.example.toml
│   └── src/
│       ├── main.rs               Entry point, thread orchestration
│       ├── config.rs             TOML config loading + validation
│       ├── kmsg.rs               /dev/kmsg real-time reader
│       ├── classify.rs           OOM / panic / segfault / oops classifier
│       ├── telegram.rs           Outbound sendMessage helper
│       ├── bot.rs                Interactive bot: pairing, whitelist, AI chat
│       ├── mei.rs                Intel ME (HECI /dev/mei0) + AMD PSP (sysfs)
│       ├── pmu.rs                PMU counters via perf_event_open
│       ├── hwdiag.rs             lm-sensors + PCI + firmware periodic summary
│       └── llm/
│           ├── mod.rs            LlmBackend trait + factory
│           ├── anthropic.rs      Anthropic Messages API
│           ├── openai.rs         OpenAI Chat Completions
│           ├── deepseek.rs       DeepSeek (OpenAI-compatible)
│           ├── gemini.rs         Google Gemini generateContent
│           └── local.rs          Local GGUF via llama-cpp-2 (feature-gated)
│
├── docs/
│   └── SECURITY.md               Security architecture and threat model
│
└── scripts/
    ├── sysentinel.service         systemd unit
    ├── install.sh
    └── uninstall.sh
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

# Load
sudo insmod kernel_module/sysentinel_metrics.ko
cat /proc/sysentinel_metrics
# → uptime_s=3600 modules=72 hypervisor=KVM/Intel_VT-x kvm_features=0x000001ff me_fw=18.0.1234.0 psp=n/a

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
| `/definehome` | Bind/verify that THIS machine is your PC (hardware fingerprint) |
| `/definehome delete` | Forget the saved HOME profile (you changed PCs) |
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
| `/firmware` | Intel ME and AMD PSP firmware version |
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
| `CAP_PERFMON` | Hardware PMU counters (IPC, LLC misses) | Yes (falls back to software counters) |
| `CAP_KILL` | Ring-3 session kill (`no` on a login alert, `/login kill`, timeout auto-close) | Yes — only when the kernel module is loaded with `write_gid` do kills go through the module instead |
| None extra | ME/PSP queries read via the kernel-module devnode + sysfs (no `mei` group) | — |
| Network (HTTPS) | Telegram + LLM cloud APIs | Only if using cloud backends |

The systemd unit grants `CAP_SYSLOG`, `CAP_PERFMON` and `CAP_KILL` via
`AmbientCapabilities`, and applies strict filesystem sandboxing
(`ProtectSystem=strict`). `ProtectHome` and `PrivateTmp` are off on purpose so
the module analyser can find an intruder's `.ko` in `/home`/`/root`/`/tmp`.

---

## Security

See [`docs/SECURITY.md`](docs/SECURITY.md) for the full threat model.

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

```
daemon/      MIT OR GPL-2.0-or-later
kernel_module/  GPL-2.0-only
```

The daemon is dual-licensed so you can use it in projects that prefer MIT.
The kernel module must be GPL-2.0-only because it links against kernel symbols.
