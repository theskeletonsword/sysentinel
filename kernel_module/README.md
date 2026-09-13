# kernel_module/sysentinel_metrics

> ## ⚠️ THIS DIRECTORY IS **NOT** APACHE-2.0 ⚠️
>
> The rest of this repository is Apache-2.0. **This directory is
> `MIT OR GPL-2.0-or-later`**, and the distinction matters in practice:
>
> - The **source** here is dual-licensed — you may take it under MIT alone.
> - The **built `sysentinel_metrics.ko` is GPL-2.0.** It is linked against the
>   Linux kernel, so the binary is a combined work with GPL-2.0 code and must be
>   redistributed under the GPL, with corresponding source. The MIT option does
>   not survive that link. **Do not ship the `.ko` inside a proprietary product.**
>
> Both halves earn their keep: the **GPL** half is what lets this module bind
> `EXPORT_SYMBOL_GPL` symbols (`mei_cl_bus`, the ccp platform-access API) — a
> module Linux does not consider free is refused them; the **MIT** half keeps
> the source reusable outside a kernel tree.
>
> Licence texts: [`LICENSE-MIT`](LICENSE-MIT) · [`LICENSE-GPL`](LICENSE-GPL)
> (full GPLv2 text). Every source file here carries
> `SPDX-License-Identifier: MIT OR GPL-2.0-or-later`, and every
> `MODULE_LICENSE` reads `"Dual MIT/GPL"` — the ident Linux defines for that
> pair. See the root [`NOTICE`](../NOTICE) for the whole picture.

A Rust kernel module built against `rust-for-linux` (`CONFIG_RUST=y`) that
publishes `/proc/sysentinel_metrics`: a one-line ring-0 snapshot (uptime,
loaded-module count, free/total memory, hypervisor, KVM features, Intel ME
firmware, AMD PSP presence, and the CR0/CR2/CR3/CR4/CR8 registers) plus a
**write channel for privileged control commands** (`reboot`, `poweroff`,
`triplefault restart`, `triplefault shutdown`, `kernelpanic`, `crX=0x…`).

rust-for-linux 7.1 has no `/proc` abstraction, so the module humbly splits
the work: `src/proc_entry.c` creates the procfs entry and delegates to the
Rust exports `rs_render_snapshot()` / `rs_exec_command()` in
`sysentinel_core.rs`. The interface deliberately lives in `/proc` — no `/dev`
node, no udev rules, no permission games.

## Security model

- **Reads** are world-readable (mode `0644`): uptime/memory/ME version are
  not secrets.
- **Writes are gate-kept in-ring, in the C shim**: only `capable(CAP_SYS_ADMIN)`
  (uid 0) or membership of the GID given by the `write_gid` module parameter
  can send commands. Default `write_gid=0` = root only.
- Commands are immediate side effects. The daemon therefore adds a
  human-confirmation step (arm + `confirm` within 60 s) before it ever
  writes. **Do not `echo reboot > /proc/sysentinel_metrics` casually.**
- **`triplefault*` fires exactly once per boot.** The reserved verbs are
  `triplefault` / `triplefault restart` (hard CPU reset: `lidt` a bogus IDT
  descriptor then `int3` → `#BP` → `#NP` → `#DF` → triple fault → `RESET`;
  the path ends in `cli; hlt`, never a spin) and `triplefault shutdown`
  (`kernel_power_off()`, forced low-level power-down). A per-boot atomic
  latch refuses any duplicate with `-EBUSY`, and the daemon keeps its own
  per-session latch — the machine can never reboot/power-off in a loop, and
  each new boot re-arms the command for the next confirmed use.
- **`kernelpanic` calls the kernel's real `panic()`** (`__noreturn`, exported
  like the other control symbols). Terminal by definition — the machine halts
  or reboots exactly once per its own `panic=N` policy; nothing here loops.
  The daemon never falls back to ring-3 SysRq, since that needs
  `CAP_SYS_ADMIN` plus `CONFIG_MAGIC_SYSRQ`. Implemented in
  `src/triplefault.c` (`sysentinel_kernel_panic`).

```sh
# Enable the 'sysentinel' service account to issue controls:
sudo modprobe sysentinel_metrics write_gid=$(id -g sysentinel)
```

## Honest build note

`rust-for-linux`'s `kernel` crate API is still evolving release to
release. The module in this tree is written and verified against the
**7.1.8-200.fc44** API shape (`module!`, `KVec`/`GFP_KERNEL`, `asm!`, and
the `IovIterDest` helpers). If your kernel differs, check your tree's
`samples/rust/` and `rust/kernel/` and adjust.

The loaded-module count is intentionally a `0` placeholder — the in-kernel
module list is not exposed through a safe Rust API.

## Build

The kernel's prebuilt `rust/` metadata (`.rmeta`) was compiled by the
distro's exact `rustc`; on Fedora this is **`/usr/bin/rustc`**
(`CONFIG_RUSTC_VERSION_TEXT`). The `Makefile` pins `RUSTC`/`HOSTRUSTC` to
`/usr/bin/rustc` when present, so a plain `make` just works:

```sh
make
sudo make modules_install
# Replace the currently-loaded old-build module (pre-/proc interface):
sudo rmmod sysentinel_metrics 2>/dev/null || true
sudo modprobe sysentinel_metrics
cat /proc/sysentinel_metrics
# uptime_s=12345 modules=64 mem_free_kb=204800 mem_total_kb=8388608 \
# hypervisor=bare-metal ring3=intel-me cr0=0x0000000080050033 \
# me_fw=18.1.2204.0 me_live=ok(v18.1.2204.0,rt=2ms)
sudo rmmod sysentinel_metrics
```

`ring3=` is the on-board HAL dispatcher deciding which ring −3 channel to
engage — **Intel → `intel-me`**, **AMD/Hygon → `amd-psp`**, **neither →
`none`** (old/VIA/ARM-class silicon engages nothing). The channel follows it:
Intel prints `me_fw`/`me_live`, AMD prints `psp=up(...)`, and `none` prints
neither.

The snapshot line carries the ring −3 alliance on top of the raw metrics —
exactly one side per host, per the dispatcher:

```text
# Intel host:
me_fw=18.1.2204.0 me_live=ok(v18.1.2204.0,rt=2ms) smm=off ro=ok(rt=0us)
# AMD host:
psp=up(hsti=0x00002100,flags=tsme,rt=1ms) smm=off ro=ok(rt=0us)
# neither (old/VIA/ARM silicon): no ME/PSP tokens at all
# SMM opt-in (arm "smm on"; the channel is ACPI-only, no SMI is ever fired):
smm=off ro=ok(rt=1us)
# after arming on firmware with a published SMM bridge + WSMT mitigations:
smm=acpi smm_iface=fadt-smi@0xb2(en=0xf0,pstate=0x80) smm_wsmt=0x00000001(fixed-buffers) hvm_lat=3us ro=ok(rt=1us)
# after arming on firmware that declares an SMI bridge but no mitigations:
smm=acpi smm_iface=fadt-smi@0xb2 smm_wsmt=none ro=ok(rt=1us)
# after arming on firmware with no SMM surface at all:
smm=acpi smm_iface=none smm_wsmt=none crosstalk=bare-metal ro=ok(rt=1us)
```

- `me_live` is not a cached sticker: every `/proc` read (rate-limited to one
  MKHI exchange per 5 s) re-runs `GET_FW_VERSION` over the live HECI bus so
  the daemon sees the module ↔ Intel ME channel working **right now**.
- `me_drift=1` flags the live version differing from the probe-time one.
- `psp=up(...)` is the AMD PSP answering a real `PSP_CMD_HSTI_QUERY` handshake
  (fused HSTI word) through the ccp driver's exported platform-access API; on
  platforms where the mailbox is firewalled it degrades to `psp=plat`.

Ring −2 (SMM) channel — **firmware posture, by reads only**. Raising an SMI
is a final-word action: an SMI with the wrong command byte on a firmware-
specific dispatch can mean shutdown or a wedged machine, so this module
simply does not do it. There is no code path — command, flag or read — that
touches the APM ports (0xB2/0xB3) or any other SMM-triggering I/O. `smm on`
only performs a read-only scan of the tables the firmware itself publishes:

- **FADT `smi_command`** — the firmware's official SMM command port plus the
  spec-defined command values it documents (`acpi_enable`, `acpi_disable`,
  `s4_bios_request`, `pstate_control` of `struct acpi_table_fadt`), surfaced
  read-only as `smm_iface=fadt-smi@0x…(en=…,pstate=…,s4=…)`. The kernel writes
  through that port only with those declared values (reference:
  `drivers/acpi/processor_perflib.c`, FreeBSD `sys/x86/cpufreq/smist.c`) — we
  only report the declaration, never act on it.
- **WSMT (Windows SMM Security Mitigations Table)** — `smm_wsmt=0x…(fixed-
  buffers,comm-nested-ptr,system-res)`: the firmware's own claim of which SMM
  mitigations it enabled. A firmware that declares an SMM bridge (FADT) but no
  WSMT protections (`smm_wsmt=none`; or `smm_wsmt=0x00000000(unprotected)`) is
  exactly the configuration an SMM bootkit needs — a measurable posture.
- Both reads go through the same read-only ACPI subsystem the kernel uses for
  power/sleep discovery (`acpi_gbl_FADT`, `acpi_get_table`); firmware-published
  buffer addresses are **never** remapped or written.
- `smm=off` — not armed (default); `smm=acpi` — armed, posture scanned;
  `smm=err(c=…)` — a table read failed unexpectedly.
- `hvm_lat=…us` / `crosstalk=bare-metal` — the latency instrument narrowed to
  the ring −1 hypercall (VM only), since there is no SMM latency to measure
  without firing an SMI.
- `ro=ok(rt=…us)` / `ro=dirty` — passive canary watch on the module's own
  rodata; always active, never raises SMIs.

Build variants:

- `make MEI=y` (default) — links the MEI C shim (`src/mei_shim.c`) so the
  module can query Intel ME firmware via the kernel's MEI bus. Requires
  `CONFIG_INTEL_MEI=y` in the host kernel.
- `make PSP=y` (default) — links `src/psp_shim.c` against the ccp driver's
  exported platform-access API (requires `CONFIG_CRYPTO_DEV_CCP_DD`, built-in
  or loaded before this module) for the live AMD PSP handshake.
- `make MEI=n PSP=n` — metrics-only.

`src/triplefault.c` (the hard-reset helper) and `src/smm_shim.c` (the ring −2
ACPI posture reader) are always compiled in. The smm shim performs **zero
SMM-triggering I/O by construction** — it is a read-only ACPI table reader —
and its tokens appear only after the privileged `smm on` write.
The `triplefault shutdown` verb additionally links the exported
`kernel_power_off()` symbol (same function family as the `kernel_restart`
the module already uses); if your kernel doesn't export it, the module will
refuse to load and build with `make MEI=n`-style `modprobe` will tell you —
just remove the verb on such kernels (a reboot/poweroff loop is impossible
regardless; a missing symbol only fails at load time).

## License

**MIT OR GPL-2.0-or-later** (SPDX headers on every `.rs`/`.c` file).
Declared to the kernel as `Dual MIT/GPL` (see `module!` in
`sysentinel_core.rs`), which `license_is_gpl_compatible()` treats as
GPL-compatible, so the module may still link the GPL-only symbols it uses
(cr4, MSR/LSTAR debugging, `kernel_restart`/`kernel_power_off`, …).
The repository itself is Apache 2.0.