# kernel_module/sysentinel_metrics

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
# hypervisor=bare-metal cr0=0x0000000080050033 psp=n/a
sudo rmmod sysentinel_metrics
```

Build variants:

- `make MEI=y` (default) — links the MEI C shim (`src/mei_shim.c`) so the
  module can query Intel ME firmware via the kernel's MEI bus. Requires
  `CONFIG_INTEL_MEI=y` in the host kernel.
- `make MEI=n` — metrics-only.

`src/triplefault.c` (the hard-reset helper) is always compiled in. The
`triplefault shutdown` verb additionally links the exported
`kernel_power_off()` symbol (same function family as the `kernel_restart`
the module already uses); if your kernel doesn't export it, the module will
refuse to load and build with `make MEI=n`-style `modprobe` will tell you —
just remove the verb on such kernels (a reboot/poweroff loop is impossible
regardless; a missing symbol only fails at load time).

## License

GPL-2.0-only. Linking against internal kernel symbols (via the `kernel`
crate) requires this; see the top-level `README.md` for why the rest of
the project is dual-licensed instead.