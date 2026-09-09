// SPDX-License-Identifier: MIT OR GPL-2.0-or-later
//
// sysentinel_metrics: emergency host-down helpers.
//
// These are the "pull the power" controls the daemon only ever sends after
// an explicit ARM + `confirm` from the paired chat:
//
//   1. sysentinel_triplefault_reset — one-shot triple-fault hard reset.
//      The daemon's `/triplefault restart` (and conversational equivalents)
//      call this through rs_exec_command -> "triplefault" / "triplefault restart".
//
//      How it works (classic "kill switch"):
//        1. `lidt` a deliberately bogus IDT descriptor: all zeros → limit 0,
//           base 0, present bit 0. Every descriptor lookup faults.
//        2. `int3` raises #BP. The CPU tries to fetch the #BP gate from the
//           bogus IDT → not-present → #NP; the #NP handler lookup fails again
//           → #DF; the #DF handler lookup fails → triple fault → the CPU
//           asserts RESET.
//        3. If the firmware/VM refuses to reset (e.g. QEMU in shutdown state),
//           `cli; hlt` parks the CPU in a halted state. It can NEVER spin
//           back into a reboot loop: there is no loop instruction, no
//           watchdog re-arm and no retry — this fires exactly once.
//
//      The module additionally refuses any second "triplefault*" write in
//      the same boot (per-boot latch in sysentinel_core.rs), so even a buggy
//      or compromised daemon cannot re-trigger it.
//
//   2. sysentinel_kernel_panic — deliberate kernel panic.
//      The daemon's `/kernelpanic` call this through rs_exec_command ->
//      "kernelpanic". It calls the kernel's real `panic()`, which is
//      terminal by definition: the machine halts (or reboots after a few
//      seconds when `panic=N` is set — that is the kernel's own one-shot
//      policy, nothing here loops or retries).

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/panic.h>

long sysentinel_triplefault_reset(void)
{
	pr_emerg("sysentinel_metrics: TRIPLE FAULT RESET - hardware reinitialize now\n");

	/*
	 * The 10 zero bytes at `1:` double as the IDT descriptor (limit 0,
	 * base 0, type 0). `lidt (%%rax)` loads it, then `int3` trips the
	 * fault cascade. The fall-through bytes after `int3` are the same
	 * descriptor table; `hlt` parks the CPU if the reset never comes.
	 */
	asm volatile(
		"cli\n\t"
		"leaq 1f(%%rip), %%rax\n\t"
		"lidt (%%rax)\n\t"
		"int3\n\t"
		"1: .byte 0,0,0,0,0,0,0,0,0,0\n\t"
		"hlt\n"
		:
		:
		: "rax", "memory");

	/* Unreachable on any real CPU that honours its reset line. */
	return -EIO;
}

long sysentinel_kernel_panic(void)
{
	pr_emerg("sysentinel_metrics: FORCED KERNEL PANIC - explicit user-confirmed control\n");

	/*
	 * Terminal by definition: prints "Kernel panic - not syncing: …" and
	 * halts (or reboots after `panic=N` seconds per the kernel's own
	 * one-shot policy). `panic()` is a __noreturn export, so this function
	 * never returns on any sane kernel.
	 */
	panic("sysentinel_metrics: forced kernel panic (confirmed control)");

	/* Unreachable. */
	return -EIO;
}