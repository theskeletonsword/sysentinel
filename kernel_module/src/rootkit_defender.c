// SPDX-License-Identifier: GPL-2.0-only
//
// sysentinel_metrics — ring0 rootkit defender.
//
// Because this module already lives in ring0 (kernel mode), it is the only
// part of sysentinel that can directly see AND undo what a malicious ring0
// rootkit does. This file defends the crime sites a kernel rootkit has to
// touch to intercept the kernel — and keeps the module honest about what a
// stock Linux kernel will and will not let an out-of-tree module reach.
//
// # What we can guard
//
// ┌──────────────────────┬──────────────┬──────────────────────────────────────┐
// │ Surface              │ Scan         │ Clean                               │
// ├──────────────────────┼──────────────┼──────────────────────────────────────┤
// │ MSR_LSTAR (syscall   │ compare vs   │ wrmsrl back to the module-load      │
// │ entry point)         │ load-time    │ baseline (the classic "syscall       │
// │                      │ baseline     │ hook" unhook)                       │
// │ IDT (interrupt       │ compare vs   │ write the 16-byte baseline gate     │
// │ descriptor table)    │ load-time    │ back with CR0.WP cleared (RO pages  │
// │                      │ baseline +   │ become writable for supervisor),    │
// │                      │ name every   │ then WP restored — catches IDT      │
// │                      │ changed gate │ hijacks to trampoline memory        │
// │ int $0x80 gate       │ resolved via │ above                               │
// │                      │ sprint_symbol│                                      │
// │ CR0.WP (write-       │ reported     │ `cr0_wp on` restores it             │
// │ protect on kernel RO │ (metric)     │                                      │
// │ pages)               │              │                                      │
// │ rogue processes /    │ —            │ SIGKILL any pid (kill_pid) — even   │
// │ sessions             │              │ ring3 payloads of a rootkit         │
// └──────────────────────┴──────────────┴──────────────────────────────────────┘
//
// # What a stock kernel deliberately hides from us
//
// - `sys_call_table` and `kallsyms_lookup_name()` are NOT exported to
//   modules on this kernel (post-5.7 hardening), so we cannot snapshot or
//   restore the syscall table by name. We compensate with the LSTAR + IDT
//   entry-point guards above (that is where syscall hooks must land anyway)
//   and by watching CR0.WP — a rootkit that rewrites read-only kernel pages
//   must first clear WP, which our `/proc/sysentinel_metrics` read reports.
// - IDT/mem writes that need page-table permission changes (set_memory_*)
//   are not exported either; the CR0.WP trick below is the sanctioned way.
//
// # Safety rules
//
// - Clean is a *surgical* action: it only rewrites gates that DIFFER from
//   the module-load baseline and only re-points MSR_LSTAR to the baseline.
//   Nothing else in the kernel is touched.
// - The daemon must make a human confirm before sending `rootkit clean`
//   (same rule as `reboot`). Scan is read-only and always safe.
// - SIGKILL guards: pid 1 is refused, and killing the module's own task is
//   refused. Everything else is fair game (the admin asked).

#include <linux/module.h>
#include <linux/kallsyms.h>
#include <linux/mutex.h>
#include <linux/proc_fs.h>
#include <linux/sched.h>
#include <linux/sched/signal.h>
#include <linux/uaccess.h>

#include <asm/desc.h>		/* store_idt(), struct desc_ptr		  */
#include <asm/msr.h>		/* rdmsrl() / wrmsrl()		   	  */
#include <asm/processor.h>

// ── MSR_LSTAR ────────────────────────────────────────────────────────────────

#define MSR_LSTAR 0xc0000082

static u64 lstar_baseline;

/// True if any entry point was caught deviating from its baseline.
static bool defense_tampered;

// ── IDT baseline ─────────────────────────────────────────────────────────────

// Stored raw: an IDT gate is 16 bytes; vector v lives at idt_base + (v * 16).
#define IDT_VECTORS 256

static void *idt_baseline;	/* kmalloc'ed 256*16 snapshot in CPU0/init CPU */

/// Fresh copy of the CURRENT caller-CPU IDT.
static int idt_capture(void *out, u32 maxbytes)
{
	struct desc_ptr idtr;
	unsigned long base;
	u32 need;

	store_idt(&idtr);
	base = idtr.address;
	need = min_t(u32, (u32)idtr.size + 1, maxbytes);
	memcpy(out, (const void *)base, need);
	return need;
}

/// Write one 16-byte gate back with CR0.WP momentarily cleared.
///
/// The IDT lives in read-only `cpu_entry_area` pages; with WP=0 a supervisor
/// write to a RO page is permitted (this is the classic rootkit-unhook move,
/// and the same primitive our `cr0_wp off/on` commands expose). WP is always
/// re-set before returning.
static int idt_write_gate(int vector, const void *gate16)
{
	struct desc_ptr idtr;
	unsigned long cr0, next;
	char *dst;

	store_idt(&idtr);
	dst = (char *)idtr.address + (vector * 16);

	asm volatile("mov %%cr0, %0" : "=r"(cr0));
	next = cr0 & ~(1UL << 16);			/* clear WP   */
	asm volatile("mov %0, %%cr0" :: "r"(next));
	memcpy(dst, gate16, 16);
	asm volatile("mov %0, %%cr0" :: "r"(cr0));	/* restore WP */
	return 0;
}

/// Compare, per vector, current gates vs baseline. Returns the vector of the
/// first mismatch, or -1 if clean. Writes the changed gate's handler into
/// `name` (best-effort via sprint_symbol).
static int idt_first_diff(char *name, size_t namelen)
{
	struct desc_ptr idtr;
	u16 *cur;
	int v;

	store_idt(&idtr);
	cur = (u16 *)idtr.address;

	for (v = 0; v < IDT_VECTORS; v++) {
		if (memcmp(cur + v * 8, (u16 *)idt_baseline + v * 8, 16) != 0) {
			unsigned long handler =
				((unsigned long)*(u32 *)((u8 *)cur + v * 16 + 2)) |
				(((unsigned long)*(u16 *)((u8 *)cur + v * 16 + 8)) << 32);
			if (name && namelen)
				sprint_symbol(name, handler);
			return v;
		}
	}
	return -1;
}

// ── Report buffer (built by scan, drained via /proc) ─────────────────────────

#define DEFENSE_REPORT_MAX 4096

static DEFINE_MUTEX(defense_lock);
static char defense_report[DEFENSE_REPORT_MAX];
static size_t defense_report_len;

static void report_clear(void)
{
	defense_report[0] = '\0';
	defense_report_len = 0;
}

static __printf(1, 2) void report_add(const char *fmt, ...)
{
	va_list ap;
	int n;

	if (defense_report_len >= DEFENSE_REPORT_MAX - 1)
		return;
	va_start(ap, fmt);
	n = vscnprintf(defense_report + defense_report_len,
		       DEFENSE_REPORT_MAX - defense_report_len, fmt, ap);
	va_end(ap);
	if (n > 0)
		defense_report_len += n;
}

// ── Scan ─────────────────────────────────────────────────────────────────────

/// Refresh the report buffer with the current ring0 integrity picture.
/// Returns 0 (read-only; never fails on modern kernels).
long sysentinel_defense_scan(void)
{
	struct desc_ptr idtr;
	u64 lstar_now = 0;
	unsigned long cr0;
	char name[KSYM_SYMBOL_LEN];
	int diff, changed = 0;
	int int80 = -1;
	u8 cur[IDT_VECTORS * 16];
	int v;

	mutex_lock(&defense_lock);
	report_clear();
	defense_tampered = false;

	store_idt(&idtr);
	rdmsrl(MSR_LSTAR, lstar_now);
	asm volatile("mov %%cr0, %0" : "=r"(cr0));

	// MSR_LSTAR — the procto-capture syscall entry.
	if (lstar_now != lstar_baseline) {
		defense_tampered = true;
		report_add("lstar=HOOKED current=0x%llx baseline=0x%llx\n",
			   lstar_now, lstar_baseline);
	} else {
		report_add("lstar=clean 0x%llx\n", lstar_now);
	}

	// IDT — any gate that no longer matches boot.
	idt_capture(cur, sizeof(cur));
	for (v = 0; v < IDT_VECTORS; v++) {
		if (memcmp(cur + v * 16, (u8 *)idt_baseline + v * 16, 16) != 0) {
			unsigned long handler =
				((unsigned long)*(u32 *)(cur + v * 16 + 2)) |
				(((unsigned long)*(u16 *)(cur + v * 16 + 8)) << 32);
			sprint_symbol(name, handler);
			report_add("idt vector 0x%02x CHANGED -> %s\n", v, name);
			if (v == 0x80)
				int80 = v;
			changed++;
		}
	}
	if (changed)
		defense_tampered = true;
	report_add("idt changed=%d total_gates=%u\n", changed,
		   (u32)idtr.size + 1);

	// int $0x80 is a favourite of syscall-interceptor rootkits.
	if (int80 < 0) {
		unsigned long handler =
			((unsigned long)*(u32 *)(cur + 0x80 * 16 + 2)) |
			(((unsigned long)*(u16 *)(cur + 0x80 * 16 + 8)) << 32);
		sprint_symbol(name, handler);
		report_add("int80=%s\n", name);
	}

	report_add("cr0_wp=%s cr0=0x%lx\n", (cr0 & (1UL << 16)) ? "on" : "off",
		   cr0);
	report_add("scan done\n");

	// Make the deviation visible in real time through kmsg so the daemon's
	// /dev/kmsg reader can alert without polling the proc node.
	if (defense_tampered)
		pr_warn("sysentinel_defense: RING0 INTEGRITY BREACH detected — "
			"run `rootkit clean` after human confirmation\n");

	diff = idt_first_diff(name, sizeof(name));
	(void)diff;
	mutex_unlock(&defense_lock);
	return 0;
}

// ── Clean ────────────────────────────────────────────────────────────────────

/// Undo whatever scan found: re-point MSR_LSTAR and restore every deviating
/// IDT gate from the module-load baseline. Always leaves CR0.WP set.
long sysentinel_defense_clean(void)
{
	struct desc_ptr idtr;
	u8 cur[IDT_VECTORS * 16];
	u64 lstar_now = 0;
	int restored = 0;
	int v;

	mutex_lock(&defense_lock);

	rdmsrl(MSR_LSTAR, lstar_now);
	if (lstar_now != lstar_baseline) {
		wrmsrl(MSR_LSTAR, lstar_baseline);
		pr_warn("sysentinel_defense: restored MSR_LSTAR %#llx -> "
			"%#llx\n", lstar_now, lstar_baseline);
	}

	store_idt(&idtr);
	idt_capture(cur, sizeof(cur));
	for (v = 0; v < IDT_VECTORS; v++) {
		if (memcmp(cur + v * 16, (u8 *)idt_baseline + v * 16, 16) != 0) {
			idt_write_gate(v, (u8 *)idt_baseline + v * 16);
			pr_warn("sysentinel_defense: restored IDT vector "
				"0x%02x\n", v);
			restored++;
		}
	}

	// Always end with write protection on — never leave the door open.
	{
		unsigned long cr0;
		asm volatile("mov %%cr0, %0" : "=r"(cr0));
		if (!(cr0 & (1UL << 16))) {
			cr0 |= (1UL << 16);
			asm volatile("mov %0, %%cr0" :: "r"(cr0));
			pr_warn("sysentinel_defense: restored CR0.WP\n");
		}
	}

	defense_tampered = false;
	report_clear();
	report_add("clean done restored=%d sleeping baseline re-check below\n",
		   restored);
	mutex_unlock(&defense_lock);

	// Re-scan so the report reflects the now-clean state.
	sysentinel_defense_scan();
	return 0;
}

// ── Rogue process / session termination ──────────────────────────────────────

/// SIGKILL any pid (ring0 can kill processes that hide in userspace).
/// Guards: only pids > 1, never the calling task itself.
long sysentinel_kill_process(long pid)
{
	struct pid *target;
	int rc;

	if (pid <= 1 || pid == (long)task_pid_nr(current))
		return -EINVAL;

	target = find_vpid((pid_t)pid);
	if (!target)
		return -ESRCH;

	rc = kill_pid(target, SIGKILL, 0);
	pr_warn("sysentinel_defense: SIGKILL pid %ld -> %d\n", pid, rc);
	return rc;
}

// ── Lightweight status for the metrics snapshot ──────────────────────────────

/// 1 = LSTAR deviates from baseline (likely hooked), 0 = clean, -EINVAL if
/// the defender never initialised.
long sysentinel_defense_lstar_status(void)
{
	u64 now = 0;

	if (!idt_baseline)
		return -EINVAL;
	rdmsrl(MSR_LSTAR, now);
	return now == lstar_baseline ? 0 : 1;
}

// ── /proc/sysentinel_defense ─────────────────────────────────────────────────

static struct proc_dir_entry *defense_entry;

static ssize_t defense_proc_read(struct file *f, char __user *buf,
				 size_t count, loff_t *off)
{
	ssize_t n;

	mutex_lock(&defense_lock);
	n = defense_report_len;
	if ((loff_t)n <= *off) {
		mutex_unlock(&defense_lock);
		return 0;
	}
	n -= *off;
	if (n > count)
		n = count;
	if (copy_to_user(buf, defense_report + *off, n)) {
		mutex_unlock(&defense_lock);
		return -EFAULT;
	}
	*off += n;
	mutex_unlock(&defense_lock);
	return n;
}

static const struct proc_ops defense_proc_fops = {
	.proc_read = defense_proc_read,
};

// ── Init / exit ──────────────────────────────────────────────────────────────

long sysentinel_defense_init(void)
{
	// Baseline on the current (init) CPU. This must run as early as
	// possible — the snapshot IS the trusted good state. If a rootkit is
	// already resident before loading, its hooks become the "baseline";
	// scan will only ever see deviations *from* that point.
	rdmsrl(MSR_LSTAR, lstar_baseline);

	idt_baseline = kzalloc(IDT_VECTORS * 16, GFP_KERNEL);
	if (!idt_baseline)
		return -ENOMEM;
	if (idt_capture(idt_baseline, IDT_VECTORS * 16) < IDT_VECTORS * 16) {
		kfree(idt_baseline);
		idt_baseline = NULL;
		return -EIO;
	}

	defense_report_len = 0;
	defense_report[0] = '\0';

	defense_entry = proc_create("sysentinel_defense", 0444, NULL,
				     &defense_proc_fops);
	if (!defense_entry) {
		kfree(idt_baseline);
		idt_baseline = NULL;
		return -ENOMEM;
	}

	pr_info("sysentinel_defense: armed (LSTAR baseline 0x%llx, 256 IDT "
		"gates snapshotted)\n", lstar_baseline);
	return 0;
}

void sysentinel_defense_exit(void)
{
	proc_remove(defense_entry);
	defense_entry = NULL;
	kfree(idt_baseline);
	idt_baseline = NULL;
	lstar_baseline = 0;
}