// SPDX-License-Identifier: MIT OR GPL-2.0-or-later
//
// sysentinel_metrics — guest hypercall watcher.
//
// Intercepts every hypercall a guest VM makes to the KVM hypervisor and
// exposes them as a drainable log via /proc/sysentinel_hypercalls.
//
// # How it works
//
// When a guest vCPU executes `vmcall` / `vmmcall`, the host's KVM takes a
// #VMEXIT and runs `kvm_emulate_hypercall()`. That function is an exported
// symbol, so this file kprobes it. The probe fires in the vCPU thread context
// on the host with `%rdi` holding `struct kvm_vcpu *`, from which we read the
// hypercall number and its three/four arguments (the guest's RAX/RBX/RCX/RDX/
// RSI as saved by KVM), the vCPU id, and the host-side task running the vCPU.
//
// Records land in a small raw-spinlock-protected ring buffer. Each read of
// /proc/sysentinel_hypercalls DRAINS the buffer (each record is shown once),
// a natural polling interface for the daemon.
//
// # Failure modes
//
// - Only meaningful on a KVM HOST (bare metal running guests). Inside a VM
//   the kprobe simply never fires and the node reports "no hypervisor".
// - kvm_emulate_hypercall lives in the kvm module. If `kvm` is not loaded at
//   module-init time, kprobe registration fails with ENOENT and the node
//   reports the watcher as unavailable. Reloading sysentinel_metrics after
//   loading `kvm` retries the attach.
// - The probe runs in preempt-disabled / possibly-IRQ context, so it only
//   copies into the ring — no allocation, no sleeping, no pr_* output.
//
// # Non-interference invariant (do not break)
//
// Hypercalls are INTERCEPTED AND REPORTED, never answered. The probe must
// never modify regs, return an injected error, veto the guest, or terminate
// the vCPU/VM/QEMU process in reaction to a hypercall. We cannot distinguish
// a guest's own experiments from a VM-escape attempt, and a faulty veto is
// worse than the thing it pretends to stop; the watcher is an audit log, not
// a firewall. The only kernel action driven by guest activity elsewhere in
// this module is `/proc/sysentinel_hypercalls` being drained by the daemon.

#include <linux/capability.h>
#include <linux/cred.h>
#include <linux/kernel.h>
#include <linux/kprobes.h>
#include <linux/slab.h>
#include <linux/uidgid.h>
#include <linux/kvm_host.h>
#include <linux/module.h>
#include <linux/proc_fs.h>
#include <linux/sched.h>
#include <linux/uaccess.h>

#include "sysentinel_shared.h"

#include <asm/kvm_host.h>	/* struct kvm_vcpu, VCPU_REGS_* */

// ── Ring buffer ──────────────────────────────────────────────────────────────

#define HCW_RING_ENTRIES 128
#define HCW_MAX_LINE 256

/// One captured guest hypercall.
struct hcw_entry {
	unsigned long nr;	/* hypercall number (guest RAX)	    */
	unsigned long a0;	/* arg0 = guest RBX		    */
	unsigned long a1;	/* arg1 = guest RCX		    */
	unsigned long a2;	/* arg2 = guest RDX		    */
	unsigned long a3;	/* arg3 = guest RSI		    */
	u32 vcpu_id;		/* KVM VCPU id (the guest that asked) */
	pid_t pid;		/* host-side task PID (vCPU thread)  */
	char comm[TASK_COMM_LEN]; /* host-side task name		    */
};

static struct hcw_entry hcw_ring[HCW_RING_ENTRIES];
static unsigned int hcw_head;	/* next free slot		    */
static unsigned int hcw_tail;	/* oldest unread slot		    */
static DEFINE_RAW_SPINLOCK(hcw_lock);

/// True once kprobe registration succeeded. Gate for the whole feature.
static bool hcw_watching;

// ── Kprobe ───────────────────────────────────────────────────────────────────

static int hcw_pre_handler(struct kprobe *kp, struct pt_regs *regs);

static struct kprobe sysentinel_kvm_hc_kp = {
	.symbol_name = "kvm_emulate_hypercall",
	.pre_handler = hcw_pre_handler,
};

/// Fires on *every* host-side handling of a guest hypercall.
static int hcw_pre_handler(struct kprobe *kp, struct pt_regs *regs)
{
	struct kvm_vcpu *vcpu;
	struct hcw_entry *e;
	struct task_struct *tsk;
	unsigned long flags;
	unsigned int next;

	if (!hcw_watching)
		return 0;

	vcpu = (struct kvm_vcpu *)regs->di;
	if (!vcpu)
		return 0;

	raw_spin_lock_irqsave(&hcw_lock, flags);

	// Ring full → drop the oldest so a flood that outpaces the daemon
	// never wedges the reader (the daemon always sees the freshest).
	next = (hcw_head + 1) % HCW_RING_ENTRIES;
	if (next == hcw_tail)
		hcw_tail = (hcw_tail + 1) % HCW_RING_ENTRIES;

	e = &hcw_ring[hcw_head];
	e->nr = vcpu->arch.regs[VCPU_REGS_RAX];
	e->a0 = vcpu->arch.regs[VCPU_REGS_RBX];
	e->a1 = vcpu->arch.regs[VCPU_REGS_RCX];
	e->a2 = vcpu->arch.regs[VCPU_REGS_RDX];
	e->a3 = vcpu->arch.regs[VCPU_REGS_RSI];
	e->vcpu_id = vcpu->vcpu_id;
	e->pid = task_pid_nr(current);
	tsk = current;
	memcpy(e->comm, tsk->comm, TASK_COMM_LEN);

	hcw_head = next;
	raw_spin_unlock_irqrestore(&hcw_lock, flags);
	return 0;
}

// ── Ring buffer helpers (caller holds hcw_lock unless noted) ─────────────────

static unsigned int hcw_count_locked(void)
{
	if (hcw_head >= hcw_tail)
		return hcw_head - hcw_tail;
	return HCW_RING_ENTRIES - hcw_tail + hcw_head;
}

/// Format one record into `buf` (up to `cap` bytes). Returns bytes written.
static int hcw_format(struct hcw_entry *e, char *buf, size_t cap)
{
	return scnprintf(buf, cap,
			 "vcpu=%u pid=%d comm=%s hypercall=0x%lx (%lu)"
			 " a0=0x%lx a1=0x%lx a2=0x%lx a3=0x%lx\n",
			 e->vcpu_id, e->pid, e->comm, e->nr, e->nr,
			 e->a0, e->a1, e->a2, e->a3);
}

// ── /proc/sysentinel_hypercalls (drain) ──────────────────────────────────────

static ssize_t hcw_proc_read(struct file *f, char __user *buf, size_t count,
			     loff_t *off)
{
	char *line;
	unsigned long flags;
	size_t used = 0;
	unsigned int drained = 0;
	unsigned int tail_before;
	ssize_t ret;
	int w;

	if (count == 0)
		return 0;

	/*
	 * Restricted for two separate reasons, and the second is the one that
	 * bites:
	 *
	 *   - the records carry guest register contents — guest-physical
	 *     addresses, guest kernel pointers, whatever the guest passed —
	 *     so on a host running someone else's VM this is cross-guest
	 *     disclosure to any local account; and
	 *   - reading DRAINS the ring. An unprivileged process in a loop on
	 *     this file empties the log before the daemon ever sees it, which
	 *     turns the audit trail off from an account that should not be
	 *     able to touch it at all. A log that anyone can quietly empty is
	 *     not a log.
	 */
	if (!sysentinel_caller_is_privileged())
		return -EPERM;

	/*
	 * PAGE_SIZE on the kernel stack is a quarter of it, under a procfs
	 * read that already has the caller's frames below.
	 */
	line = kmalloc(PAGE_SIZE, GFP_KERNEL);
	if (!line)
		return -ENOMEM;

	raw_spin_lock_irqsave(&hcw_lock, flags);

	if (*off == 0) {
		if (!hcw_watching) {
			raw_spin_unlock_irqrestore(&hcw_lock, flags);
			w = scnprintf(line, PAGE_SIZE,
				      "hypercall_watch=unavailable "
				      "(kprobe kvm_emulate_hypercall not attached; "
				      "is the kvm module loaded?)\n");
			if (w > (int)count)
				w = count;
			if (w > 0 && copy_to_user(buf, line, w)) {
				kfree(line);
				return -EFAULT;
			}
			*off += w;
			kfree(line);
			return w;
		}
		w = scnprintf(line, PAGE_SIZE,
			      "hypercall_watch=active entries=%u\n",
			      hcw_count_locked());
		if (w > 0)
			used += w;
	}

	/*
	 * Format out of the ring but do NOT advance the tail yet: the copy to
	 * userspace can fault, and records dropped on a fault are records the
	 * daemon never gets to see. The tail moves only once the bytes have
	 * actually landed.
	 */
	tail_before = hcw_tail;
	{
		unsigned int cursor = hcw_tail;

		while (cursor != hcw_head && used + HCW_MAX_LINE < count &&
		       used + HCW_MAX_LINE < PAGE_SIZE) {
			w = hcw_format(&hcw_ring[cursor], line + used,
				       PAGE_SIZE - used);
			if (w <= 0)
				break;
			used += w;
			cursor = (cursor + 1) % HCW_RING_ENTRIES;
			drained++;
		}
	}
	raw_spin_unlock_irqrestore(&hcw_lock, flags);

	if (used == 0) {
		kfree(line);
		return 0;
	}
	if (used > count)
		used = count;
	if (copy_to_user(buf, line, used)) {
		kfree(line);
		return -EFAULT;
	}
	kfree(line);

	/* Delivered. Now they may go. */
	raw_spin_lock_irqsave(&hcw_lock, flags);
	if (hcw_tail == tail_before)
		hcw_tail = (tail_before + drained) % HCW_RING_ENTRIES;
	raw_spin_unlock_irqrestore(&hcw_lock, flags);

	*off += used;
	ret = used;
	return ret;
}

static const struct proc_ops hcw_proc_fops = {
	.proc_read = hcw_proc_read,
};

// ── Session termination (privileged, gate-kept by procfs write path) ─────────
//
// Closes an account's session by SIGTERM-ing the session leader, then enforcing
// SIGKILL. The existing write path authorisation (capable(CAP_SYS_ADMIN) or
// membership of the write_gid module parameter's group) applies, exactly like
// the `reboot` / `poweroff` control commands.

long sysentinel_session_kill(long pid)
{
	struct pid *target;
	int rc;

	/*
	 * Same guards as sysentinel_kill_process, which had them and this did
	 * not: never pid 1, and never the task carrying out the request. The
	 * kernel protects init from most signals on its own, but "something
	 * else will probably stop us" is not a guard, and closing a session by
	 * killing the process doing the closing is a bug either way.
	 */
	if (pid <= 1 || pid == (long)task_pid_nr(current))
		return -EINVAL;

	target = find_vpid((pid_t)pid);
	if (!target)
		return -ESRCH;

	rc = kill_pid(target, SIGTERM, 0);
	if (rc != 0)
		return rc;

	// The daemon only sends this after a human confirmed; go all the way
	// so a half-attached SSH session can't linger.
	return kill_pid(target, SIGKILL, 0);
}

// ── Init / exit (called from the Rust crate root) ────────────────────────────

static struct proc_dir_entry *hcw_entry;

long sysentinel_hypercall_watcher_init(void)
{
	int rc;

	rc = register_kprobe(&sysentinel_kvm_hc_kp);
	if (rc != 0) {
		// kvm module not loaded, or the symbol is not kprobeable.
		pr_info("sysentinel_metrics: hypercall watcher OFF — "
			"register_kprobe(kvm_emulate_hypercall) failed: %d "
			"(load the kvm module, then reload sysentinel_metrics)\n",
			rc);
		hcw_watching = false;
	} else {
		hcw_watching = true;
		pr_info("sysentinel_metrics: hypercall watcher ON — "
			"guest -> hypervisor hypercalls will be reported\n");
	}

	hcw_entry = proc_create("sysentinel_hypercalls", 0440, NULL,
				&hcw_proc_fops);
	if (hcw_entry)
		proc_set_user(hcw_entry, GLOBAL_ROOT_UID,
			      sysentinel_write_kgid());
	if (!hcw_entry) {
		if (hcw_watching)
			unregister_kprobe(&sysentinel_kvm_hc_kp);
		hcw_watching = false;
		return -ENOMEM;
	}
	return 0;
}

void sysentinel_hypercall_watcher_exit(void)
{
	proc_remove(hcw_entry);
	hcw_entry = NULL;
	if (hcw_watching) {
		unregister_kprobe(&sysentinel_kvm_hc_kp);
		hcw_watching = false;
	}
}