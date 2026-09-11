// SPDX-License-Identifier: MIT OR GPL-2.0-or-later
//
// sysentinel_metrics procfs shim.
//
// rust-for-linux 7.1 has no `/proc` abstraction, so this small C file is
// what publishes the module's interface as `/proc/sysentinel_metrics`
// (instead of a misc chardev in /dev). It owns no logic: reads delegate to
// the Rust-side `rs_render_snapshot()` callback and writes (control
// commands) to `rs_exec_command()`.
//
// Permission model:
//   - read: 0644, anyone — but the snapshot is rendered according to WHO is
//     reading. CR2 (last page-fault address) and CR3 (page-table base) are
//     held back from callers that have not cleared the write gate, because
//     those two are what a local exploit wants in order to defeat kernel
//     address randomisation. Everything else in the line is feature bits and
//     firmware versions, and stays readable so an unprivileged daemon can
//     still report status.
//   - write: the module itself gate-keeps via `capable(CAP_SYS_ADMIN)` or
//     membership of the GID in the `write_gid` module parameter
//     (0 = root only). There is no /dev node and no udev rule involved.
//
// Control commands accepted at write time (see rs_exec_command in
// sysentinel_core.rs): `reboot`, `poweroff`, `cr0_wp on|off`, `status`.

#include <linux/capability.h>
#include <linux/cred.h>
#include <linux/fs.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/proc_fs.h>
#include <linux/slab.h>
#include <linux/uidgid.h>
#include <linux/uaccess.h>

// Rust-side callbacks (defined in sysentinel_core.rs, #[no_mangle]).
// Return 0 / positive on success, a negative errno otherwise.
extern long rs_render_snapshot(unsigned char *buf, unsigned long cap,
			       int privileged);
extern long rs_exec_command(const char *cmd);

static struct proc_dir_entry *sysentinel_entry;

// GID allowed to issue control commands (poweroff/reboot/cr0 manipulation).
// 0 means "only uid 0 (capable(CAP_SYS_ADMIN))". Set at modprobe time:
//   modprobe sysentinel_metrics write_gid=$(id -g sysentinel)
static unsigned int write_gid = 0;
module_param(write_gid, uint, 0644);
MODULE_PARM_DESC(write_gid,
		 "GID allowed to send control commands; 0 = root only");

// Does the caller clear the same bar that guards control commands?
static bool sysentinel_caller_is_privileged(void)
{
	return capable(CAP_SYS_ADMIN) ||
	       in_group_p(make_kgid(&init_user_ns, write_gid));
}

static ssize_t sysentinel_proc_read(struct file *f, char __user *buf,
				    size_t count, loff_t *off)
{
	char *line;
	ssize_t n;

	if (count == 0)
		return 0;

	line = kmalloc(PAGE_SIZE, GFP_KERNEL);
	if (!line)
		return -ENOMEM;

	n = rs_render_snapshot((unsigned char *)line, PAGE_SIZE,
			       sysentinel_caller_is_privileged() ? 1 : 0);
	if (n < 0)
		goto out;

	n = simple_read_from_buffer(buf, count, off, line, n);
out:
	kfree(line);
	return n;
}

static ssize_t sysentinel_proc_write(struct file *f, const char __user *buf,
				     size_t count, loff_t *off)
{
	char cmd[64];
	long n;

	if (count == 0 || count >= sizeof(cmd))
		return -EINVAL;

	// Inode mode grants read to everyone; writes are gate-kept here.
	if (!sysentinel_caller_is_privileged())
		return -EPERM;

	if (copy_from_user(cmd, buf, count))
		return -EFAULT;
	cmd[count] = '\0';

	// Tolerate a trailing newline from echo/cat piping.
	if (cmd[count - 1] == '\n')
		cmd[count - 1] = '\0';

	n = rs_exec_command(cmd);
	if (n < 0)
		return n;

	*off += count;
	return count;
}

static const struct proc_ops sysentinel_proc_fops = {
	.proc_read	= sysentinel_proc_read,
	.proc_write	= sysentinel_proc_write,
};

long sysentinel_proc_init(void)
{
	sysentinel_entry = proc_create("sysentinel_metrics", 0644, NULL,
				       &sysentinel_proc_fops);
	if (!sysentinel_entry)
		return -ENOMEM;
	return 0;
}

void sysentinel_proc_exit(void)
{
	proc_remove(sysentinel_entry);
	sysentinel_entry = NULL;
}