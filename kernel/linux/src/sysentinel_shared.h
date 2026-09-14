/* SPDX-License-Identifier: MIT OR GPL-2.0-or-later */
/*
 * Who is allowed to read the restricted proc nodes, in one place.
 *
 * Three files publish something a local attacker would like: the control
 * registers in the metrics line, MSR_LSTAR in the defender's report, and the
 * guest register contents in the hypercall log — which is also drained by
 * reading it, so an unprivileged reader can empty the audit trail as well as
 * read it. They all answer the same question, and they answer it here rather
 * than each growing its own idea of "privileged".
 *
 * The bar is the one that already guarded control commands: CAP_SYS_ADMIN, or
 * membership of the group named by the `write_gid` module parameter.
 */
#ifndef SYSENTINEL_SHARED_H
#define SYSENTINEL_SHARED_H

#include <linux/types.h>
#include <linux/uidgid.h>

bool sysentinel_caller_is_privileged(void);
kgid_t sysentinel_write_kgid(void);

#endif /* SYSENTINEL_SHARED_H */
