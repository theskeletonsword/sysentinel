// SPDX-License-Identifier: MIT OR GPL-2.0-or-later
/*
 * sysentinel SMM shim — ring −2 (SMM) firmware-posture reader.
 *
 * This shim is ACPI-ONLY and PROVABLY NEVER raises an SMI. There is no code
 * path, command or flag that performs an outb() to an APM port (0xB2/0xB3) or
 * any other SMM-triggering I/O: the ring −2 channel observes the firmware's
 * SMM posture strictly through the tables the firmware itself publishes, the
 * way an anti-bootkit audit should — read the declaration, never poke the
 * machine.
 *
 *   - FADT `smi_command`: the firmware's official SMM command port and the
 *     spec-defined command values it documents (acpi_enable / acpi_disable /
 *     s4_bios_request / pstate_control). The kernel itself writes through
 *     them, but ONLY with those declared values (drivers/acpi/processor_perflib.c
 *     pstate path; FreeBSD sys/x86/cpufreq/smist.c). We read-and-report, and
 *     never write — surface them so the audit can see the declared bridge.
 *   - WSMT (Windows SMM Security Mitigations Table): the firmware's own claims
 *     about which SMM mitigations are active (fixed CommBuffers, nested-pointer
 *     protection, system-resource protection). The posture measurement: a weak
 *     or absent WSMT with a published calling interface is exactly the
 *     configuration an SMM bootkit needs.
 *
 * Both reads use acpi_get_table()/acpi_gbl_FADT — the same read-only ACPI
 * subsystem the kernel uses to discover power/sleep interfaces. No SMI, no
 * port I/O, no memremap of firmware memory, no firmware-address writes.
 */
#include <linux/acpi.h>
#include <linux/kernel.h>
#include <linux/types.h>

/* Rust-facing exports (declared here so -Wmissing-prototypes stays quiet). */
int sysentinel_smm_fadt_scan(u64 *port, u8 *acpi_en, u8 *acpi_dis,
			     u8 *pstate_ctl, u8 *s4_bios);
int sysentinel_smm_wsmt_scan(u32 *flags, int *present);

/*
 * Report the firmware's OFFICIAL SMM command interface from the FADT
 * (`smi_command` port + the spec-defined command values it documents). Read-
 * only: nothing here ever writes the port. Returns 1 when a port is declared,
 * 0 when the firmware publishes none.
 */
#ifdef CONFIG_ACPI
int sysentinel_smm_fadt_scan(u64 *port, u8 *acpi_en, u8 *acpi_dis,
			     u8 *pstate_ctl, u8 *s4_bios)
{
	u64 p = (u64)acpi_gbl_FADT.smi_command;

	if (port)
		*port = p;
	if (acpi_en)
		*acpi_en = acpi_gbl_FADT.acpi_enable;
	if (acpi_dis)
		*acpi_dis = acpi_gbl_FADT.acpi_disable;
	if (pstate_ctl)
		*pstate_ctl = acpi_gbl_FADT.pstate_control;
	if (s4_bios)
		*s4_bios = acpi_gbl_FADT.s4_bios_request;

	return p != 0;
}

/*
 * Read the WSMT "Windows SMM Security Mitigations Table": the firmware's own
 * claim of which SMM mitigations are active. Read-only. Returns the raw
 * protection_flags word and sets *present = 1 when the table exists.
 */
int sysentinel_smm_wsmt_scan(u32 *flags, int *present)
{
	struct acpi_table_wsmt *wsmt;
	acpi_status status;

	if (present)
		*present = 0;
	if (flags)
		*flags = 0;

	status = acpi_get_table(ACPI_SIG_WSMT, 1,
				(struct acpi_table_header **)&wsmt);
	if (ACPI_FAILURE(status))
		return -EIO;

	if (flags)
		*flags = wsmt->protection_flags;
	if (present)
		*present = 1;

	acpi_put_table(&wsmt->header);
	return 0;
}
#else
int sysentinel_smm_fadt_scan(u64 *port, u8 *acpi_en, u8 *acpi_dis,
			     u8 *pstate_ctl, u8 *s4_bios)
{
	if (port)
		*port = 0;
	if (acpi_en)
		*acpi_en = 0;
	if (acpi_dis)
		*acpi_dis = 0;
	if (pstate_ctl)
		*pstate_ctl = 0;
	if (s4_bios)
		*s4_bios = 0;
	return 0;
}

int sysentinel_smm_wsmt_scan(u32 *flags, int *present)
{
	if (present)
		*present = 0;
	if (flags)
		*flags = 0;
	return -EOPNOTSUPP;
}
#endif