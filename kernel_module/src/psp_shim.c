// SPDX-License-Identifier: MIT OR GPL-2.0-or-later
//
// psp_shim.c — C glue between the Rust psp module and the in-kernel AMD
// CCP/PSP driver (drivers/crypto/ccp/).
//
// The PSP (Platform Security Processor) is ring -3 firmware running on an
// always-on ARM coprocessor embedded in every modern AMD SoC. Mainline Linux
// exposes a sanctioned, out-of-kernel-driver channel to it: the *platform
// access* API (include/uapi/linux/psp-platform-access.h, implemented in
// drivers/crypto/ccp/platform-access.c). The three symbols we use are
// exported for exactly this purpose:
//
//   int  psp_check_platform_access_status(void);           (EXPORT_SYMBOL)
//   int  psp_send_platform_access_msg(enum, struct psp_request *); (EXPORT_SYMBOL_GPL)
//
// Build requirement: CONFIG_CRYPTO_DEV_CCP_DD=y (or =m, loaded before
// sysentinel) with the platform-access feature compiled in. On AMD boxes
// where the platform mailbox is firewalled from the x86 side (most client
// Ryzen) psp_check_platform_access_status() returns -ENODEV and we degrade
// gracefully to vendor-presence only.
//
// The handshake itself mirrors drivers/crypto/ccp/hsti.c: a PSP_CMD_HSTI_QUERY
// round-trip. The PSP replies by filling a Host Security Table (HSTI) word
// with its fused capabilities — bitted evidence (TSME, debug unlock,
// anti-rollback, ROM Armor, TPM availability, …) that the secure processor is
// alive and cooperating, not just present in silicon.

#include <linux/module.h>
#include <linux/types.h>
#include <linux/ktime.h>
#include <linux/timekeeping.h>
#include <linux/psp-platform-access.h>

/* Result shared with Rust (must match the PspQueryResult repr(C) in psp.rs). */
struct sysentinel_psp_result {
	/* 0 = PSP answered the handshake; negative errno otherwise. */
	int  state;
	/* Fused HSTI capability word (valid only when `state` == 0). */
	u32  hsti;
	/* PSP command-response status field (0 = processed OK). */
	u32  status;
	/* Mailbox round-trip time in microseconds. */
	u64  rt_us;
};

/*
 * sysentinel_psp_query() - run one live PSP handshake.
 *
 * Never sleeps (the mailbox path is poll-based, 500 ms bound) and is safe to
 * call from the /proc read path.
 *
 * Returns 0 on success. The classification always lands in `out->state`:
 * a negative errno means the PSP did not answer (platform access off, busy,
 * timed out, or rejected the command); 0 means the HSTI word is valid.
 */
int sysentinel_psp_query(struct sysentinel_psp_result *out)
{
	struct {
		struct psp_req_buffer_hdr header;
		u32 hsti;
	} __packed req;
	u64 t0;
	int ret;

	if (!out)
		return -EINVAL;

	memset(out, 0, sizeof(*out));

	/* Is the PSP platform-access mailbox enabled and bound? */
	ret = psp_check_platform_access_status();
	if (ret < 0) {
		out->state = ret;
		return 0;
	}

	memset(&req, 0, sizeof(req));
	req.header.payload_size = sizeof(req);

	t0 = ktime_get_ns();
	ret = psp_send_platform_access_msg(PSP_CMD_HSTI_QUERY,
					   (struct psp_request *)&req);
	out->rt_us = (ktime_get_ns() - t0) / NSEC_PER_USEC;
	out->status = req.header.status;

	/* ret < 0 → transport-level denial (busy/timeout/no device). */
	if (ret < 0) {
		out->state = ret;
		return 0;
	}

	/* header.status != 0 → the PSP processed the command and refused. */
	if (req.header.status != 0) {
		out->state = -EIO;
		return 0;
	}

	out->state = 0;
	out->hsti  = req.hsti;
	return 0;
}
EXPORT_SYMBOL_GPL(sysentinel_psp_query);

MODULE_LICENSE("GPL");