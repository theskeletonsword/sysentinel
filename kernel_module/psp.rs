// SPDX-License-Identifier: MIT OR GPL-2.0-or-later
//
// AMD Platform Security Processor (PSP) detection and live handshake.

//! AMD Platform Security Processor (PSP) detection and live handshake.
//!
//! Presence is decided by CPU vendor: the PSP is silicon on every AMD/Hygon
//! SoC. But "present" is weak ring -3 evidence — it says nothing about whether
//! the secure processor is actually there and cooperating. So, when this
//! module is built with `--cfg psp_available` (make `PSP=y`), we also perform
//! a real handshake: send `PSP_CMD_HSTI_QUERY` to the PSP through the kernel's
//! CCP/PSP driver (see `src/psp_shim.c`). The PSP answers by filling a Host
//! Security Table (HSTI) word — board-fused evidence (TSME, debug unlock,
//! anti-rollback, ROM Armor, TPM availability, …) that the ring -3 firmware is
//! alive and answering.
//!
//! On AMD platforms where the platform-access mailbox is firewalled from the
//! x86 side (a defence of most client Ryzen), the query degrades cleanly:
//! `PlatformAccessOff`, still reporting the PSP as present silicon.
//!
//! # Reference
//!
//! - Kernel driver: `drivers/crypto/ccp/platform-access.c` + `hsti.c`.
//! - Sanctioned header: `include/uapi/linux/psp-platform-access.h`.
//! - Bit layout of the HSTI word: `union psp_cap_register` in
//!   `drivers/crypto/ccp/psp-dev.h`.

#![allow(dead_code)]
#![allow(clippy::all)]

use kernel::prelude::*;

/// Result struct filled by the C shim (must match `struct sysentinel_psp_result`
/// in `src/psp_shim.c`).
#[repr(C)]
struct PspQueryResult {
    /// 0 = PSP answered the handshake; negative errno otherwise.
    state: i32,
    /// Fused HSTI capability word (valid only when `state == 0`).
    hsti: u32,
    /// PSP command-response status (0 = processed OK).
    status: u32,
    /// Mailbox round-trip time in microseconds.
    rt_us: u64,
}

/// FFI to the exported ccp platform-access glue (`src/psp_shim.c`), compiled
/// only when the kernel ships the CCP/PSP driver (`--cfg psp_available`).
#[cfg(psp_available)]
extern "C" {
    fn sysentinel_psp_query(out: *mut PspQueryResult) -> core::ffi::c_int;
}

/// HSTI security-capability bit positions, per `union psp_cap_register` in
/// `drivers/crypto/ccp/psp-dev.h`. The PSP fills these in its reply.
mod hsti_bits {
    pub const SECURITY_REPORTING: u32 = 1 << 7;
    pub const FUSED_PART: u32 = 1 << 8;
    pub const BOOT_INTEGRITY: u32 = 1 << 9;
    pub const DEBUG_LOCK_ON: u32 = 1 << 10;
    pub const TSME_STATUS: u32 = 1 << 13;
    pub const ANTI_ROLLBACK_STATUS: u32 = 1 << 15;
    pub const RPMC_PRODUCTION_ENABLED: u32 = 1 << 16;
    pub const RPMC_SPIROM_AVAILABLE: u32 = 1 << 17;
    pub const HSP_TPM_AVAILABLE: u32 = 1 << 18;
    pub const ROM_ARMOR_ENFORCED: u32 = 1 << 19;
}

/// PSP status classification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PspStatus {
    /// The PSP answered a live HSTI handshake with the given fused
    /// capabilities; `rt_us` is the mailbox round-trip time.
    Up { hsti: u32, rt_us: u64 },
    /// AMD SoC, but the platform-access mailbox is not reachable from the x86
    /// side (platform features off / firewalled). Degraded presence only.
    PlatformAccessOff,
    /// AMD SoC, mailbox busy (retry later).
    MailboxBusy,
    /// AMD SoC, mailbox timed out.
    MailboxTimeout,
    /// AMD SoC, the PSP processed the command and refused (status != 0).
    Denied,
    /// AMD SoC; no ccp platform-access glue in this build (no `psp_available`).
    Present,
    /// No AMD secure processor (Intel/ARM/…).
    NotApplicable,
}

impl PspStatus {
    /// Short machine-readable token for the metrics line.
    pub fn as_str(self) -> &'static str {
        match self {
            PspStatus::Up { .. } => "up",
            PspStatus::PlatformAccessOff => "plat",
            PspStatus::MailboxBusy => "busy",
            PspStatus::MailboxTimeout => "timeout",
            PspStatus::Denied => "denied",
            PspStatus::Present => "present",
            PspStatus::NotApplicable => "n/a",
        }
    }

    /// Concatenate the HSTI security flags that are set into `buf` as a
    /// comma-separated list (e.g. `tsme,dbglock,antiroll`), mirroring the
    /// ccp driver's sysfs attribute names. Returns the number of bytes used.
    pub fn hsti_flags_buf(&self, buf: &mut [u8; 64]) -> usize {
        let hsti = match self {
            PspStatus::Up { hsti, .. } => *hsti,
            _ => return 0,
        };

        let mut out = _Buf { buf, pos: 0 };
        let mut first = true;
        let mut push = |label: &str, out: &mut _Buf<'_>| {
            if first {
                first = false;
            } else {
                let _ = out.write(b",");
            }
            let _ = out.write(label.as_bytes());
        };

        if hsti & hsti_bits::FUSED_PART != 0 {
            push("fused", &mut out);
        }
        if hsti & hsti_bits::BOOT_INTEGRITY != 0 {
            push("bootint", &mut out);
        }
        if hsti & hsti_bits::DEBUG_LOCK_ON != 0 {
            push("dbglock", &mut out);
        }
        if hsti & hsti_bits::TSME_STATUS != 0 {
            push("tsme", &mut out);
        }
        if hsti & hsti_bits::ANTI_ROLLBACK_STATUS != 0 {
            push("antiroll", &mut out);
        }
        if hsti & hsti_bits::RPMC_PRODUCTION_ENABLED != 0 {
            push("rpmcprod", &mut out);
        }
        if hsti & hsti_bits::RPMC_SPIROM_AVAILABLE != 0 {
            push("rpmcrom", &mut out);
        }
        if hsti & hsti_bits::HSP_TPM_AVAILABLE != 0 {
            push("hsptpm", &mut out);
        }
        if hsti & hsti_bits::ROM_ARMOR_ENFORCED != 0 {
            push("romarmor", &mut out);
        }
        out.pos
    }

    /// True when the handshake token is "the PSP answered".
    pub fn is_up(self) -> bool {
        matches!(self, PspStatus::Up { .. })
    }
}

/// Bounded writer for flag decoding (no heap on the read path).
struct _Buf<'a> {
    buf: &'a mut [u8; 64],
    pos: usize,
}

impl _Buf<'_> {
    fn write(&mut self, bytes: &[u8]) -> core::fmt::Result {
        let remaining = self.buf.len().saturating_sub(self.pos);
        let n = bytes.len().min(remaining);
        self.buf[self.pos..self.pos + n].copy_from_slice(&bytes[..n]);
        self.pos += n;
        Ok(())
    }
}

/// Probe the PSP: presence first, then (when compiled with the ccp glue) a
/// live HSTI handshake. Rounds down to [`PspStatus::Present`] if the query
/// cannot run.
pub fn detect() -> PspStatus {
    if !crate::hypercall::cpu_vendor_is_amd() {
        return PspStatus::NotApplicable;
    }

    #[cfg(psp_available)]
    {
        let mut out = PspQueryResult {
            state: 0,
            hsti: 0,
            status: 0,
            rt_us: 0,
        };
        // SAFETY: `out` points to a writable stack struct; the C shim only
        // writes to it and never retains the pointer.
        let rc = unsafe { sysentinel_psp_query(&mut out) };

        if rc == 0 {
            if out.state == 0 {
                return PspStatus::Up {
                    hsti: out.hsti,
                    rt_us: out.rt_us,
                };
            }
            if out.state == -(ENODEV.to_errno() as i32) {
                return PspStatus::PlatformAccessOff;
            }
            if out.state == -(EBUSY.to_errno() as i32) {
                return PspStatus::MailboxBusy;
            }
            if out.state == -(ETIMEDOUT.to_errno() as i32) {
                return PspStatus::MailboxTimeout;
            }
            // Any other negative errno (EIO from a refused command, etc.).
            return PspStatus::Denied;
        }
    }

    PspStatus::Present
}