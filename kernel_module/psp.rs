// SPDX-License-Identifier: GPL-2.0-only
//
// AMD Platform Security Processor (PSP) presence detection.

//! AMD Platform Security Processor (PSP) presence detection.
//!
//! The PSP is a dedicated coprocessor embedded in modern AMD SoCs. Mainline
//! Linux exposes no stable, unprivileged node for it on stock kernels (no
//! `/dev/psp`; the TEE path only exists on SEV guests/VMs), and `STRICT_DEVMEM`
//! blocks raw SMN access via `/dev/mem`. The portable, dependency-free signal
//! used here is CPU vendor: the PSP exists iff the physical CPU is AMD.
//! Reading the actual firmware version would require privileged SP access and
//! is out of scope for this detector.

/// PSP presence classification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PspStatus {
    /// AMD SoC — the PSP is part of the silicon.
    Present,
    /// No AMD secure processor (Intel/ARM/…).
    NotApplicable,
}

impl PspStatus {
    /// Short machine-readable token for the metrics line.
    pub fn as_str(self) -> &'static str {
        match self {
            PspStatus::Present => "present",
            PspStatus::NotApplicable => "n/a",
        }
    }
}

/// Detect PSP presence on the current CPU.
pub fn detect() -> PspStatus {
    if crate::hypercall::cpu_vendor_is_amd() {
        PspStatus::Present
    } else {
        PspStatus::NotApplicable
    }
}