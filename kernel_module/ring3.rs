// SPDX-License-Identifier: MIT OR GPL-2.0-or-later
//
// Ring −3 partner dispatch for the kernel module.

//! Ring −3 partner dispatch — the kernel-side mirror of the daemon's HAL
//! (`daemon/src/hal.rs`).
//!
//! Modern silicon carries one ring −3 coprocessor, and engaging the wrong one
//! is worse than engaging none: a HECI/MKHI client on an AMD box never binds,
//! and an SMN/ccp mailbox probe on an Intel box is meaningless. So the module
//! decides **once**, from the CPU vendor string, which channel to engage:
//!
//! - **Intel** → the Management Engine over HECI/MKHI (`mei_driver.rs`).
//! - **AMD/Hygon** → the Platform Security Processor over the ccp driver's
//!   platform-access mailbox (`psp.rs`).
//! - **neither** (old/VIA/ARM-class silicon, or vendor we can't vouch for) →
//!   engage nothing, report nothing.
//!
//! The selection is pure CPUID — no I/O, no probing of unbound devices — so it
//! is safe to call from module init and from the `/proc` read path.

/// Which ring −3 partner this CPU carries.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Partner {
    /// Intel: ME/MKHI over the HECI (MEI) bus.
    IntelMe,
    /// AMD/Hygon: Platform Security Processor.
    AmdPsp,
    /// Neither (rare on modern CPUs — old/VIA/ARM-class silicon).
    None,
}

/// Select the ring −3 partner for the current CPU.
pub fn partner() -> Partner {
    if crate::hypercall::cpu_vendor_is_intel() {
        Partner::IntelMe
    } else if crate::hypercall::cpu_vendor_is_amd() {
        Partner::AmdPsp
    } else {
        Partner::None
    }
}

impl Partner {
    /// True when this silicon's ring −3 channel is Intel ME over HECI/MKHI.
    pub fn is_intel_me(self) -> bool {
        self == Partner::IntelMe
    }

    /// True when this silicon's ring −3 channel is the AMD PSP.
    pub fn is_amd_psp(self) -> bool {
        self == Partner::AmdPsp
    }

    /// Human-readable label for module logs.
    pub fn label(self) -> &'static str {
        match self {
            Partner::IntelMe => "Intel ME (HECI/MKHI)",
            Partner::AmdPsp => "AMD PSP (ccp platform-access)",
            Partner::None => "none (no ME/PSP-class coprocessor)",
        }
    }

    /// Short machine-readable token for the metrics line (same vocabulary as
    /// the daemon HAL's `Coprocessor::short()`).
    pub fn short(self) -> &'static str {
        match self {
            Partner::IntelMe => "intel-me",
            Partner::AmdPsp => "amd-psp",
            Partner::None => "none",
        }
    }
}