// SPDX-License-Identifier: MIT OR GPL-2.0-or-later
//!
//! Architecture-agnostic hypercall interface.
//!
//! # Overview
//!
//! Provides safe Rust wrappers around architecture-specific hypervisor-call
//! instructions. The correct instruction is selected at runtime based on
//! CPUID / system-register interrogation so that the same module binary can
//! run on Intel, AMD, and AArch64 guests without recompilation.
//!
//! | Architecture | Instruction  | Hypervisor ABI                      |
//! |---|---|---|
//! | x86_64       | `vmcall`     | KVM (Intel VT-x), VMware, Hyper-V   |
//! | x86_64       | `vmmcall`    | KVM (AMD SVM)                       |
//! | AArch64      | `hvc #0`     | SMCCC — KVM, Xen, Hafnium           |
//!
//! # Safety contract
//!
//! `vmcall` / `vmmcall` / `hvc` are privileged instructions. On bare-metal
//! or under an incompatible hypervisor they raise `#UD` or `#GP`, causing
//! an oops/panic in ring-0 context. This module **always** calls
//! `detect_hypervisor()` and returns `Err(ENODEV)` on bare-metal instead of
//! issuing the instruction blindly.
//!
//! The raw `unsafe fn vmcall`, `unsafe fn vmmcall`, and `unsafe fn hvc`
//! wrappers are intentionally `pub(super)` rather than `pub` — callers
//! inside this crate should use the safe `hypercall()` dispatcher instead.
//!
//! # Calling convention (KVM / Linux ABI)
//!
//! Reference: `Documentation/virt/kvm/api.rst`, `include/uapi/linux/kvm_para.h`
//!
//! ```text
//! Input  : RAX/X0 = hypercall number
//!          RBX/X1 = arg0,  RCX/X2 = arg1,  RDX/X3 = arg2
//! Output : RAX/X0 = return value (negative errno on error)
//! ```
//!
//! On x86_64 the hypervisor may clobber RBX, RCX, RDX.
//! On AArch64 (SMCCC) the hypervisor may clobber X4–X7 and X17.

#![allow(dead_code)]

use kernel::prelude::*;

// ── Hypervisor kind ──────────────────────────────────────────────────────────

/// Identifies the underlying hypervisor, if any.
///
/// Used to select the correct hypercall instruction. Detection is performed
/// once at module init time and is not expected to change while the module
/// is loaded (you cannot live-migrate between hypervisors without a reboot).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HypervisorKind {
    /// KVM running on an Intel VT-x physical CPU. Use `vmcall`.
    KvmIntel,
    /// KVM running on an AMD SVM physical CPU. Use `vmmcall`.
    KvmAmd,
    /// VMware (ESXi, Workstation, Fusion). Uses `vmcall`.
    Vmware,
    /// Xen hypervisor. Uses `vmcall` on x86, `hvc` on AArch64.
    Xen,
    /// Microsoft Hyper-V. Uses `vmcall`.
    HyperV,
    /// QEMU/TCG (software emulation, no hardware extension). `vmcall` works
    /// if KVM is not emulated; typically avoid hypercalls here.
    QemuTcg,
    /// Hypervisor present (CPUID bit set) but vendor string unrecognised.
    Unknown,
    /// No hypervisor detected — bare-metal execution. Hypercalls MUST NOT
    /// be issued in this case.
    None,
}

// ── Hypercall result ─────────────────────────────────────────────────────────

/// Values in RAX/RBX/RCX/RDX (x86_64) or X0/X1/X2/X3 (AArch64) as returned
/// by the hypervisor after a hypercall.
///
/// Only `rax` (the primary return value) is guaranteed to be meaningful by
/// all KVM-compatible ABIs. The other fields are provided for hypervisors that
/// return additional data in secondary registers.
#[derive(Debug, Clone, Copy, Default)]
pub struct HypercallResult {
    /// Primary return value (RAX / X0). Negative = errno.
    pub rax: u64,
    /// Secondary return (RBX / X1). Meaning is hypercall-number-specific.
    pub rbx: u64,
    /// Tertiary return (RCX / X2).
    pub rcx: u64,
    /// Quaternary return (RDX / X3).
    pub rdx: u64,
}

// ── CPUID-based hypervisor detection (x86_64) ────────────────────────────────

/// Detect the hypervisor by querying CPUID on x86_64.
///
/// Two CPUID leaves are used:
/// 1. Leaf 0x1, ECX bit 31 — "Hypervisor Present Bit" set by all conformant
///    Type-1 and Type-2 hypervisors (KVM, VMware, Hyper-V, Xen …).
/// 2. Leaf 0x4000_0000 — returns a 12-byte ASCII vendor string in
///    EBX:ECX:EDX (note: *not* the same order as leaf 0x0).
///
/// CPUID never faults, so this function is safe to call on bare-metal.
#[cfg(target_arch = "x86_64")]
pub fn detect_hypervisor() -> HypervisorKind {
    // ── Step 1: check the hypervisor present bit ─────────────────────────────
    let ecx_leaf1: u32;
    // SAFETY: CPUID is always available on x86_64 and never faults at any
    // privilege level. The output registers are fully specified.
    unsafe {
        core::arch::asm!(
            // EBX cannot be named as an asm operand (LLVM reserves it as the
            // PIC base pointer), so save/restore it around the instruction.
            "push rbx",
            "cpuid",
            "pop rbx",
            // EAX = leaf number in, discarded out
            inout("eax") 1u32 => _,
            out("ecx") ecx_leaf1,
            out("edx") _,
            options(nostack, preserves_flags),
        );
    }

    // Bit 31 of ECX is the "Hypervisor Present Bit".
    if (ecx_leaf1 >> 31) & 1 == 0 {
        return HypervisorKind::None;
    }

    // ── Step 2: read the 12-byte vendor string from leaf 0x40000000 ──────────
    let (ebx, ecx, edx): (u32, u32, u32);
    unsafe {
        core::arch::asm!(
            "push rbx",
            "cpuid",
            "mov {tmp:e}, ebx",
            "pop rbx",
            inout("eax") 0x4000_0000u32 => _,
            tmp = out(reg) ebx,
            out("ecx") ecx,
            out("edx") edx,
            options(nostack, preserves_flags),
        );
    }

    // Reconstruct the 12-byte vendor string (EBX bytes 0-3, ECX bytes 4-7,
    // EDX bytes 8-11), each register in little-endian byte order.
    let mut vendor = [0u8; 12];
    vendor[0..4].copy_from_slice(&ebx.to_le_bytes());
    vendor[4..8].copy_from_slice(&ecx.to_le_bytes());
    vendor[8..12].copy_from_slice(&edx.to_le_bytes());

    match &vendor {
        b"KVMKVMKVM\0\0\0" => {
            // KVM: distinguish Intel (vmcall) vs AMD (vmmcall) by the physical
            // CPU vendor string from CPUID leaf 0x0.
            let (cpu_ebx, cpu_ecx, cpu_edx): (u32, u32, u32);
            unsafe {
                core::arch::asm!(
                    "push rbx",
                    "cpuid",
                    "mov {tmp:e}, ebx",
                    "pop rbx",
                    inout("eax") 0u32 => _,
                    tmp = out(reg) cpu_ebx,
                    out("ecx") cpu_ecx,
                    out("edx") cpu_edx,
                    options(nostack, preserves_flags),
                );
            }

            // "GenuineIntel": EBX=0x756e_6547 EDX=0x4965_6e69 ECX=0x6c65_746e
            // "AuthenticAMD": EBX=0x6874_7541 EDX=0x6974_6e65 ECX=0x444d_4163
            // "HygonGenuine": EBX=0x6f79_4879 — AMD-compatible, use vmmcall
            if cpu_ebx == 0x756e_6547 && cpu_edx == 0x4965_6e69 {
                HypervisorKind::KvmIntel
            } else {
                HypervisorKind::KvmAmd
            }
        }
        b"VMwareVMware" => HypervisorKind::Vmware,
        b"XenVMMXenVMM" => HypervisorKind::Xen,
        b"Microsoft Hv" => HypervisorKind::HyperV,
        b"TCGTCGTCGTCG" => HypervisorKind::QemuTcg,
        _ => HypervisorKind::Unknown,
    }
}

// ── System-register-based hypervisor detection (AArch64) ─────────────────────

/// Detect hypervisor presence on AArch64 by reading `ID_AA64PFR0_EL1`.
///
/// Bits [35:32] encode EL2 support:
/// - `0b0001` — EL2 is implemented (hypervisor can be present).
/// - `0b0000` — EL2 not implemented (bare-metal-only system).
///
/// Reading system registers at EL1 never faults.
#[cfg(target_arch = "aarch64")]
pub fn detect_hypervisor() -> HypervisorKind {
    let pfr0: u64;
    // SAFETY: `mrs` on ID_AA64PFR0_EL1 is a read-only system register
    // accessible at EL1 and EL0 (when EL1 hasn't trapped it). It never faults.
    unsafe {
        core::arch::asm!(
            "mrs {val}, ID_AA64PFR0_EL1",
            val = out(reg) pfr0,
            options(nostack, preserves_flags),
        );
    }
    let el2_field = (pfr0 >> 32) & 0xF;
    if el2_field != 0 {
        // EL2 present; we cannot distinguish KVM from Xen from EL1, but
        // both use the SMCCC `hvc #0` path.
        HypervisorKind::Unknown
    } else {
        HypervisorKind::None
    }
}

/// On all other architectures, we cannot detect hypervisors and refuse to call.
#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
pub fn detect_hypervisor() -> HypervisorKind {
    HypervisorKind::None
}

// ── CPU vendor (ring −3 partner selection) ───────────────────────────────────

/// Return the 12-byte CPU vendor string from CPUID leaf 0 (EBX, ECX, EDX,
/// each little-endian). `[0; 12]` on architectures without CPUID.
#[cfg(target_arch = "x86_64")]
fn cpu_vendor() -> [u8; 12] {
    let (ebx, ecx, edx): (u32, u32, u32);
    unsafe {
        core::arch::asm!(
            "push rbx",
            "cpuid",
            "mov {tmp:e}, ebx",
            "pop rbx",
            inout("eax") 0u32 => _,
            tmp = out(reg) ebx,
            out("ecx") ecx,
            out("edx") edx,
            options(nostack, preserves_flags),
        );
    }

    let mut vendor = [0u8; 12];
    vendor[0..4].copy_from_slice(&ebx.to_le_bytes());
    vendor[4..8].copy_from_slice(&ecx.to_le_bytes());
    vendor[8..12].copy_from_slice(&edx.to_le_bytes());
    vendor
}

#[cfg(not(target_arch = "x86_64"))]
fn cpu_vendor() -> [u8; 12] {
    [0; 12]
}

/// Return whether the physical CPU is AMD (or the AMD-compatible Hygon).
///
/// The AMD Platform Security Processor (PSP) is an on-die coprocessor present
/// on every modern AMD SoC. Mainline Linux exposes no stable sysfs node or
/// `/dev` entry for it on stock kernels, so CPU vendor is the portable,
/// dependency-free signal used by the module's `ring3` dispatcher.
pub fn cpu_vendor_is_amd() -> bool {
    let vendor = cpu_vendor();
    vendor == *b"AuthenticAMD" || vendor == *b"HygonGenuine"
}

/// Return whether the physical CPU is Intel.
///
/// Intel System-on-Chip (SOC) platforms carry the Management Engine (ME),
/// reachable over the HECI/MEI bus — the counterpart of AMD's PSP. Used by the
/// module's `ring3` dispatcher to pick which ring −3 channel to engage.
pub fn cpu_vendor_is_intel() -> bool {
    cpu_vendor() == *b"GenuineIntel"
}

// ── Raw hypercall instructions ────────────────────────────────────────────────

/// Issue an Intel VT-x `vmcall` instruction (x86_64 only).
///
/// The KVM hypercall ABI is used:
///   RAX = hypercall number (in) / return value (out)
///   RBX = arg0, RCX = arg1, RDX = arg2
///
/// # Safety
///
/// The caller MUST have verified (via [`detect_hypervisor`]) that a VMX-mode
/// hypervisor is active. On bare-metal or under an SVM hypervisor without
/// `vmcall` support, this instruction raises a `#GP` fault.
///
/// The kernel's Rust inline-asm requirement for `rbx` on x86_64: `rbx` is a
/// callee-saved register used as a PIC base on some targets. Using it as an
/// operand is safe here because we save/restore via the `inout` constraint,
/// and kernel Rust is compiled without PIC (kernel is at a fixed VA).
#[cfg(target_arch = "x86_64")]
pub unsafe fn vmcall(nr: u64, a0: u64, a1: u64, a2: u64) -> HypercallResult {
    let (out_rax, out_rcx, out_rdx): (u64, u64, u64);
    unsafe {
        core::arch::asm!(
            // RBX cannot be named as an asm operand (LLVM reserves it as the
            // PIC base pointer). Load arg0 into RBX inside the asm and fully
            // save/restore RBX around the hypercall.
            "push rbx",
            "mov {a0_tmp}, rbx",
            "vmcall",
            "pop rbx",
            a0_tmp = in(reg) a0,
            inout("rax") nr => out_rax,
            inout("rcx") a1 => out_rcx,
            inout("rdx") a2 => out_rdx,
            options(nostack, preserves_flags),
        );
    }
    // KVM preserves RBX across the hypercall, so it still holds `a0`.
    HypercallResult { rax: out_rax, rbx: a0, rcx: out_rcx, rdx: out_rdx }
}

/// Issue an AMD SVM `vmmcall` instruction (x86_64 only).
///
/// Same KVM hypercall ABI as `vmcall` — only the instruction mnemonic differs.
///
/// # Safety
///
/// The caller MUST have verified that an AMD SVM hypervisor is active. On
/// bare-metal or under an Intel hypervisor, this raises `#UD`.
#[cfg(target_arch = "x86_64")]
pub unsafe fn vmmcall(nr: u64, a0: u64, a1: u64, a2: u64) -> HypercallResult {
    let (out_rax, out_rcx, out_rdx): (u64, u64, u64);
    unsafe {
        core::arch::asm!(
            "push rbx",
            "mov {a0_tmp}, rbx",
            "vmmcall",
            "pop rbx",
            a0_tmp = in(reg) a0,
            inout("rax") nr => out_rax,
            inout("rcx") a1 => out_rcx,
            inout("rdx") a2 => out_rdx,
            options(nostack, preserves_flags),
        );
    }
    HypercallResult { rax: out_rax, rbx: a0, rcx: out_rcx, rdx: out_rdx }
}

/// Issue an AArch64 `hvc #0` (Hypervisor Call) instruction.
///
/// Uses the SMCCC (SMC Calling Convention) ABI:
///   X0 = function identifier (in) / primary return value (out)
///   X1 = arg0 (in) / secondary return (out)
///   X2 = arg1 (in) / tertiary return (out)
///   X3 = arg2 (in) / quaternary return (out)
///   X4–X7 may be clobbered by the hypervisor.
///   X17 (IP1) may be clobbered.
///
/// # Safety
///
/// The caller MUST be running at EL1 with an EL2 hypervisor present. At EL0
/// (user-space), `hvc` is always trapped by EL1 (the kernel) and will not
/// reach the hypervisor directly. On a bare-metal EL1 system, `hvc` raises
/// an exception to EL2 stub code that will panic.
#[cfg(target_arch = "aarch64")]
pub unsafe fn hvc(nr: u64, a0: u64, a1: u64, a2: u64) -> HypercallResult {
    let (r0, r1, r2, r3): (u64, u64, u64, u64);
    core::arch::asm!(
        "hvc #0",
        inout("x0") nr => r0,
        inout("x1") a0 => r1,
        inout("x2") a1 => r2,
        inout("x3") a2 => r3,
        // SMCCC says X4–X7 and X17 may be clobbered by the callee.
        lateout("x4") _,
        lateout("x5") _,
        lateout("x6") _,
        lateout("x7") _,
        lateout("x17") _,
        // NOTE: `preserves_flags` is intentionally NOT used — hvc may
        // modify the NZCV flags depending on the implementation.
        options(nostack),
    );
    HypercallResult { rax: r0, rbx: r1, rcx: r2, rdx: r3 }
}

// ── Safe, architecture-agnostic dispatcher ────────────────────────────────────

/// KVM hypercall numbers (from `include/uapi/linux/kvm_para.h`).
pub mod kvm_hc {
    /// KVM_HC_VAPIC_POLL_IRQ — check for pending virtual APICinterrupts.
    pub const VAPIC_POLL_IRQ: u64 = 1;
    /// KVM_HC_MMU_OP — multi-call MMU operation (deprecated).
    pub const MMU_OP: u64 = 2;
    /// KVM_HC_FEATURES — query supported KVM hypercall feature bits.
    pub const FEATURES: u64 = 3;
    /// KVM_HC_PPC_MAP_MAGIC_PAGE — PowerPC only; listed for completeness.
    pub const PPC_MAP_MAGIC_PAGE: u64 = 4;
    /// KVM_HC_KICK_CPU — kick a virtual CPU out of HLT.
    pub const KICK_CPU: u64 = 5;
    /// KVM_HC_SEND_IPI — send an inter-processor interrupt.
    pub const SEND_IPI: u64 = 10;
}

/// Architecture-agnostic safe hypercall dispatcher.
///
/// Detects the hypervisor on each call (detection is cheap — two CPUID
/// instructions — and the result can be cached by the caller if performance
/// is critical). Routes to `vmcall`, `vmmcall`, or `hvc` based on the
/// detected hypervisor type. Returns:
///   - `Ok(result)` — hypercall issued successfully.
///   - `Err(ENODEV)` — no hypervisor detected (bare-metal).
///   - `Err(ENOSYS)` — hypervisor present but hypercall not supported on this path.
///
/// # Example
///
/// ```no_run
/// // Query KVM feature flags from inside a guest kernel:
/// match hypercall(kvm_hc::FEATURES, 0, 0, 0) {
///     Ok(r) => pr_info!("KVM features: {:#x}\n", r.rax),
///     Err(e) => pr_warn!("Not virtualised or hypercall not available: {e}\n"),
/// }
/// ```
pub fn hypercall(nr: u64, a0: u64, a1: u64, a2: u64) -> Result<HypercallResult> {
    match detect_hypervisor() {
        HypervisorKind::None => {
            pr_debug!(
                "sysentinel: hypercall(nr={nr:#x}) skipped — bare-metal system\n"
            );
            Err(ENODEV)
        }

        #[cfg(target_arch = "x86_64")]
        HypervisorKind::KvmIntel
        | HypervisorKind::Vmware
        | HypervisorKind::Xen
        | HypervisorKind::HyperV
        | HypervisorKind::Unknown => {
            // All of these use the VMX VMCALL path on x86_64.
            // SAFETY: `detect_hypervisor()` confirmed a VMX-capable hypervisor
            // is active. VMCALL at ring 0 performs a VM exit, not a fault.
            let result = unsafe { vmcall(nr, a0, a1, a2) };
            pr_debug!(
                "sysentinel: vmcall(nr={nr:#x}) -> rax={:#x}\n",
                result.rax
            );
            Ok(result)
        }

        #[cfg(target_arch = "x86_64")]
        HypervisorKind::KvmAmd | HypervisorKind::QemuTcg => {
            // AMD SVM path — VMMCALL.
            // SAFETY: detected an SVM-capable KVM hypervisor.
            let result = unsafe { vmmcall(nr, a0, a1, a2) };
            pr_debug!(
                "sysentinel: vmmcall(nr={nr:#x}) -> rax={:#x}\n",
                result.rax
            );
            Ok(result)
        }

        #[cfg(target_arch = "aarch64")]
        HypervisorKind::Unknown | HypervisorKind::KvmIntel | HypervisorKind::KvmAmd => {
            // AArch64: EL2 is present; use hvc #0 (SMCCC).
            // SAFETY: ID_AA64PFR0_EL1 confirmed EL2 is implemented.
            let result = unsafe { hvc(nr, a0, a1, a2) };
            pr_debug!(
                "sysentinel: hvc(nr={nr:#x}) -> x0={:#x}\n",
                result.rax
            );
            Ok(result)
        }

        // Any remaining variant on any architecture: we don't know the ABI.
        #[allow(unreachable_patterns)]
        _ => {
            pr_warn!(
                "sysentinel: hypercall(nr={nr:#x}) — hypervisor present but \
                 ABI unknown; refusing to call\n"
            );
Err(ENOTSUPP)
        }
    }
}

/// Query the KVM feature bitmask via `KVM_HC_FEATURES`.
///
/// Returns the bitmask of supported KVM hypercall features, or
/// `Err(ENODEV)` on bare-metal and `Err(ENOTSUPP)` on non-KVM hypervisors.
///
/// Feature bits are defined in `include/uapi/linux/kvm_para.h`:
/// ```text
/// KVM_FEATURE_CLOCKSOURCE        = 0  (bit 0)
/// KVM_FEATURE_NOP_IO_DELAY       = 1
/// KVM_FEATURE_MMU_OP             = 2
/// KVM_FEATURE_CLOCKSOURCE2       = 3
/// KVM_FEATURE_ASYNC_PF           = 4
/// KVM_FEATURE_STEAL_TIME         = 5
/// KVM_FEATURE_PV_EOI             = 6
/// KVM_FEATURE_PV_UNHALT          = 7
/// KVM_FEATURE_PV_TLB_FLUSH       = 9
/// KVM_FEATURE_ASYNC_PF_VMEXIT    = 10
/// KVM_FEATURE_PV_SEND_IPI        = 11
/// KVM_FEATURE_POLL_CONTROL       = 12
/// KVM_FEATURE_PV_SCHED_YIELD     = 13
/// KVM_FEATURE_ASYNC_PF_INT       = 14
/// KVM_FEATURE_MSI_EXT_DEST_ID    = 15
/// KVM_FEATURE_HC_MAP_GPA_RANGE   = 16
/// KVM_FEATURE_MIGRATION_CONTROL  = 17
/// ```
pub fn kvm_query_features() -> Result<u64> {
    let r = hypercall(kvm_hc::FEATURES, 0, 0, 0)?;
    Ok(r.rax)
}

/// Measure one round-trip of the KVM `FEATURES` hypercall in microseconds, used
/// by the ring −1/ring −2 cross-ring comparison.
///
/// Returns `None` on bare-metal (no hypercall to time) or if the hypervisor
/// does not implement `KVM_HC_FEATURES`. `KVM_HC_FEATURES` is the same benign
/// read-only hypercall this module already issues for the `kvm_features=`
/// token, so timining it here adds no new exposure.
pub fn hypercall_latency_us() -> Option<u64> {
    if detect_hypervisor() == HypervisorKind::None {
        return None;
    }
    let t0 = kernel::time::Instant::<kernel::time::BootTime>::now()
        .elapsed()
        .as_nanos()
        .unsigned_abs();
    if kvm_query_features().is_err() {
        return None;
    }
    let t1 = kernel::time::Instant::<kernel::time::BootTime>::now()
        .elapsed()
        .as_nanos()
        .unsigned_abs();
    Some(t1.saturating_sub(t0) / 1000)
}

/// Returns a human-readable description of the detected hypervisor.
///
/// Intended for use in `/proc/sysentinel_metrics` output and kernel log
/// messages at module init.
pub fn hypervisor_description() -> &'static str {
    match detect_hypervisor() {
        HypervisorKind::KvmIntel => "KVM/Intel VT-x",
        HypervisorKind::KvmAmd   => "KVM/AMD SVM",
        HypervisorKind::Vmware   => "VMware",
        HypervisorKind::Xen      => "Xen",
        HypervisorKind::HyperV   => "Microsoft Hyper-V",
        HypervisorKind::QemuTcg  => "QEMU/TCG (software emulation)",
        HypervisorKind::Unknown  => "unknown hypervisor",
        HypervisorKind::None     => "none (bare-metal)",
    }
}
