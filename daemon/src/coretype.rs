// SPDX-License-Identifier: Apache-2.0
//!
//! Which kind of core is each logical CPU? — a clean-room core-type oracle.
//!
//! # Why this file exists, and why it cites no kernel
//!
//! Heterogeneous CPUs (Intel P/E, ARM big.LITTLE) put two different
//! microarchitectures in one package. Telling them apart is the prerequisite
//! for reading their performance counters honestly, because their counters are
//! *different hardware* and averaging across them describes neither.
//!
//! Linux knows the answer and will tell you — but this repository is
//! Apache-2.0 and the kernel is GPL-2.0, so the knowledge here is derived by
//! **clean room**: every fact below comes from a processor vendor's own public
//! architecture manual and is confirmed against the silicon, never from
//! reading kernel source.
//!
//! | Arch | Interface | Authority |
//! |------|-----------|-----------|
//! | x86 (Intel) | `CPUID.1AH` sub-leaf 0, executed **on** the CPU being identified | Intel® 64 and IA-32 SDM, order no. 325462, *Table 21-63 — Leaf 1AH Native Model ID Enumeration* |
//! | aarch64 | `MIDR_EL1` implementer + part number, read from sysfs | Arm® Architecture Reference Manual, ARM DDI 0487, *D13.2.98 MIDR_EL1* |
//!
//! What the Intel table specifies, and what this machine returned when asked:
//!
//! - The leaf is valid when `MAX_LEAF ≥ 1AH` and `CPUID.1AH:EAX != 0`. Sub-leaf
//!   0 is the only valid one and `ECX` must be zero.
//! - `EAX[31:24]` is `CORE_TYPE`: `20H` = Intel® Atom®, `40H` = Intel® Core®.
//!   `10H` and `30H` are reserved.
//! - `EAX[23:0]` is `CORE_NATIVE_MODEL_ID`, which is *not* unique across core
//!   types and is unrelated to the model ID in `CPUID.01H`.
//! - Its domain is the **logical processor**: the answer describes whichever
//!   CPU executed the instruction, so identifying a package means pinning to
//!   each CPU in turn. That is what [`identify_cpus`] does, restoring the
//!   caller's CPU affinity afterwards.
//!
//! Two cautions the manual states outright and this module honours:
//!
//! - The `CORE_TYPE` value "has no significance, neither large nor small" and
//!   implies no other attribute. So `40H` is not ranked above `20H` here; the
//!   values are only ever mapped to the vendor's own names, and reserved
//!   encodings are preserved verbatim in [`CoreClass::Other`] rather than
//!   guessed at.
//! - The leaf "exists on all logical processors in a hybrid package, it may
//!   also be present in other processor configurations" — so its mere presence
//!   proves nothing. Only *more than one distinct core type* means hybrid,
//!   which is what [`CoreTopology::is_heterogeneous`] tests.
//!
//! # What this buys over asking the kernel
//!
//! An independent answer, which makes cross-validation possible: the PMU
//! grouping in sysfs and the core types in silicon are two separate sources,
//! and agreement between them is evidence neither provides alone. It also
//! keeps working where the kernel's grouping is absent — a kernel too old to
//! split the PMUs still runs on hardware that answers `CPUID.1AH` truthfully.
//!
//! The AMD manual in hand (BKDG for NPT Family 0Fh, publication 32559, 2007)
//! predates heterogeneous topology entirely and documents no equivalent leaf,
//! so no AMD path is guessed at: AMD parts fall through to [`CoreClass::Other`]
//! and the caller falls back to PMU grouping.

use std::collections::BTreeMap;
use std::sync::OnceLock;

/// The microarchitecture class of one logical CPU.
///
/// Deliberately *not* an ordered "fast/slow" enum: the Intel SDM says the
/// `CORE_TYPE` value carries no such meaning, so this type carries none either.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum CoreClass {
    /// `CPUID.1AH:EAX[31:24] == 40H` — Intel® Core®, commonly "P-core".
    IntelCore,
    /// `CPUID.1AH:EAX[31:24] == 20H` — Intel® Atom®, commonly "E-core".
    IntelAtom,
    /// aarch64: `MIDR_EL1` implementer (bits [31:24]) and part number
    /// (bits [15:4]). Distinct part numbers in one package are big.LITTLE.
    ArmPart { implementer: u8, part: u16 },
    /// A reserved or unrecognised encoding, kept as reported rather than
    /// mapped onto a guess.
    Other(u32),
}

impl CoreClass {
    /// The vendor's own name for this core type, plus the industry shorthand
    /// where one exists. Never a value judgement.
    pub fn label(&self) -> String {
        match self {
            CoreClass::IntelCore => "P-cores (Intel Core)".to_string(),
            CoreClass::IntelAtom => "E-cores (Intel Atom)".to_string(),
            CoreClass::ArmPart { implementer, part } => {
                format!("{} part {part:#05x}", arm_implementer_name(*implementer))
            }
            CoreClass::Other(raw) => format!("core type {raw:#x}"),
        }
    }

    /// Short label for compact report lines.
    pub fn short_label(&self) -> String {
        match self {
            CoreClass::IntelCore => "P-cores".to_string(),
            CoreClass::IntelAtom => "E-cores".to_string(),
            CoreClass::ArmPart { part, .. } => format!("part {part:#05x}"),
            CoreClass::Other(raw) => format!("type {raw:#x}"),
        }
    }
}

/// Arm implementer codes, exactly as published in the Arm ARM (ARM DDI 0487,
/// *D13.2.98 MIDR_EL1*, the "Implementer, bits [31:24]" assigned-codes table).
///
/// The table is reproduced from that manual and nowhere else — deliberately, so
/// this file has a single, checkable, permissively-usable provenance. Codes the
/// manual does not publish are not guessed at from other sources: the manual
/// states plainly that "Arm can assign codes that are not published in this
/// manual", which is exactly why an unrecognised code keeps its raw value
/// instead of being mapped to a name.
fn arm_implementer_name(code: u8) -> String {
    match code {
        0x00 => "reserved for software use".to_string(),
        0x41 => "Arm".to_string(),
        0x42 => "Broadcom".to_string(),
        0x43 => "Cavium".to_string(),
        0x44 => "Digital Equipment Corporation".to_string(),
        0x46 => "Fujitsu".to_string(),
        0x49 => "Infineon".to_string(),
        0x4d => "Motorola/Freescale".to_string(),
        0x4e => "NVIDIA".to_string(),
        0x50 => "Applied Micro Circuits".to_string(),
        0x51 => "Qualcomm".to_string(),
        0x56 => "Marvell".to_string(),
        0x69 => "Intel".to_string(),
        0xc0 => "Ampere Computing".to_string(),
        // Arm assigns codes it does not publish. Naming one from any other
        // source would be a guess, and the raw code is more useful than a
        // wrong name.
        other => format!("implementer {other:#04x}"),
    }
}

/// One logical CPU's identity.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CoreIdentity {
    pub cpu: u32,
    pub class: CoreClass,
    /// `CORE_NATIVE_MODEL_ID` (`CPUID.1AH:EAX[23:0]`) on Intel; the full
    /// `MIDR_EL1` on aarch64; zero when unknown. Not unique across core types.
    pub native_model_id: u32,
}

/// A set of CPUs sharing one microarchitecture.
#[derive(Debug, Clone)]
pub struct CoreCluster {
    pub class: CoreClass,
    /// Ascending, deduplicated.
    pub cpus: Vec<u32>,
}

/// What the silicon says about this package.
#[derive(Debug, Clone, Default)]
pub struct CoreTopology {
    /// One entry per distinct core class, ordered by class.
    pub clusters: Vec<CoreCluster>,
    /// How the answer was obtained, for the report and for auditing.
    pub source: &'static str,
}

impl CoreTopology {
    /// True when more than one core class is present — the only sound test for
    /// "hybrid", since the enumeration leaf may exist on uniform parts too.
    pub fn is_heterogeneous(&self) -> bool {
        self.clusters.len() > 1
    }

    /// The cluster owning `cpu`, if any.
    pub fn class_of(&self, cpu: u32) -> Option<CoreClass> {
        self.clusters
            .iter()
            .find(|c| c.cpus.binary_search(&cpu).is_ok())
            .map(|c| c.class)
    }

    /// `P-cores ×16 + E-cores ×16`, or empty when nothing was identified.
    pub fn describe(&self) -> String {
        self.clusters
            .iter()
            .map(|c| format!("{} ×{}", c.class.short_label(), c.cpus.len()))
            .collect::<Vec<_>>()
            .join(" + ")
    }
}

// ── CPU affinity pinning ──────────────────────────────────────────────────────

/// Saves the calling thread's CPU affinity and restores it on drop, so a failed
/// probe can never leave the daemon pinned to one core.
struct AffinityGuard {
    saved: Option<libc::cpu_set_t>,
}

impl AffinityGuard {
    fn capture() -> Self {
        // SAFETY: `set` is a valid, writable cpu_set_t for the duration of the
        // call; pid 0 means the calling thread.
        let saved = unsafe {
            let mut set: libc::cpu_set_t = std::mem::zeroed();
            if libc::sched_getaffinity(0, std::mem::size_of::<libc::cpu_set_t>(), &mut set) == 0 {
                Some(set)
            } else {
                None
            }
        };
        AffinityGuard { saved }
    }

    /// Move the calling thread onto exactly `cpu`. `false` when the CPU is
    /// offline or excluded from the thread's allowed mask.
    fn pin_to(&self, cpu: u32) -> bool {
        // SAFETY: `set` is a valid cpu_set_t; CPU_SET stays within its bounds
        // because we reject CPU numbers the set cannot represent.
        unsafe {
            let mut set: libc::cpu_set_t = std::mem::zeroed();
            libc::CPU_ZERO(&mut set);
            if cpu as usize >= 8 * std::mem::size_of::<libc::cpu_set_t>() {
                return false;
            }
            libc::CPU_SET(cpu as usize, &mut set);
            libc::sched_setaffinity(0, std::mem::size_of::<libc::cpu_set_t>(), &set) == 0
        }
    }
}

impl Drop for AffinityGuard {
    fn drop(&mut self) {
        if let Some(set) = self.saved {
            // SAFETY: `set` was produced by sched_getaffinity and is a valid mask.
            unsafe {
                libc::sched_setaffinity(0, std::mem::size_of::<libc::cpu_set_t>(), &set);
            }
        }
    }
}

// ── x86: CPUID.1AH ────────────────────────────────────────────────────────────

/// `CORE_TYPE` encodings from SDM Table 21-63. `10H` and `30H` are reserved and
/// deliberately absent — a reserved value reaches [`CoreClass::Other`] intact.
#[cfg(any(target_arch = "x86_64", target_arch = "x86"))]
const CORE_TYPE_INTEL_ATOM: u32 = 0x20;
#[cfg(any(target_arch = "x86_64", target_arch = "x86"))]
const CORE_TYPE_INTEL_CORE: u32 = 0x40;

/// Native Model ID Enumeration leaf.
#[cfg(any(target_arch = "x86_64", target_arch = "x86"))]
const LEAF_NATIVE_MODEL_ID: u32 = 0x1a;

/// True when this is a gENUINEiNTEL part, the only vendor whose manual defines
/// leaf 1AH. Probing it elsewhere would be reading undefined registers.
#[cfg(any(target_arch = "x86_64", target_arch = "x86"))]
fn is_genuine_intel() -> bool {
    #[cfg(target_arch = "x86_64")]
    use std::arch::x86_64::__cpuid;
    #[cfg(target_arch = "x86")]
    use std::arch::x86::__cpuid;

    // Leaf 0 is architecturally defined on every x86 part, and `__cpuid` is
    // safe on x86/x86_64 because the instruction is unconditionally available.
    let r = __cpuid(0);
    // Vendor string arrives as EBX, EDX, ECX in that order.
    r.ebx == u32::from_le_bytes(*b"Genu")
        && r.edx == u32::from_le_bytes(*b"ineI")
        && r.ecx == u32::from_le_bytes(*b"ntel")
}

/// Read `CPUID.1AH` on *this* CPU. `None` when the leaf is unsupported or
/// reports itself invalid (`EAX == 0`).
#[cfg(any(target_arch = "x86_64", target_arch = "x86"))]
fn read_native_model_id_here() -> Option<u32> {
    #[cfg(target_arch = "x86_64")]
    use std::arch::x86_64::{__cpuid, __cpuid_count};
    #[cfg(target_arch = "x86")]
    use std::arch::x86::{__cpuid, __cpuid_count};

    // Leaf 0 reports the highest leaf this part implements, which is what
    // gates the second call below.
    let max_leaf = __cpuid(0).eax;
    if max_leaf < LEAF_NATIVE_MODEL_ID {
        return None;
    }
    // Guarded by MAX_LEAF above; sub-leaf 0 is the only valid one, and zero in
    // ECX is what the manual requires.
    let eax = __cpuid_count(LEAF_NATIVE_MODEL_ID, 0).eax;
    (eax != 0).then_some(eax)
}

#[cfg(any(target_arch = "x86_64", target_arch = "x86"))]
fn identify_x86(cpus: &[u32]) -> Option<Vec<CoreIdentity>> {
    if !is_genuine_intel() {
        return None;
    }
    // Cheap pre-check on the current CPU: no leaf here, no leaf anywhere.
    read_native_model_id_here()?;

    let guard = AffinityGuard::capture();
    let mut out = Vec::with_capacity(cpus.len());
    for &cpu in cpus {
        if !guard.pin_to(cpu) {
            continue; // offline, or outside our allowed mask
        }
        let Some(eax) = read_native_model_id_here() else {
            continue;
        };
        let core_type = eax >> 24;
        let class = match core_type {
            CORE_TYPE_INTEL_CORE => CoreClass::IntelCore,
            CORE_TYPE_INTEL_ATOM => CoreClass::IntelAtom,
            other => CoreClass::Other(other),
        };
        out.push(CoreIdentity {
            cpu,
            class,
            native_model_id: eax & 0x00ff_ffff,
        });
    }
    // `guard` restores the caller's affinity here.
    drop(guard);

    (!out.is_empty()).then_some(out)
}

#[cfg(not(any(target_arch = "x86_64", target_arch = "x86")))]
fn identify_x86(_cpus: &[u32]) -> Option<Vec<CoreIdentity>> {
    None
}

// ── aarch64: MIDR_EL1 ─────────────────────────────────────────────────────────

/// Read each CPU's `MIDR_EL1` from sysfs.
///
/// The register is readable only at EL1, but Linux publishes it per-CPU, so no
/// privileged instruction and no pinning is needed. Fields per ARM DDI 0487
/// D13.2.98: implementer is bits [31:24], part number bits [15:4].
fn identify_aarch64(cpus: &[u32]) -> Option<Vec<CoreIdentity>> {
    if !cfg!(target_arch = "aarch64") {
        return None;
    }
    let mut out = Vec::with_capacity(cpus.len());
    for &cpu in cpus {
        let path = format!("/sys/devices/system/cpu/cpu{cpu}/regs/identification/midr_el1");
        let Ok(raw) = std::fs::read_to_string(&path) else {
            continue;
        };
        let text = raw.trim().trim_start_matches("0x");
        let Ok(midr) = u64::from_str_radix(text, 16) else {
            continue;
        };
        out.push(CoreIdentity {
            cpu,
            class: CoreClass::ArmPart {
                implementer: ((midr >> 24) & 0xff) as u8,
                part:        ((midr >> 4) & 0xfff) as u16,
            },
            native_model_id: midr as u32,
        });
    }
    (!out.is_empty()).then_some(out)
}

// ── Public API ────────────────────────────────────────────────────────────────

/// Identify each of `cpus`, using whichever vendor-documented interface this
/// architecture provides. `None` when no interface is available.
///
/// On x86 this briefly pins the calling thread to each CPU in turn, because
/// `CPUID.1AH` describes only the logical processor that executed it. The
/// caller's affinity is always restored, including on early return.
pub fn identify_cpus(cpus: &[u32]) -> Option<Vec<CoreIdentity>> {
    if cpus.is_empty() {
        return None;
    }
    identify_x86(cpus).or_else(|| identify_aarch64(cpus))
}

/// Group `cpus` into clusters by core class.
pub fn cluster(cpus: &[u32]) -> CoreTopology {
    let Some(ids) = identify_cpus(cpus) else {
        return CoreTopology::default();
    };
    let source = if cfg!(any(target_arch = "x86_64", target_arch = "x86")) {
        "CPUID.1AH (Intel SDM Table 21-63)"
    } else {
        "MIDR_EL1 (ARM DDI 0487 D13.2.98)"
    };

    let mut by_class: BTreeMap<CoreClass, Vec<u32>> = BTreeMap::new();
    for id in ids {
        by_class.entry(id.class).or_default().push(id.cpu);
    }
    let clusters = by_class
        .into_iter()
        .map(|(class, mut cpus)| {
            cpus.sort_unstable();
            cpus.dedup();
            CoreCluster { class, cpus }
        })
        .collect();

    CoreTopology { clusters, source }
}

/// The core topology of this machine, probed once and cached.
///
/// Caching is safe because core types are fixed at power-on; a CPU that comes
/// online later does not change the class of the CPUs already identified.
pub fn topology() -> &'static CoreTopology {
    static TOPOLOGY: OnceLock<CoreTopology> = OnceLock::new();
    TOPOLOGY.get_or_init(|| cluster(&online_cpus()))
}

/// Online CPUs, from the list the kernel publishes.
pub fn online_cpus() -> Vec<u32> {
    let list = std::fs::read_to_string("/sys/devices/system/cpu/online")
        .ok()
        .map(|s| parse_cpu_list(&s))
        .unwrap_or_default();
    if !list.is_empty() {
        return list;
    }
    // SAFETY: sysconf with a valid name; returns -1 on failure, no pointers.
    let n = unsafe { libc::sysconf(libc::_SC_NPROCESSORS_ONLN) };
    if n > 0 {
        (0..n as u32).collect()
    } else {
        vec![0]
    }
}

/// Parse a kernel CPU list — `"0-15"`, `"0,2,4"`, `"0-3,8-11"`.
pub fn parse_cpu_list(s: &str) -> Vec<u32> {
    let mut out = Vec::new();
    for part in s.trim().split(',').filter(|p| !p.is_empty()) {
        match part.split_once('-') {
            Some((a, b)) => {
                if let (Ok(a), Ok(b)) = (a.trim().parse::<u32>(), b.trim().parse::<u32>()) {
                    // A descending range is malformed; skip rather than spin.
                    if a <= b {
                        out.extend(a..=b);
                    }
                }
            }
            None => {
                if let Ok(v) = part.trim().parse::<u32>() {
                    out.push(v);
                }
            }
        }
    }
    out
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_kernel_cpu_lists() {
        assert_eq!(parse_cpu_list("0-15"),    (0..=15).collect::<Vec<_>>());
        assert_eq!(parse_cpu_list("0,2,4"),   vec![0, 2, 4]);
        assert_eq!(parse_cpu_list("0-3,8-9"), vec![0, 1, 2, 3, 8, 9]);
        assert_eq!(parse_cpu_list("7\n"),     vec![7]);
        assert!(parse_cpu_list("").is_empty());
        // Malformed input must not hang or panic.
        assert!(parse_cpu_list("9-2").is_empty());
        assert!(parse_cpu_list("garbage").is_empty());
    }

    #[test]
    fn affinity_is_restored_after_probing() {
        // The daemon must never be left pinned by a topology probe.
        // SAFETY: valid cpu_set_t, pid 0 = calling thread.
        let before = unsafe {
            let mut set: libc::cpu_set_t = std::mem::zeroed();
            assert_eq!(
                libc::sched_getaffinity(0, std::mem::size_of::<libc::cpu_set_t>(), &mut set),
                0
            );
            set
        };

        let _ = identify_cpus(&online_cpus());

        // SAFETY: as above.
        let after = unsafe {
            let mut set: libc::cpu_set_t = std::mem::zeroed();
            assert_eq!(
                libc::sched_getaffinity(0, std::mem::size_of::<libc::cpu_set_t>(), &mut set),
                0
            );
            set
        };

        let n = online_cpus().iter().copied().max().unwrap_or(0) as usize + 1;
        for cpu in 0..n.min(8 * std::mem::size_of::<libc::cpu_set_t>()) {
            // SAFETY: `cpu` is within the set's bounds by construction.
            unsafe {
                assert_eq!(
                    libc::CPU_ISSET(cpu, &before),
                    libc::CPU_ISSET(cpu, &after),
                    "affinity for cpu{cpu} changed across the probe"
                );
            }
        }
    }

    #[test]
    fn core_type_encodings_match_the_manual() {
        // SDM Table 21-63: 20H is Atom, 40H is Core. Reserved encodings must
        // survive as-is rather than being mapped onto a guess.
        assert_eq!(CoreClass::IntelAtom.short_label(), "E-cores");
        assert_eq!(CoreClass::IntelCore.short_label(), "P-cores");
        assert!(CoreClass::IntelCore.label().contains("Intel Core"));
        assert!(CoreClass::IntelAtom.label().contains("Intel Atom"));
        // 10H and 30H are reserved: they must not become Core or Atom.
        for reserved in [0x10u32, 0x30] {
            let c = CoreClass::Other(reserved);
            assert_ne!(c, CoreClass::IntelCore);
            assert_ne!(c, CoreClass::IntelAtom);
            assert!(c.label().contains("core type"));
        }
    }

    #[test]
    fn arm_implementer_table_matches_the_published_manual() {
        // Every code below is published in ARM DDI 0487 D13.2.98. This test
        // exists to keep the table pinned to that document: an entry added
        // from some other source (a kernel header, say) would not appear in
        // the manual and has no business here.
        let published: &[(u8, &str)] = &[
            (0x41, "Arm"),
            (0x42, "Broadcom"),
            (0x43, "Cavium"),
            (0x44, "Digital Equipment Corporation"),
            (0x46, "Fujitsu"),
            (0x49, "Infineon"),
            (0x4d, "Motorola/Freescale"),
            (0x4e, "NVIDIA"),
            (0x50, "Applied Micro Circuits"),
            (0x51, "Qualcomm"),
            (0x56, "Marvell"),
            (0x69, "Intel"),
            (0xc0, "Ampere Computing"),
        ];
        for (code, name) in published {
            assert_eq!(&arm_implementer_name(*code), name, "code {code:#04x}");
        }
        // The manual says Arm may assign codes it does not publish, so an
        // unlisted code must keep its raw value rather than acquire a name
        // from anywhere else.
        for unpublished in [0x48u8, 0x61, 0x7f, 0xab] {
            let got = arm_implementer_name(unpublished);
            assert!(
                got.starts_with("implementer "),
                "{unpublished:#04x} must stay unnamed, got {got:?}"
            );
        }
    }

    #[test]
    fn clusters_partition_the_cpus_they_identify() {
        let topo = topology();
        if topo.clusters.is_empty() {
            println!("no vendor core-type interface here — nothing to check");
            return;
        }
        // No CPU may appear in two clusters, and each list is sorted.
        let mut seen = std::collections::HashSet::new();
        for c in &topo.clusters {
            assert!(!c.cpus.is_empty(), "{:?} cluster is empty", c.class);
            assert!(c.cpus.windows(2).all(|w| w[0] < w[1]), "cpus must be sorted+unique");
            for cpu in &c.cpus {
                assert!(seen.insert(*cpu), "CPU {cpu} in two clusters");
            }
        }
        // class_of must agree with the cluster it came from.
        for c in &topo.clusters {
            for cpu in &c.cpus {
                assert_eq!(topo.class_of(*cpu), Some(c.class));
            }
        }
        println!("{} via {}", topo.describe(), topo.source);
    }

    #[test]
    fn presence_of_the_leaf_is_not_proof_of_hybrid() {
        // The SDM notes leaf 1AH "may also be present in other processor
        // configurations", so a single identified class is NOT heterogeneous.
        let uniform = CoreTopology {
            clusters: vec![CoreCluster { class: CoreClass::IntelCore, cpus: vec![0, 1] }],
            source: "test",
        };
        assert!(!uniform.is_heterogeneous());

        let hybrid = CoreTopology {
            clusters: vec![
                CoreCluster { class: CoreClass::IntelCore, cpus: vec![0, 1] },
                CoreCluster { class: CoreClass::IntelAtom, cpus: vec![2, 3] },
            ],
            source: "test",
        };
        assert!(hybrid.is_heterogeneous());
        assert_eq!(hybrid.describe(), "P-cores ×2 + E-cores ×2");
    }
}

#[cfg(test)]
mod probe_report {
    #[test]
    fn print_detected_topology() {
        let t = super::topology();
        println!("source:     {}", t.source);
        println!("hybrid:     {}", t.is_heterogeneous());
        for c in &t.clusters {
            println!("  {:<24} cpus {:?}", c.class.label(), c.cpus);
        }
    }
}
