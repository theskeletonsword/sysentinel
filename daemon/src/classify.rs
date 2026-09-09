// SPDX-License-Identifier: Apache-2.0
//! Classifies raw kmsg records into the event categories we alert on.

use crate::kmsg::KmsgRecord;
use serde::Serialize;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Info,
    Warning,
    Error,
    Critical,
}

impl Severity {
    pub fn from_str_name(s: &str) -> Option<Self> {
        match s.to_ascii_lowercase().as_str() {
            "info" => Some(Self::Info),
            "warning" => Some(Self::Warning),
            "error" => Some(Self::Error),
            "critical" => Some(Self::Critical),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum EventKind {
    OomKill,
    KernelPanic,
    Segfault,
    Oops,
    /// SIGILL / illegal instruction (traps, invalid opcode, GPF).
    IllegalInstruction,
    /// A process dumped core (SIGABRT/SIGSEGV/SIGILL, "core dumped").
    CoreDump,
    /// SELinux AVC denial (audit line) — user-tunable via `/settings`.
    Selinux,
    /// Any other dmesg record serious enough to surface (raw priority ≥ err).
    Other,
}

#[derive(Debug, Clone, Serialize)]
pub struct ClassifiedEvent {
    pub kind: EventKind,
    pub severity: Severity,
    pub raw_message: String,
}

/// Inspect a raw kmsg record and decide whether it represents an
/// event worth surfacing, and how severe it is.
///
/// This is intentionally a plain substring/pattern classifier — no
/// external state, no learned model — so its behavior is fully
/// auditable by reading this function.
pub fn classify(record: &KmsgRecord) -> Option<ClassifiedEvent> {
    let msg = &record.message;
    let lower = msg.to_ascii_lowercase();

    let kind = if lower.contains("out of memory") || lower.contains("oom-kill") || lower.contains("killed process")
    {
        EventKind::OomKill
    } else if lower.contains("kernel panic") {
        EventKind::KernelPanic
    } else if lower.contains("segfault at") || lower.contains("segmentation fault") {
        EventKind::Segfault
    } else if lower.starts_with("bug:") || lower.contains(" oops: ") || lower.contains("oops:") {
        EventKind::Oops
    } else if lower.contains("illegal instruction")
        || lower.contains("sigill")
        || lower.contains("invalid opcode")
        || lower.contains("general protection fault")
        || lower.contains("trap invalid opcode")
        || lower.starts_with("traps:")
    {
        EventKind::IllegalInstruction
    } else if lower.contains("core dumped") || lower.contains("dumped core") {
        EventKind::CoreDump
    } else if lower.contains("avc:")
        || lower.contains("avc: denied")
        || lower.contains("selinux:")
        || lower.contains("selinux")
    {
        EventKind::Selinux
    } else {
        EventKind::Other
    };

    // For "Other" we fall back to the raw syslog priority: only
    // surface it if the kernel itself flagged it as error-or-worse.
    // This keeps routine info/notice/warning chatter from flooding
    // Telegram while still catching unanticipated error patterns.
    let severity = match kind {
        EventKind::KernelPanic => Severity::Critical,
        EventKind::OomKill => Severity::Error,
        EventKind::Segfault => Severity::Error,
        EventKind::Oops => Severity::Error,
        EventKind::IllegalInstruction => Severity::Error,
        EventKind::CoreDump => Severity::Error,
        // SELinux denials are normally *audit* entries with a low syslog
        // priority, so they must not be filtered by the priority fallback.
        EventKind::Selinux => Severity::Warning,
        EventKind::Other => match record.priority {
            Some(0..=2) => Severity::Critical, // emerg/alert/crit
            Some(3) => Severity::Error,        // err
            Some(4) => Severity::Warning,      // warning
            _ => Severity::Info,
        },
    };

    if kind == EventKind::Other && severity == Severity::Info {
        // Not interesting enough to classify as an event at all.
        return None;
    }

    Some(ClassifiedEvent {
        kind,
        severity,
        raw_message: msg.clone(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kmsg::KmsgRecord;

    fn rec(msg: &str, prio: Option<u8>) -> KmsgRecord {
        KmsgRecord {
            priority: prio,
            message: msg.to_string(),
        }
    }

    #[test]
    fn detects_oom() {
        let ev = classify(&rec("Out of memory: Killed process 123 (firefox)", Some(3))).unwrap();
        assert_eq!(ev.kind, EventKind::OomKill);
        assert_eq!(ev.severity, Severity::Error);
    }

    #[test]
    fn detects_panic_as_critical() {
        let ev = classify(&rec("Kernel panic - not syncing: Fatal exception", Some(0))).unwrap();
        assert_eq!(ev.kind, EventKind::KernelPanic);
        assert_eq!(ev.severity, Severity::Critical);
    }

    #[test]
    fn ignores_routine_info() {
        assert!(classify(&rec("eth0: link becomes ready", Some(6))).is_none());
    }

    #[test]
    fn detects_selinux_denial_even_at_low_priority() {
        let ev = classify(&rec(
            "audit: type=1400 audit(1715000000.123:456) avc:  denied { read } \
             for pid=1234 comm=\"navigator\" scontext=... tcontext=... tclass=file",
            Some(6),
        ))
        .unwrap();
        assert_eq!(ev.kind, EventKind::Selinux);
        assert_eq!(ev.severity, Severity::Warning);
    }

    #[test]
    fn detects_illegal_instruction() {
        let ev = classify(&rec(
            "traps: python3[4711] trap invalid opcode ip:7f42a0 complete",
            Some(4),
        ))
        .unwrap();
        assert_eq!(ev.kind, EventKind::IllegalInstruction);
        assert_eq!(ev.severity, Severity::Error);
    }

    #[test]
    fn detects_core_dump() {
        let ev = classify(&rec(
            "PKGBUILD[42]: segfault at 0 ip 00007f.. sp 00007f.. error 14 in libc.so",
            Some(4),
        ))
        .unwrap();
        let ev2 = classify(&rec("firefox[999] core dumped", Some(4))).unwrap();
        assert_eq!(ev2.kind, EventKind::CoreDump);
        assert_eq!(ev.severity, Severity::Error);
    }
}
