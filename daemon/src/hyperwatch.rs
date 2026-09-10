// SPDX-License-Identifier: Apache-2.0
//!
//! Hypercall watcher — what did the VM just ask the hypervisor?
//!
//! INTERCEPT ONLY, ACT NEVER, SAY IT IN YOUR VOICE: this loop reports guest
//! hypercalls to Telegram through the persona — the same conversational way
//! OOM / dmesg / SELinux alerts are told, never a cold log dump — and takes
//! no further action. It must not terminate, stop, or "fix" a VM on
//! bad-looking hypercalls — we cannot tell a guest experimenting from one
//! attempting a VM escape, and a wrong assumed veto is itself an outage.
//! (The kernel side holds the same invariant: the kprobe modifies nothing.)
//!
//! # Primary source: kernel module
//!
//! `sysentinel_metrics` kprobes the exported KVM symbol
//! `kvm_emulate_hypercall` and drains into `/proc/sysentinel_hypercalls`.
//! Each read is a DRAIN (records appear once). Lines look like:
//!
//! ```text
//! vcpu=0 pid=1234 comm=qemu-system-x8 hypercall=0x6 (6) a0=0x1 a1=0x2 a2=0x3 a3=0x4
//! ```
//!
//! # Ring-3 fallback (Secure Boot blocks unsigned modules)
//!
//! If the proc node is absent or says `hypercall_watch=unavailable`, this
//! watcher switches to the KVM tracepoint the ftrace way: it asks the kernel
//! to enable `events/kvm/kvm_hypercall` (best-effort — that write needs root
//! once; the install script does it) and then tails `trace_pipe`, parsing
//! `kvm_hypercall: nr 0x… r10 … r11 … r12 … r13 …` lines. The trace will only
//! exist if something enabled it; otherwise we report the tip periodically.
//!
//! Bursts are batched into a compact digest (throttled to ≤1 message / 10 s).

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use crate::bot::{self, SharedBotState};
use crate::config::Config;
use crate::llm;
use crate::settings::Settings;

/// Human name for the Linux KVM hypercall numbers (arch/x86 KVM_HC_*).
fn hc_name(nr: u64) -> Option<&'static str> {
    match nr {
        1 => Some("VAPIC_POLL_IRQ"),
        2 => Some("MMU_OP"),
        3 => Some("FEATURES"),
        4 => Some("PPC_MAP_MAGIC_PAGE / MIPS_GET_CLOCK_FREQ"),
        5 => Some("KICK_CPU / MIPS_EXIT_VM"),
        6 => Some("SEND_IPI"),
        7 => Some("UMIP"),
        8 => Some("MEMORY_MAP"),
        9 => Some("MEMORY_UNMAP"),
        10 => Some("VCPU_PREEMPTED"),
        11 => Some("INTERRUPT"),
        12 => Some("ENABLE_CAP"),
        13 => Some("MEMORY_MODIFY"),
        _ => None,
    }
}

/// A decoded guest hypercall (whatever source it came from).
#[derive(Debug, Clone)]
struct HcRecord {
    vcpu: String,
    pid: i64,
    comm: String,
    nr: u64,
    a0: u64,
    a1: u64,
    a2: u64,
    a3: u64,
}

impl HcRecord {
    fn describe(&self) -> String {
        let name = hc_name(self.nr).unwrap_or("UNKNOWN_HYPERCALL");
        format!(
            "  · vcpu={} pid={} (`{}`)  `{}` (0x{:x})\n     a0=0x{:x} a1=0x{:x} a2=0x{:x} a3=0x{:x}",
            self.vcpu, self.pid, self.comm, name, self.nr, self.a0, self.a1, self.a2, self.a3
        )
    }
}

// ── Module-backed reader ──────────────────────────────────────────────────────

/// Read (and drain) the proc node. Returns Ok(records) when the module is
/// active, or Err(reason) when it is not and the fallback should take over.
fn read_module() -> std::result::Result<Vec<HcRecord>, String> {
    let raw = std::fs::read_to_string("/proc/sysentinel_hypercalls")
        .map_err(|e| format!("proc node unavailable: {e}"))?;
    let mut records = Vec::new();
    for line in raw.lines() {
        if line.starts_with("hypercall_watch=") {
            if line.contains("unavailable") {
                return Err("module reports hypercall_watch=unavailable".into());
            }
            continue; // "hypercall_watch=active entries=N"
        }
        if let Some(r) = parse_module_line(line) {
            records.push(r);
        }
    }
    Ok(records)
}

fn parse_u64(s: &str) -> Option<u64> {
    s.strip_prefix("0x").or(Some(s)).and_then(|v| u64::from_str_radix(v, 16).ok())
}

fn parse_module_line(line: &str) -> Option<HcRecord> {
    let mut vcpu = None;
    let mut pid = None;
    let mut comm = None;
    let mut nr = None;
    let mut a0 = None;
    let mut a1 = None;
    let mut a2 = None;
    let mut a3 = None;
    for tok in line.split_whitespace() {
        let mut it = tok.splitn(2, '=');
        let (k, v) = (it.next()?, it.next()?);
        match k {
            "vcpu" => vcpu = Some(v.to_string()),
            "pid" => pid = v.parse().ok(),
            "comm" => comm = Some(v.to_string()),
            "hypercall" => nr = parse_u64(v),
            "a0" => a0 = parse_u64(v),
            "a1" => a1 = parse_u64(v),
            "a2" => a2 = parse_u64(v),
            "a3" => a3 = parse_u64(v),
            _ => {}
        }
    }
    Some(HcRecord {
        vcpu: vcpu.unwrap_or_else(|| "?".into()),
        pid: pid.unwrap_or(-1),
        comm: comm.unwrap_or_else(|| "?".into()),
        nr: nr?,
        a0: a0.unwrap_or(0),
        a1: a1.unwrap_or(0),
        a2: a2.unwrap_or(0),
        a3: a3.unwrap_or(0),
    })
}

// ── tracefs (ring-3) fallback reader ──────────────────────────────────────────

struct TracefsFallback {
    /// The tracefs root we found mounted, or None.
    root: Option<std::path::PathBuf>,
    /// When we last told the user how to enable the tracepoint.
    last_tip: Instant,
}

impl TracefsFallback {
    fn locate() -> Option<std::path::PathBuf> {
        for root in ["/sys/kernel/tracing", "/sys/kernel/debug/tracing"] {
            if std::path::Path::new(root).join("trace_pipe").exists() {
                return Some(std::path::PathBuf::from(root));
            }
        }
        None
    }

    /// Best-effort: ask the kernel to enable the KVM tracepoint. Needs root —
    /// only the install-time helper or a setcap covers this; on failure we say
    /// so (once per few minutes), then still try to read whatever is there.
    fn try_enable(&self, root: &std::path::Path) -> bool {
        let path = root.join("events/kvm/kvm_hypercall/enable");
        std::fs::write(&path, "1").is_ok()
    }

    /// Non-blocking read of trace_pipe; parse kvm_hypercall lines.
    fn read(&self, root: &std::path::Path) -> Vec<HcRecord> {
        let mut recs = Vec::new();
        let cpath = match std::ffi::CString::new(root.join("trace_pipe").to_string_lossy().as_bytes()) {
            Ok(c) => c,
            Err(_) => return recs,
        };
        let fd = unsafe { libc::open(cpath.as_ptr(), libc::O_RDONLY | libc::O_NONBLOCK) };
        if fd < 0 {
            return recs;
        }
        let mut buf = [0u8; 8192];
        loop {
            let n = unsafe { libc::read(fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len()) };
            if n <= 0 {
                break; // EAGAIN (empty) or EOF — stop polling for now.
            }
            let text = String::from_utf8_lossy(&buf[..n as usize]);
            for line in text.lines() {
                if let Some(r) = parse_trace_line(line) {
                    recs.push(r);
                }
            }
        }
        unsafe { libc::close(fd) };
        recs
    }
}

/// `... kvm_hypercall: nr 0x6 r10 0x1 r11 0x2 r12 0x3 r13 0x4` (KVM x86).
fn parse_trace_line(line: &str) -> Option<HcRecord> {
    let marker = "kvm_hypercall:";
    let idx = line.find(marker)?;
    // vCPU thread's task name ends in a pid: `qemu-system-x85-12345`.
    let task_head = &line[..line.find('[').unwrap_or(0)];
    let pid = task_head
        .split('-')
        .next_back()
        .and_then(|p| p.trim().parse::<i64>().ok())
        .unwrap_or(-1);

    let body = line[idx + marker.len()..].trim();
    let mut nr = None;
    let mut a0 = None;
    let mut a1 = None;
    let mut a2 = None;
    let mut a3 = None;
    let mut toks = body.split_whitespace();
    while let Some(k) = toks.next() {
        let v = toks.next()?;
        match k {
            "nr" => nr = parse_trace_hex(v),
            "r10" => a0 = parse_trace_hex(v),
            "r11" => a1 = parse_trace_hex(v),
            "r12" => a2 = parse_trace_hex(v),
            "r13" => a3 = parse_trace_hex(v),
            _ => {}
        }
    }
    Some(HcRecord {
        vcpu: format!("tid{pid}"),
        pid,
        comm: "kvm-vcpu".into(),
        nr: nr?,
        a0: a0.unwrap_or(0),
        a1: a1.unwrap_or(0),
        a2: a2.unwrap_or(0),
        a3: a3.unwrap_or(0),
    })
}

fn parse_trace_hex(s: &str) -> Option<u64> {
    u64::from_str_radix(s.trim_start_matches("0x"), 16).ok()
}

// ── Main loop ─────────────────────────────────────────────────────────────────

/// Polls the module node (primary) or the KVM tracepoint (ring-3, Secure Boot
/// fallback) and tells the user the digest **in the persona's voice** — the
/// same conversational treatment OOM / dmesg / login alerts get, because a
/// hypercall report is passive and never needs a confirmation gate.
pub fn run_hypercall_loop(
    config: &Config,
    state: &Arc<Mutex<SharedBotState>>,
    settings: &Arc<Mutex<Settings>>,
    llm: &dyn llm::LlmBackend,
    dry_run: bool,
) {
    let mut fallback = TracefsFallback { root: None, last_tip: Instant::now() };
    let mut backoff_until = Instant::now();
    let mut last_send = Instant::now() - Duration::from_secs(10);

    log::info!("hyperwatch: watching guest hypercalls (module proc → tracefs fallback)");

    loop {
        std::thread::sleep(Duration::from_secs(3));

        let enabled = settings.lock().expect("settings mutex").hypercall;
        if !enabled {
            continue;
        }

        // Decide source.
        if std::time::Instant::now() < backoff_until {
            continue;
        }

        let via_module = read_module();

        let records = match via_module {
            Ok(recs) => recs,
            Err(_module_unavailable) => {
                // Ring-3 fallback.
                if fallback.root.is_none() {
                    fallback.root = TracefsFallback::locate();
                }
                match &fallback.root {
                    None => {
                        if fallback.last_tip.elapsed() > Duration::from_secs(300) {
                            fallback.last_tip = Instant::now();
                            log::warn!(
                                "hyperwatch: neither module nor tracefs reached; \
                                 enable KVM hypercall interception with:\n  \
                                 sudo sh -c 'echo 1 > /sys/kernel/tracing/events/kvm/kvm_hypercall/enable'"
                            );
                        }
                        backoff_until = Instant::now() + Duration::from_secs(60);
                        continue;
                    }
                    Some(root) => {
                        let _ = fallback.try_enable(root);
                        fallback.read(root)
                    }
                }
            }
        };

        if records.is_empty() {
            continue;
        }

        // Batching + throttle: one digest per burst, ≤ every 10 s, else the
        // ring always drains silently and nothing is lost.

        let now = Instant::now();
        if last_send.elapsed() < Duration::from_secs(10) {
            last_send = now;
            continue;
        }

        let chat_id = {
            let g = state.lock().expect("bot state mutex");
            g.paired_chat_id.or(config.telegram.chat_id).filter(|&id| id != 0)
        };

        let mut facts = format!("The guest asked the hypervisor something ({} hypercall{})\n", records.len(), if records.len() == 1 { "" } else { "s" });
        for r in records.iter().take(12) {
            facts.push_str(&r.describe());
            facts.push('\n');
        }
        if records.len() > 12 {
            facts.push_str(&format!("  … and {} more", records.len() - 12));
        }

        // Passive notice → the persona's voice, never a canned template.
        let text = speak_hypercall_persona(config, settings, llm, &facts);

        if dry_run {
            log::info!("DRY RUN — hyperwatch: {text}");
            last_send = now;
            continue;
        }
        if let Some(chat_id) = chat_id {
            if let Err(e) = bot::send_message(&config.telegram.bot_token, chat_id, &text, Some("Markdown")) {
                log::error!("hyperwatch send failed: {e:#}");
            }
        } else {
            log::info!("hyperwatch: {} hypercalls seen (not paired — not sent)", records.len());
        }
        last_send = now;
    }
}

/// Speak a hypercall report through the persona. Falls back to the raw facts
/// when the LLM is off or errors — a passive notice must never block on the
/// LLM, and with backend "none" it never spends a call.
fn speak_hypercall_persona(
    config: &Config,
    settings: &Arc<Mutex<Settings>>,
    llm: &dyn llm::LlmBackend,
    facts: &str,
) -> String {
    if !config.llm.llm_enabled() {
        return facts.to_string();
    }
    let persona = llm::resolved_persona(config);
    let override_txt = {
        let g = settings.lock().expect("settings mutex");
        g.system_prompt_override.clone()
    };
    let sys_prompt = llm::effective_system_prompt(config, override_txt.as_deref());
    let directive = format!(
        "These are live facts / things that just happened on this machine. You ARE \
         the machine. A running VM poked the hypervisor — tell the user about it in \
         YOUR voice, spontaneously, in your own words, NEVER a formatted log line, \
         NEVER inventing anything beyond what's here.\n\
         IMPORTANT: this is a passive observation. Do NOT ask for confirmation or \
         propose stopping/shutting down the VM — it is not your role to act on it; \
         just inform.\n\
         language: {}\ntone: {}\n\
         Write in {}, with the persona above. Be brief (max 4 lines), no titles, \
         no preamble. Use only what's here:\n\n{}",
        persona.language,
        persona.tone,
        persona.language,
        facts
    );
    llm.explain(&llm::ExplainRequest {
        system_prompt: &sys_prompt,
        event_text: &directive,
        max_tokens: config.llm.max_tokens,
    })
    .unwrap_or_else(|e| {
        log::warn!("hyperwatch persona voice dropped ({e:#}); forwarding raw facts");
        facts.to_string()
    })
}