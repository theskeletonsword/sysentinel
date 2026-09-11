// SPDX-License-Identifier: Apache-2.0
//!
//! SELinux AVC denial handling — the "de qué se trata / lo permito o no"
//! workflow.
//!
//! When the kmsg watcher sees an `avc: denied` line it stores it here; the
//! bot can then explain the denial (via `audit2allow`-generated rules),
//! *allow* it (build + load a policy module), or mark it ignored (default
//! SELinux posture is already "deny", so ignoring is just suppressing the
//! noise). Everything is driven by the user with `/selinux`.
//!
//! Permission model: `auc/d` tool paths are executed only when the user asks
//! for it through `/selinux allow`. If the daemon runs unprivileged the apply
//! step prints the exact `sudo` commands instead of failing silently.

use anyhow::{Context, Result};

/// A denial that has been flagged but not yet acted upon.
#[derive(Debug, Clone)]
pub struct AvcDenial {
    pub id: u32,
    pub raw: String,
    pub comm: Option<String>,
    pub permissions: String,
    pub scontext: String,
    pub tcontext: String,
    pub tclass: String,
}

/// Stable fingerprint used to suppress repeated identical denials.
pub fn fingerprint(avc: &AvcDenial) -> String {
    format!(
        "{}|{}|{}|{}",
        avc.comm.as_deref().unwrap_or(""),
        avc.permissions,
        avc.scontext,
        avc.tcontext
    )
}

/// Best-effort parse of an `avc: denied` line. Falls back to the raw line so
/// the flow never breaks on an unexpected format.
pub fn parse_avc(id: u32, raw: &str) -> AvcDenial {
    let lower = raw.to_lowercase();
    let mut comm = None;
    let mut permissions = String::new();
    let mut scontext = String::new();
    let mut tcontext = String::new();
    let mut tclass = String::new();

    // perms ` denied { read write } `
    if let Some(start) = lower.find(" denied {") {
        if let Some(end) = lower[start..].find('}') {
            permissions = raw[start + " denied {".len()..start + end].trim().to_string();
        }
    }

    for k in ["comm=", "scontext=", "tcontext=", "tclass="] {
        let Some(pos) = lower.find(k) else { continue };
        let rest = &raw[pos + k.len()..];
        let val = if k == "comm=" {
            // comm="name" — quoted.
            let rest = rest.trim_start_matches('"');
            let end = rest.find('"').unwrap_or(rest.len());
            rest[..end].to_string()
        } else {
            // unquoted, ends at the next word boundary / space.
            match rest.split_whitespace().next() {
                Some(w) => w.trim_end_matches(':').to_string(),
                None => String::new(),
            }
        };
        match k {
            "comm=" => comm = Some(val),
            "scontext=" => scontext = val,
            "tcontext=" => tcontext = val,
            "tclass=" => tclass = val,
            _ => {}
        }
    }

    AvcDenial { id, raw: raw.to_string(), comm, permissions, scontext, tcontext, tclass }
}

/// Render an AVC denial for chat display (id, comm, permission, contexts).
pub fn render(avc: &AvcDenial) -> String {
    format!(
        "`#{id}` — {comm} denied {{ {perms} }}\n   scontext: `{sctx}`\n   tcontext: `{tctx}`\n   class: `{class}`",
        id = avc.id,
        comm = avc.comm.as_deref().unwrap_or("?"),
        perms = avc.permissions,
        sctx = avc.scontext,
        tctx = avc.tcontext,
        class = avc.tclass,
    )
}

/// Feed a single AVC line to `audit2allow` and return its `.te` output.
///
/// This is the *explanation* half of the flow: it shows exactly which allow
/// rule would lift the denial, so the user can decide before loading it.
pub fn explain_rule(avc: &AvcDenial) -> Result<String> {
    let mut child = std::process::Command::new("audit2allow")
        .args(["-i", "-"])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .context("spawning audit2allow (is the policycoreutils-python-utils package installed?)")?;

    {
        use std::io::Write;
        let stdin = child.stdin.as_mut().context("audit2allow stdin")?;
        stdin.write_all(avc.raw.as_bytes()).context("feeding AVC to audit2allow")?;
    }

    let out = child.wait_with_output()?;
    if !out.status.success() {
        let stderr = String::from_utf8_lossy(&out.stderr).trim().to_string();
        anyhow::bail!("audit2allow failed: {stderr}");
    }
    let text = String::from_utf8_lossy(&out.stdout).to_string();
    Ok(text.trim().to_string())
}

/// Apply an allow-rule for this denial: build a policy module and load it.
///
/// Requires the SELinux policy tools and enough privilege. When the daemon
/// runs unprivileged the returned `Result` carries the exact `sudo` commands
/// the user needs to run — the bot can just forward them.
pub fn apply_allow(avc: &AvcDenial, module_name: &str) -> Result<String> {
    // The name reaches the filesystem and the policy store, so it is checked
    // rather than trusted. Callers pass `allow<id>` today; a later one passing
    // something with a `/` or a `..` in it must not become a path.
    anyhow::ensure!(
        !module_name.is_empty()
            && module_name.len() <= 32
            && module_name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_'),
        "selinux: refusing the module name {module_name:?} — letters, digits and _ only"
    );
    let module = format!("sysentinel_{module_name}");

    // The AVC text went to `/tmp/<predictable>.log` before, written with
    // `fs::write`, which follows symlinks: any local user could pre-create that
    // path pointing at a file the daemon may write and have it clobbered.
    let te = crate::scratch::write(&format!("{module}.log"), avc.raw.as_bytes())
        .context("selinux: staging the AVC for audit2allow")?;

    // `audit2allow -M <name>` writes `<name>.te` and `<name>.pp` into the
    // CURRENT DIRECTORY, not beside `-i`. The old code looked for the .pp in
    // /tmp, where audit2allow had never put it, so loading could only ever
    // fail. Run it in the scratch directory and the two agree.
    let workdir = te
        .path()
        .parent()
        .map(|p| p.to_path_buf())
        .unwrap_or_else(|| std::path::PathBuf::from("."));
    let module_build = std::process::Command::new("audit2allow")
        .current_dir(&workdir)
        .args(["-M", &module, "-i", te.as_str()])
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .output()
        .context("running audit2allow (is the policycoreutils-python-utils package installed?)")?;

    if !module_build.status.success() {
        let stderr = String::from_utf8_lossy(&module_build.stderr).trim().to_string();
        return Err(anyhow::anyhow!(
            "audit2allow -M failed: {stderr}\n\
             Install with: sudo dnf install policycoreutils-python-utils"
        ));
    }

    let pp = workdir.join(format!("{module}.pp"));
    let pp_path = pp.display().to_string();
    let module_load = std::process::Command::new("semodule")
        .args(["-i", &pp_path])
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .output()
        .context("running semodule")?;

    // audit2allow leaves a .te beside the .pp; neither is needed once the
    // module is loaded, and the scratch directory is not a filing cabinet.
    let te_artifact = workdir.join(format!("{module}.te"));
    let _ = std::fs::remove_file(&te_artifact);

    if !module_load.status.success() {
        let stderr = String::from_utf8_lossy(&module_load.stderr).trim().to_string();
        // Unprivileged daemon: transfer the exact actions to the user. The .pp
        // stays for them to load — it lives in the daemon's 0700 scratch
        // directory, which root can read and nobody else can.
        return Ok(format!(
            "Policy module built but needs root to load:\n\
             *audit2allow worked* (module `{module}`),\n\
             `semodule -i` failed: {stderr}\n\n\
             Run this to apply it:\n\
             ```\nsudo semodule -i {pp_path}\n```"
        ));
    }

    let _ = std::fs::remove_file(&pp);

    Ok(format!(
        "✅ Policy loaded (`{module}`): the denied access is now allowed.\n\
         Roll back with: `sudo semodule -r {module}`"
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    const AVC: &str = "type=1400 audit(1715000000.123:456): avc: denied { open read } \
     for pid=9999 comm=\"beam.smp\" name=\"config.yaml\" dev=\"dm-0\" ino=123 \
     scontext=system_u:system_r:init_t:s0 tcontext=system_u:object_r:user_home_t:s0 \
     tclass=file permissive=0";

    #[test]
    fn parses_permissions_and_contexts() {
        let a = parse_avc(1, AVC);
        assert_eq!(a.permissions, "open read");
        assert_eq!(a.comm.as_deref(), Some("beam.smp"));
        assert!(a.scontext.contains("system_r:init_t"));
        assert!(a.tcontext.contains("object_r:user_home_t"));
        assert_eq!(a.tclass, "file");
    }

    #[test]
    fn fingerprint_is_stable() {
        let a1 = parse_avc(1, AVC);
        let a2 = parse_avc(2, AVC);
        assert_eq!(fingerprint(&a1), fingerprint(&a2));
    }

    #[test]
    fn lenient_on_unexpected_format() {
        let a = parse_avc(9, "avc: denied { exec } for name=\"x\"");
        assert_eq!(a.permissions, "exec");
        assert_eq!(a.comm, None);
    }
}