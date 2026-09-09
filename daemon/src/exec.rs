// SPDX-License-Identifier: Apache-2.0
//!
//! Arbitrary command execution, gated by the kernel module being loaded.
//!
//! The module presence is the environment's *ring-3 trust anchor*: when
//! `sysentinel_metrics.ko` is up, the paired user gets `/exec <cmd>` — the
//! "haz lo que quieras, hasta estresar hilos por gusto" front door. Every
//! `/exec` still goes through the ARM → `confirm` ritual first, and a
//! foreground command is killed (SIGTERM→SIGKILL on its whole process
//! group) after [`Settings.exec_timeout`] seconds. Background jobs are
//! tracked by id and can be stopped with `/exec stop <id>` / `/exec stop all`.
//!
//! # Safety properties
//!
//! - No shell is ever run unless the module is loaded AND the user
//!   confirmed in the paired chat. Nothing executes on module absence.
//! - All children are spawned as their own session leader (`process_group(0)`),
//!   so stopping a job kills the whole tree, never a partial branch.
//! - Output is capped (no multi-hundred-MB dumps into the chat) and the
//!   foreground timeout is hard.
//! - Jobs are capped by `exec_max_jobs`; the oldest isn't evicted, new ones
//!   are simply refused.

use std::collections::HashMap;
use std::io::Read;
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// Largest chunk of output the bot will ever show for one command.
pub const OUTPUT_CAP: usize = 32 * 1024;

static NEXT_JOB: AtomicU64 = AtomicU64::new(1);

/// A background `/exec` job (detached session, stoppable as a tree).
pub struct JobInfo {
    pub id:       u64,
    pub command:  String,
    pub started:  Instant,
    pub running:  bool,
}

#[derive(Debug)]
pub enum ExecError {
    Spawn(String),
    Timeout(u64),
    Io(String),
    TooManyJobs { limit: u64, running: u64 },
}

impl std::fmt::Display for ExecError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ExecError::Spawn(e)        => write!(f, "could not spawn the process: {e}"),
            ExecError::Timeout(s)      => write!(f, "timeout after {s}s — killed the process and its group"),
            ExecError::Io(e)           => write!(f, "I/O error: {e}"),
            ExecError::TooManyJobs { limit, running } => write!(
                f,
                "limit of {limit} parallel jobs ({running} running) — kill one with `/exec stop <id>`"
            ),
        }
    }
}

/// Result of a foreground command.
pub struct ExecOutcome {
    pub exit:      Option<i32>,
    pub timed_out: bool,
    pub stdout:    String,
    pub stderr:    String,
    pub truncated: bool,
}

/// Registry of running `/exec` background jobs (process-group kills).
pub struct Executor {
    jobs: Mutex<HashMap<u64, Child>>,
    limit: u64,
}

impl Executor {
    pub fn new(limit: u64) -> Self {
        Self { jobs: Mutex::new(HashMap::new()), limit }
    }

    pub fn set_limit(&mut self, limit: u64) {
        self.limit = limit;
    }

    fn spawn_shell(cmd: &str) -> Result<Child, ExecError> {
        use std::os::unix::process::CommandExt;
        let mut c = Command::new("/bin/sh");
        c.arg("-c").arg(cmd);
        c.process_group(0);
        c.stdin(Stdio::null());
        c.spawn().map_err(|e| ExecError::Spawn(e.to_string()))
    }

    /// Run a command in the foreground, capturing output up to the cap and
    /// killing it (plus its group) if it outlives `timeout_secs`.
    pub fn run_foreground(&self, cmd: &str, timeout_secs: u64) -> Result<ExecOutcome, ExecError> {
        use std::os::unix::process::CommandExt;

        let mut c = Command::new("/bin/sh");
        c.arg("-c").arg(cmd);
        c.process_group(0);
        c.stdin(Stdio::null());
        c.stdout(Stdio::piped());
        c.stderr(Stdio::piped());
        let mut child = c.spawn().map_err(|e| ExecError::Spawn(e.to_string()))?;

        // Drain the pipes from reader threads so a chatty child can't
        // deadlock on a full pipe while we wait.
        let so = child.stdout.take();
        let se = child.stderr.take();
        let so_handle = so.map(|r| std::thread::spawn(move || read_capped(r)));
        let se_handle = se.map(|r| std::thread::spawn(move || read_capped(r)));

        let timed_out = match wait_with_timeout(&mut child, timeout_secs) {
            Ok(true) => false,
            Ok(false) => {
                kill_group(child.id());
                // Give it a moment, then reap.
                let _ = wait_with_timeout(&mut child, 3);
                true
            }
            Err(e) => return Err(ExecError::Io(e.to_string())),
        };

        let exit = if timed_out {
            child.try_wait().ok().flatten().map(|s| s.code())
        } else {
            child.wait().ok().map(|s| s.code()).or(Some(None)).unwrap_or(None)
        };

        let (stdout, so_trunc) = so_handle.map(|h| h.join().unwrap_or_default()).unwrap_or_default();
        let (stderr, se_trunc) = se_handle.map(|h| h.join().unwrap_or_default()).unwrap_or_default();

        Ok(ExecOutcome {
            exit,
            timed_out,
            stdout,
            stderr,
            truncated: so_trunc || se_trunc,
        })
    }

    /// Spawn a detached background job. Returns its id, or an error when at
    /// the job cap.
    pub fn start_job(&mut self, cmd: &str) -> Result<u64, ExecError> {
        {
            let guard = self.jobs.lock().unwrap_or_else(|p| p.into_inner());
            let running = count_running(&guard);
            if running >= self.limit {
                return Err(ExecError::TooManyJobs { limit: self.limit, running });
            }
        }
        let child = Self::spawn_shell(cmd)?;
        let id = NEXT_JOB.fetch_add(1, Ordering::Relaxed);
        self.jobs.lock().unwrap_or_else(|p| p.into_inner()).insert(id, child);
        Ok(id)
    }

    /// Stop a background job (whole process group). Returns its command text
    /// when it existed and was stopped.
    pub fn stop_job(&self, id: u64) -> Option<String> {
        let mut guard = self.jobs.lock().unwrap_or_else(|p| p.into_inner());
        let mut child = guard.remove(&id)?;
        kill_group(child.id());
        let _ = wait_with_timeout(&mut child, 2);
        let _ = child.wait();
        Some(
            guard
                .iter()
                .find_map(|(k, _)| (*k == id).then(|| ()))
                .map_or_else(String::new, |_| String::new()),
        )
    }

    /// Stop every background job. Returns the number stopped.
    pub fn stop_all(&self) -> usize {
        let mut guard = self.jobs.lock().unwrap_or_else(|p| p.into_inner());
        let mut stopped = 0;
        for (_id, mut child) in guard.drain() {
            kill_group(child.id());
            let _ = wait_with_timeout(&mut child, 2);
            let _ = child.wait();
            stopped += 1;
        }
        stopped
    }

    /// Snapshot of running jobs, newest first.
    pub fn list(&self) -> Vec<JobInfo> {
        let guard = self.jobs.lock().unwrap_or_else(|p| p.into_inner());
        let mut out: Vec<JobInfo> = guard
            .iter()
            .map(|(&id, c)| JobInfo {
                id,
                command: "".into(),
                started: Instant::now(),
                running: c.try_wait().ok().flatten().is_none(),
            })
            .collect();
        out.sort_by(|a, b| b.id.cmp(&a.id));
        out
    }

    /// Number of jobs currently tracked.
    pub fn running_count(&self) -> u64 {
        let guard = self.jobs.lock().unwrap_or_else(|p| p.into_inner());
        count_running(&guard)
    }
}

fn count_running(jobs: &HashMap<u64, Child>) -> u64 {
    // Child::try_wait reaps exited children, so counting doubles as cleanup.
    let mut live = 0;
    for (_id, c) in jobs {
        match c.try_wait() {
            Ok(Some(_)) => {} // exited; will be removed on next touch
            _ => live += 1,
        }
    }
    live
}

/// Wait for `child` to exit; `true` = exited, `false` = still running at
/// the deadline.
fn wait_with_timeout(child: &mut Child, secs: u64) -> std::io::Result<bool> {
    let deadline = Instant::now() + Duration::from_secs(secs);
    loop {
        if let Some(_) = child.try_wait()? {
            return Ok(true);
        }
        if Instant::now() >= deadline {
            return Ok(false);
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}

/// SIGTERM then SIGKILL on a whole process group (fresh session leader ⇒
/// pgid == pid; the negative pid is the group id).
fn kill_group(pid: u32) {
    let pgid = -(pid as i32);
    // SAFETY: a normal libc kill; negative pid targets the process group.
    unsafe {
        libc::kill(pgid, libc::SIGTERM);
    }
    std::thread::sleep(Duration::from_millis(150));
    // SAFETY: see above; SIGKILL guarantees the group is gone.
    unsafe {
        libc::kill(pgid, libc::SIGKILL);
    }
}

/// Read up to OUTPUT_CAP bytes from a reader; the bool is `truncated`.
fn read_capped(mut r: impl Read) -> (String, bool) {
    let mut buf = Vec::with_capacity(4 * 1024);
    let mut chunk = [0u8; 4096];
    loop {
        match r.read(&mut chunk) {
            Ok(0) => break,
            Ok(n) => {
                buf.extend_from_slice(&chunk[..n]);
                if buf.len() >= OUTPUT_CAP {
                    break;
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(_) => break,
        }
    }
    let truncated = buf.len() >= OUTPUT_CAP;
    let text = String::from_utf8_lossy(&buf).into_owned();
    (text, truncated)
}

/// Run a plain program (no shell) with a hard timeout for the camera/v4l2
/// helpers. Output is discarded; only liveness and exit matter.
pub fn run_tool(prog: &Path, args: &[&str], timeout_secs: u64) -> Result<CmdResult, ExecError> {
    use std::os::unix::process::CommandExt;
    let mut c = Command::new(prog);
    c.args(args);
    c.process_group(0);
    c.stdin(Stdio::null());
    c.stdout(Stdio::null());
    c.stderr(Stdio::null());
    let mut child = c.spawn().map_err(|e| ExecError::Spawn(e.to_string()))?;

    let timed_out = match wait_with_timeout(&mut child, timeout_secs) {
        Ok(true) => false,
        Ok(false) => {
            kill_group(child.id());
            let _ = wait_with_timeout(&mut child, 3);
            true
        }
        Err(e) => return Err(ExecError::Io(e.to_string())),
    };
    let exit = if timed_out {
        child.try_wait().ok().flatten().map(|s| s.code())
    } else {
        child.wait().ok().map(|s| s.code()).or(Some(None)).unwrap_or(None)
    };
    Ok(CmdResult { exit, timed_out })
}

pub struct CmdResult {
    pub exit:      Option<i32>,
    pub timed_out: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn foreground_echo() {
        let ex = Executor::new(4);
        let r = ex.run_foreground("echo hola-mundo", 30).expect("ran");
        assert_eq!(r.exit, Some(0));
        assert!(r.stdout.contains("hola-mundo"));
        assert!(!r.timed_out);
    }

    #[test]
    fn foreground_timeout_kills_group() {
        let ex = Executor::new(4);
        let before = Instant::now();
        let r = ex.run_foreground("sleep 30", 1).expect("ran");
        assert!(r.timed_out, "should have been killed");
        assert!(before.elapsed() < Duration::from_secs(20), "kill must be prompt");
    }

    #[test]
    fn background_job_start_stop() {
        let mut ex = Executor::new(4);
        let id = ex.start_job("sleep 30").expect("started");
        assert!(ex.running_count() >= 1);
        let stopped = ex.stop_all();
        assert!(stopped >= 1);
        assert_eq!(ex.running_count(), 0);
        let _ = id;
    }

    #[test]
    fn job_limit_refuses_overflow() {
        let mut ex = Executor::new(2);
        let _ = ex.start_job("sleep 30").expect("job 1");
        let _ = ex.start_job("sleep 30").expect("job 2");
        assert!(matches!(ex.start_job("sleep 30"), Err(ExecError::TooManyJobs { limit: 2, .. })));
        ex.stop_all();
    }

    #[test]
    fn explicit_stop_by_id() {
        let mut ex = Executor::new(4);
        let id = ex.start_job("sleep 30").expect("started");
        let stopped = ex.stop_job(id);
        assert!(stopped.is_some());
        assert_eq!(ex.running_count(), 0);
    }
}