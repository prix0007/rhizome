//! Run an absolute-path subprocess with no shell, a minimal environment, a
//! timeout and capped output. Works the same on macOS, Linux and Windows.

use std::path::Path;
use std::process::Stdio;
use std::time::Duration;

use tokio::io::AsyncReadExt;
use tokio::process::Command;

use crate::platform::{Os, minimal_env, system_root};

pub const MAX_OUTPUT: u64 = 1024 * 1024;
const MAX_ERR_OUTPUT: u64 = 64 * 1024;

#[derive(Debug, thiserror::Error)]
pub enum CmdError {
    #[error("failed to spawn {0}: {1}")]
    Spawn(String, std::io::Error),
    #[error("{0} timed out")]
    Timeout(String),
    #[error("reading output of {0} failed: {1}")]
    Read(String, std::io::Error),
    #[error("{0} failed: {1}")]
    Failed(String, String),
}

/// Full result of a subprocess: exit success plus capped stdout and stderr.
#[derive(Debug)]
pub struct CmdOutput {
    pub success: bool,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
}

/// Run `program` (an absolute path, never looked up through `PATH`) with
/// `args`, a minimal environment, no stdin, and capped stdout/stderr.
pub async fn run_full(
    program: impl AsRef<Path>,
    args: &[String],
    timeout: Duration,
) -> Result<CmdOutput, CmdError> {
    let program = program.as_ref();
    let name = program.display().to_string();
    debug_assert!(
        program.is_absolute(),
        "subprocesses must use absolute paths"
    );
    let mut cmd = Command::new(program);
    cmd.args(args).env_clear();
    for (k, v) in minimal_env(Os::current(), &system_root()) {
        cmd.env(k, v);
    }
    let mut child = cmd
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .map_err(|e| CmdError::Spawn(name.clone(), e))?;
    let stdout = child
        .stdout
        .take()
        .expect("stdout is piped")
        .take(MAX_OUTPUT);
    let mut stderr = child
        .stderr
        .take()
        .expect("stderr is piped")
        .take(MAX_ERR_OUTPUT);
    let work = async {
        let (mut out, mut err) = (Vec::new(), Vec::new());
        // Read both pipes together so a full stderr cannot block stdout. The
        // stdout reader is dropped the moment it is done (or capped), which
        // gives a chatty child SIGPIPE so stderr then reaches EOF too.
        let out_fut = async {
            let mut so = stdout;
            let r = so.read_to_end(&mut out).await;
            drop(so);
            r
        };
        let err_fut = stderr.read_to_end(&mut err);
        let (a, b) = tokio::join!(out_fut, err_fut);
        a?;
        b?;
        let status = child.wait().await?;
        Ok::<_, std::io::Error>(CmdOutput {
            success: status.success(),
            stdout: out,
            stderr: err,
        })
    };
    match tokio::time::timeout(timeout, work).await {
        Err(_) => Err(CmdError::Timeout(name)),
        Ok(Err(e)) => Err(CmdError::Read(name, e)),
        Ok(Ok(r)) => Ok(r),
    }
}

/// Returns (exit success, stdout bytes capped at `MAX_OUTPUT`).
pub async fn run_capped(
    program: impl AsRef<Path>,
    args: &[String],
    timeout: Duration,
) -> Result<(bool, Vec<u8>), CmdError> {
    let o = run_full(program, args, timeout).await?;
    Ok((o.success, o.stdout))
}

// These tests run tiny Unix utilities by absolute path.
#[cfg(all(test, unix))]
mod tests {
    use super::*;

    #[tokio::test]
    async fn captures_stdout_without_a_shell() {
        let (ok, out) = run_capped("/bin/echo", &["a; echo b".into()], Duration::from_secs(5))
            .await
            .unwrap();
        assert!(ok);
        assert_eq!(String::from_utf8(out).unwrap(), "a; echo b\n");
    }

    #[tokio::test]
    async fn times_out_and_kills() {
        let r = run_capped("/bin/sleep", &["5".into()], Duration::from_millis(100)).await;
        assert!(matches!(r, Err(CmdError::Timeout(_))));
    }

    #[tokio::test]
    async fn run_full_captures_stderr_and_exit_status() {
        let out = run_full(
            "/bin/sh",
            &[
                "-c".into(),
                "echo out; echo ping: sendto: No route to host 1>&2; exit 3".into(),
            ],
            Duration::from_secs(5),
        )
        .await
        .unwrap();
        assert!(!out.success);
        assert_eq!(String::from_utf8_lossy(&out.stdout), "out\n");
        assert!(String::from_utf8_lossy(&out.stderr).contains("No route to host"));
    }

    #[tokio::test]
    async fn run_full_reports_success() {
        let out = run_full("/usr/bin/true", &[], Duration::from_secs(5))
            .await
            .unwrap();
        assert!(out.success);
    }

    #[tokio::test]
    async fn missing_binary_is_a_spawn_error() {
        let r = run_capped("/nonexistent/prog", &[], Duration::from_secs(1)).await;
        assert!(matches!(r, Err(CmdError::Spawn(..))));
    }

    #[tokio::test]
    async fn output_is_capped() {
        // `yes` produces unbounded output; the cap stops the read and the timeout/kill ends it.
        let r = run_capped("/usr/bin/yes", &[], Duration::from_secs(10))
            .await
            .unwrap();
        assert_eq!(r.1.len() as u64, MAX_OUTPUT);
    }
}
