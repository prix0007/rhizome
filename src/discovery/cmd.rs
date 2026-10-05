//! Run an absolute-path subprocess with no shell, a cleared environment,
//! a timeout and a capped stdout.

use std::process::Stdio;
use std::time::Duration;

use tokio::io::AsyncReadExt;
use tokio::process::Command;

pub const MAX_OUTPUT: u64 = 1024 * 1024;
const MAX_ERR_OUTPUT: u64 = 64 * 1024;
const SAFE_PATH: &str = "/usr/bin:/bin:/usr/sbin:/sbin";

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

/// Like `run_capped` but also returns (capped) stderr.
pub async fn run_full(
    program: &'static str,
    args: &[String],
    timeout: Duration,
) -> Result<CmdOutput, CmdError> {
    debug_assert!(
        program.starts_with('/'),
        "subprocesses must use absolute paths"
    );
    let mut child = Command::new(program)
        .args(args)
        .env_clear()
        .env("PATH", SAFE_PATH)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .map_err(|e| CmdError::Spawn(program.into(), e))?;
    let mut stdout = child
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
        // Read both pipes together so a full stderr cannot block stdout.
        let (a, b) = tokio::join!(stdout.read_to_end(&mut out), stderr.read_to_end(&mut err));
        a?;
        b?;
        drop((stdout, stderr));
        let status = child.wait().await?;
        Ok::<_, std::io::Error>(CmdOutput {
            success: status.success(),
            stdout: out,
            stderr: err,
        })
    };
    match tokio::time::timeout(timeout, work).await {
        Err(_) => Err(CmdError::Timeout(program.into())),
        Ok(Err(e)) => Err(CmdError::Read(program.into(), e)),
        Ok(Ok(r)) => Ok(r),
    }
}

/// Returns (exit success, stdout bytes capped at `MAX_OUTPUT`).
pub async fn run_capped(
    program: &'static str,
    args: &[String],
    timeout: Duration,
) -> Result<(bool, Vec<u8>), CmdError> {
    debug_assert!(
        program.starts_with('/'),
        "subprocesses must use absolute paths"
    );
    let mut child = Command::new(program)
        .args(args)
        .env_clear()
        .env("PATH", SAFE_PATH)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .kill_on_drop(true)
        .spawn()
        .map_err(|e| CmdError::Spawn(program.into(), e))?;
    let mut stdout = child
        .stdout
        .take()
        .expect("stdout is piped")
        .take(MAX_OUTPUT);
    let work = async {
        let mut buf = Vec::new();
        stdout.read_to_end(&mut buf).await?;
        // Close our end so a chatty child gets SIGPIPE instead of blocking forever.
        drop(stdout);
        let status = child.wait().await?;
        Ok::<_, std::io::Error>((status.success(), buf))
    };
    match tokio::time::timeout(timeout, work).await {
        Err(_) => Err(CmdError::Timeout(program.into())),
        Ok(Err(e)) => Err(CmdError::Read(program.into(), e)),
        Ok(Ok(r)) => Ok(r),
    }
}

#[cfg(test)]
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
