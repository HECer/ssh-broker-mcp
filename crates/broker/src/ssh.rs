use anyhow::{anyhow, Context, Result};
use std::path::{Path, PathBuf};
use tokio::process::Command;
use tokio::process::Child;

#[derive(Debug, Clone)]
pub struct ControlMaster {
    pub user: String,
    pub host: String,
    pub port: u16,
    pub control_path: PathBuf,
    pub known_hosts_path: PathBuf,
}

impl ControlMaster {
    pub fn destination(&self) -> String {
        format!("{}@{}", self.user, self.host)
    }

    pub async fn open(&self) -> Result<()> {
        // ControlPersist keeps the master alive for subsequent Exec calls.
        // -M: master mode, -N: no command, -f: background after auth
        let status = Command::new("ssh")
            .arg("-MNf")
            .arg("-p")
            .arg(self.port.to_string())
            .arg("-o")
            .arg("BatchMode=yes")
            .arg("-o")
            .arg("StrictHostKeyChecking=yes")
            .arg("-o")
            .arg(format!("UserKnownHostsFile={}", self.known_hosts_path.display()))
            .arg("-o")
            .arg("ControlMaster=yes")
            .arg("-o")
            .arg("ControlPersist=10m")
            .arg("-o")
            .arg(format!("ControlPath={}", self.control_path.display()))
            .arg(self.destination())
            .status()
            .await
            .context("spawn ssh ControlMaster")?;

        if !status.success() {
            return Err(anyhow!("ssh ControlMaster failed with status: {}", status));
        }
        Ok(())
    }

    /// Opens a ControlMaster connection using password (and optionally OTP) via a controlled
    /// SSH_ASKPASS flow. Secrets are never returned over RPC; they must be present locally.
    ///
    /// Notes:
    /// - This is currently implemented for Unix platforms (POSIX shell-based askpass helper).
    /// - On non-Unix platforms this returns an error.
    pub async fn open_password_totp(&self, password: &str, totp_code: Option<&str>) -> Result<()> {
        #[cfg(not(unix))]
        {
            let _ = (password, totp_code);
            return Err(anyhow!("password+otp auth is not supported on this platform yet"));
        }

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;

            let runtime_dir = self
                .control_path
                .parent()
                .unwrap_or_else(|| Path::new("."))
                .to_path_buf();
            let sid = self
                .control_path
                .file_stem()
                .and_then(|s| s.to_str())
                .unwrap_or("session");

            let dir = runtime_dir.join("askpass");
            tokio::fs::create_dir_all(&dir).await?;

            let secret_path = dir.join(format!("{sid}.secret"));
            let script_path = dir.join(format!("{sid}.sh"));

            // Two-line secret file:
            // 1) password
            // 2) totp (optional)
            let mut secret = String::new();
            secret.push_str(password);
            secret.push('\n');
            if let Some(code) = totp_code {
                secret.push_str(code);
            }
            secret.push('\n');
            tokio::fs::write(&secret_path, secret).await?;
            tokio::fs::set_permissions(&secret_path, std::fs::Permissions::from_mode(0o600)).await?;

            // Askpass script prints either password or OTP based on prompt text.
            // ssh invokes $SSH_ASKPASS with the prompt as argv[1].
            let script = r#"#!/bin/sh
prompt=\"$1\"
f=\"$SSH_BROKER_ASKPASS_FILE\"
case \"$prompt\" in
  *[Vv]erification*|*[Oo][Tt][Pp]*|*[Tt]oken*|*[Pp]asscode*)
    sed -n '2p' \"$f\"
    ;;
  *)
    sed -n '1p' \"$f\"
    ;;
esac
"#;
            tokio::fs::write(&script_path, script).await?;
            tokio::fs::set_permissions(&script_path, std::fs::Permissions::from_mode(0o700)).await?;

            // ControlPersist keeps the master alive for subsequent Exec calls.
            // -M: master mode, -N: no command, -f: background after auth
            let status = Command::new("ssh")
                .arg("-MNf")
                .arg("-p")
                .arg(self.port.to_string())
                .arg("-o")
                .arg("BatchMode=no")
                .arg("-o")
                .arg("NumberOfPasswordPrompts=1")
                .arg("-o")
                .arg("PreferredAuthentications=password,keyboard-interactive")
                .arg("-o")
                .arg("KbdInteractiveAuthentication=yes")
                .arg("-o")
                .arg("StrictHostKeyChecking=yes")
                .arg("-o")
                .arg(format!("UserKnownHostsFile={}", self.known_hosts_path.display()))
                .arg("-o")
                .arg("ControlMaster=yes")
                .arg("-o")
                .arg("ControlPersist=10m")
                .arg("-o")
                .arg(format!("ControlPath={}", self.control_path.display()))
                .env("SSH_ASKPASS", &script_path)
                .env("SSH_ASKPASS_REQUIRE", "force")
                .env("SSH_BROKER_ASKPASS_FILE", &secret_path)
                // ssh requires DISPLAY to be set to use askpass.
                .env("DISPLAY", "ssh-broker")
                .arg(self.destination())
                .status()
                .await
                .context("spawn ssh ControlMaster (password_totp)")?;

            // Best-effort cleanup.
            let _ = tokio::fs::remove_file(&secret_path).await;
            let _ = tokio::fs::remove_file(&script_path).await;

            if !status.success() {
                return Err(anyhow!("ssh ControlMaster failed with status: {}", status));
            }
            Ok(())
        }
    }

    pub async fn exec(&self, command: &str, timeout_ms: Option<u64>) -> Result<ExecOutput> {
        let mut cmd = Command::new("ssh");
        cmd.arg("-p")
            .arg(self.port.to_string())
            .arg("-o")
            .arg("BatchMode=yes")
            .arg("-o")
            .arg("StrictHostKeyChecking=yes")
            .arg("-o")
            .arg(format!("UserKnownHostsFile={}", self.known_hosts_path.display()))
            .arg("-o")
            .arg(format!("ControlPath={}", self.control_path.display()))
            .arg("-S")
            .arg(&self.control_path)
            .arg(self.destination())
            .arg("--")
            .arg(command);

        let fut = cmd.output();
        let output = match timeout_ms {
            Some(ms) if ms > 0 => tokio::time::timeout(std::time::Duration::from_millis(ms), fut)
                .await
                .context("exec timeout")??,
            _ => fut.await?,
        };

        Ok(ExecOutput {
            exit_code: output.status.code().unwrap_or(-1),
            stdout: output.stdout,
            stderr: output.stderr,
        })
    }

    pub async fn spawn_shell(&self, request_tty: bool) -> Result<Child> {
        let mut cmd = Command::new("ssh");
        if request_tty {
            cmd.arg("-tt");
        }
        cmd.arg("-p")
            .arg(self.port.to_string())
            .arg("-o")
            .arg("BatchMode=yes")
            .arg("-o")
            .arg("StrictHostKeyChecking=yes")
            .arg("-o")
            .arg(format!("UserKnownHostsFile={}", self.known_hosts_path.display()))
            .arg("-o")
            .arg(format!("ControlPath={}", self.control_path.display()))
            .arg("-S")
            .arg(&self.control_path)
            .arg(self.destination())
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped());
        let child = cmd.spawn().context("spawn ssh shell")?;
        Ok(child)
    }

    pub async fn scp_upload(&self, local_path: &Path, remote_path: &str) -> Result<()> {
        let status = Command::new("scp")
            .arg("-P")
            .arg(self.port.to_string())
            .arg("-o")
            .arg("BatchMode=yes")
            .arg("-o")
            .arg("StrictHostKeyChecking=yes")
            .arg("-o")
            .arg(format!("UserKnownHostsFile={}", self.known_hosts_path.display()))
            .arg("-o")
            .arg(format!("ControlPath={}", self.control_path.display()))
            .arg(local_path)
            .arg(format!("{}:{}", self.destination(), remote_path))
            .status()
            .await
            .context("scp upload")?;
        if !status.success() {
            return Err(anyhow!("scp upload failed: {}", status));
        }
        Ok(())
    }

    pub async fn scp_download(&self, remote_path: &str, local_path: &Path) -> Result<()> {
        let status = Command::new("scp")
            .arg("-P")
            .arg(self.port.to_string())
            .arg("-o")
            .arg("BatchMode=yes")
            .arg("-o")
            .arg("StrictHostKeyChecking=yes")
            .arg("-o")
            .arg(format!("UserKnownHostsFile={}", self.known_hosts_path.display()))
            .arg("-o")
            .arg(format!("ControlPath={}", self.control_path.display()))
            .arg(format!("{}:{}", self.destination(), remote_path))
            .arg(local_path)
            .status()
            .await
            .context("scp download")?;
        if !status.success() {
            return Err(anyhow!("scp download failed: {}", status));
        }
        Ok(())
    }

    pub fn forward_arg(&self, forward_type: i32, bind_addr: &str, bind_port: u16, target_host: &str, target_port: u16) -> Result<String> {
        // Keep this simple and explicit. The enum values come from proto.
        // 1=LOCAL, 2=REMOTE, 3=DYNAMIC
        match forward_type {
            1 => Ok(format!("{bind_addr}:{bind_port}:{target_host}:{target_port}")),
            2 => Ok(format!("{bind_addr}:{bind_port}:{target_host}:{target_port}")),
            3 => Ok(format!("{bind_addr}:{bind_port}")),
            _ => Err(anyhow!("unknown forward_type")),
        }
    }

    pub async fn spawn_forward(&self, forward_type: i32, spec: &str) -> Result<Child> {
        let mut cmd = Command::new("ssh");
        cmd.arg("-N")
            .arg("-p")
            .arg(self.port.to_string())
            .arg("-o")
            .arg("BatchMode=yes")
            .arg("-o")
            .arg("StrictHostKeyChecking=yes")
            .arg("-o")
            .arg(format!("UserKnownHostsFile={}", self.known_hosts_path.display()))
            .arg("-o")
            .arg(format!("ControlPath={}", self.control_path.display()))
            .arg("-S")
            .arg(&self.control_path);
        match forward_type {
            1 => {
                cmd.arg("-L").arg(spec);
            }
            2 => {
                cmd.arg("-R").arg(spec);
            }
            3 => {
                cmd.arg("-D").arg(spec);
            }
            _ => return Err(anyhow!("unknown forward_type")),
        }
        cmd.arg(self.destination())
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::piped());
        let child = cmd.spawn().context("spawn ssh forward")?;
        Ok(child)
    }

    pub async fn close(&self) -> Result<()> {
        let status = Command::new("ssh")
            .arg("-p")
            .arg(self.port.to_string())
            .arg("-o")
            .arg("BatchMode=yes")
            .arg("-o")
            .arg("StrictHostKeyChecking=yes")
            .arg("-o")
            .arg(format!("UserKnownHostsFile={}", self.known_hosts_path.display()))
            .arg("-o")
            .arg(format!("ControlPath={}", self.control_path.display()))
            .arg("-S")
            .arg(&self.control_path)
            .arg("-O")
            .arg("exit")
            .arg(self.destination())
            .status()
            .await
            .context("close ControlMaster")?;

        if !status.success() {
            return Err(anyhow!("ssh -O exit failed: {}", status));
        }
        Ok(())
    }
}

#[derive(Debug, Clone)]
pub struct ExecOutput {
    pub exit_code: i32,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
}

pub fn ensure_host_allowed(host: &str, allowed: &[String]) -> Result<()> {
    // Backwards-compatible wrapper. Prefer using crate::policy::ensure_host_allowed.
    crate::policy::ensure_host_allowed(host, allowed)
}

pub fn ensure_username_allowed(
    username: &str,
    default_username: &str,
    allowed_usernames: &[String],
) -> Result<()> {
    if allowed_usernames.is_empty() {
        if username == default_username {
            return Ok(());
        }
        return Err(anyhow!("username not allowed by credential policy"));
    }
    if allowed_usernames.iter().any(|u| u == username) {
        Ok(())
    } else {
        Err(anyhow!("username not allowed by credential policy"))
    }
}

pub fn control_path(runtime_dir: &Path, session_id: &str) -> PathBuf {
    // OpenSSH has a relatively short unix socket path limit.
    // Keep it short: <runtime>/<session>.sock
    runtime_dir.join(format!("{session_id}.sock"))
}
