use crate::{
    audit::AuditLogger,
    limits::Limits,
    rate_limit::RateLimiter,
    sessions::SessionManager,
    ssh::{control_path, ensure_host_allowed, ensure_username_allowed, ControlMaster},
};
use serde::{Deserialize, Serialize};
use ssh_broker_common::{ids, store::CredentialStore};
use ssh_broker_proto::sshbroker::v1::{
    credential_service_server::CredentialService, session_service_server::SessionService, CloseSessionRequest, CloseSessionResponse, DeleteCredentialRequest, DeleteCredentialResponse, ExecRequest, ExecResponse,
    ListCredentialsRequest, ListCredentialsResponse, OpenSessionRequest, OpenSessionResponse, ScpDownloadRequest, ScpDownloadResponse, ScpUploadRequest, ScpUploadResponse, ShellClientMsg, ShellServerMsg,
    StartForwardRequest, StartForwardResponse, StopForwardRequest, StopForwardResponse,
};
use std::path::PathBuf;
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;
use tonic::{Request, Response, Status};
use tracing::{info, warn};
use totp_rs::{Algorithm, Secret, TOTP};

#[derive(Debug, Deserialize)]
struct PasswordTotpSecret {
    password: String,
    #[serde(default)]
    totp_seed: String,
}

#[derive(Clone)]
pub struct CredentialSvc {
    store: CredentialStore,
    rate_limiter: RateLimiter,
    audit: AuditLogger,
}

impl CredentialSvc {
    pub fn new(store: CredentialStore, rate_limiter: RateLimiter, audit: AuditLogger) -> Self {
        Self {
            store,
            rate_limiter,
            audit,
        }
    }
}

#[tonic::async_trait]
impl CredentialService for CredentialSvc {
    async fn list_credentials(
        &self,
        request: Request<ListCredentialsRequest>,
    ) -> Result<Response<ListCredentialsResponse>, Status> {
        enforce_rate_limit(&self.rate_limiter, &request).await?;
        self.audit
            .write(&AuditEvent::simple("list_credentials", peer(&request)))
            .await
            .map_err(to_status)?;
        let list = self.store.list_meta().await.map_err(to_status)?;
        let credentials = list
            .into_iter()
            .map(|m| ssh_broker_proto::sshbroker::v1::CredentialMeta {
                credential_id: m.credential_id,
                label: m.label,
                username: m.username,
                auth_type: m.auth_type,
                allowed_hosts: m.allowed_hosts,
                allowed_usernames: m.allowed_usernames,
            })
            .collect();

        Ok(Response::new(ListCredentialsResponse { credentials }))
    }

    async fn delete_credential(
        &self,
        request: Request<DeleteCredentialRequest>,
    ) -> Result<Response<DeleteCredentialResponse>, Status> {
        enforce_rate_limit(&self.rate_limiter, &request).await?;
        let peer = peer(&request);
        let id = request.into_inner().credential_id;
        self.audit
            .write(&AuditEvent::delete_credential(peer, &id))
            .await
            .map_err(to_status)?;
        self.store.delete(&id).await.map_err(to_status)?;
        Ok(Response::new(DeleteCredentialResponse {}))
    }
}

#[derive(Clone)]
pub struct SessionSvc {
    store: CredentialStore,
    sessions: SessionManager,
    known_hosts_path: PathBuf,
    limits: Limits,
    rate_limiter: RateLimiter,
    audit: AuditLogger,
}

impl SessionSvc {
    pub fn new(
        store: CredentialStore,
        sessions: SessionManager,
        known_hosts_path: PathBuf,
        limits: Limits,
        rate_limiter: RateLimiter,
        audit: AuditLogger,
    ) -> Self {
        Self {
            store,
            sessions,
            known_hosts_path,
            limits,
            rate_limiter,
            audit,
        }
    }
}

 #[tonic::async_trait]
 impl SessionService for SessionSvc {
     async fn open_session(
         &self,
         request: Request<OpenSessionRequest>,
     ) -> Result<Response<OpenSessionResponse>, Status> {
        enforce_rate_limit(&self.rate_limiter, &request).await?;
        let peer = peer(&request);
         let req = request.into_inner();
         let credential_id = req.credential_id;
         let host = req.host;
         let port = if req.port == 0 { 22 } else { req.port as u16 };

         let meta = self
             .store
             .get_meta(&credential_id)
             .await
             .map_err(to_status)?
             .ok_or_else(|| Status::not_found("unknown credential_id"))?;

         ensure_host_allowed(&host, &meta.allowed_hosts).map_err(to_status)?;

        let user = if !req.username_override.is_empty() {
            req.username_override
        } else {
            meta.username.clone()
        };
        ensure_username_allowed(&user, &meta.username, &meta.allowed_usernames).map_err(to_status)?;

         tokio::fs::create_dir_all(self.sessions.runtime_dir())
             .await
             .map_err(to_status)?;

         let session_id = ids::new_session_id();
         let cp = control_path(self.sessions.runtime_dir(), &session_id);

         let cm = ControlMaster {
             user,
             host,
             port,
             control_path: cp,
            known_hosts_path: self.known_hosts_path.clone(),
         };

        if meta.auth_type == "password_totp" {
            warn!("using password_totp auth (via SSH_ASKPASS); prefer keys/agent/certs when possible");
            let secret_raw = self
                .store
                .get_secret(&credential_id)
                .map_err(to_status)?
                .ok_or_else(|| Status::failed_precondition("missing secret material in keyring"))?;
            let secret: PasswordTotpSecret = serde_json::from_str(&secret_raw)
                .map_err(|e| Status::failed_precondition(format!("invalid stored secret JSON: {e}")))?;
            let totp_code = if secret.totp_seed.trim().is_empty() {
                None
            } else {
                Some(generate_totp(&secret.totp_seed).map_err(to_status)?)
            };
            cm.open_password_totp(&secret.password, totp_code.as_deref())
                .await
                .map_err(to_status)?;
        } else {
            cm.open().await.map_err(to_status)?;
        }

         self.sessions.insert(session_id.clone(), cm).await;
         info!(%session_id, "opened session");
        self.audit
            .write(&AuditEvent::open_session(
                peer,
                &session_id,
                &credential_id,
                &host,
                port,
                &user,
            ))
            .await
            .map_err(to_status)?;

         Ok(Response::new(OpenSessionResponse { session_id }))
     }

     async fn exec(&self, request: Request<ExecRequest>) -> Result<Response<ExecResponse>, Status> {
        enforce_rate_limit(&self.rate_limiter, &request).await?;
        let peer = peer(&request);
         let req = request.into_inner();
         let cm = self.sessions.require(&req.session_id).await.map_err(to_status)?;
         let timeout_ms = if req.timeout_ms == 0 {
             None
         } else {
             Some(req.timeout_ms as u64)
         };

        let mut out = cm.exec(&req.command, timeout_ms).await.map_err(to_status)?;
        truncate_output(&mut out.stdout, &mut out.stderr, self.limits.max_exec_output_bytes);
        info!(session_id = %req.session_id, "exec");
        self.audit
            .write(&AuditEvent::exec(
                peer,
                &req.session_id,
                if self.audit.log_commands() {
                    Some(req.command.as_str())
                } else {
                    None
                },
                out.exit_code,
            ))
            .await
            .map_err(to_status)?;

         Ok(Response::new(ExecResponse {
             exit_code: out.exit_code,
             stdout: out.stdout,
             stderr: out.stderr,
         }))
     }

    type ShellStream = ReceiverStream<Result<ShellServerMsg, Status>>;

    async fn shell(
        &self,
        request: Request<tonic::Streaming<ShellClientMsg>>,
    ) -> Result<Response<Self::ShellStream>, Status> {
        enforce_rate_limit(&self.rate_limiter, &request).await?;
        let peer = peer(&request);
        let mut inbound = request.into_inner();
        let sessions = self.sessions.clone();
        let limits = self.limits.clone();
        let audit = self.audit.clone();

        let (tx, rx) = mpsc::channel::<Result<ShellServerMsg, Status>>(32);

        tokio::spawn(async move {
            use std::sync::{
                atomic::{AtomicBool, AtomicU64, Ordering},
                Arc,
            };
            let bytes = Arc::new(AtomicU64::new(0));
            let over_limit = Arc::new(AtomicBool::new(false));
            let start = std::time::Instant::now();
            let first = match inbound.message().await {
                Ok(Some(m)) => m,
                Ok(None) => return,
                Err(e) => {
                    let _ = tx
                        .send(Err(Status::invalid_argument(format!(
                            "shell stream error: {e}"
                        ))))
                        .await;
                    return;
                }
            };

            let (session_id, request_tty) = match first.msg {
                Some(ssh_broker_proto::sshbroker::v1::shell_client_msg::Msg::Open(o)) => {
                    (o.session_id, o.request_tty)
                }
                _ => {
                    let _ = tx
                        .send(Err(Status::invalid_argument(
                            "first shell message must be open",
                        )))
                        .await;
                    return;
                }
            };

            let cm = match sessions.require(&session_id).await {
                Ok(cm) => cm,
                Err(e) => {
                    let _ = tx.send(Err(to_status(e))).await;
                    return;
                }
            };

            let mut child = match cm.spawn_shell(request_tty).await {
                Ok(c) => c,
                Err(e) => {
                    let _ = tx.send(Err(to_status(e))).await;
                    return;
                }
            };

            let _ = tx
                .send(Ok(ShellServerMsg {
                    msg: Some(ssh_broker_proto::sshbroker::v1::shell_server_msg::Msg::Opened(
                        ssh_broker_proto::sshbroker::v1::ShellOpened {},
                    )),
                }))
                .await;
            let _ = audit
                .write(&AuditEvent::simple("shell_open", peer.clone()))
                .await;

            let mut stdin = child.stdin.take();
            let mut stdout = child.stdout.take();
            let mut stderr = child.stderr.take();

            // stdout reader
            if let Some(mut out) = stdout.take() {
                let tx2 = tx.clone();
                let bytes2 = bytes.clone();
                let limits2 = limits.clone();
                let over2 = over_limit.clone();
                tokio::spawn(async move {
                    let mut buf = vec![0u8; 16 * 1024];
                    loop {
                        match tokio::io::AsyncReadExt::read(&mut out, &mut buf).await {
                            Ok(0) => break,
                            Ok(n) => {
                                let total = bytes2.fetch_add(n as u64, Ordering::Relaxed) + n as u64;
                                if total as usize > limits2.max_shell_output_bytes {
                                    over2.store(true, Ordering::Relaxed);
                                    let _ = tx2.send(Err(Status::resource_exhausted("shell output limit exceeded"))).await;
                                    break;
                                }
                                let _ = tx2
                                    .send(Ok(ShellServerMsg {
                                        msg: Some(
                                            ssh_broker_proto::sshbroker::v1::shell_server_msg::Msg::Output(
                                                ssh_broker_proto::sshbroker::v1::ShellOutput {
                                                    stdout: buf[..n].to_vec(),
                                                    stderr: vec![],
                                                },
                                            ),
                                        ),
                                    }))
                                    .await;
                            }
                            Err(_) => break,
                        }
                    }
                });
            }

            // stderr reader
            if let Some(mut err) = stderr.take() {
                let tx2 = tx.clone();
                let bytes2 = bytes.clone();
                let limits2 = limits.clone();
                let over2 = over_limit.clone();
                tokio::spawn(async move {
                    let mut buf = vec![0u8; 16 * 1024];
                    loop {
                        match tokio::io::AsyncReadExt::read(&mut err, &mut buf).await {
                            Ok(0) => break,
                            Ok(n) => {
                                let total = bytes2.fetch_add(n as u64, Ordering::Relaxed) + n as u64;
                                if total as usize > limits2.max_shell_output_bytes {
                                    over2.store(true, Ordering::Relaxed);
                                    let _ = tx2.send(Err(Status::resource_exhausted("shell output limit exceeded"))).await;
                                    break;
                                }
                                let _ = tx2
                                    .send(Ok(ShellServerMsg {
                                        msg: Some(
                                            ssh_broker_proto::sshbroker::v1::shell_server_msg::Msg::Output(
                                                ssh_broker_proto::sshbroker::v1::ShellOutput {
                                                    stdout: vec![],
                                                    stderr: buf[..n].to_vec(),
                                                },
                                            ),
                                        ),
                                    }))
                                    .await;
                            }
                            Err(_) => break,
                        }
                    }
                });
            }

            // inbound loop
            loop {
                if start.elapsed().as_secs() > limits.max_shell_seconds {
                    break;
                }
                if over_limit.load(Ordering::Relaxed) {
                    break;
                }
                let m = match inbound.message().await {
                    Ok(Some(m)) => m,
                    Ok(None) => break,
                    Err(_) => break,
                };
                match m.msg {
                    Some(ssh_broker_proto::sshbroker::v1::shell_client_msg::Msg::Input(i)) => {
                        if let Some(s) = stdin.as_mut() {
                            let _ = tokio::io::AsyncWriteExt::write_all(s, &i.data).await;
                        }
                    }
                    Some(ssh_broker_proto::sshbroker::v1::shell_client_msg::Msg::Resize(_r)) => {
                        // Best-effort: resizing remote PTY via OpenSSH is non-trivial without a local PTY.
                        // We currently ignore resize messages.
                    }
                    Some(ssh_broker_proto::sshbroker::v1::shell_client_msg::Msg::Close(_)) => {
                        break;
                    }
                    Some(ssh_broker_proto::sshbroker::v1::shell_client_msg::Msg::Open(_)) | None => {}
                }
            }

            // Ensure stdin is closed so ssh can terminate if needed.
            drop(stdin);

            if start.elapsed().as_secs() > limits.max_shell_seconds || over_limit.load(Ordering::Relaxed) {
                let _ = child.kill().await;
            }

            let exit = match tokio::time::timeout(std::time::Duration::from_secs(5), child.wait()).await {
                Ok(Ok(s)) => s.code().unwrap_or(-1),
                Ok(Err(_)) => -1,
                Err(_) => {
                    let _ = child.kill().await;
                    -1
                }
            };
            let _ = audit
                .write(&AuditEvent::shell_exit(peer.clone(), &session_id, exit))
                .await;

            let _ = tx
                .send(Ok(ShellServerMsg {
                    msg: Some(ssh_broker_proto::sshbroker::v1::shell_server_msg::Msg::Exit(
                        ssh_broker_proto::sshbroker::v1::ShellExit { exit_code: exit },
                    )),
                }))
                .await;
        });

        Ok(Response::new(ReceiverStream::new(rx)))
    }

    async fn scp_upload(
        &self,
        request: Request<tonic::Streaming<ScpUploadRequest>>,
    ) -> Result<Response<ScpUploadResponse>, Status> {
        enforce_rate_limit(&self.rate_limiter, &request).await?;
        let peer = peer(&request);
        let mut inbound = request.into_inner();
        let first = inbound
            .message()
            .await
            .map_err(|e| Status::invalid_argument(e.to_string()))?
            .ok_or_else(|| Status::invalid_argument("missing upload open"))?;

        let open = match first.msg {
            Some(ssh_broker_proto::sshbroker::v1::scp_upload_request::Msg::Open(o)) => o,
            _ => return Err(Status::invalid_argument("first upload message must be open")),
        };

        let cm = self.sessions.require(&open.session_id).await.map_err(to_status)?;
        let tmp_path = self
            .sessions
            .runtime_dir()
            .join(format!("upload_{}_tmp", ids::new_session_id()));

        let mut f = tokio::fs::File::create(&tmp_path).await.map_err(to_status)?;
        let mut total: u64 = 0;
        while let Some(m) = inbound.message().await.map_err(to_status)? {
            if let Some(ssh_broker_proto::sshbroker::v1::scp_upload_request::Msg::Chunk(c)) = m.msg {
                total += c.data.len() as u64;
                if total > self.limits.max_scp_bytes {
                    let _ = tokio::fs::remove_file(&tmp_path).await;
                    return Err(Status::resource_exhausted("scp upload size limit exceeded"));
                }
                tokio::io::AsyncWriteExt::write_all(&mut f, &c.data)
                    .await
                    .map_err(to_status)?;
            }
        }
        tokio::io::AsyncWriteExt::flush(&mut f).await.map_err(to_status)?;
        drop(f);

        if !open.overwrite {
            let test_cmd = format!("test ! -e {}", shell_quote(&open.remote_path));
            let out = cm.exec(&test_cmd, Some(10_000)).await.map_err(to_status)?;
            if out.exit_code != 0 {
                let _ = tokio::fs::remove_file(&tmp_path).await;
                return Err(Status::already_exists("remote file exists"));
            }
        }

        cm.scp_upload(&tmp_path, &open.remote_path).await.map_err(to_status)?;
        let _ = tokio::fs::remove_file(&tmp_path).await;
        info!(session_id = %open.session_id, bytes = total, "scp upload");
        self.audit
            .write(&AuditEvent::scp_upload(
                peer,
                &open.session_id,
                &open.remote_path,
                total,
            ))
            .await
            .map_err(to_status)?;

        Ok(Response::new(ScpUploadResponse {
            bytes_written: total,
        }))
    }

    type ScpDownloadStream = ReceiverStream<Result<ScpDownloadResponse, Status>>;

    async fn scp_download(
        &self,
        request: Request<ScpDownloadRequest>,
    ) -> Result<Response<Self::ScpDownloadStream>, Status> {
        enforce_rate_limit(&self.rate_limiter, &request).await?;
        let peer = peer(&request);
        let req = request.into_inner();
        let cm = self.sessions.require(&req.session_id).await.map_err(to_status)?;
        let tmp_path = self
            .sessions
            .runtime_dir()
            .join(format!("download_{}_tmp", ids::new_session_id()));

        cm.scp_download(&req.remote_path, &tmp_path).await.map_err(to_status)?;
        let meta = tokio::fs::metadata(&tmp_path).await.map_err(to_status)?;
        if meta.len() > self.limits.max_scp_bytes {
            let _ = tokio::fs::remove_file(&tmp_path).await;
            return Err(Status::resource_exhausted("scp download size limit exceeded"));
        }

        let (tx, rx) = mpsc::channel::<Result<ScpDownloadResponse, Status>>(16);
        tokio::spawn(async move {
            let mut f = match tokio::fs::File::open(&tmp_path).await {
                Ok(f) => f,
                Err(e) => {
                    let _ = tx.send(Err(to_status(e))).await;
                    return;
                }
            };
            let mut buf = vec![0u8; 64 * 1024];
            loop {
                match tokio::io::AsyncReadExt::read(&mut f, &mut buf).await {
                    Ok(0) => break,
                    Ok(n) => {
                        if tx
                            .send(Ok(ScpDownloadResponse {
                                data: buf[..n].to_vec(),
                            }))
                            .await
                            .is_err()
                        {
                            break;
                        }
                    }
                    Err(e) => {
                        let _ = tx.send(Err(to_status(e))).await;
                        break;
                    }
                }
            }
            let _ = tokio::fs::remove_file(&tmp_path).await;
        });

        info!(session_id = %req.session_id, "scp download");
        self.audit
            .write(&AuditEvent::scp_download(
                peer,
                &req.session_id,
                &req.remote_path,
                meta.len(),
            ))
            .await
            .map_err(to_status)?;
        Ok(Response::new(ReceiverStream::new(rx)))
    }

    async fn start_forward(
        &self,
        request: Request<StartForwardRequest>,
    ) -> Result<Response<StartForwardResponse>, Status> {
        enforce_rate_limit(&self.rate_limiter, &request).await?;
        let peer = peer(&request);
        let req = request.into_inner();
        let cm = self.sessions.require(&req.session_id).await.map_err(to_status)?;
        let forward_id = ids::new_session_id();

        let bind_addr = if req.bind_addr.is_empty() { "127.0.0.1" } else { &req.bind_addr };
        let bind_port = req.bind_port as u16;
        let target_host = if req.target_host.is_empty() { "127.0.0.1" } else { &req.target_host };
        let target_port = req.target_port as u16;

        let spec = cm
            .forward_arg(req.forward_type, bind_addr, bind_port, target_host, target_port)
            .map_err(to_status)?;

        let child = cm.spawn_forward(req.forward_type, &spec).await.map_err(to_status)?;
        self.sessions
            .add_forward(&req.session_id, &forward_id, child)
            .await;

        info!(session_id = %req.session_id, forward_id = %forward_id, "start forward");
        self.audit
            .write(&AuditEvent::start_forward(peer, &req.session_id, &forward_id, req.forward_type))
            .await
            .map_err(to_status)?;
        Ok(Response::new(StartForwardResponse { forward_id }))
    }

    async fn stop_forward(
        &self,
        request: Request<StopForwardRequest>,
    ) -> Result<Response<StopForwardResponse>, Status> {
        enforce_rate_limit(&self.rate_limiter, &request).await?;
        let peer = peer(&request);
        let req = request.into_inner();
        self.sessions
            .stop_forward(&req.session_id, &req.forward_id)
            .await
            .map_err(to_status)?;
        info!(session_id = %req.session_id, forward_id = %req.forward_id, "stop forward");
        self.audit
            .write(&AuditEvent::stop_forward(peer, &req.session_id, &req.forward_id))
            .await
            .map_err(to_status)?;
        Ok(Response::new(StopForwardResponse {}))
    }

     async fn close_session(
         &self,
         request: Request<CloseSessionRequest>,
     ) -> Result<Response<CloseSessionResponse>, Status> {
        enforce_rate_limit(&self.rate_limiter, &request).await?;
        let peer = peer(&request);
         let session_id = request.into_inner().session_id;
        self.sessions.stop_all_forwards(&session_id).await;
         let cm = self
             .sessions
             .remove(&session_id)
             .await
             .ok_or_else(|| Status::not_found("unknown session_id"))?;

         cm.close().await.map_err(to_status)?;
         // Best-effort socket cleanup.
         let _ = tokio::fs::remove_file(&cm.control_path).await;
         info!(%session_id, "closed session");
        self.audit
            .write(&AuditEvent::simple("close_session", peer))
            .await
            .map_err(to_status)?;
         Ok(Response::new(CloseSessionResponse {}))
     }
 }

 fn to_status<E: std::fmt::Display>(e: E) -> Status {
     Status::internal(e.to_string())
 }

fn generate_totp(seed_base32: &str) -> anyhow::Result<String> {
    let secret_bytes = Secret::Encoded(seed_base32.trim().to_string()).to_bytes()?;
    let totp = TOTP::new(Algorithm::SHA1, 6, 1, 30, secret_bytes)?;
    Ok(totp.generate_current()?)
}

fn shell_quote(s: &str) -> String {
    // Minimal, conservative quoting for remote POSIX shell.
    // This is not perfect for every remote shell, but avoids obvious injection.
    format!("'{}'", s.replace('\'', r#"'\\''"#))
}

#[derive(Debug, Serialize)]
struct AuditEvent<'a> {
    ts_unix_ms: i64,
    kind: &'a str,
    peer: String,
    session_id: Option<&'a str>,
    credential_id: Option<&'a str>,
    host: Option<&'a str>,
    port: Option<u16>,
    username: Option<&'a str>,
    command: Option<&'a str>,
    path: Option<&'a str>,
    bytes: Option<u64>,
    exit_code: Option<i32>,
    forward_id: Option<&'a str>,
    forward_type: Option<i32>,
}

impl<'a> AuditEvent<'a> {
    fn base(kind: &'a str, peer: String) -> Self {
        Self {
            ts_unix_ms: chrono::Utc::now().timestamp_millis(),
            kind,
            peer,
            session_id: None,
            credential_id: None,
            host: None,
            port: None,
            username: None,
            command: None,
            path: None,
            bytes: None,
            exit_code: None,
            forward_id: None,
            forward_type: None,
        }
    }

    fn simple(kind: &'a str, peer: String) -> Self {
        Self::base(kind, peer)
    }

    fn delete_credential(peer: String, credential_id: &'a str) -> Self {
        let mut e = Self::base("delete_credential", peer);
        e.credential_id = Some(credential_id);
        e
    }

    fn open_session(
        peer: String,
        session_id: &'a str,
        credential_id: &'a str,
        host: &'a str,
        port: u16,
        username: &'a str,
    ) -> Self {
        let mut e = Self::base("open_session", peer);
        e.session_id = Some(session_id);
        e.credential_id = Some(credential_id);
        e.host = Some(host);
        e.port = Some(port);
        e.username = Some(username);
        e
    }

    fn exec(peer: String, session_id: &'a str, command: Option<&'a str>, exit_code: i32) -> Self {
        let mut e = Self::base("exec", peer);
        e.session_id = Some(session_id);
        e.command = command;
        e.exit_code = Some(exit_code);
        e
    }

    fn shell_exit(peer: String, session_id: &'a str, exit_code: i32) -> Self {
        let mut e = Self::base("shell_exit", peer);
        e.session_id = Some(session_id);
        e.exit_code = Some(exit_code);
        e
    }

    fn scp_upload(peer: String, session_id: &'a str, remote_path: &'a str, bytes: u64) -> Self {
        let mut e = Self::base("scp_upload", peer);
        e.session_id = Some(session_id);
        e.path = Some(remote_path);
        e.bytes = Some(bytes);
        e
    }

    fn scp_download(peer: String, session_id: &'a str, remote_path: &'a str, bytes: u64) -> Self {
        let mut e = Self::base("scp_download", peer);
        e.session_id = Some(session_id);
        e.path = Some(remote_path);
        e.bytes = Some(bytes);
        e
    }

    fn start_forward(peer: String, session_id: &'a str, forward_id: &'a str, forward_type: i32) -> Self {
        let mut e = Self::base("start_forward", peer);
        e.session_id = Some(session_id);
        e.forward_id = Some(forward_id);
        e.forward_type = Some(forward_type);
        e
    }

    fn stop_forward(peer: String, session_id: &'a str, forward_id: &'a str) -> Self {
        let mut e = Self::base("stop_forward", peer);
        e.session_id = Some(session_id);
        e.forward_id = Some(forward_id);
        e
    }
}

fn peer<T>(req: &Request<T>) -> String {
    req.remote_addr()
        .map(|a| a.to_string())
        .unwrap_or_else(|| "local".to_string())
}

async fn enforce_rate_limit<T>(rl: &RateLimiter, req: &Request<T>) -> Result<(), Status> {
    let key = req
        .remote_addr()
        .map(|a| a.to_string())
        .unwrap_or_else(|| "local".to_string());
    let ok = rl.check(&key).await.map_err(to_status)?;
    if ok {
        Ok(())
    } else {
        Err(Status::resource_exhausted("rate limit exceeded"))
    }
}

fn truncate_output(stdout: &mut Vec<u8>, stderr: &mut Vec<u8>, max: usize) {
    if max == 0 {
        stdout.clear();
        stderr.clear();
        return;
    }
    let total = stdout.len() + stderr.len();
    if total <= max {
        return;
    }

    // Prefer keeping stderr intact when possible.
    if stderr.len() >= max {
        stderr.truncate(max);
        stdout.clear();
        return;
    }
    let remaining = max - stderr.len();
    stdout.truncate(remaining);
}
