use crate::{
    sessions::SessionManager,
    ssh::{control_path, ensure_host_allowed, ensure_username_allowed, ControlMaster},
};
use ssh_broker_common::{ids, store::CredentialStore};
 use ssh_broker_proto::sshbroker::v1::{
     credential_service_server::CredentialService, session_service_server::SessionService,
     CloseSessionRequest, CloseSessionResponse, DeleteCredentialRequest, DeleteCredentialResponse,
     ExecRequest, ExecResponse, ListCredentialsRequest, ListCredentialsResponse, OpenSessionRequest,
    OpenSessionResponse, ScpDownloadRequest, ScpDownloadResponse, ScpUploadRequest, ScpUploadResponse,
    ShellClientMsg, ShellServerMsg, StartForwardRequest, StartForwardResponse, StopForwardRequest,
    StopForwardResponse,
 };
use std::path::PathBuf;
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;
 use tonic::{Request, Response, Status};
 use tracing::{info, warn};
 
 #[derive(Clone)]
 pub struct CredentialSvc {
     store: CredentialStore,
 }
 
 impl CredentialSvc {
     pub fn new(store: CredentialStore) -> Self {
         Self { store }
     }
 }
 
 #[tonic::async_trait]
 impl CredentialService for CredentialSvc {
     async fn list_credentials(
         &self,
         _request: Request<ListCredentialsRequest>,
     ) -> Result<Response<ListCredentialsResponse>, Status> {
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
         let id = request.into_inner().credential_id;
         self.store.delete(&id).await.map_err(to_status)?;
         Ok(Response::new(DeleteCredentialResponse {}))
     }
 }
 
 #[derive(Clone)]
 pub struct SessionSvc {
     store: CredentialStore,
     sessions: SessionManager,
    known_hosts_path: PathBuf,
 }
 
 impl SessionSvc {
    pub fn new(store: CredentialStore, sessions: SessionManager, known_hosts_path: PathBuf) -> Self {
        Self { store, sessions, known_hosts_path }
     }
 }
 
 #[tonic::async_trait]
 impl SessionService for SessionSvc {
     async fn open_session(
         &self,
         request: Request<OpenSessionRequest>,
     ) -> Result<Response<OpenSessionResponse>, Status> {
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
 
         // For now, rely on OpenSSH key/agent/cert auth (BatchMode=yes).
         // Password/OTP can be supported by enabling a tightly-controlled SSH_ASKPASS flow,
         // but that is intentionally omitted from this minimal skeleton.
         if meta.auth_type == "password_totp" {
             warn!("credential auth_type=password_totp is not supported in this skeleton (BatchMode=yes)");
         }
 
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
 
         cm.open().await.map_err(to_status)?;
 
         self.sessions.insert(session_id.clone(), cm).await;
         info!(%session_id, "opened session");
 
         Ok(Response::new(OpenSessionResponse { session_id }))
     }
 
     async fn exec(&self, request: Request<ExecRequest>) -> Result<Response<ExecResponse>, Status> {
         let req = request.into_inner();
         let cm = self.sessions.require(&req.session_id).await.map_err(to_status)?;
         let timeout_ms = if req.timeout_ms == 0 {
             None
         } else {
             Some(req.timeout_ms as u64)
         };
 
        let out = cm.exec(&req.command, timeout_ms).await.map_err(to_status)?;
        info!(session_id = %req.session_id, "exec");
 
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
        let mut inbound = request.into_inner();
        let sessions = self.sessions.clone();

        let (tx, rx) = mpsc::channel::<Result<ShellServerMsg, Status>>(32);

        tokio::spawn(async move {
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

            let mut stdin = child.stdin.take();
            let mut stdout = child.stdout.take();
            let mut stderr = child.stderr.take();

            // stdout reader
            if let Some(mut out) = stdout.take() {
                let tx2 = tx.clone();
                tokio::spawn(async move {
                    let mut buf = vec![0u8; 16 * 1024];
                    loop {
                        match tokio::io::AsyncReadExt::read(&mut out, &mut buf).await {
                            Ok(0) => break,
                            Ok(n) => {
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
                tokio::spawn(async move {
                    let mut buf = vec![0u8; 16 * 1024];
                    loop {
                        match tokio::io::AsyncReadExt::read(&mut err, &mut buf).await {
                            Ok(0) => break,
                            Ok(n) => {
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

            let exit = match child.wait().await {
                Ok(s) => s.code().unwrap_or(-1),
                Err(_) => -1,
            };

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

        Ok(Response::new(ScpUploadResponse {
            bytes_written: total,
        }))
    }

    type ScpDownloadStream = ReceiverStream<Result<ScpDownloadResponse, Status>>;

    async fn scp_download(
        &self,
        request: Request<ScpDownloadRequest>,
    ) -> Result<Response<Self::ScpDownloadStream>, Status> {
        let req = request.into_inner();
        let cm = self.sessions.require(&req.session_id).await.map_err(to_status)?;
        let tmp_path = self
            .sessions
            .runtime_dir()
            .join(format!("download_{}_tmp", ids::new_session_id()));

        cm.scp_download(&req.remote_path, &tmp_path).await.map_err(to_status)?;

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
        Ok(Response::new(ReceiverStream::new(rx)))
    }

    async fn start_forward(
        &self,
        request: Request<StartForwardRequest>,
    ) -> Result<Response<StartForwardResponse>, Status> {
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
        Ok(Response::new(StartForwardResponse { forward_id }))
    }

    async fn stop_forward(
        &self,
        request: Request<StopForwardRequest>,
    ) -> Result<Response<StopForwardResponse>, Status> {
        let req = request.into_inner();
        self.sessions
            .stop_forward(&req.session_id, &req.forward_id)
            .await
            .map_err(to_status)?;
        info!(session_id = %req.session_id, forward_id = %req.forward_id, "stop forward");
        Ok(Response::new(StopForwardResponse {}))
    }
 
     async fn close_session(
         &self,
         request: Request<CloseSessionRequest>,
     ) -> Result<Response<CloseSessionResponse>, Status> {
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
         Ok(Response::new(CloseSessionResponse {}))
     }
 }
 
 fn to_status<E: std::fmt::Display>(e: E) -> Status {
     Status::internal(e.to_string())
 }

fn shell_quote(s: &str) -> String {
    // Minimal, conservative quoting for remote POSIX shell.
    // This is not perfect for every remote shell, but avoids obvious injection.
    format!("'{}'", s.replace('\'', r#"'\''"#))
}
