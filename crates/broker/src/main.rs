 mod config;
 mod services;
 mod sessions;
 mod ssh;
 
 use anyhow::Result;
 use config::Config;
 use services::{CredentialSvc, SessionSvc};
 use sessions::SessionManager;
 use ssh_broker_common::store::CredentialStore;
 use ssh_broker_proto::sshbroker::v1::{
     credential_service_server::CredentialServiceServer,
     session_service_server::SessionServiceServer,
 };
use std::{net::SocketAddr, path::PathBuf};
 use tonic::transport::{Identity, Server, ServerTlsConfig};
 use tracing::{info, warn};
 
 #[tokio::main]
 async fn main() -> Result<()> {
     let cfg = Config::parse();
 
     tracing_subscriber::fmt()
         .with_env_filter(cfg.log_filter.clone())
         .init();
 
    let store = CredentialStore::open(&cfg.sqlite_url, &cfg.keyring_service).await?;
    let sessions = SessionManager::new(cfg.runtime_dir.clone());
    let known_hosts_path = cfg.known_hosts_path();
 
     let cred_svc = CredentialSvc::new(store.clone());
    let sess_svc = SessionSvc::new(store, sessions, known_hosts_path);
 
     // Local (UDS) listener (recommended default).
     if let Some(uds_path) = cfg.listen_uds.clone() {
        #[cfg(unix)]
        {
            serve_uds(uds_path, cred_svc.clone(), sess_svc.clone()).await?;
        }
        #[cfg(not(unix))]
        {
            warn!("UDS listener is not supported on this platform; use TCP + (m)TLS instead");
        }
     }
 
     // Optional remote listener.
     if let Some(addr) = cfg.listen_tcp {
         serve_tcp(addr, cfg, cred_svc, sess_svc).await?;
     } else {
         info!("No TCP listener configured (local-only mode).");
     }
 
     Ok(())
 }
 
#[cfg(unix)]
 async fn serve_uds(
     uds_path: PathBuf,
     cred_svc: CredentialSvc,
     sess_svc: SessionSvc,
 ) -> Result<()> {
    use tokio::net::UnixListener;
    use tokio_stream::wrappers::UnixListenerStream;

     if uds_path.exists() {
         warn!(path = %uds_path.display(), "UDS path exists; removing");
         tokio::fs::remove_file(&uds_path).await?;
     }
 
     if let Some(parent) = uds_path.parent() {
         tokio::fs::create_dir_all(parent).await?;
     }
 
     let listener = UnixListener::bind(&uds_path)?;
     // Restrict permissions (best effort).
     #[cfg(unix)]
     {
         use std::os::unix::fs::PermissionsExt;
         tokio::fs::set_permissions(&uds_path, std::fs::Permissions::from_mode(0o600)).await?;
     }
 
     info!(path = %uds_path.display(), "Serving gRPC over Unix socket");
 
     let incoming = UnixListenerStream::new(listener);
     Server::builder()
         .add_service(CredentialServiceServer::new(cred_svc))
         .add_service(SessionServiceServer::new(sess_svc))
         .serve_with_incoming(incoming)
         .await?;
     Ok(())
 }
 
 async fn serve_tcp(
     addr: SocketAddr,
     cfg: Config,
     cred_svc: CredentialSvc,
     sess_svc: SessionSvc,
 ) -> Result<()> {
     let mut builder = Server::builder();
 
     if cfg.tls_enabled() {
         let cert = tokio::fs::read(cfg.tls_cert_path.unwrap()).await?;
         let key = tokio::fs::read(cfg.tls_key_path.unwrap()).await?;
         let identity = Identity::from_pem(cert, key);
 
         let client_ca = tokio::fs::read(cfg.tls_client_ca_path.unwrap()).await?;
 
         let tls = ServerTlsConfig::new()
             .identity(identity)
             .client_ca_root(tonic::transport::Certificate::from_pem(client_ca));
 
         builder = builder.tls_config(tls)?;
         info!(%addr, "Serving gRPC over TCP with mTLS");
     } else {
         info!(%addr, "Serving gRPC over TCP WITHOUT TLS (not recommended)");
     }
 
     builder
         .add_service(CredentialServiceServer::new(cred_svc))
         .add_service(SessionServiceServer::new(sess_svc))
         .serve(addr)
         .await?;
 
     Ok(())
 }
