 use clap::Parser;
 use std::{net::SocketAddr, path::PathBuf};
 
 #[derive(Debug, Clone, Parser)]
 #[command(name = "ssh-broker", about = "SSH Broker gRPC service (secrets never returned over RPC)")]
 pub struct Config {
     /// SQLite connection string (e.g. sqlite:/var/lib/ssh-broker/creds.db)
     #[arg(long, env = "SSH_BROKER_SQLITE_URL", default_value = "sqlite:ssh-broker.db")]
     pub sqlite_url: String,
 
     /// Keyring service name under which secrets will be stored.
     #[arg(long, env = "SSH_BROKER_KEYRING_SERVICE", default_value = "ssh-broker")]
     pub keyring_service: String,
 
     /// Runtime directory for ephemeral session state (ControlMaster sockets, logs, etc.)
     #[arg(long, env = "SSH_BROKER_RUNTIME_DIR", default_value = "./run")]
     pub runtime_dir: PathBuf,
 
    /// Path to known_hosts file used by the broker. Defaults to <runtime_dir>/known_hosts.
    #[arg(long, env = "SSH_BROKER_KNOWN_HOSTS")]
    pub known_hosts_path: Option<PathBuf>,

     /// Serve gRPC over a Unix domain socket (recommended for local mode).
     #[arg(long, env = "SSH_BROKER_LISTEN_UDS")]
     pub listen_uds: Option<PathBuf>,
 
     /// Serve gRPC over TCP (optional, for remote mode).
     #[arg(long, env = "SSH_BROKER_LISTEN_TCP")]
     pub listen_tcp: Option<SocketAddr>,
 
     /// Enable TLS/mTLS for TCP listener by providing server certificate (PEM).
     #[arg(long, env = "SSH_BROKER_TLS_CERT")]
     pub tls_cert_path: Option<PathBuf>,
 
     /// TLS private key (PEM).
     #[arg(long, env = "SSH_BROKER_TLS_KEY")]
     pub tls_key_path: Option<PathBuf>,
 
     /// Client CA root (PEM). If set, client certs are required (mTLS).
     #[arg(long, env = "SSH_BROKER_TLS_CLIENT_CA")]
     pub tls_client_ca_path: Option<PathBuf>,
 
     /// tracing-subscriber env filter.
     #[arg(long, env = "RUST_LOG", default_value = "info")]
     pub log_filter: String,
 }
 
 impl Config {
     pub fn parse() -> Self {
         <Self as Parser>::parse()
     }
 
     pub fn tls_enabled(&self) -> bool {
         self.tls_cert_path.is_some() && self.tls_key_path.is_some() && self.tls_client_ca_path.is_some()
     }

     pub fn known_hosts_path(&self) -> PathBuf {
         self.known_hosts_path
             .clone()
             .unwrap_or_else(|| self.runtime_dir.join("known_hosts"))
     }
 }
