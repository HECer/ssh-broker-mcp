 use anyhow::{anyhow, Result};
 use clap::{Parser, Subcommand};
 use serde_json::json;
 use ssh_broker_common::{ids, model::CredentialMeta, store::CredentialStore};
 use tracing::info;
 
 #[derive(Debug, Parser)]
 #[command(name = "ssh-broker-enroll", about = "Local enrollment CLI for ssh-broker (writes secrets locally; never over RPC)")]
 struct Cli {
     #[arg(long, env = "SSH_BROKER_SQLITE_URL", default_value = "sqlite:ssh-broker.db")]
     sqlite_url: String,
 
     #[arg(long, env = "SSH_BROKER_KEYRING_SERVICE", default_value = "ssh-broker")]
     keyring_service: String,
 
     #[command(subcommand)]
     cmd: Command,
 }
 
 #[derive(Debug, Subcommand)]
 enum Command {
     Add {
         #[arg(long)]
         label: String,
 
         #[arg(long)]
         username: String,
 
         /// ssh_key | password_totp | ssh_cert
         #[arg(long, default_value = "ssh_key")]
         auth_type: String,
 
         /// Repeatable; if empty, broker will refuse to connect.
         #[arg(long = "allowed-host")]
         allowed_hosts: Vec<String>,
 
        /// Repeatable; if empty, only `--username` is allowed.
        #[arg(long = "allowed-username")]
        allowed_usernames: Vec<String>,

         /// Optional: supply your own credential_id.
         #[arg(long)]
         credential_id: Option<String>,
     },
     Delete {
         #[arg(long)]
         credential_id: String,
     },
     List,

    /// Adds the SSH host key for a host to the broker-managed known_hosts file.
    /// This supports strict host key checking (recommended for production).
    HostkeyAdd {
        #[arg(long)]
        host: String,
        #[arg(long, default_value_t = 22)]
        port: u16,
        /// Path to the known_hosts file. Defaults to ./run/known_hosts
        #[arg(long, default_value = "./run/known_hosts")]
        known_hosts_path: String,
    },
 }
 
 #[tokio::main]
 async fn main() -> Result<()> {
     tracing_subscriber::fmt().with_env_filter("info").init();
 
     let cli = Cli::parse();
     let store = CredentialStore::open(&cli.sqlite_url, &cli.keyring_service).await?;
 
     match cli.cmd {
         Command::Add {
             label,
             username,
             auth_type,
             allowed_hosts,
            allowed_usernames,
             credential_id,
         } => {
             let credential_id = credential_id.unwrap_or_else(ids::new_credential_id);
 
             let meta = CredentialMeta {
                 credential_id: credential_id.clone(),
                 label,
                 username,
                 auth_type: auth_type.clone(),
                 allowed_hosts,
                allowed_usernames,
             };
 
             // Secrets are stored ONLY when needed.
             match auth_type.as_str() {
                 "ssh_key" | "ssh_cert" => {}
                 "password_totp" => {
                     let password = rpassword::prompt_password("SSH password: ")?;
                     let totp_seed =
                         rpassword::prompt_password("TOTP seed (base32) (optional): ")?;
 
                     // Store as JSON so the broker can evolve formats without schema changes.
                     let secret = json!({
                         "password": password,
                         "totp_seed": totp_seed,
                     })
                     .to_string();
 
                     store.set_secret(&credential_id, &secret)?;
                 }
                 other => return Err(anyhow!("unknown auth_type: {other}")),
             }
 
             store.upsert_meta(&meta).await?;
             info!("credential_id={credential_id}");
         }
         Command::Delete { credential_id } => {
             store.delete(&credential_id).await?;
             info!("deleted credential_id={credential_id}");
         }
         Command::List => {
             let list = store.list_meta().await?;
             println!("{}", serde_json::to_string_pretty(&list)?);
         }
        Command::HostkeyAdd {
            host,
            port,
            known_hosts_path,
        } => {
            tokio::fs::create_dir_all(
                std::path::Path::new(&known_hosts_path)
                    .parent()
                    .unwrap_or(std::path::Path::new(".")),
            )
            .await?;

            // Use ssh-keyscan to fetch host keys and append to known_hosts.
            // Note: ssh-keyscan availability varies by platform; if absent, instruct user to add manually.
            let output = tokio::process::Command::new("ssh-keyscan")
                .arg("-p")
                .arg(port.to_string())
                .arg("-T")
                .arg("5")
                .arg(&host)
                .output()
                .await;

            let out = match output {
                Ok(o) if o.status.success() => o.stdout,
                Ok(o) => {
                    return Err(anyhow!(
                        "ssh-keyscan failed: status={:?}, stderr={}",
                        o.status.code(),
                        String::from_utf8_lossy(&o.stderr)
                    ))
                }
                Err(e) => {
                    return Err(anyhow!(
                        "failed to run ssh-keyscan ({e}). Install OpenSSH tools or add the host key manually to {known_hosts_path}."
                    ))
                }
            };

            use tokio::io::AsyncWriteExt;
            let mut f = tokio::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(&known_hosts_path)
                .await?;
            f.write_all(&out).await?;
            f.write_all(b"\n").await?;

            info!("added host key for {host}:{port} -> {known_hosts_path}");
        }
     }
 
     Ok(())
 }
