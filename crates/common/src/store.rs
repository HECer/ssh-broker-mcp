 use crate::model::CredentialMeta;
 use anyhow::{Context, Result};
 use keyring::Entry;
 use sqlx::{sqlite::SqlitePoolOptions, SqlitePool};
 
 /// Stores non-sensitive metadata in SQLite and secrets in the OS keyring.
 #[derive(Clone)]
 pub struct CredentialStore {
     pool: SqlitePool,
     keyring_service: String,
 }
 
 impl CredentialStore {
     pub async fn open(sqlite_path: &str, keyring_service: &str) -> Result<Self> {
         let pool = SqlitePoolOptions::new()
             .max_connections(5)
             .connect(sqlite_path)
             .await
             .with_context(|| format!("connect sqlite: {sqlite_path}"))?;
 
        // Basic schema. We use simple, best-effort migrations to keep the skeleton lightweight.
        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS credentials (
              credential_id     TEXT PRIMARY KEY,
              label             TEXT NOT NULL,
              username          TEXT NOT NULL,
              auth_type         TEXT NOT NULL,
              allowed_hosts     TEXT NOT NULL,
              allowed_usernames TEXT NOT NULL DEFAULT '[]'
            );
            "#,
        )
        .execute(&pool)
        .await?;

        // Best-effort migration for older DBs that don't have allowed_usernames.
        let _ = sqlx::query(
            r#"ALTER TABLE credentials ADD COLUMN allowed_usernames TEXT NOT NULL DEFAULT '[]';"#,
        )
        .execute(&pool)
        .await;
 
         Ok(Self {
             pool,
             keyring_service: keyring_service.to_string(),
         })
     }
 
     pub async fn upsert_meta(&self, meta: &CredentialMeta) -> Result<()> {
         let allowed_hosts = serde_json::to_string(&meta.allowed_hosts)?;
        let allowed_usernames = serde_json::to_string(&meta.allowed_usernames)?;
         sqlx::query(
             r#"
            INSERT INTO credentials (credential_id, label, username, auth_type, allowed_hosts, allowed_usernames)
            VALUES (?1, ?2, ?3, ?4, ?5, ?6)
             ON CONFLICT(credential_id) DO UPDATE SET
               label=excluded.label,
               username=excluded.username,
               auth_type=excluded.auth_type,
              allowed_hosts=excluded.allowed_hosts,
              allowed_usernames=excluded.allowed_usernames;
             "#,
         )
         .bind(&meta.credential_id)
         .bind(&meta.label)
         .bind(&meta.username)
         .bind(&meta.auth_type)
         .bind(&allowed_hosts)
        .bind(&allowed_usernames)
         .execute(&self.pool)
         .await?;
         Ok(())
     }
 
     pub async fn list_meta(&self) -> Result<Vec<CredentialMeta>> {
         let rows = sqlx::query!(
             r#"
            SELECT credential_id, label, username, auth_type, allowed_hosts, allowed_usernames
             FROM credentials
             ORDER BY label ASC;
             "#
         )
         .fetch_all(&self.pool)
         .await?;
 
         let mut out = Vec::with_capacity(rows.len());
         for r in rows {
             let allowed_hosts: Vec<String> = serde_json::from_str(&r.allowed_hosts)?;
            let allowed_usernames: Vec<String> =
                serde_json::from_str(&r.allowed_usernames).unwrap_or_default();
             out.push(CredentialMeta {
                 credential_id: r.credential_id,
                 label: r.label,
                 username: r.username,
                 auth_type: r.auth_type,
                 allowed_hosts,
                allowed_usernames,
             });
         }
         Ok(out)
     }
 
     pub async fn get_meta(&self, credential_id: &str) -> Result<Option<CredentialMeta>> {
         let row = sqlx::query!(
             r#"
            SELECT credential_id, label, username, auth_type, allowed_hosts, allowed_usernames
             FROM credentials
             WHERE credential_id = ?1;
             "#,
             credential_id
         )
         .fetch_optional(&self.pool)
         .await?;
 
         Ok(row.map(|r| CredentialMeta {
             credential_id: r.credential_id,
             label: r.label,
             username: r.username,
             auth_type: r.auth_type,
             allowed_hosts: serde_json::from_str(&r.allowed_hosts).unwrap_or_default(),
            allowed_usernames: serde_json::from_str(&r.allowed_usernames).unwrap_or_default(),
         }))
     }
 
     pub async fn delete(&self, credential_id: &str) -> Result<()> {
         sqlx::query!("DELETE FROM credentials WHERE credential_id = ?1;", credential_id)
             .execute(&self.pool)
             .await?;
 
         // Best-effort: secret may or may not exist.
         let _ = self.keyring_entry(credential_id).delete_password();
         Ok(())
     }
 
     /// Stores secret material in the OS keyring (write-only from the broker's perspective).
     /// The broker itself never exposes this over RPC.
     pub fn set_secret(&self, credential_id: &str, secret: &str) -> Result<()> {
         self.keyring_entry(credential_id)
             .set_password(secret)
             .context("set keyring secret")?;
         Ok(())
     }
 
     pub fn get_secret(&self, credential_id: &str) -> Result<Option<String>> {
         match self.keyring_entry(credential_id).get_password() {
             Ok(s) => Ok(Some(s)),
             Err(keyring::Error::NoEntry) => Ok(None),
             Err(e) => Err(e).context("get keyring secret"),
         }
     }
 
     fn keyring_entry(&self, credential_id: &str) -> Entry {
         Entry::new(&self.keyring_service, credential_id)
             .expect("keyring entry should be constructible")
     }
 }
