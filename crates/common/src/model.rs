 use serde::{Deserialize, Serialize};
 
 #[derive(Debug, Clone, Serialize, Deserialize)]
 pub struct CredentialMeta {
     pub credential_id: String,
     pub label: String,
     pub username: String,
     pub auth_type: String,
     pub allowed_hosts: Vec<String>,
    /// Optional username allowlist. If empty, only `username` is allowed.
    pub allowed_usernames: Vec<String>,
 }
