 use uuid::Uuid;
 
 pub fn new_credential_id() -> String {
     format!("cred_{}", Uuid::now_v7().simple())
 }
 
 pub fn new_session_id() -> String {
     format!("sess_{}", Uuid::now_v7().simple())
 }
