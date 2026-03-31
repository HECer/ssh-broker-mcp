 use anyhow::{anyhow, Result};
 use clap::Parser;
 use futures_util::StreamExt;
 use serde::{Deserialize, Serialize};
 use serde_json::json;
 use ssh_broker_proto::sshbroker::v1::{
     credential_service_client::CredentialServiceClient, session_service_client::SessionServiceClient,
     DeleteCredentialRequest, ExecRequest, OpenSessionRequest, ScpDownloadRequest, StartForwardRequest,
     StopForwardRequest,
 };
 use std::io::Write;
 use tokio::io::{AsyncBufReadExt, BufReader};
 use tonic::transport::{Channel, Endpoint};
 use tracing::info;
 
 /// Minimal MCP stdio adapter for ssh-broker.
 ///
 /// Implements a small subset of the MCP JSON-RPC surface:
 /// - initialize
 /// - tools/list
 /// - tools/call
 ///
 /// This is designed to keep secrets out of the AI/MCP layer: the adapter only calls the broker via gRPC.
 #[derive(Debug, Parser)]
 struct Args {
     /// Broker address, e.g. http://127.0.0.1:7443
     #[arg(long, env = "SSH_BROKER_ADDR", default_value = "http://127.0.0.1:7443")]
     broker_addr: String,
 
     #[arg(long, env = "RUST_LOG", default_value = "info")]
     log_filter: String,
 }
 
 #[derive(Debug, Deserialize)]
 struct JsonRpcReq {
     jsonrpc: Option<String>,
     id: serde_json::Value,
     method: String,
     #[serde(default)]
     params: serde_json::Value,
 }
 
 #[derive(Debug, Serialize)]
 struct JsonRpcResp {
     jsonrpc: &'static str,
     id: serde_json::Value,
     #[serde(skip_serializing_if = "Option::is_none")]
     result: Option<serde_json::Value>,
     #[serde(skip_serializing_if = "Option::is_none")]
     error: Option<JsonRpcErr>,
 }
 
 #[derive(Debug, Serialize)]
 struct JsonRpcErr {
     code: i64,
     message: String,
 }
 
 #[tokio::main]
 async fn main() -> Result<()> {
     let args = Args::parse();
     tracing_subscriber::fmt()
         .with_env_filter(args.log_filter.clone())
         .init();
 
     let endpoint = Endpoint::try_from(args.broker_addr.clone())?;
     let channel = endpoint.connect().await?;
     let cred_client = CredentialServiceClient::new(channel.clone());
     let sess_client = SessionServiceClient::new(channel);
 
     run_stdio(cred_client, sess_client).await
 }
 
 async fn run_stdio(
     mut cred: CredentialServiceClient<Channel>,
     mut sess: SessionServiceClient<Channel>,
 ) -> Result<()> {
     let stdin = tokio::io::stdin();
     let mut lines = BufReader::new(stdin).lines();
 
     while let Some(line) = lines.next_line().await? {
         if line.trim().is_empty() {
             continue;
         }
         let req: JsonRpcReq = match serde_json::from_str(&line) {
             Ok(v) => v,
             Err(e) => {
                 write_resp(JsonRpcResp {
                     jsonrpc: "2.0",
                     id: serde_json::Value::Null,
                     result: None,
                     error: Some(JsonRpcErr {
                         code: -32700,
                         message: format!("parse error: {e}"),
                     }),
                 })?;
                 continue;
             }
         };
 
         let resp = handle_req(&mut cred, &mut sess, req).await;
         write_resp(resp)?;
     }
 
     Ok(())
 }
 
 async fn handle_req(
     cred: &mut CredentialServiceClient<Channel>,
     sess: &mut SessionServiceClient<Channel>,
     req: JsonRpcReq,
 ) -> JsonRpcResp {
     match req.method.as_str() {
         "initialize" => ok(req.id, json!({ "serverInfo": { "name": "ssh-broker-mcp", "version": "0.1.0" } })),
         "tools/list" => ok(req.id, tools_list()),
         "tools/call" => match tools_call(cred, sess, req.params).await {
             Ok(v) => ok(req.id, v),
             Err(e) => err(req.id, -32000, e.to_string()),
         },
         other => err(req.id, -32601, format!("method not found: {other}")),
     }
 }
 
 fn tools_list() -> serde_json::Value {
     // Minimal tool surface; extend as needed.
     json!({
       "tools": [
         { "name": "list_credentials", "description": "List credential metadata (no secrets).", "inputSchema": { "type": "object", "properties": {} } },
         { "name": "delete_credential", "description": "Delete a credential by id.", "inputSchema": { "type": "object", "properties": { "credential_id": { "type": "string" } }, "required": ["credential_id"] } },
         { "name": "open_session", "description": "Open an SSH session by credential id + host.", "inputSchema": { "type": "object", "properties": { "credential_id": {"type":"string"}, "host":{"type":"string"}, "port":{"type":"integer"} }, "required":["credential_id","host"] } },
         { "name": "exec", "description": "Execute a command in an SSH session.", "inputSchema": { "type": "object", "properties": { "session_id":{"type":"string"}, "command":{"type":"string"}, "timeout_ms":{"type":"integer"} }, "required":["session_id","command"] } },
         { "name": "close_session", "description": "Close an SSH session.", "inputSchema": { "type": "object", "properties": { "session_id":{"type":"string"} }, "required":["session_id"] } },
         { "name": "scp_download", "description": "Download a remote file (base64 chunks).", "inputSchema": { "type": "object", "properties": { "session_id":{"type":"string"}, "remote_path":{"type":"string"} }, "required":["session_id","remote_path"] } },
         { "name": "start_forward", "description": "Start port forwarding.", "inputSchema": { "type": "object", "properties": { "session_id":{"type":"string"}, "forward_type":{"type":"integer"}, "bind_addr":{"type":"string"}, "bind_port":{"type":"integer"}, "target_host":{"type":"string"}, "target_port":{"type":"integer"} }, "required":["session_id","forward_type","bind_port"] } },
         { "name": "stop_forward", "description": "Stop port forwarding.", "inputSchema": { "type": "object", "properties": { "session_id":{"type":"string"}, "forward_id":{"type":"string"} }, "required":["session_id","forward_id"] } }
       ]
     })
 }
 
 async fn tools_call(
     cred: &mut CredentialServiceClient<Channel>,
     sess: &mut SessionServiceClient<Channel>,
     params: serde_json::Value,
 ) -> Result<serde_json::Value> {
     let tool = params
         .get("name")
         .and_then(|v| v.as_str())
         .ok_or_else(|| anyhow!("missing params.name"))?;
     let args = params.get("arguments").cloned().unwrap_or_else(|| json!({}));
 
     match tool {
         "list_credentials" => {
            let resp = cred
                .list_credentials(ssh_broker_proto::sshbroker::v1::ListCredentialsRequest {})
                .await?
                .into_inner();
             Ok(json!({ "credentials": resp.credentials }))
         }
         "delete_credential" => {
             let credential_id = args
                 .get("credential_id")
                 .and_then(|v| v.as_str())
                 .ok_or_else(|| anyhow!("missing credential_id"))?;
             cred.delete_credential(DeleteCredentialRequest {
                 credential_id: credential_id.to_string(),
             })
             .await?;
             Ok(json!({ "ok": true }))
         }
         "open_session" => {
             let credential_id = args
                 .get("credential_id")
                 .and_then(|v| v.as_str())
                 .ok_or_else(|| anyhow!("missing credential_id"))?;
             let host = args
                 .get("host")
                 .and_then(|v| v.as_str())
                 .ok_or_else(|| anyhow!("missing host"))?;
             let port = args.get("port").and_then(|v| v.as_u64()).unwrap_or(22);
             let resp = sess
                 .open_session(OpenSessionRequest {
                     credential_id: credential_id.to_string(),
                     host: host.to_string(),
                     port: port as u32,
                     username_override: "".to_string(),
                 })
                 .await?
                 .into_inner();
             Ok(json!({ "session_id": resp.session_id }))
         }
         "exec" => {
             let session_id = args
                 .get("session_id")
                 .and_then(|v| v.as_str())
                 .ok_or_else(|| anyhow!("missing session_id"))?;
             let command = args
                 .get("command")
                 .and_then(|v| v.as_str())
                 .ok_or_else(|| anyhow!("missing command"))?;
             let timeout_ms = args.get("timeout_ms").and_then(|v| v.as_u64()).unwrap_or(0);
             let resp = sess
                 .exec(ExecRequest {
                     session_id: session_id.to_string(),
                     command: command.to_string(),
                     timeout_ms: timeout_ms as u32,
                 })
                 .await?
                 .into_inner();
             Ok(json!({
               "exit_code": resp.exit_code,
               "stdout_b64": base64::encode(resp.stdout),
               "stderr_b64": base64::encode(resp.stderr)
             }))
         }
         "close_session" => {
             let session_id = args
                 .get("session_id")
                 .and_then(|v| v.as_str())
                 .ok_or_else(|| anyhow!("missing session_id"))?;
             sess.close_session(ssh_broker_proto::sshbroker::v1::CloseSessionRequest {
                 session_id: session_id.to_string(),
             })
             .await?;
             Ok(json!({ "ok": true }))
         }
         "scp_download" => {
             let session_id = args
                 .get("session_id")
                 .and_then(|v| v.as_str())
                 .ok_or_else(|| anyhow!("missing session_id"))?;
             let remote_path = args
                 .get("remote_path")
                 .and_then(|v| v.as_str())
                 .ok_or_else(|| anyhow!("missing remote_path"))?;
 
             let mut stream = sess
                 .scp_download(ScpDownloadRequest {
                     session_id: session_id.to_string(),
                     remote_path: remote_path.to_string(),
                 })
                 .await?
                 .into_inner();
 
             // Return all chunks in one response for simplicity (caller should keep files small).
             // For large files, extend MCP tool surface to stream artifacts.
             let mut chunks: Vec<String> = Vec::new();
             while let Some(msg) = stream.next().await {
                 let msg = msg?;
                 chunks.push(base64::encode(msg.data));
             }
             Ok(json!({ "chunks_b64": chunks }))
         }
         "start_forward" => {
             let session_id = args
                 .get("session_id")
                 .and_then(|v| v.as_str())
                 .ok_or_else(|| anyhow!("missing session_id"))?;
             let forward_type = args
                 .get("forward_type")
                 .and_then(|v| v.as_u64())
                 .ok_or_else(|| anyhow!("missing forward_type"))?;
             let bind_addr = args.get("bind_addr").and_then(|v| v.as_str()).unwrap_or("").to_string();
             let bind_port = args.get("bind_port").and_then(|v| v.as_u64()).ok_or_else(|| anyhow!("missing bind_port"))?;
             let target_host = args.get("target_host").and_then(|v| v.as_str()).unwrap_or("").to_string();
             let target_port = args.get("target_port").and_then(|v| v.as_u64()).unwrap_or(0);
             let resp = sess
                 .start_forward(StartForwardRequest {
                     session_id: session_id.to_string(),
                     forward_type: forward_type as i32,
                     bind_addr,
                     bind_port: bind_port as u32,
                     target_host,
                     target_port: target_port as u32,
                 })
                 .await?
                 .into_inner();
             Ok(json!({ "forward_id": resp.forward_id }))
         }
         "stop_forward" => {
             let session_id = args
                 .get("session_id")
                 .and_then(|v| v.as_str())
                 .ok_or_else(|| anyhow!("missing session_id"))?;
             let forward_id = args
                 .get("forward_id")
                 .and_then(|v| v.as_str())
                 .ok_or_else(|| anyhow!("missing forward_id"))?;
             sess.stop_forward(StopForwardRequest {
                 session_id: session_id.to_string(),
                 forward_id: forward_id.to_string(),
             })
             .await?;
             Ok(json!({ "ok": true }))
         }
         other => Err(anyhow!("unknown tool: {other}")),
     }
 }
 
 fn ok(id: serde_json::Value, result: serde_json::Value) -> JsonRpcResp {
     JsonRpcResp {
         jsonrpc: "2.0",
         id,
         result: Some(result),
         error: None,
     }
 }
 
 fn err(id: serde_json::Value, code: i64, message: String) -> JsonRpcResp {
     JsonRpcResp {
         jsonrpc: "2.0",
         id,
         result: None,
         error: Some(JsonRpcErr { code, message }),
     }
 }
 
 fn write_resp(resp: JsonRpcResp) -> Result<()> {
     let s = serde_json::to_string(&resp)?;
     let mut stdout = std::io::stdout().lock();
     stdout.write_all(s.as_bytes())?;
     stdout.write_all(b"\n")?;
     stdout.flush()?;
     Ok(())
 }
