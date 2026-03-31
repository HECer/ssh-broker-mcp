 # ssh-broker (Rust) — gRPC SSH Broker with credential zero-knowledge for MCP/AI
 
 This repo is a **clean skeleton** for the architecture you described:
 
 - The **MCP server / AI never sees credentials** (no passwords, no private keys, no TOTP seeds).
 - The system still provides **full SSH functionality** by exposing **session handles** (opaque IDs) over gRPC.
 - Credential management supports **add (out-of-band)** and **delete**; there is **no view/edit** API for secrets.
 
 ## Architecture
 
 - `ssh-broker` (trusted): gRPC server that opens SSH sessions using **system OpenSSH**.
 - `ssh-broker-enroll` (trusted, local-only): CLI that writes credential metadata to SQLite and secrets to the OS keyring.
 - Untrusted callers (MCP tools, LLMs, etc.) only interact with `ssh-broker` over gRPC and can only reference `credential_id`.
 
 ## Threat model / guarantees
 
 - **Guaranteed by construction**: no gRPC method returns secret material (there is no “get password/key” method in the proto).
 - **Not possible** with password/OTP: “nobody knows the password” headlessly. A trusted component (the broker machine) must have the secret.
 - Stronger option: use **ssh-agent / FIDO2 / TPM / SSH certificates** so secrets are non-exportable or short-lived.
 
 ## Local vs Remote
 
 ### Local mode (recommended)
- On Linux/macOS: gRPC over **Unix domain socket** with filesystem permissions (`0600`).
- On Windows: use **TCP loopback** (and preferably mTLS).
 
 Example:
 ```bash
 cargo run -p ssh-broker -- --listen-uds ./run/ssh-broker.sock
 ```
 
 ### Remote mode (optional)
 - gRPC over TCP with **mTLS** (recommended).
 
 Example:
 ```bash
 cargo run -p ssh-broker -- \
   --listen-tcp 0.0.0.0:7443 \
   --tls-cert ./tls/server.crt \
   --tls-key  ./tls/server.key \
   --tls-client-ca ./tls/client-ca.crt
 ```
 
 ## Credential enrollment (add/delete without exposing secrets)
 
 Add an SSH-key-based credential (no secret stored):
 ```bash
 cargo run -p ssh-broker-enroll -- add \
   --label prod \
   --username ubuntu \
   --auth-type ssh_key \
   --allowed-host my.vps.example.com
 ```
 
 List credentials (metadata only):
 ```bash
 cargo run -p ssh-broker-enroll -- list
 ```
 
 Delete (removes metadata + keyring secret):
 ```bash
 cargo run -p ssh-broker-enroll -- delete --credential-id cred_...
 ```
 
 ## Host key pinning (recommended for production)
 
 The broker uses **strict** host key checking by default (`StrictHostKeyChecking=yes`) and a broker-managed `known_hosts` file.
 
 Add a host key to the broker-known hosts:
 ```bash
 cargo run -p ssh-broker-enroll -- hostkey-add --host my.vps.example.com --port 22
 ```
 
 ## How sessions work (OpenSSH ControlMaster)
 
 - `OpenSession` starts an OpenSSH **ControlMaster** connection (multiplexing socket).
 - `Exec` runs commands via that control socket (fast, avoids re-auth each time).
 - `CloseSession` sends `ssh -O exit` and removes the socket.
 
 The broker runs OpenSSH with `BatchMode=yes` in this skeleton:
 - Works well with keys / agent / certs.
 - **Password/OTP is intentionally not implemented here**, because doing it safely requires a tightly controlled `SSH_ASKPASS` flow or equivalent. You can add it later as an explicit opt-in.
 
 ## Next steps to reach production
 
 - Add explicit **policy**: host allowlists by CIDR/pattern, username allowlists, rate limits.
 - Shell (`Shell`), SCP (`ScpUpload`/`ScpDownload`), and port forwarding (`StartForward`/`StopForward`) are implemented, but should be hardened with limits (max bytes, timeouts) for production.
 - Implement password/OTP auth safely (opt-in) OR migrate to keys/certs.
 - The MCP stdio adapter is available as `ssh-broker-mcp` (see `crates/mcp-adapter`), but you should review the exact MCP expectations of your client and extend the tool schemas as needed.
