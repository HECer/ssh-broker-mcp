# ssh-broker-mcp (Rust) — SSH broker + MCP adapter (zero-knowledge credentials)

This repo is a **clean skeleton** for the architecture you described:

- The **MCP server / AI never sees credentials** (no passwords, no private keys, no TOTP seeds).
- The system still provides **full SSH functionality** by exposing **session handles** (opaque IDs) over gRPC.
- Credential management supports **add (out-of-band)** and **delete**; there is **no view/edit** API for secrets.

## Architecture / components

- `ssh-broker` (trusted): gRPC server that opens SSH sessions using **system OpenSSH**.
- `ssh-broker-enroll` (trusted, local-only): CLI that writes credential metadata to SQLite and secrets to the OS keyring.
- `ssh-broker-mcp` (untrusted): MCP stdio adapter that talks to `ssh-broker` via gRPC.
  - Untrusted callers (MCP tools, LLMs, etc.) only interact with `ssh-broker` over gRPC and can only reference `credential_id`.

## Threat model / guarantees

- **Guaranteed by construction**: no gRPC method returns secret material (there is no “get password/key” method in the proto).
- **Password/OTP requires a trusted component**: if you want headless auth, the broker host must hold/derive the secret (e.g., stored in OS keyring), or you need an interactive user prompt.
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

## UI (separate service)

This repo includes a **separate UI service** (clean separation from the broker):
- `ssh-broker-ui` (Rust/axum): serves HTTP and talks to `ssh-broker` over gRPC (UDS locally or TCP+mTLS remotely).
- `ui-web` (React/Vite): frontend that calls the UI service `/api/*`.

### Run UI locally (no auth)
1) Start broker:
```bash
cargo run -p ssh-broker -- --listen-uds ./run/ssh-broker.sock
```

2) Build UI:
```bash
cd ui-web
npm install
npm run build
```

3) Start UI service:
```bash
cargo run -p ssh-broker-ui -- \
  --broker-uds ./run/ssh-broker.sock \
  --http-addr 127.0.0.1:8080 \
  --static-dir ui-web/dist \
  --auth-mode none
```

### OIDC/SSO (UI service)
Set:
- `SSH_BROKER_UI_AUTH_MODE=oidc`
- `SSH_BROKER_UI_COOKIE_KEY_B64` (generate: `openssl rand -base64 64`)
- `SSH_BROKER_UI_OIDC_ISSUER`
- `SSH_BROKER_UI_OIDC_CLIENT_ID`
- `SSH_BROKER_UI_OIDC_CLIENT_SECRET`
- `SSH_BROKER_UI_OIDC_REDIRECT_URL` (must end with `/auth/callback`)

## How sessions work (OpenSSH ControlMaster)

- `OpenSession` starts an OpenSSH **ControlMaster** connection (multiplexing socket).
- `Exec` runs commands via that control socket (fast, avoids re-auth each time).
- `CloseSession` sends `ssh -O exit` and removes the socket.

The broker runs OpenSSH with `BatchMode=yes` for key/cert/agent auth:
- Works well with keys / agent / certs.
- For `auth_type=password_totp`, the broker uses a controlled `SSH_ASKPASS` flow (**Unix-only for now**). Secrets are stored locally by `ssh-broker-enroll` in the OS keyring and are never returned over gRPC.

## Production hardening (implemented)

### Policy
- `allowed_hosts` supports **exact**, **glob** (e.g. `*.example.com`), and **CIDR** (e.g. `10.0.0.0/8`) entries.
- Optional username allowlist via `allowed_usernames` (if empty, only the default username is allowed).

### Limits + rate limiting
The broker enforces limits by default; you can tune them via env vars:
- `SSH_BROKER_MAX_RPM` (0 disables)
- `SSH_BROKER_MAX_EXEC_BYTES`
- `SSH_BROKER_MAX_SHELL_BYTES`
- `SSH_BROKER_MAX_SHELL_SECONDS`
- `SSH_BROKER_MAX_SCP_BYTES`

### Audit logging
Audit events are written as JSONL to `<runtime_dir>/audit.jsonl` by default:
- `SSH_BROKER_AUDIT_PATH`
- `SSH_BROKER_AUDIT_LOG_COMMANDS` (off by default; enabling may capture secrets if you run commands containing secrets)

### Notes on password / OTP
This project is production-oriented toward **SSH keys / ssh-agent / SSH certificates**. Password/OTP is supported via `auth_type=password_totp`, but remains an explicit opt-in.
