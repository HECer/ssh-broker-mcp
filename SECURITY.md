 # Security Policy
 
 ## Threat model (high level)
 - The **AI / MCP layer is untrusted** and must never receive secret material (passwords, private keys, TOTP seeds).
 - `ssh-broker` is the **trusted boundary** that may access secrets (directly or via OS keychain/Vault/hardware).
 
 ## Reporting a vulnerability
 Please open a GitHub issue with the label `security` and avoid posting secret material.
 
 ## Operational recommendations
 - Prefer **SSH keys / ssh-agent / SSH certificates** over password/OTP for production automation.
 - Use **mTLS** if exposing the broker over TCP.
 - Keep a strict **host allowlist** and **host key pinning** (`known_hosts`) enabled.
 - Enable auditing and avoid logging command arguments if they can contain secrets.
