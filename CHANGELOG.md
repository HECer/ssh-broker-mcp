# Changelog

All notable changes to this project will be documented in this file.

## Unreleased
- (none)

## 0.3.0
- Add password+OTP support (`auth_type=password_totp`) via controlled `SSH_ASKPASS` flow (Unix-only currently).
- Add separate UI service crate (`ssh-broker-ui`) and a minimal React frontend (`ui-web`).

## 0.2.1
- Production hardening: host allowlist policy (exact/glob/CIDR).
- Production hardening: per-peer rate limiting and output/transfer limits.
- Production hardening: structured JSONL audit logging (with optional command logging).

## 0.2.0
- Shell streaming, SCP, and port forwarding RPCs.
- Username allowlisting and strict host-key checking support.
- MCP stdio adapter (`ssh-broker-mcp`).

## 0.1.0
- Initial public scaffold (gRPC broker + local enrollment CLI).
