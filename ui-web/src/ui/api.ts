export type Credential = {
  credentialId: string;
  label: string;
  username: string;
  authType: string;
  allowedHosts: string[];
  allowedUsernames: string[];
};

function toCredential(x: any): Credential {
  return {
    credentialId: x.credentialId ?? x.credential_id,
    label: x.label,
    username: x.username,
    authType: x.authType ?? x.auth_type,
    allowedHosts: x.allowedHosts ?? x.allowed_hosts ?? [],
    allowedUsernames: x.allowedUsernames ?? x.allowed_usernames ?? []
  };
}

export async function listCredentials(): Promise<Credential[]> {
  const r = await fetch("/api/credentials");
  if (!r.ok) throw new Error(`list_credentials failed: ${r.status}`);
  const j = await r.json();
  return (j.credentials ?? []).map(toCredential);
}

export async function deleteCredential(id: string): Promise<void> {
  const r = await fetch(`/api/credentials/${encodeURIComponent(id)}`, { method: "DELETE" });
  if (!r.ok) throw new Error(`delete_credential failed: ${r.status}`);
}

export async function openSession(input: { credentialId: string; host: string; port?: number; usernameOverride?: string }): Promise<string> {
  const r = await fetch("/api/sessions/open", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      credential_id: input.credentialId,
      host: input.host,
      port: input.port ?? 22,
      username_override: input.usernameOverride ?? ""
    })
  });
  if (!r.ok) throw new Error(`open_session failed: ${r.status}`);
  const j = await r.json();
  return j.session_id;
}

function b64ToUtf8(b64: string): string {
  const bytes = Uint8Array.from(atob(b64), (c) => c.charCodeAt(0));
  return new TextDecoder("utf-8", { fatal: false }).decode(bytes);
}

export async function exec(input: { sessionId: string; command: string; timeoutMs?: number }): Promise<{ exitCode: number; stdout: string; stderr: string }> {
  const r = await fetch("/api/sessions/exec", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      session_id: input.sessionId,
      command: input.command,
      timeout_ms: input.timeoutMs ?? 0
    })
  });
  if (!r.ok) throw new Error(`exec failed: ${r.status}`);
  const j = await r.json();
  return {
    exitCode: j.exit_code,
    stdout: b64ToUtf8(j.stdout_b64 ?? ""),
    stderr: b64ToUtf8(j.stderr_b64 ?? "")
  };
}

export async function closeSession(sessionId: string): Promise<void> {
  const r = await fetch("/api/sessions/close", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ session_id: sessionId })
  });
  if (!r.ok) throw new Error(`close_session failed: ${r.status}`);
}
