import React, { useMemo, useState } from "react";
import { closeSession, deleteCredential, exec, listCredentials, openSession, type Credential } from "./api";

type Toast = { kind: "ok" | "err"; msg: string };

function useToast() {
  const [toast, setToast] = useState<Toast | null>(null);
  const show = (t: Toast) => {
    setToast(t);
    window.setTimeout(() => setToast(null), 3200);
  };
  return { toast, show };
}

export function App() {
  const { toast, show } = useToast();
  const [creds, setCreds] = useState<Credential[]>([]);
  const [busy, setBusy] = useState(false);

  const [openForm, setOpenForm] = useState({ credentialId: "", host: "", port: 22, usernameOverride: "" });
  const [sessionId, setSessionId] = useState("");
  const [execCmd, setExecCmd] = useState("uname -a");
  const [execOut, setExecOut] = useState<{ exitCode: number; stdout: string; stderr: string } | null>(null);

  const credIndex = useMemo(() => new Map(creds.map((c) => [c.credentialId, c])), [creds]);

  async function refresh() {
    setBusy(true);
    try {
      const r = await listCredentials();
      setCreds(r);
      show({ kind: "ok", msg: `Loaded ${r.length} credential(s)` });
    } catch (e: any) {
      show({ kind: "err", msg: e?.message ?? String(e) });
    } finally {
      setBusy(false);
    }
  }

  async function onDelete(id: string) {
    if (!confirm(`Delete credential ${id}?`)) return;
    setBusy(true);
    try {
      await deleteCredential(id);
      setCreds((xs) => xs.filter((x) => x.credentialId !== id));
      show({ kind: "ok", msg: "Credential deleted" });
    } catch (e: any) {
      show({ kind: "err", msg: e?.message ?? String(e) });
    } finally {
      setBusy(false);
    }
  }

  async function onOpenSession() {
    setBusy(true);
    try {
      const sid = await openSession(openForm);
      setSessionId(sid);
      show({ kind: "ok", msg: `Session opened: ${sid}` });
    } catch (e: any) {
      show({ kind: "err", msg: e?.message ?? String(e) });
    } finally {
      setBusy(false);
    }
  }

  async function onExec() {
    if (!sessionId) {
      show({ kind: "err", msg: "Set a session id first" });
      return;
    }
    setBusy(true);
    try {
      const r = await exec({ sessionId, command: execCmd });
      setExecOut(r);
      show({ kind: "ok", msg: `Exit ${r.exitCode}` });
    } catch (e: any) {
      show({ kind: "err", msg: e?.message ?? String(e) });
    } finally {
      setBusy(false);
    }
  }

  async function onClose() {
    if (!sessionId) return;
    setBusy(true);
    try {
      await closeSession(sessionId);
      show({ kind: "ok", msg: "Session closed" });
      setSessionId("");
      setExecOut(null);
    } catch (e: any) {
      show({ kind: "err", msg: e?.message ?? String(e) });
    } finally {
      setBusy(false);
    }
  }

  const selected = credIndex.get(openForm.credentialId);

  return (
    <div className="app">
      <header className="top">
        <div className="brand">
          <div className="sigil" aria-hidden />
          <div className="brandText">
            <div className="kicker">CONTROL PLANE</div>
            <div className="title">ssh-broker</div>
          </div>
        </div>
        <div className="actions">
          <button className="btn ghost" onClick={refresh} disabled={busy}>
            Refresh
          </button>
          <a className="btn ghost" href="/auth/logout">
            Logout
          </a>
        </div>
      </header>

      <main className="grid">
        <section className="panel">
          <div className="panelHead">
            <h2>Credentials</h2>
            <span className="hint">metadata only • secrets never shown</span>
          </div>
          <div className="tableWrap">
            <table className="table">
              <thead>
                <tr>
                  <th>Label</th>
                  <th>User</th>
                  <th>Auth</th>
                  <th>Allowed hosts</th>
                  <th />
                </tr>
              </thead>
              <tbody>
                {creds.map((c) => (
                  <tr key={c.credentialId}>
                    <td>
                      <div className="mono strong">{c.label}</div>
                      <div className="mono dim">{c.credentialId}</div>
                    </td>
                    <td className="mono">{c.username}</td>
                    <td className="mono">{c.authType}</td>
                    <td className="mono dim">{(c.allowedHosts ?? []).join(", ") || "—"}</td>
                    <td className="right">
                      <button className="btn danger" onClick={() => onDelete(c.credentialId)} disabled={busy}>
                        Delete
                      </button>
                    </td>
                  </tr>
                ))}
                {creds.length === 0 && (
                  <tr>
                    <td className="dim mono" colSpan={5}>
                      No credentials loaded yet. Click Refresh.
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
          <div className="panelFoot">
            <div className="hint">
              Add credentials with <span className="mono">ssh-broker-enroll</span>. For <span className="mono">password_totp</span>, the broker uses a controlled{" "}
              <span className="mono">SSH_ASKPASS</span> flow.
            </div>
          </div>
        </section>

        <section className="panel">
          <div className="panelHead">
            <h2>Session</h2>
            <span className="hint">open • exec • close</span>
          </div>

          <div className="form">
            <label>
              <span>Credential</span>
              <select
                value={openForm.credentialId}
                onChange={(e) => setOpenForm((s) => ({ ...s, credentialId: e.target.value }))}
              >
                <option value="">Select…</option>
                {creds.map((c) => (
                  <option key={c.credentialId} value={c.credentialId}>
                    {c.label} ({c.username})
                  </option>
                ))}
              </select>
            </label>
            <div className="row">
              <label>
                <span>Host</span>
                <input value={openForm.host} onChange={(e) => setOpenForm((s) => ({ ...s, host: e.target.value }))} placeholder="my.vps.example.com" />
              </label>
              <label>
                <span>Port</span>
                <input
                  value={openForm.port}
                  onChange={(e) => setOpenForm((s) => ({ ...s, port: Number(e.target.value) || 22 }))}
                  inputMode="numeric"
                />
              </label>
            </div>
            <label>
              <span>Username override (optional)</span>
              <input
                value={openForm.usernameOverride}
                onChange={(e) => setOpenForm((s) => ({ ...s, usernameOverride: e.target.value }))}
                placeholder={selected?.username ?? "ubuntu"}
              />
            </label>
            <div className="row">
              <button className="btn primary" onClick={onOpenSession} disabled={busy || !openForm.credentialId || !openForm.host}>
                Open session
              </button>
              <button className="btn ghost" onClick={onClose} disabled={busy || !sessionId}>
                Close
              </button>
            </div>
          </div>

          <div className="divider" />

          <div className="form">
            <label>
              <span>Session id</span>
              <input value={sessionId} onChange={(e) => setSessionId(e.target.value)} placeholder="sess_..." className="mono" />
            </label>
            <label>
              <span>Command</span>
              <input value={execCmd} onChange={(e) => setExecCmd(e.target.value)} className="mono" />
            </label>
            <button className="btn primary" onClick={onExec} disabled={busy || !sessionId || !execCmd}>
              Exec
            </button>
          </div>

          {execOut && (
            <div className="out">
              <div className="outBar">
                <div className="pill">exit {execOut.exitCode}</div>
                <div className="hint mono">stdout + stderr are truncated by broker limits</div>
              </div>
              <pre className="pre">{execOut.stdout || "(no stdout)"}</pre>
              {execOut.stderr && (
                <>
                  <div className="outBar">
                    <div className="pill warn">stderr</div>
                  </div>
                  <pre className="pre err">{execOut.stderr}</pre>
                </>
              )}
            </div>
          )}
        </section>
      </main>

      {toast && (
        <div className={`toast ${toast.kind}`}>
          <div className="toastInner">
            <div className="dot" aria-hidden />
            <div className="mono">{toast.msg}</div>
          </div>
        </div>
      )}
    </div>
  );
}
