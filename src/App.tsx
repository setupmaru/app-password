import { FormEvent, ReactNode, useCallback, useEffect, useMemo, useState } from "react";
import { invoke } from "@tauri-apps/api/core";

type ProtectedApp = {
  id: string;
  name: string;
  path: string;
  protectionEnabled: boolean;
  exists: boolean;
  grantedUntil: number | null;
};

type Snapshot = {
  initialized: boolean;
  apps: ProtectedApp[];
  settings: { unlockMinutes: number };
  lockoutRemainingSeconds: number;
};

type LaunchResponse = {
  status: "needsPassword" | "invalidPassword" | "cooldown" | "missing" | "launched";
  message: string;
  attemptsRemaining: number;
  lockoutRemainingSeconds: number;
  grantedUntil: number | null;
};

type AuthDialog = {
  app: ProtectedApp;
  password: string;
  message: string;
  busy: boolean;
  cooldown: number;
};

type Toast = { kind: "success" | "error"; message: string };

function Icon({ children, size = 18 }: { children: ReactNode; size?: number }) {
  return (
    <svg
      aria-hidden="true"
      width={size}
      height={size}
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="1.8"
      strokeLinecap="round"
      strokeLinejoin="round"
    >
      {children}
    </svg>
  );
}

function ShieldLogo({ large = false }: { large?: boolean }) {
  return (
    <span className={`shield-logo ${large ? "shield-logo--large" : ""}`} aria-hidden="true">
      <svg viewBox="0 0 32 32" fill="none">
        <path d="M16 3.5 27 8v7.5c0 7-4.7 11.3-11 13-6.3-1.7-11-6-11-13V8l11-4.5Z" fill="currentColor" />
        <path d="M12.2 15.1v-1.6a3.8 3.8 0 0 1 7.6 0v1.6m-8.9 0h10.2v7.1H10.9v-7.1Z" stroke="white" strokeWidth="1.7" />
        <circle cx="16" cy="18.4" r="1" fill="white" />
      </svg>
    </span>
  );
}

function friendlyError(error: unknown) {
  if (typeof error === "string") return error;
  if (error instanceof Error) return error.message;
  return "요청을 처리하지 못했습니다.";
}

function formatRemaining(expiresAt: number | null, now: number) {
  if (!expiresAt || expiresAt <= now) return null;
  const seconds = expiresAt - now;
  const minutes = Math.floor(seconds / 60);
  const rest = seconds % 60;
  return minutes > 0 ? `${minutes}분 ${rest}초 허용` : `${rest}초 허용`;
}

function EmptyState({ onAdd, busy }: { onAdd: () => void; busy: boolean }) {
  return (
    <section className="empty-state">
      <div className="empty-icon">
        <Icon size={32}>
          <rect x="4" y="4" width="16" height="16" rx="4" />
          <path d="M12 8v8m-4-4h8" />
        </Icon>
      </div>
      <h2>보호할 앱을 추가해 보세요</h2>
      <p>실행 파일을 선택하면 App Password를 통해 안전하게 실행할 수 있습니다.</p>
      <button className="button button--primary" onClick={onAdd} disabled={busy}>
        <Icon>
          <path d="M12 5v14m-7-7h14" />
        </Icon>
        첫 번째 앱 추가
      </button>
    </section>
  );
}

function SetupScreen({ onComplete }: { onComplete: (snapshot: Snapshot) => void }) {
  const [password, setPassword] = useState("");
  const [confirmation, setConfirmation] = useState("");
  const [showPassword, setShowPassword] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");

  const checks = useMemo(
    () => [
      { label: "8자 이상", met: password.length >= 8 },
      { label: "영문과 숫자 조합 권장", met: /[A-Za-z]/.test(password) && /\d/.test(password) },
    ],
    [password],
  );

  async function submit(event: FormEvent) {
    event.preventDefault();
    if (password.length < 8) {
      setError("마스터 비밀번호는 8자 이상이어야 합니다.");
      return;
    }
    if (password !== confirmation) {
      setError("입력한 비밀번호가 서로 다릅니다.");
      return;
    }
    setBusy(true);
    setError("");
    try {
      const snapshot = await invoke<Snapshot>("set_master_password", { password });
      setPassword("");
      setConfirmation("");
      onComplete(snapshot);
    } catch (reason) {
      setError(friendlyError(reason));
    } finally {
      setBusy(false);
    }
  }

  return (
    <main className="setup-shell">
      <div className="setup-glow setup-glow--one" />
      <div className="setup-glow setup-glow--two" />
      <section className="setup-card">
        <ShieldLogo large />
        <div className="eyebrow">처음 시작하기</div>
        <h1>나만의 앱 잠금</h1>
        <p className="setup-copy">
          선택한 앱을 열기 전, 한 번 더 확인하세요. 모든 설정은 이 컴퓨터 안에만 저장됩니다.
        </p>

        <form onSubmit={submit} className="setup-form">
          <label className="field-label" htmlFor="master-password">
            마스터 비밀번호
          </label>
          <div className="password-field">
            <input
              id="master-password"
              type={showPassword ? "text" : "password"}
              value={password}
              onChange={(event) => setPassword(event.target.value)}
              placeholder="8자 이상 입력"
              autoFocus
              autoComplete="new-password"
            />
            <button type="button" className="icon-button input-action" onClick={() => setShowPassword((value) => !value)}>
              <Icon>
                {showPassword ? (
                  <>
                    <path d="m3 3 18 18" />
                    <path d="M10.6 10.7a2 2 0 0 0 2.7 2.7M9.9 5.2A10.8 10.8 0 0 1 12 5c5.5 0 9 7 9 7a15 15 0 0 1-2 3M6.6 6.6C4.3 8.2 3 12 3 12s3.5 7 9 7c1.2 0 2.4-.3 3.4-.8" />
                  </>
                ) : (
                  <>
                    <path d="M2.5 12s3.5-7 9.5-7 9.5 7 9.5 7-3.5 7-9.5 7-9.5-7-9.5-7Z" />
                    <circle cx="12" cy="12" r="2.5" />
                  </>
                )}
              </Icon>
              <span className="sr-only">비밀번호 표시 전환</span>
            </button>
          </div>

          <label className="field-label" htmlFor="master-confirmation">
            비밀번호 확인
          </label>
          <input
            id="master-confirmation"
            type={showPassword ? "text" : "password"}
            value={confirmation}
            onChange={(event) => setConfirmation(event.target.value)}
            placeholder="한 번 더 입력"
            autoComplete="new-password"
          />

          <div className="password-checks">
            {checks.map((check) => (
              <span key={check.label} className={check.met ? "password-check password-check--met" : "password-check"}>
                <Icon size={14}>
                  <path d="m5 12 4 4L19 6" />
                </Icon>
                {check.label}
              </span>
            ))}
          </div>

          {error && <div className="inline-error">{error}</div>}
          <button className="button button--primary button--wide" disabled={busy}>
            {busy ? <span className="spinner" /> : "App Password 시작하기"}
          </button>
        </form>

        <div className="privacy-note">
          <Icon size={16}>
            <path d="M12 2 5 5v5c0 4.7 3 8.5 7 10 4-1.5 7-5.3 7-10V5l-7-3Z" />
          </Icon>
          비밀번호 원문은 저장되지 않으며 Argon2id로 검증됩니다.
        </div>
      </section>
    </main>
  );
}

function AuthModal({ dialog, onChange, onClose, onSubmit }: {
  dialog: AuthDialog;
  onChange: (password: string) => void;
  onClose: () => void;
  onSubmit: (event: FormEvent) => void;
}) {
  return (
    <div className="modal-backdrop" role="presentation" onMouseDown={(event) => event.target === event.currentTarget && onClose()}>
      <section className="modal" role="dialog" aria-modal="true" aria-labelledby="auth-title">
        <button className="icon-button modal-close" onClick={onClose} aria-label="닫기">
          <Icon><path d="m6 6 12 12M18 6 6 18" /></Icon>
        </button>
        <div className="modal-lock"><ShieldLogo /></div>
        <div className="eyebrow">보호된 앱</div>
        <h2 id="auth-title">{dialog.app.name} 열기</h2>
        <p>계속하려면 마스터 비밀번호를 입력하세요.</p>
        <form onSubmit={onSubmit}>
          <label className="field-label" htmlFor="unlock-password">마스터 비밀번호</label>
          <input
            id="unlock-password"
            type="password"
            value={dialog.password}
            onChange={(event) => onChange(event.target.value)}
            autoFocus
            autoComplete="current-password"
            disabled={dialog.busy || dialog.cooldown > 0}
          />
          {dialog.message && <div className="inline-error">{dialog.message}</div>}
          <div className="modal-actions">
            <button type="button" className="button button--ghost" onClick={onClose}>취소</button>
            <button className="button button--primary" disabled={dialog.busy || !dialog.password || dialog.cooldown > 0}>
              {dialog.busy ? <span className="spinner" /> : dialog.cooldown > 0 ? `${dialog.cooldown}초 후 재시도` : "인증하고 실행"}
            </button>
          </div>
        </form>
      </section>
    </div>
  );
}

function ChangePasswordModal({ onClose, onSaved }: { onClose: () => void; onSaved: (snapshot: Snapshot) => void }) {
  const [currentPassword, setCurrentPassword] = useState("");
  const [newPassword, setNewPassword] = useState("");
  const [confirmation, setConfirmation] = useState("");
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);

  async function submit(event: FormEvent) {
    event.preventDefault();
    if (newPassword.length < 8) return setError("새 비밀번호는 8자 이상이어야 합니다.");
    if (newPassword !== confirmation) return setError("새 비밀번호가 서로 다릅니다.");
    setBusy(true);
    setError("");
    try {
      const snapshot = await invoke<Snapshot>("change_master_password", { currentPassword, newPassword });
      onSaved(snapshot);
    } catch (reason) {
      setError(friendlyError(reason));
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="modal-backdrop" role="presentation" onMouseDown={(event) => event.target === event.currentTarget && onClose()}>
      <section className="modal modal--compact" role="dialog" aria-modal="true" aria-labelledby="change-title">
        <button className="icon-button modal-close" onClick={onClose} aria-label="닫기"><Icon><path d="m6 6 12 12M18 6 6 18" /></Icon></button>
        <div className="eyebrow">보안 설정</div>
        <h2 id="change-title">마스터 비밀번호 변경</h2>
        <form onSubmit={submit} className="stacked-form">
          <label className="field-label" htmlFor="current-password">현재 비밀번호</label>
          <input id="current-password" type="password" value={currentPassword} onChange={(event) => setCurrentPassword(event.target.value)} autoFocus />
          <label className="field-label" htmlFor="new-password">새 비밀번호</label>
          <input id="new-password" type="password" value={newPassword} onChange={(event) => setNewPassword(event.target.value)} />
          <label className="field-label" htmlFor="new-confirmation">새 비밀번호 확인</label>
          <input id="new-confirmation" type="password" value={confirmation} onChange={(event) => setConfirmation(event.target.value)} />
          {error && <div className="inline-error">{error}</div>}
          <div className="modal-actions">
            <button type="button" className="button button--ghost" onClick={onClose}>취소</button>
            <button className="button button--primary" disabled={busy}>{busy ? <span className="spinner" /> : "변경하기"}</button>
          </div>
        </form>
      </section>
    </div>
  );
}

export default function App() {
  const [snapshot, setSnapshot] = useState<Snapshot | null>(null);
  const [loading, setLoading] = useState(true);
  const [adding, setAdding] = useState(false);
  const [now, setNow] = useState(() => Math.floor(Date.now() / 1000));
  const [auth, setAuth] = useState<AuthDialog | null>(null);
  const [changingPassword, setChangingPassword] = useState(false);
  const [toast, setToast] = useState<Toast | null>(null);

  const refresh = useCallback(async () => {
    try {
      setSnapshot(await invoke<Snapshot>("get_snapshot"));
    } catch (reason) {
      setToast({ kind: "error", message: friendlyError(reason) });
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    refresh();
    const timer = window.setInterval(() => setNow(Math.floor(Date.now() / 1000)), 1000);
    return () => window.clearInterval(timer);
  }, [refresh]);

  useEffect(() => {
    if (!toast) return;
    const timer = window.setTimeout(() => setToast(null), 3200);
    return () => window.clearTimeout(timer);
  }, [toast]);

  useEffect(() => {
    if (!auth || auth.cooldown <= 0) return;
    const timer = window.setTimeout(() => {
      setAuth((current) => current ? { ...current, cooldown: Math.max(0, current.cooldown - 1), message: current.cooldown === 1 ? "" : current.message } : null);
    }, 1000);
    return () => window.clearTimeout(timer);
  }, [auth]);

  async function addApplication() {
    setAdding(true);
    try {
      const next = await invoke<Snapshot | null>("add_application");
      if (next) {
        setSnapshot(next);
        setToast({ kind: "success", message: "보호할 앱을 추가했습니다." });
      }
    } catch (reason) {
      setToast({ kind: "error", message: friendlyError(reason) });
    } finally {
      setAdding(false);
    }
  }

  async function toggleProtection(app: ProtectedApp) {
    try {
      setSnapshot(await invoke<Snapshot>("set_protection_enabled", { id: app.id, enabled: !app.protectionEnabled }));
    } catch (reason) {
      setToast({ kind: "error", message: friendlyError(reason) });
    }
  }

  async function removeApplication(app: ProtectedApp) {
    if (!window.confirm(`${app.name}을(를) 목록에서 제거할까요?\n실제 프로그램은 삭제되지 않습니다.`)) return;
    try {
      setSnapshot(await invoke<Snapshot>("remove_application", { id: app.id }));
      setToast({ kind: "success", message: "목록에서 제거했습니다." });
    } catch (reason) {
      setToast({ kind: "error", message: friendlyError(reason) });
    }
  }

  async function lockAll() {
    try {
      setSnapshot(await invoke<Snapshot>("lock_all"));
      setToast({ kind: "success", message: "모든 임시 허용을 해제했습니다." });
    } catch (reason) {
      setToast({ kind: "error", message: friendlyError(reason) });
    }
  }

  async function updateMinutes(minutes: number) {
    try {
      setSnapshot(await invoke<Snapshot>("update_unlock_minutes", { minutes }));
      setToast({ kind: "success", message: `인증 유지 시간을 ${minutes}분으로 변경했습니다.` });
    } catch (reason) {
      setToast({ kind: "error", message: friendlyError(reason) });
    }
  }

  async function requestLaunch(app: ProtectedApp) {
    try {
      const response = await invoke<LaunchResponse>("launch_application", { id: app.id, password: null });
      if (response.status === "needsPassword") {
        setAuth({ app, password: "", message: "", busy: false, cooldown: snapshot?.lockoutRemainingSeconds ?? 0 });
      } else if (response.status === "launched") {
        setToast({ kind: "success", message: response.message });
        refresh();
      } else {
        setToast({ kind: "error", message: response.message });
      }
    } catch (reason) {
      setToast({ kind: "error", message: friendlyError(reason) });
    }
  }

  async function authenticatedLaunch(event: FormEvent) {
    event.preventDefault();
    if (!auth) return;
    setAuth({ ...auth, busy: true, message: "" });
    try {
      const response = await invoke<LaunchResponse>("launch_application", { id: auth.app.id, password: auth.password });
      if (response.status === "launched") {
        setAuth(null);
        setToast({ kind: "success", message: response.message });
        refresh();
      } else {
        setAuth((current) => current ? {
          ...current,
          password: "",
          busy: false,
          message: response.message,
          cooldown: response.lockoutRemainingSeconds,
        } : null);
      }
    } catch (reason) {
      setAuth((current) => current ? { ...current, busy: false, message: friendlyError(reason) } : null);
    }
  }

  if (loading || !snapshot) {
    return <main className="loading-screen"><ShieldLogo large /><span className="spinner spinner--large" /><p>보안 설정을 불러오는 중…</p></main>;
  }

  if (!snapshot.initialized) {
    return <SetupScreen onComplete={setSnapshot} />;
  }

  const protectedCount = snapshot.apps.filter((app) => app.protectionEnabled).length;
  const currentlyOpen = snapshot.apps.filter((app) => app.grantedUntil && app.grantedUntil > now).length;

  return (
    <div className="app-shell">
      <header className="topbar">
        <div className="brand"><ShieldLogo /><span>App Password</span></div>
        <div className="topbar-actions">
          <button className="icon-button" onClick={() => setChangingPassword(true)} title="마스터 비밀번호 변경">
            <Icon><circle cx="12" cy="12" r="3" /><path d="M19.4 15a1.7 1.7 0 0 0 .3 1.9l.1.1-2.8 2.8-.1-.1a1.7 1.7 0 0 0-1.9-.3 1.7 1.7 0 0 0-1 1.6v.2h-4V21a1.7 1.7 0 0 0-1-1.6 1.7 1.7 0 0 0-1.9.3l-.1.1L4.2 17l.1-.1a1.7 1.7 0 0 0 .3-1.9A1.7 1.7 0 0 0 3 14H2.8v-4H3a1.7 1.7 0 0 0 1.6-1 1.7 1.7 0 0 0-.3-1.9L4.2 7 7 4.2l.1.1A1.7 1.7 0 0 0 9 4.6 1.7 1.7 0 0 0 10 3V2.8h4V3a1.7 1.7 0 0 0 1 1.6 1.7 1.7 0 0 0 1.9-.3l.1-.1L19.8 7l-.1.1a1.7 1.7 0 0 0-.3 1.9 1.7 1.7 0 0 0 1.6 1h.2v4H21a1.7 1.7 0 0 0-1.6 1Z" /></Icon>
          </button>
        </div>
      </header>

      <main className="content">
        <section className="hero-row">
          <div>
            <div className="eyebrow"><span className="status-dot" />로컬 보호 실행 중</div>
            <h1>보호된 앱</h1>
            <p>앱을 열기 전 마스터 비밀번호로 본인임을 확인합니다.</p>
          </div>
          <button className="button button--primary" onClick={addApplication} disabled={adding}>
            {adding ? <span className="spinner" /> : <Icon><path d="M12 5v14m-7-7h14" /></Icon>}
            앱 추가
          </button>
        </section>

        <section className="summary-grid">
          <article className="summary-card">
            <span className="summary-icon summary-icon--purple"><Icon><rect x="4" y="4" width="16" height="16" rx="4" /><path d="M9 12h6m-3-3v6" /></Icon></span>
            <div><strong>{snapshot.apps.length}</strong><span>등록된 앱</span></div>
          </article>
          <article className="summary-card">
            <span className="summary-icon summary-icon--green"><Icon><path d="M12 3 5 6v5c0 4.4 2.8 8 7 10 4.2-2 7-5.6 7-10V6l-7-3Z" /><path d="m9 12 2 2 4-4" /></Icon></span>
            <div><strong>{protectedCount}</strong><span>보호 활성</span></div>
          </article>
          <article className="summary-card">
            <span className="summary-icon summary-icon--amber"><Icon><circle cx="12" cy="12" r="9" /><path d="M12 7v5l3 2" /></Icon></span>
            <div><strong>{currentlyOpen}</strong><span>임시 허용</span></div>
          </article>
          <article className="summary-card summary-card--setting">
            <span>인증 유지</span>
            <select value={snapshot.settings.unlockMinutes} onChange={(event) => updateMinutes(Number(event.target.value))}>
              {[1, 5, 15, 30, 60].map((minutes) => <option key={minutes} value={minutes}>{minutes}분</option>)}
            </select>
          </article>
        </section>

        <section className="panel">
          <div className="panel-header">
            <div><h2>앱 목록</h2><p>실행 버튼을 누르면 잠금 상태를 확인합니다.</p></div>
            <button className="button button--secondary" onClick={lockAll} disabled={currentlyOpen === 0}>
              <Icon><rect x="5" y="10" width="14" height="11" rx="2" /><path d="M8 10V7a4 4 0 0 1 8 0v3" /></Icon>
              지금 모두 잠그기
            </button>
          </div>

          {snapshot.apps.length === 0 ? <EmptyState onAdd={addApplication} busy={adding} /> : (
            <div className="app-list">
              {snapshot.apps.map((app) => {
                const remaining = formatRemaining(app.grantedUntil, now);
                return (
                  <article className="app-row" key={app.id}>
                    <div className="app-avatar">{app.name.slice(0, 1).toUpperCase()}</div>
                    <div className="app-info">
                      <div className="app-name-row">
                        <h3>{app.name}</h3>
                        {!app.exists ? <span className="badge badge--danger">파일 없음</span> : remaining ? <span className="badge badge--open">{remaining}</span> : app.protectionEnabled ? <span className="badge"><span className="badge-dot" />잠김</span> : <span className="badge badge--muted">보호 꺼짐</span>}
                      </div>
                      <p title={app.path}>{app.path}</p>
                    </div>
                    <label className="switch" title="보호 사용">
                      <input type="checkbox" checked={app.protectionEnabled} onChange={() => toggleProtection(app)} />
                      <span className="switch-track"><span /></span>
                      <span className="sr-only">{app.name} 보호 사용</span>
                    </label>
                    <button className="button button--launch" onClick={() => requestLaunch(app)} disabled={!app.exists}>
                      <Icon><path d="m9 18 6-6-6-6" /></Icon>실행
                    </button>
                    <button className="icon-button icon-button--danger" onClick={() => removeApplication(app)} title="목록에서 제거">
                      <Icon><path d="M4 7h16M9 7V4h6v3m3 0-1 14H7L6 7m4 4v6m4-6v6" /></Icon>
                    </button>
                  </article>
                );
              })}
            </div>
          )}
        </section>

        <aside className="mode-notice">
          <Icon size={20}><circle cx="12" cy="12" r="9" /><path d="M12 11v5m0-8h.01" /></Icon>
          <div><strong>현재는 안전한 런처 보호 모드입니다.</strong><span>이 화면을 통하지 않고 원래 실행 파일을 직접 열면 우회할 수 있습니다. 다음 단계에서 Windows 시스템 서비스와 연결할 수 있습니다.</span></div>
        </aside>
      </main>

      {auth && <AuthModal dialog={auth} onChange={(password) => setAuth({ ...auth, password, message: "" })} onClose={() => !auth.busy && setAuth(null)} onSubmit={authenticatedLaunch} />}
      {changingPassword && <ChangePasswordModal onClose={() => setChangingPassword(false)} onSaved={(next) => { setSnapshot(next); setChangingPassword(false); setToast({ kind: "success", message: "마스터 비밀번호를 변경하고 모든 앱을 다시 잠갔습니다." }); }} />}
      {toast && <div className={`toast toast--${toast.kind}`}><Icon>{toast.kind === "success" ? <path d="m5 12 4 4L19 6" /> : <><circle cx="12" cy="12" r="9" /><path d="M12 8v5m0 3h.01" /></>}</Icon>{toast.message}</div>}
    </div>
  );
}

