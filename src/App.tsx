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
  guardActive: boolean;
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

function EmptyState({ onRefresh, busy }: { onRefresh: () => void; busy: boolean }) {
  return (
    <section className="empty-state">
      <div className="empty-icon">
        <Icon size={32}>
          <rect x="4" y="4" width="16" height="16" rx="4" />
          <path d="M12 8v8m-4-4h8" />
        </Icon>
      </div>
      <h2>설치된 앱을 찾지 못했습니다</h2>
      <p>Windows 앱 설치 정보를 다시 검색해 실행 가능한 데스크톱 앱을 불러옵니다.</p>
      <button className="button button--primary" onClick={onRefresh} disabled={busy}>
        <Icon>
          <path d="M20 11a8 8 0 1 0-2.3 5.7M20 4v7h-7" />
        </Icon>
        {busy ? "검색 중…" : "다시 검색"}
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
          Windows에 설치된 앱에서 보호할 항목을 켜세요. 모든 설정은 이 컴퓨터 안에만 저장됩니다.
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
  const [scanning, setScanning] = useState(false);
  const [togglingPath, setTogglingPath] = useState<string | null>(null);
  const [query, setQuery] = useState("");
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
    const clockTimer = window.setInterval(() => setNow(Math.floor(Date.now() / 1000)), 1000);
    const refreshTimer = window.setInterval(refresh, 3_000);
    return () => {
      window.clearInterval(clockTimer);
      window.clearInterval(refreshTimer);
    };
  }, [refresh]);

  useEffect(() => {
    if (!snapshot?.initialized) return;
    let requestInFlight = false;
    const poll = async () => {
      if (requestInFlight) return;
      requestInFlight = true;
      try {
        const app = await invoke<ProtectedApp | null>("poll_guard_event");
        if (app) {
          setAuth((current) => current ?? {
            app,
            password: "",
            message: "",
            busy: false,
            cooldown: snapshot.lockoutRemainingSeconds,
          });
        }
      } catch {
        // 서비스 상태는 상단 표시에서 별도로 갱신됩니다.
      } finally {
        requestInFlight = false;
      }
    };
    void poll();
    const timer = window.setInterval(poll, 500);
    return () => window.clearInterval(timer);
  }, [snapshot?.initialized, snapshot?.lockoutRemainingSeconds]);

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

  async function scanApplications() {
    setScanning(true);
    try {
      setSnapshot(await invoke<Snapshot>("refresh_installed_applications"));
      setToast({ kind: "success", message: "Windows 앱 목록을 새로 불러왔습니다." });
    } catch (reason) {
      setToast({ kind: "error", message: friendlyError(reason) });
    } finally {
      setScanning(false);
    }
  }

  async function toggleProtection(app: ProtectedApp) {
    setTogglingPath(app.path);
    try {
      const enabled = !app.protectionEnabled;
      setSnapshot(await invoke<Snapshot>("set_application_protection", {
        name: app.name,
        path: app.path,
        enabled,
      }));
      setToast({
        kind: "success",
        message: enabled ? `${app.name} 보호를 켰습니다.` : `${app.name} 보호를 껐습니다.`,
      });
    } catch (reason) {
      setToast({ kind: "error", message: friendlyError(reason) });
    } finally {
      setTogglingPath(null);
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
  const normalizedQuery = query.trim().toLocaleLowerCase();
  const visibleApps = normalizedQuery
    ? snapshot.apps.filter((app) =>
        app.name.toLocaleLowerCase().includes(normalizedQuery)
        || app.path.toLocaleLowerCase().includes(normalizedQuery))
    : snapshot.apps;

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
            <div className={`eyebrow ${snapshot.guardActive ? "" : "eyebrow--danger"}`}>
              <span className={`status-dot ${snapshot.guardActive ? "" : "status-dot--danger"}`} />
              {snapshot.guardActive ? "Windows 보호 서비스 실행 중" : "Windows 보호 서비스 연결 안 됨"}
            </div>
            <h1>Windows 앱</h1>
            <p>토글을 켠 앱은 원래 실행 파일로 열어도 마스터 비밀번호로 보호됩니다.</p>
          </div>
          <button className="button button--primary" onClick={scanApplications} disabled={scanning}>
            {scanning ? <span className="spinner" /> : <Icon><path d="M20 11a8 8 0 1 0-2.3 5.7M20 4v7h-7" /></Icon>}
            앱 새로고침
          </button>
        </section>

        <section className="summary-grid">
          <article className="summary-card">
            <span className="summary-icon summary-icon--purple"><Icon><rect x="4" y="4" width="16" height="16" rx="4" /><path d="M9 12h6m-3-3v6" /></Icon></span>
            <div><strong>{snapshot.apps.length}</strong><span>검색된 앱</span></div>
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
            <div><h2>설치된 앱 목록</h2><p>30초마다 자동으로 확인하며, 토글을 켜면 보호 목록에 등록됩니다.</p></div>
            <div className="panel-actions">
              <label className="search-box">
                <Icon size={16}><circle cx="11" cy="11" r="7" /><path d="m20 20-4-4" /></Icon>
                <span className="sr-only">앱 검색</span>
                <input value={query} onChange={(event) => setQuery(event.target.value)} placeholder="앱 이름 검색" />
              </label>
              <button className="button button--secondary" onClick={lockAll} disabled={currentlyOpen === 0}>
                <Icon><rect x="5" y="10" width="14" height="11" rx="2" /><path d="M8 10V7a4 4 0 0 1 8 0v3" /></Icon>
                지금 모두 잠그기
              </button>
            </div>
          </div>

          {snapshot.apps.length === 0 ? <EmptyState onRefresh={scanApplications} busy={scanning} /> : visibleApps.length === 0 ? (
            <div className="search-empty">“{query}”와 일치하는 앱이 없습니다.</div>
          ) : (
            <div className="app-list">
              {visibleApps.map((app) => {
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
                      <input
                        type="checkbox"
                        checked={app.protectionEnabled}
                        disabled={togglingPath === app.path}
                        onChange={() => toggleProtection(app)}
                      />
                      <span className="switch-track"><span /></span>
                      <span className="sr-only">{app.name} 보호 사용</span>
                    </label>
                    <button
                      className="button button--launch"
                      onClick={() => requestLaunch(app)}
                      disabled={!app.exists || !app.protectionEnabled}
                      title={app.protectionEnabled ? "App Password로 실행" : "보호 토글을 먼저 켜세요"}
                    >
                      <Icon><path d="m9 18 6-6-6-6" /></Icon>실행
                    </button>
                  </article>
                );
              })}
            </div>
          )}
        </section>

      </main>

      {auth && <AuthModal dialog={auth} onChange={(password) => setAuth({ ...auth, password, message: "" })} onClose={() => !auth.busy && setAuth(null)} onSubmit={authenticatedLaunch} />}
      {changingPassword && <ChangePasswordModal onClose={() => setChangingPassword(false)} onSaved={(next) => { setSnapshot(next); setChangingPassword(false); setToast({ kind: "success", message: "마스터 비밀번호를 변경하고 모든 앱을 다시 잠갔습니다." }); }} />}
      {toast && <div className={`toast toast--${toast.kind}`}><Icon>{toast.kind === "success" ? <path d="m5 12 4 4L19 6" /> : <><circle cx="12" cy="12" r="9" /><path d="M12 8v5m0 3h.01" /></>}</Icon>{toast.message}</div>}
    </div>
  );
}
