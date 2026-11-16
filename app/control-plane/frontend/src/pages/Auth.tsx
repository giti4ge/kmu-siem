import { useQueryClient } from "@tanstack/react-query";
import { VersionTag } from "../FilePick";
import QRCode from "qrcode";
import { type FormEvent, type ReactNode, useEffect, useRef, useState } from "react";
import { useTranslation } from "react-i18next";
import { api, ApiError, type Me, setCsrf } from "../api";

export function ErrorBox({ error }: { error: unknown }) {
  const { t } = useTranslation();
  if (!error) return null;
  const key = error instanceof ApiError ? error.key : "unknown";
  const id = error instanceof ApiError ? error.approvalId : undefined;
  return <div className="error">{t(`errors.${key}`, { defaultValue: t("errors.unknown"), id })}</div>;
}

function Centered({ title, children }: { title: string; children: ReactNode }) {
  const { t } = useTranslation();
  return (
    <div className="flex min-h-screen items-center justify-center p-4">
      <div className="card w-full max-w-sm">
        <div className="mb-1 text-sm text-slate-500">{t("app.name")}</div>
        <h1 className="mb-4 text-xl font-semibold">{title}</h1>
        {children}
      </div>
      <VersionTag className="fixed bottom-2 left-0 right-0 text-center" />
    </div>
  );
}

// Nach jedem Anmeldeschritt: neuen Zustand übernehmen (CSRF-Token, Stufe)
function useAccept() {
  const qc = useQueryClient();
  return (me: Me) => {
    setCsrf(me.csrf_token);
    qc.setQueryData(["me"], me);
  };
}

export function LoginPage() {
  const { t } = useTranslation();
  const accept = useAccept();
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState<unknown>(null);
  const [busy, setBusy] = useState(false);
  const submit = async (e: FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      accept(await api<Me>("POST", "/api/auth/login", { username, password }));
    } catch (err) {
      setError(err);
      setPassword("");
    } finally {
      setBusy(false);
    }
  };
  return (
    <Centered title={t("auth.login_title")}>
      <form onSubmit={submit} className="flex flex-col gap-3">
        <ErrorBox error={error} />
        <div>
          <label className="label" htmlFor="u">{t("auth.username")}</label>
          <input id="u" className="input" autoComplete="username" autoFocus value={username}
            onChange={(e) => setUsername(e.target.value)} required />
        </div>
        <div>
          <label className="label" htmlFor="p">{t("auth.password")}</label>
          <input id="p" className="input" type="password" autoComplete="current-password" value={password}
            onChange={(e) => setPassword(e.target.value)} required />
        </div>
        <button className="btn" disabled={busy}>{t("auth.login")}</button>
      </form>
    </Centered>
  );
}

function CodeForm({ path, label }: { path: string; label: string }) {
  const { t } = useTranslation();
  const accept = useAccept();
  const [code, setCode] = useState("");
  const [error, setError] = useState<unknown>(null);
  const submit = async (e: FormEvent) => {
    e.preventDefault();
    setError(null);
    try {
      accept(await api<Me>("POST", path, { code }));
    } catch (err) {
      setError(err);
      setCode("");
    }
  };
  return (
    <form onSubmit={submit} className="flex flex-col gap-3">
      <ErrorBox error={error} />
      <div>
        <label className="label" htmlFor="c">{label}</label>
        <input id="c" className="input tracking-widest" inputMode="numeric" autoComplete="one-time-code"
          pattern="[0-9]{6}" maxLength={6} autoFocus value={code} onChange={(e) => setCode(e.target.value)} required />
      </div>
      <button className="btn">{t("auth.confirm")}</button>
    </form>
  );
}

export function MfaPage() {
  const { t } = useTranslation();
  return (
    <Centered title={t("auth.mfa_title")}>
      <p className="mb-3 text-sm text-slate-600">{t("auth.mfa_hint")}</p>
      <CodeForm path="/api/auth/totp/verify" label={t("auth.code")} />
    </Centered>
  );
}

export function EnrollPage() {
  const { t } = useTranslation();
  const [setup, setSetup] = useState<{ secret: string; uri: string } | null>(null);
  const [error, setError] = useState<unknown>(null);
  const canvas = useRef<HTMLCanvasElement>(null);
  useEffect(() => {
    api<{ secret: string; uri: string }>("POST", "/api/auth/totp/setup").then(setSetup, setError);
  }, []);
  useEffect(() => {
    // QR-Code lokal erzeugen – das Geheimnis verlässt den Browser nicht
    if (setup && canvas.current) QRCode.toCanvas(canvas.current, setup.uri, { width: 200, margin: 1 });
  }, [setup]);
  return (
    <Centered title={t("auth.enroll_title")}>
      <p className="mb-3 text-sm text-slate-600">{t("auth.enroll_hint")}</p>
      <ErrorBox error={error} />
      {setup && (
        <>
          <canvas ref={canvas} className="mx-auto mb-2" />
          <p className="mb-4 break-all text-center font-mono text-xs text-slate-500">{setup.secret}</p>
          <CodeForm path="/api/auth/totp/enable" label={t("auth.code")} />
        </>
      )}
    </Centered>
  );
}

export function PasswordPage({ forced = false }: { forced?: boolean }) {
  const { t } = useTranslation();
  const accept = useAccept();
  const [current, setCurrent] = useState("");
  const [next, setNext] = useState("");
  const [repeat, setRepeat] = useState("");
  const [error, setError] = useState<unknown>(null);
  const [done, setDone] = useState(false);
  const submit = async (e: FormEvent) => {
    e.preventDefault();
    setError(null);
    setDone(false);
    if (next !== repeat) return setError(new ApiError(400, "password_mismatch"));
    try {
      accept(await api<Me>("POST", "/api/auth/password", { current_password: current, new_password: next }));
      setDone(true);
      setCurrent("");
      setNext("");
      setRepeat("");
    } catch (err) {
      setError(err);
    }
  };
  const form = (
    <form onSubmit={submit} className="flex max-w-sm flex-col gap-3">
      <ErrorBox error={error} />
      {done && <div className="rounded bg-green-50 px-3 py-2 text-sm text-green-800">{t("auth.password_changed")}</div>}
      <div>
        <label className="label" htmlFor="pc">{t("auth.current_password")}</label>
        <input id="pc" className="input" type="password" autoComplete="current-password" value={current}
          onChange={(e) => setCurrent(e.target.value)} required />
      </div>
      <div>
        <label className="label" htmlFor="pn">{t("auth.new_password")}</label>
        <input id="pn" className="input" type="password" autoComplete="new-password" value={next}
          onChange={(e) => setNext(e.target.value)} required minLength={12} />
        <p className="mt-1 text-xs text-slate-500">{t("auth.password_rules")}</p>
      </div>
      <div>
        <label className="label" htmlFor="pr">{t("auth.repeat_password")}</label>
        <input id="pr" className="input" type="password" autoComplete="new-password" value={repeat}
          onChange={(e) => setRepeat(e.target.value)} required />
      </div>
      <button className="btn">{t("common.save")}</button>
    </form>
  );
  if (forced) return <Centered title={t("auth.password_forced")}>{form}</Centered>;
  return (
    <div>
      <h1 className="mb-4 text-xl font-semibold">{t("nav.account")}</h1>
      <div className="card">{form}</div>
    </div>
  );
}
