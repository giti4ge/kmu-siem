// REST-Client: Cookie-Sitzung (same-origin), CSRF-Token im Header für zustandsändernde Aufrufe.
// Fehler kommen als {"detail": {"error": "<schlüssel>"}} und werden im UI übersetzt.

let csrfToken = "";

export function setCsrf(token: string) {
  csrfToken = token;
}

export function getCsrf() {
  return csrfToken;
}

export class ApiError extends Error {
  constructor(public status: number, public key: string) {
    super(key);
  }
}

export async function api<T>(method: string, path: string, body?: unknown): Promise<T> {
  const headers: Record<string, string> = {};
  if (body !== undefined) headers["Content-Type"] = "application/json";
  if (method !== "GET" && csrfToken) headers["X-CSRF-Token"] = csrfToken;
  const res = await fetch(path, {
    method,
    headers,
    credentials: "same-origin",
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  if (res.status === 204) return undefined as T;
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new ApiError(res.status, data?.detail?.error ?? `http_${res.status}`);
  return data as T;
}

export type Role = {
  id: number;
  name: string;
  description: string;
  builtin: boolean;
  mfa_required: boolean;
  permissions: string[];
  data_scope: { categories?: string[]; masked_fields?: string[] };
};

export type User = {
  id: number;
  username: string;
  display_name: string;
  email: string;
  language: "de" | "en";
  enabled: boolean;
  totp_enabled: boolean;
  must_change_password: boolean;
  last_login_at: string | null;
  roles: { id: number; name: string }[];
};

export type Me = {
  user: User;
  stage: "ok" | "mfa_verify" | "mfa_enroll" | "password_change";
  permissions: string[];
  csrf_token: string;
};

export type AuditEntry = {
  seq: number;
  ts: string;
  actor: string;
  action: string;
  target: string;
  outcome: string;
  ip: string;
  details: string;
};
