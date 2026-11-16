import { useRef } from "react";
import { useTranslation } from "react-i18next";

// Einheitlicher, übersetzter „Datei auswählen“-Knopf (statt des browsereigenen Elements)
export function FilePick({ label, accept, disabled, onFile }: { label: string; accept?: string; disabled?: boolean; onFile: (f: File) => void }) {
  const { t } = useTranslation();
  const ref = useRef<HTMLInputElement>(null);
  return (
    <span className="inline-flex items-center gap-2">
      <input ref={ref} type="file" accept={accept} className="hidden" aria-label={label} disabled={disabled}
        onChange={(e) => { const f = e.target.files?.[0]; if (f) onFile(f); e.target.value = ""; }} />
      <button type="button" className="btn-secondary" disabled={disabled} onClick={() => ref.current?.click()}>{t("common.choose_file")}</button>
      <span className="text-sm text-slate-600">{label}</span>
    </span>
  );
}

export function VersionTag({ className = "" }: { className?: string }) {
  const { t } = useTranslation();
  return <div className={`text-xs text-slate-500 ${className}`}>{t("app.version", { version: __APP_VERSION__, date: __APP_DATE__ })}</div>;
}
