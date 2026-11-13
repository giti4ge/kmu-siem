import i18n from "i18next";
import { initReactI18next } from "react-i18next";
import de from "./de.json";
import en from "./en.json";

const stored = localStorage.getItem("lang");
const browser = navigator.language.startsWith("de") ? "de" : "en";

i18n.use(initReactI18next).init({
  resources: { de: { translation: de }, en: { translation: en } },
  lng: stored === "de" || stored === "en" ? stored : browser,
  fallbackLng: "de",
  interpolation: { escapeValue: false },
});

export function setLanguage(lang: "de" | "en") {
  localStorage.setItem("lang", lang);
  i18n.changeLanguage(lang);
  document.documentElement.lang = lang;
}

export default i18n;
