# ADR-0015: MS Teams über Workflows-Webhook

| Status | Datum | Entscheider |
|---|---|---|
| Akzeptiert | 2026-11-12 | Auftraggeber / Entwicklung |

## Kontext
Office-365-Connectoren (Incoming Webhooks) sind abgekündigt.

## Entscheidung
Teams-Benachrichtigungen per Power-Automate-Workflows-Webhook mit Adaptive Cards.

## Betrachtete Alternativen
| Alternative | Vorteile | Nachteile / Grund der Ablehnung |
|---|---|---|
| Microsoft Graph API | Volle Kontrolle | App-Registrierung und Berechtigungen nötig |

## Konsequenzen
- Einfache Einrichtung je Kanal
- Abhängig von Änderungen bei Microsoft

## Referenzen
- [Spezifikation](../spec/SPEC.md), Abschnitt 4.11
