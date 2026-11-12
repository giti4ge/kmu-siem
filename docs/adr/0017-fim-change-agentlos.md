# ADR-0017: FIM und Change-Auditing agentlos

| Status | Datum | Entscheider |
|---|---|---|
| Akzeptiert | 2026-11-12 | Auftraggeber / Entwicklung |

## Kontext
Vorgabe: keine Agenten. Das Referenzprodukt bietet FIM und Change-Auditing per Agent.

## Entscheidung
Umsetzung über Windows-Auditing (SACL, AD-Ereignisse) und WEF; Hashing von Dateiinhalten ist bewusst ausgeklammert.

## Betrachtete Alternativen
| Alternative | Vorteile | Nachteile / Grund der Ablehnung |
|---|---|---|
| Agent | Inhalts-Hashes möglich | Widerspricht der Vorgabe |

## Konsequenzen
- Wer, wann und was ist erkennbar, nicht der Inhalt
- Hohe Ereignismenge bei breiten SACLs

## Referenzen
- [Spezifikation](../spec/SPEC.md), Abschnitt 4.4b
