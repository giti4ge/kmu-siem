# ADR-0024: KI-Anbieter und Beweisbindung

| Status | Datum | Entscheider |
|---|---|---|
| Akzeptiert | 2026-11-14 | Auftraggeber / Entwicklung |

## Kontext
ADR-12 erlaubte nur externe KI-APIs. Der Auftraggeber will zusätzlich Google Gemini und einen lokalen Modell-Endpunkt, der nicht auf der Appliance läuft. Für die Forensik muss Halluzination technisch begrenzt werden.

## Entscheidung
Anbieter: OpenAI-kompatibel, Anthropic, Azure OpenAI, Google Gemini sowie ein eigener OpenAI-kompatibler Endpunkt außerhalb der Appliance. Die Appliance betreibt kein Modell. Anonymizer ist für externe Anbieter verpflichtend, für den eigenen Endpunkt abschaltbar. Die Forensik-Analyse arbeitet mit Beweisbindung (Ereignis-IDs je Aussage), lokaler Prüfung, zweitem Durchlauf und Kennzeichnung als Hinweis.

## Betrachtete Alternativen
| Alternative | Vorteile | Nachteile / Grund der Ablehnung |
|---|---|---|
| Modell auf der Appliance | Keine Datenweitergabe | RAM/GPU-Bedarf, vom Auftraggeber ausgeschlossen |
| Freie Textantwort | Einfach | Halluzinationen nicht prüfbar |

## Konsequenzen
- Mehr Anbieter-Adapter und Tests
- Aussagen ohne gültigen Beleg werden verworfen oder als Vermutung markiert

## Referenzen
- [Spezifikation](../spec/SPEC.md), Abschnitte 4.12, 4.15, 4.16, [Konzeptrunde 6](../KONZEPTRUNDE-6.md)
