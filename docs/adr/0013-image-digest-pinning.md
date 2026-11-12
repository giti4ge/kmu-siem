# ADR-0013: Image-Digest-Pinning im signierten Manifest

| Status | Datum | Entscheider |
|---|---|---|
| Akzeptiert | 2026-11-12 | Auftraggeber / Entwicklung |

## Kontext
Eine Signatur auf release.json schützt nicht, wenn Images per Tag aus einer manipulierbaren Registry geladen werden.

## Entscheidung
Das signierte Manifest enthält die SHA-256-Digests aller Images; Pull ausschließlich per Digest.

## Betrachtete Alternativen
| Alternative | Vorteile | Nachteile / Grund der Ablehnung |
|---|---|---|
| Tags + Content Trust | Bekannt | Zusätzliche Infrastruktur, schwächer |

## Konsequenzen
- Registry-Manipulation wirkungslos
- Manifest-Erzeugung in der CI erforderlich

## Referenzen
- [Spezifikation](../spec/SPEC.md), Abschnitt 4.14
