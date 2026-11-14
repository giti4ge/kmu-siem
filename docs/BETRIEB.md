# Betriebstagebuch

Je Erkenntnis aus dem Betrieb ein Eintrag: Beobachtung, Ursache, Änderung, Version.

**Ablauf Issue → Fixture → Release**

1. Auffälligkeit als Issue anlegen (Vorlagen: Parser-Format, Fehler, Wunsch).
2. Bei Parserfragen: im Web-UI unter *Nicht erkannte Quellen* „Probe exportieren“ (pseudonymisiert) und an das Issue anhängen; bei Fehlern: *System → Wartung → Diagnosepaket*.
3. Aus der Probe eine Fixture in `app/vector/tests/` erstellen (erst Test, dann Korrektur).
4. Korrektur per PR, CI grün, Release über den Beta- und danach den Stable-Kanal bzw. als Content-Paket.
5. Eintrag unten ergänzen.

| Datum | Beobachtung | Ursache | Änderung | Version |
|---|---|---|---|---|
