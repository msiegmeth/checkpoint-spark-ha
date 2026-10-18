# Check Point Quantum Spark für Home Assistant

🇬🇧 [English version](README.md)

Custom-Integration, die die **Security Reports** eines lokal verwalteten
**Check Point Quantum Spark** Gateways (Gaia Embedded, R81.10.x / R82.00.x)
über die lokale REST API ausliest und die Kennzahlen als Sensoren in Home
Assistant bereitstellt.

- Nur lokal (local polling), keine Cloud, keine externen Python-Pakete
- **Nur lesend**: verwendet werden ausschließlich `login`, `generate-report`,
  `logout` und Clish-Befehle, die mit `show` beginnen. Die
  Gateway-Konfiguration wird nie verändert.
- Pro Abruf eine kurze Session mit Logout – es wird keine Session gehalten.

> Community-Projekt, keine Verbindung zu Check Point Software Technologies Ltd.

## Voraussetzungen

- Quantum Spark, **lokal verwaltet** (nicht SMP/Cloud)
- Firmware R81.10.x oder R82.00.x
- REST API am Gateway aktiv (`set rest-api mode on` in Clish)
- Eigener Administrator, idealerweise mit Rolle **Read-only**
- **2FA für Administratoren aus** – die REST API kann keinen zweiten Faktor
  (siehe [Gateway-Setup](docs/gateway-setup.md#3-two-factor-authentication-2fa))
- Home Assistant 2025.8 oder neuer

Einrichtung am Gateway: [docs/gateway-setup.md](docs/gateway-setup.md)

## Installation

### HACS (empfohlen)

[![Repository in HACS öffnen](https://my.home-assistant.io/badges/hacs_repository.svg)](https://my.home-assistant.io/redirect/hacs_repository/?owner=msiegmeth&repository=checkpoint-spark-ha&category=integration)

1. Button oben klicken (oder in HACS: ⋮ → **Benutzerdefinierte Repositories**,
   Repository `https://github.com/msiegmeth/checkpoint-spark-ha`, Typ **Integration**).
2. **Herunterladen** klicken und bestätigen.
3. Home Assistant neu starten (**Einstellungen → System → ⋮ → Neu starten**).

Neue Releases werden danach in Home Assistant als Update angeboten.

### Manuell

1. Beim neuesten [Release](https://github.com/msiegmeth/checkpoint-spark-ha/releases/latest)
   `Source code (zip)` herunterladen und entpacken.
2. Den Ordner `custom_components/checkpoint_spark` in den Ordner
   `custom_components` der HA-Konfiguration kopieren (bei Bedarf anlegen).
   Ergebnis: `<config>/custom_components/checkpoint_spark/manifest.json`.
   Wege: Samba-Freigabe, SSH-/Terminal-Add-on oder Studio Code Server.
3. Home Assistant neu starten.

Manuelle Installationen werden **nicht** automatisch aktualisiert – für ein
neues Release die Schritte wiederholen.

## Konfiguration

[![Einrichtung in Home Assistant starten](https://my.home-assistant.io/badges/config_flow_start.svg)](https://my.home-assistant.io/redirect/config_flow_start/?domain=checkpoint_spark)

Button oben klicken oder **Einstellungen → Geräte & Dienste → Integration
hinzufügen → Check Point Quantum Spark**. Fehlt die Integration in der Liste,
die Browserseite neu laden (die Liste wird zwischengespeichert).

| Feld | Standard | Beschreibung |
|---|---|---|
| Host / IP | – | Adresse des Gateways, z. B. `192.168.1.1` |
| Port | `4434` | Port der REST API |
| Benutzername / Passwort | – | Administrator am Gateway |
| SSL-Zertifikat prüfen | aus | Spark nutzt standardmäßig ein selbstsigniertes Zertifikat |

Der Login wird beim Einrichten geprüft. Ändert sich das Passwort später,
fordert Home Assistant zur erneuten Anmeldung auf.

### Optionen

| Option | Standard | Bereich |
|---|---|---|
| Report-Typen | `daily` | `hourly`, `daily`, `weekly`, `monthly` (mindestens einer) |
| Abfrageintervall | 15 min | 5 – 1440 min |

## Zwei-Faktor-Authentifizierung (2FA)

Der API-Login kennt nur Benutzer und Passwort. Ist am Gateway 2FA für
Administratoren aktiv, scheitert **jeder** API-Login (Meldung „Benutzername oder
Passwort falsch“). 2FA ist ein globaler Schalter ohne dokumentierte Ausnahmen;
abschalten per SSH in Clish als Super-Administrator: `set admin-2fa off`
(die WebUI verweigert das teils mit „no privileges“). Zum Ausgleich den
Admin-Zugriff auf wenige vertrauenswürdige IPs beschränken.

## Dashboard-Karte

Die Integration bringt eine eigene Karte mit: *Karte hinzufügen* → **Check Point
Quantum Spark** → Gateway wählen. Zeitraum 1 h / 24 h / 7 Tage / 30 Tage,
Reiter Traffic, Threat Prevention (Filter Art/Richtung/Schwere, Ereignisse je
Meldung und Host zusammengefasst) und System. Marken-Icons von Simple Icons (CC0).

## Syslog am Spark einstellen

Log-Server/Syslog auf die IP von Home Assistant, Port wie in der Integration
(Standard **5140**), **UDP**, **System-Logs** und **Security-Logs** senden.
Optional *Show obfuscated fields* (mehr Details, aber auch mehr persönliche
Daten). Details: [docs/gateway-setup.md](docs/gateway-setup.md#5-syslog-for-real-time-events-optional).

## Entitäten, Dashboard, Diagnose

Siehe [README.md](README.md) – Tabellen und Hinweise gelten gleich.

## Lizenz

[MIT](LICENSE)
