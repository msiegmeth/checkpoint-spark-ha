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
- Home Assistant 2025.8 oder neuer

Einrichtung am Gateway: [docs/gateway-setup.md](docs/gateway-setup.md)

## Installation

### HACS (empfohlen)

1. HACS → ⋮ → **Benutzerdefinierte Repositories**
2. Repository `https://github.com/msiegmeth/checkpoint-spark-ha`, Typ **Integration**
3. **Check Point Quantum Spark** installieren, Home Assistant neu starten.

Neue Releases werden danach in Home Assistant als Update angeboten.

### Manuell

`custom_components/checkpoint_spark` in den Ordner `custom_components` der
HA-Konfiguration kopieren und neu starten.

## Konfiguration

**Einstellungen → Geräte & Dienste → Integration hinzufügen → Check Point Quantum Spark**

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

## Entitäten, Dashboard, Diagnose

Siehe [README.md](README.md) – Tabellen und Hinweise gelten gleich.

## Lizenz

[MIT](LICENSE)
