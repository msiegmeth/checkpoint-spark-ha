# CLAUDE.md – checkpoint-spark-ha

## Ziel
HA-Custom-Integration `checkpoint_spark`: liest über die lokale REST API eines
lokal verwalteten Check Point Quantum Spark die Security Reports
(`generate-report`), stellt Kennzahlen als Sensoren bereit, Beispiel-Dashboard
unter `examples/`.

## API
Siehe `docs/api.md`. Kurz: POST `https://<host>:4434/web-api/<cmd>`, Header
`x-chkp-sid` nach `login`; `reportData` = base64-JSON, Antwort Objekt oder
Liste; Fehllogin 400 oder 401.

## Layout
HACS-kompatibel: `custom_components/checkpoint_spark/` im Root, `docs/`,
`examples/`, `.github/workflows/` (hassfest + HACS-Validierung, Release bei Tag).

## Entwicklungsablauf
- Test einer Entwicklungsversion: `custom_components/checkpoint_spark` dieses Repos in eine
  HA-Testinstanz verlinken (relativer Symlink, falls HA in einem anderen Container läuft),
  HA neu starten. Report-Struktur über Diagnostics ansehen.
- Tests: `pip install -r requirements_test.txt && pytest` (laufen auch in GitHub Actions).
- Release: `manifest.json`-Version + **lesbarer** CHANGELOG-Abschnitt (Neu/Geändert/Behoben/
  Hinweise zum Update, für Nutzer geschrieben), Tag `vX.Y.Z`, push → GitHub-Action nimmt den
  Abschnitt als Release-Text (= Anzeige in HACS). Erst taggen, wenn die Tests grün sind.
- Versionierung: SemVer – PATCH = Fehlerbehebung, MINOR = neue Funktion, 1.0 = stabile Optionen/Entitäten.
- Installationsspezifische Hinweise (Pfade, Remotes, Zugang) stehen in `CLAUDE.local.md` (nicht im Repo).

## Regeln
- Am Gateway NUR `login`, `logout`, `generate-report` und Clish `show …`. Nie Config ändern.
- `show`-Ausgaben enthalten Geheimnisse (PPPoE-Passwort/-Hash, Setup-WLAN-Passwort): nur Whitelist-Felder
  übernehmen (`system.py`), Rohausgaben nie speichern, loggen oder committen.
- Tests: `tests/` (pytest-homeassistant-custom-component), laufen in GitHub Actions; erst taggen, wenn grün.
- Keine Zugangsdaten, Session-IDs oder ungeschwärzten Reportdaten committen.
  `docs/report-sample.json` nur anonymisiert (IPs, Hostnamen, Benutzer).
- Keine externen Requirements; aiohttp aus HA. Aktuelle HA-Konventionen
  (runtime_data, Coordinator mit config_entry, has_entity_name, Übersetzungen de/en).
- Große Attribute in `_unrecorded_attributes`.
